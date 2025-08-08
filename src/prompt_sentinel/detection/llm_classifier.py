"""LLM-based classification with multi-provider support and optional caching."""

import asyncio
import hashlib
import json
import logging
from typing import Dict, List, Optional, Tuple
from prompt_sentinel.config.settings import settings
from prompt_sentinel.cache.cache_manager import cache_manager
from prompt_sentinel.providers.base import LLMProvider
from prompt_sentinel.providers.anthropic_provider import AnthropicProvider
from prompt_sentinel.providers.openai_provider import OpenAIProvider
from prompt_sentinel.providers.gemini_provider import GeminiProvider
from prompt_sentinel.models.schemas import (
    Message,
    DetectionCategory,
    DetectionReason,
    Verdict
)

logger = logging.getLogger(__name__)


class LLMClassifierManager:
    """Manages multiple LLM providers with failover support."""
    
    def __init__(self, provider_order: Optional[List[str]] = None):
        """
        Initialize the classifier manager.
        
        Args:
            provider_order: Optional override for provider order
        """
        self.provider_order = provider_order or settings.llm_providers
        self.providers: Dict[str, LLMProvider] = {}
        self._initialize_providers()
    
    def _initialize_providers(self):
        """Initialize configured providers."""
        provider_classes = {
            "anthropic": AnthropicProvider,
            "openai": OpenAIProvider,
            "gemini": GeminiProvider,
        }
        
        for provider_name in self.provider_order:
            config = settings.get_provider_config(provider_name)
            
            if config.get("api_key") and provider_name in provider_classes:
                try:
                    provider_class = provider_classes[provider_name]
                    self.providers[provider_name] = provider_class(config)
                    print(f"Initialized {provider_name} provider")
                except Exception as e:
                    print(f"Failed to initialize {provider_name}: {e}")
    
    async def classify(
        self,
        messages: List[Message],
        use_all_providers: bool = False,
        use_cache: bool = True
    ) -> Tuple[Verdict, List[DetectionReason], float]:
        """Classify messages using LLM providers with optional caching.
        
        Sends messages to LLM providers for injection detection analysis.
        Results are cached to reduce API calls and improve performance.
        Can either use the first available provider or aggregate results
        from all providers for higher confidence.
        
        Args:
            messages: List of messages to analyze for injection attempts
            use_all_providers: If True, query all providers and combine results
            use_cache: Whether to use caching (default: True)
            
        Returns:
            Tuple containing:
            - verdict: Classification result (ALLOW/FLAG/BLOCK)
            - reasons: List of detection reasons from LLM analysis
            - confidence: Confidence score from the LLM (0.0-1.0)
            
        Example:
            >>> messages = [Message(role=Role.USER, content=\"Hello\")]
            >>> verdict, reasons, conf = await manager.classify(messages)
            >>> print(verdict)
            Verdict.ALLOW
        """
        if not self.providers:
            # No providers available, return benign
            logger.warning("No LLM providers available for classification")
            return (Verdict.ALLOW, [], 0.0)
        
        # If caching is enabled and not using all providers, try cache
        if use_cache and not use_all_providers and cache_manager.enabled:
            cache_key = self._generate_cache_key(messages)
            
            # Use cache manager's get_or_compute for automatic fallback
            result = await cache_manager.get_or_compute(
                key=cache_key,
                compute_func=lambda: self._classify_with_failover(messages),
                ttl=settings.cache_ttl_llm,
                cache_on_error=True  # Return stale cache if all LLMs fail
            )
            
            # Log cache hit if applicable
            if isinstance(result, tuple) and len(result) == 3:
                if hasattr(result[1], '__iter__') and any(
                    getattr(r, '_cache_hit', False) for r in result[1] if hasattr(r, '_cache_hit')
                ):
                    logger.debug("LLM classification cache hit")
            
            return result
        
        # No caching or using all providers
        if use_all_providers:
            return await self._classify_with_all_providers(messages)
        else:
            return await self._classify_with_failover(messages)
    
    async def _classify_with_failover(
        self,
        messages: List[Message]
    ) -> Tuple[Verdict, List[DetectionReason], float]:
        """
        Classify using providers in order with failover.
        
        Args:
            messages: Messages to classify
            
        Returns:
            Tuple of (verdict, reasons, confidence)
        """
        for provider_name in self.provider_order:
            if provider_name not in self.providers:
                continue
            
            provider = self.providers[provider_name]
            
            try:
                category, confidence, explanation = await provider.classify(messages)
                
                # Create detection reason
                reason = DetectionReason(
                    category=category,
                    description=explanation,
                    confidence=confidence,
                    source="llm",
                    patterns_matched=[f"{provider_name}_classification"]
                )
                
                # Determine verdict based on category and confidence
                verdict = self._determine_verdict(category, confidence)
                
                return (verdict, [reason], confidence)
                
            except Exception as e:
                print(f"Provider {provider_name} failed: {e}")
                continue
        
        # All providers failed
        return (Verdict.ALLOW, [], 0.0)
    
    async def _classify_with_all_providers(
        self,
        messages: List[Message]
    ) -> Tuple[Verdict, List[DetectionReason], float]:
        """
        Classify using all available providers and aggregate results.
        
        Args:
            messages: Messages to classify
            
        Returns:
            Tuple of (verdict, reasons, confidence)
        """
        tasks = []
        provider_names = []
        
        for provider_name, provider in self.providers.items():
            tasks.append(provider.classify(messages))
            provider_names.append(provider_name)
        
        if not tasks:
            return (Verdict.ALLOW, [], 0.0)
        
        # Run all classifications in parallel
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        reasons = []
        confidences = []
        categories = []
        
        for provider_name, result in zip(provider_names, results):
            if isinstance(result, Exception):
                print(f"Provider {provider_name} failed: {result}")
                continue
            
            category, confidence, explanation = result
            
            reasons.append(DetectionReason(
                category=category,
                description=f"[{provider_name}] {explanation}",
                confidence=confidence,
                source="llm",
                patterns_matched=[f"{provider_name}_classification"]
            ))
            
            confidences.append(confidence)
            categories.append(category)
        
        if not confidences:
            return (Verdict.ALLOW, [], 0.0)
        
        # Aggregate confidence (weighted average with boost for consensus)
        avg_confidence = sum(confidences) / len(confidences)
        
        # Boost confidence if multiple providers agree
        if len(set(categories)) == 1 and categories[0] != DetectionCategory.BENIGN:
            avg_confidence = min(1.0, avg_confidence * 1.2)
        
        # Get most severe category
        most_severe_category = self._get_most_severe_category(categories)
        
        # Determine verdict
        verdict = self._determine_verdict(most_severe_category, avg_confidence)
        
        return (verdict, reasons, avg_confidence)
    
    def _determine_verdict(self, category: DetectionCategory, confidence: float) -> Verdict:
        """
        Determine verdict based on category and confidence.
        
        Args:
            category: Detection category
            confidence: Confidence score
            
        Returns:
            Verdict
        """
        if category == DetectionCategory.BENIGN:
            return Verdict.ALLOW
        
        # Severity mapping
        high_severity = [
            DetectionCategory.DIRECT_INJECTION,
            DetectionCategory.JAILBREAK,
            DetectionCategory.PROMPT_LEAK
        ]
        
        medium_severity = [
            DetectionCategory.INDIRECT_INJECTION,
            DetectionCategory.ROLE_MANIPULATION,
            DetectionCategory.CONTEXT_SWITCHING
        ]
        
        # Determine based on severity and confidence
        if category in high_severity:
            if confidence >= 0.7:
                return Verdict.BLOCK
            elif confidence >= 0.5:
                return Verdict.STRIP
            else:
                return Verdict.FLAG
        elif category in medium_severity:
            if confidence >= 0.8:
                return Verdict.BLOCK
            elif confidence >= 0.6:
                return Verdict.STRIP
            else:
                return Verdict.FLAG
        else:
            # Low severity (encoding attacks, etc.)
            if confidence >= 0.9:
                return Verdict.STRIP
            elif confidence >= 0.7:
                return Verdict.FLAG
            else:
                return Verdict.ALLOW
    
    def _get_most_severe_category(self, categories: List[DetectionCategory]) -> DetectionCategory:
        """
        Get the most severe category from a list.
        
        Args:
            categories: List of detection categories
            
        Returns:
            Most severe category
        """
        severity_order = [
            DetectionCategory.DIRECT_INJECTION,
            DetectionCategory.JAILBREAK,
            DetectionCategory.PROMPT_LEAK,
            DetectionCategory.INDIRECT_INJECTION,
            DetectionCategory.ROLE_MANIPULATION,
            DetectionCategory.CONTEXT_SWITCHING,
            DetectionCategory.ENCODING_ATTACK,
            DetectionCategory.BENIGN
        ]
        
        for severity_cat in severity_order:
            if severity_cat in categories:
                return severity_cat
        
        return DetectionCategory.BENIGN
    
    async def health_check(self) -> Dict[str, bool]:
        """Check health status of all configured providers.
        
        Performs health checks on each provider to determine availability.
        Useful for monitoring and debugging provider issues.
        
        Returns:
            Dictionary mapping provider names to health status (True if healthy)
        """
        health_status = {}
        
        for provider_name, provider in self.providers.items():
            try:
                is_healthy = await provider.health_check()
                health_status[provider_name] = is_healthy
            except:
                health_status[provider_name] = False
        
        return health_status
    
    def _generate_cache_key(self, messages: List[Message]) -> str:
        """Generate a cache key from messages for LLM classification.
        
        Creates a deterministic cache key based on message content and roles.
        Truncates long content to avoid excessively long keys while maintaining
        uniqueness for different prompts.
        
        Args:
            messages: List of messages to generate key from
            
        Returns:
            Cache key string with format "llm_classify:{hash}"
        """
        # Create a deterministic string representation
        content_parts = []
        for msg in messages:
            # Include role and truncated content for key generation
            content_preview = msg.content[:200] if len(msg.content) > 200 else msg.content
            content_parts.append(f"{msg.role.value}:{content_preview}")
        
        # Include detection mode in key for different configurations
        content_parts.append(f"mode:{settings.detection_mode}")
        
        # Create hash of the combined content
        combined = "|".join(content_parts)
        content_hash = hashlib.sha256(combined.encode()).hexdigest()
        
        return f"llm_classify:{content_hash[:16]}"