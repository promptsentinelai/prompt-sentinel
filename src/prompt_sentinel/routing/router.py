# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Intelligent routing system for optimized prompt detection.

This module implements the core routing logic that determines the optimal
detection strategy based on prompt complexity analysis. It balances security
requirements with performance by routing simple prompts through fast paths
and complex prompts through comprehensive analysis.
"""

import asyncio
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any

import structlog

from prompt_sentinel.cache.cache_manager import cache_manager
from prompt_sentinel.config.settings import settings
from prompt_sentinel.detection.detector import PromptDetector

# Import experiment components
from prompt_sentinel.experiments import ExperimentManager
from prompt_sentinel.experiments.assignments import AssignmentContext
from prompt_sentinel.models.schemas import (
    DetectionResponse,
    Message,
    Verdict,
)

from .complexity_analyzer import ComplexityAnalyzer, ComplexityLevel, ComplexityScore

logger = structlog.get_logger()


class DetectionStrategy(Enum):
    """Detection strategies with different performance/accuracy tradeoffs."""

    HEURISTIC_ONLY = "heuristic_only"  # Fastest, pattern matching only
    HEURISTIC_CACHED = "heuristic_cached"  # Fast with cache lookup
    HEURISTIC_LLM_CACHED = "heuristic_llm_cached"  # Balanced with cache
    HEURISTIC_LLM_PII = "heuristic_llm_pii"  # Comprehensive
    FULL_ANALYSIS = "full_analysis"  # Complete analysis, all methods


@dataclass
class RoutingDecision:
    """Routing decision with strategy and reasoning."""

    strategy: DetectionStrategy
    complexity_score: ComplexityScore
    estimated_latency_ms: float
    cache_eligible: bool
    reasoning: str
    experiment_id: str | None = None
    variant_id: str | None = None
    experiment_override: bool = False


@dataclass
class RoutingMetrics:
    """Metrics for routing performance monitoring."""

    total_requests: int = 0
    strategy_counts: dict[str, int] | None = None
    avg_complexity_score: float = 0.0
    cache_hit_rate: float = 0.0
    avg_latency_by_strategy: dict[str, float] | None = None

    def __post_init__(self):
        if self.strategy_counts is None:
            self.strategy_counts = {}
        if self.avg_latency_by_strategy is None:
            self.avg_latency_by_strategy = {}


class IntelligentRouter:
    """Routes detection requests based on complexity analysis.

    The router analyzes prompt complexity and selects the optimal
    detection strategy, considering:
    - Prompt complexity and risk indicators
    - Current system load
    - Cache availability
    - Performance requirements
    - Security policy
    """

    def __init__(
        self,
        detector: PromptDetector | None = None,
        experiment_manager: ExperimentManager | None = None,
    ):
        """Initialize the intelligent router.

        Args:
            detector: Optional PromptDetector instance (creates new if not provided)
            experiment_manager: Optional ExperimentManager for A/B testing
        """
        self.detector = detector or PromptDetector()
        self.analyzer = ComplexityAnalyzer()
        self.metrics = RoutingMetrics()
        self.experiment_manager = experiment_manager

        # Strategy configuration
        self.strategy_config = self._load_strategy_config()

        # Performance targets (milliseconds)
        self.latency_targets = {
            DetectionStrategy.HEURISTIC_ONLY: 10,
            DetectionStrategy.HEURISTIC_CACHED: 15,
            DetectionStrategy.HEURISTIC_LLM_CACHED: 50,
            DetectionStrategy.HEURISTIC_LLM_PII: 500,
            DetectionStrategy.FULL_ANALYSIS: 2000,
        }

    async def route_detection(
        self,
        messages: list[Message],
        user_id: str | None = None,
        session_id: str | None = None,
        user_context: dict[str, Any] | None = None,
        override_strategy: DetectionStrategy | None = None,
        performance_mode: bool = False,
    ) -> tuple[DetectionResponse, RoutingDecision]:
        """Route detection request through optimal strategy.

        Args:
            messages: Messages to analyze
            user_id: User identifier for experiment assignment
            session_id: Session identifier for context
            user_context: Additional user attributes for targeting
            override_strategy: Optional strategy override for testing
            performance_mode: Prioritize performance over security

        Returns:
            Tuple of (detection response, routing decision)
        """
        start_time = time.time()

        # Analyze complexity
        complexity_score = self.analyzer.analyze(messages)

        # Check for active experiments
        experiment_id = None
        variant_id = None
        experiment_override = False

        if self.experiment_manager and user_id:
            experiment_strategy = await self._check_experiments(
                user_id, session_id, user_context, messages, complexity_score
            )
            if experiment_strategy:
                strategy, reasoning, experiment_id, variant_id = experiment_strategy
                experiment_override = True
            else:
                # Use standard routing logic
                if override_strategy:
                    strategy = override_strategy
                    reasoning = f"Strategy overridden to {override_strategy.value}"
                else:
                    strategy, reasoning = self._determine_strategy(
                        complexity_score, performance_mode
                    )
        else:
            # No experiments or user_id - use standard routing
            if override_strategy:
                strategy = override_strategy
                reasoning = f"Strategy overridden to {override_strategy.value}"
            else:
                strategy, reasoning = self._determine_strategy(complexity_score, performance_mode)

        # Check cache eligibility
        cache_eligible = self._is_cache_eligible(strategy, complexity_score)

        # Create routing decision
        decision = RoutingDecision(
            strategy=strategy,
            complexity_score=complexity_score,
            estimated_latency_ms=self.latency_targets[strategy],
            cache_eligible=cache_eligible,
            reasoning=reasoning,
            experiment_id=experiment_id,
            variant_id=variant_id,
            experiment_override=experiment_override,
        )

        # Log routing decision
        logger.info(
            "Routing decision made",
            strategy=strategy.value,
            complexity_level=complexity_score.level.value,
            complexity_score=round(complexity_score.score, 2),
            risk_indicators=[r.value for r in complexity_score.risk_indicators],
            cache_eligible=cache_eligible,
            experiment_id=experiment_id,
            variant_id=variant_id,
            experiment_override=experiment_override,
        )

        # Execute detection with selected strategy
        response = await self._execute_strategy(messages, strategy, cache_eligible)

        # Update metrics
        self._update_metrics(strategy, complexity_score, time.time() - start_time)

        # Record experiment metrics if applicable
        if experiment_id and variant_id and user_id:
            await self._record_experiment_metrics(
                experiment_id,
                variant_id,
                user_id,
                response,
                complexity_score,
                strategy,
                time.time() - start_time,
            )

        # Add routing metadata to response
        response.metadata = response.metadata or {}
        routing_metadata = {
            "strategy": strategy.value,
            "complexity_level": complexity_score.level.value,
            "complexity_score": round(complexity_score.score, 2),
            "cache_eligible": cache_eligible,
            "routing_latency_ms": round((time.time() - start_time) * 1000, 2),
        }

        if experiment_id:
            routing_metadata.update(
                {
                    "experiment_id": experiment_id,
                    "variant_id": variant_id or "",
                    "experiment_override": experiment_override,
                }
            )

        response.metadata["routing"] = routing_metadata

        return response, decision

    def _determine_strategy(
        self, complexity_score: ComplexityScore, performance_mode: bool
    ) -> tuple[DetectionStrategy, str]:
        """Determine optimal detection strategy.

        Args:
            complexity_score: Complexity analysis results
            performance_mode: Whether to prioritize performance

        Returns:
            Tuple of (strategy, reasoning)
        """
        # In performance mode, use lighter strategies
        if performance_mode:
            if complexity_score.level == ComplexityLevel.TRIVIAL:
                return DetectionStrategy.HEURISTIC_ONLY, "Performance mode: trivial complexity"
            elif complexity_score.level == ComplexityLevel.SIMPLE:
                return DetectionStrategy.HEURISTIC_CACHED, "Performance mode: simple complexity"
            elif complexity_score.level == ComplexityLevel.MODERATE:
                return (
                    DetectionStrategy.HEURISTIC_LLM_CACHED,
                    "Performance mode: moderate complexity",
                )
            else:
                # Even in performance mode, high-risk prompts need thorough analysis
                return (
                    DetectionStrategy.HEURISTIC_LLM_PII,
                    "Performance mode: high complexity requires analysis",
                )

        # Standard mode: map complexity to strategy
        strategy_map = {
            ComplexityLevel.TRIVIAL: DetectionStrategy.HEURISTIC_CACHED,
            ComplexityLevel.SIMPLE: DetectionStrategy.HEURISTIC_CACHED,
            ComplexityLevel.MODERATE: DetectionStrategy.HEURISTIC_LLM_CACHED,
            ComplexityLevel.COMPLEX: DetectionStrategy.HEURISTIC_LLM_PII,
            ComplexityLevel.CRITICAL: DetectionStrategy.FULL_ANALYSIS,
        }

        strategy = strategy_map[complexity_score.level]

        # Override based on risk indicators
        from .complexity_analyzer import RiskIndicator

        critical_risks = [
            RiskIndicator.INSTRUCTION_OVERRIDE,
            RiskIndicator.CODE_INJECTION,
            RiskIndicator.ROLE_MANIPULATION,
        ]

        if any(risk in critical_risks for risk in complexity_score.risk_indicators):
            if strategy.value < DetectionStrategy.HEURISTIC_LLM_PII.value:
                strategy = DetectionStrategy.HEURISTIC_LLM_PII
                return strategy, f"Elevated to {strategy.value} due to critical risk indicators"

        # Check if features are enabled
        if not settings.llm_classification_enabled and strategy in [
            DetectionStrategy.HEURISTIC_LLM_CACHED,
            DetectionStrategy.HEURISTIC_LLM_PII,
            DetectionStrategy.FULL_ANALYSIS,
        ]:
            strategy = DetectionStrategy.HEURISTIC_ONLY
            return strategy, "LLM classification disabled, using heuristic only"

        if not settings.pii_detection_enabled and strategy == DetectionStrategy.HEURISTIC_LLM_PII:
            strategy = DetectionStrategy.HEURISTIC_LLM_CACHED
            return strategy, "PII detection disabled, using cached LLM strategy"

        return (
            strategy,
            f"Standard routing: {complexity_score.level.value} complexity → {strategy.value}",
        )

    def _is_cache_eligible(
        self, strategy: DetectionStrategy, complexity_score: ComplexityScore
    ) -> bool:
        """Determine if result can be cached.

        Args:
            strategy: Detection strategy
            complexity_score: Complexity analysis

        Returns:
            True if result can be cached
        """
        # Don't cache if caching is disabled
        if not settings.redis_enabled or not cache_manager.connected:
            return False

        # Don't cache trivial heuristic-only detections (too fast anyway)
        if strategy == DetectionStrategy.HEURISTIC_ONLY:
            return False

        # Don't cache if there are encoding indicators (might be dynamic)
        from .complexity_analyzer import RiskIndicator

        if RiskIndicator.ENCODING in complexity_score.risk_indicators:
            return False

        # Cache strategies that benefit from it
        return strategy in [
            DetectionStrategy.HEURISTIC_CACHED,
            DetectionStrategy.HEURISTIC_LLM_CACHED,
            DetectionStrategy.HEURISTIC_LLM_PII,
        ]

    async def _execute_strategy(
        self, messages: list[Message], strategy: DetectionStrategy, use_cache: bool
    ) -> DetectionResponse:
        """Execute detection with specified strategy.

        Args:
            messages: Messages to analyze
            strategy: Detection strategy to use
            use_cache: Whether to use caching

        Returns:
            Detection response
        """
        # Build cache key if caching is enabled
        cache_key = None
        if use_cache:
            content = " ".join(msg.content for msg in messages)
            cache_key = f"route_{strategy.value}_{hash(content)}"

            # Try cache lookup
            cached_result = await cache_manager.get(cache_key)
            if cached_result:
                logger.debug("Cache hit for routed detection", strategy=strategy.value)
                # Convert cached dict to DetectionResponse
                return DetectionResponse(**cached_result)

        # Execute detection based on strategy
        if strategy == DetectionStrategy.HEURISTIC_ONLY:
            response = await self._execute_heuristic_only(messages)

        elif strategy == DetectionStrategy.HEURISTIC_CACHED:
            response = await self._execute_heuristic_only(messages)

        elif strategy == DetectionStrategy.HEURISTIC_LLM_CACHED:
            response = await self._execute_heuristic_llm(messages)

        elif strategy == DetectionStrategy.HEURISTIC_LLM_PII:
            response = await self._execute_comprehensive(messages, include_pii=True)

        elif strategy == DetectionStrategy.FULL_ANALYSIS:
            response = await self._execute_full_analysis(messages)

        else:
            # Fallback to standard detection
            response = await self.detector.detect(messages)

        # Cache result if eligible
        if use_cache and cache_key:
            await cache_manager.set(cache_key, response.dict(), ttl=settings.cache_ttl_detection)

        return response

    async def _execute_heuristic_only(self, messages: list[Message]) -> DetectionResponse:
        """Execute heuristic detection only.

        Args:
            messages: Messages to analyze

        Returns:
            Detection response
        """
        # Use detector with LLM disabled
        return await self.detector.detect(
            messages, use_heuristics=True, use_llm=False, check_pii=False
        )

    async def _execute_heuristic_llm(self, messages: list[Message]) -> DetectionResponse:
        """Execute heuristic + LLM detection.

        Args:
            messages: Messages to analyze

        Returns:
            Detection response
        """
        return await self.detector.detect(
            messages, use_heuristics=True, use_llm=True, check_pii=False
        )

    async def _execute_comprehensive(
        self, messages: list[Message], include_pii: bool = True
    ) -> DetectionResponse:
        """Execute comprehensive detection.

        Args:
            messages: Messages to analyze
            include_pii: Whether to include PII detection

        Returns:
            Detection response
        """
        return await self.detector.detect(
            messages, use_heuristics=True, use_llm=True, check_pii=include_pii
        )

    async def _execute_full_analysis(self, messages: list[Message]) -> DetectionResponse:
        """Execute full analysis with all detection methods.

        Args:
            messages: Messages to analyze

        Returns:
            Detection response with comprehensive analysis
        """
        # Run all detection methods in parallel for speed
        tasks = [
            self.detector.detect(messages, use_heuristics=True, use_llm=False, check_pii=False),
            self.detector.detect(messages, use_heuristics=False, use_llm=True, check_pii=False),
            self.detector.detect(messages, use_heuristics=False, use_llm=False, check_pii=True),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Combine results
        all_reasons: list[Any] = []
        max_confidence = 0.0
        most_severe_verdict = Verdict.ALLOW

        for result in results:
            if isinstance(result, Exception | BaseException):
                logger.error("Detection method failed", error=str(result))
                continue

            if hasattr(result, "reasons"):
                all_reasons.extend(result.reasons)
            if hasattr(result, "confidence"):
                max_confidence = max(max_confidence, result.confidence)

            # Update verdict to most severe
            if hasattr(result, "verdict"):
                if result.verdict == Verdict.BLOCK:
                    most_severe_verdict = Verdict.BLOCK
                elif result.verdict == Verdict.FLAG and most_severe_verdict != Verdict.BLOCK:
                    most_severe_verdict = Verdict.FLAG

        # Create comprehensive response
        response = DetectionResponse(
            verdict=most_severe_verdict,
            confidence=max_confidence,
            reasons=all_reasons,
            processing_time_ms=sum(
                float(r.processing_time_ms)
                for r in results
                if not isinstance(r, Exception) and hasattr(r, "processing_time_ms")
            ),
        )

        return response

    def _update_metrics(
        self,
        strategy: DetectionStrategy,
        complexity_score: ComplexityScore,
        duration_seconds: float,
    ):
        """Update routing metrics.

        Args:
            strategy: Strategy used
            complexity_score: Complexity analysis results
            duration_seconds: Total processing time
        """
        self.metrics.total_requests += 1

        # Update strategy counts
        strategy_key = strategy.value
        if self.metrics.strategy_counts is None:
            self.metrics.strategy_counts = {}
        self.metrics.strategy_counts[strategy_key] = (
            self.metrics.strategy_counts.get(strategy_key, 0) + 1
        )

        # Update average complexity score
        self.metrics.avg_complexity_score = (
            self.metrics.avg_complexity_score * (self.metrics.total_requests - 1)
            + complexity_score.score
        ) / self.metrics.total_requests

        # Update latency by strategy
        latency_ms = duration_seconds * 1000
        if self.metrics.avg_latency_by_strategy is None:
            self.metrics.avg_latency_by_strategy = {}
        if strategy_key not in self.metrics.avg_latency_by_strategy:
            self.metrics.avg_latency_by_strategy[strategy_key] = latency_ms
        else:
            count = (
                self.metrics.strategy_counts[strategy_key] if self.metrics.strategy_counts else 1
            )
            self.metrics.avg_latency_by_strategy[strategy_key] = (
                self.metrics.avg_latency_by_strategy[strategy_key] * (count - 1) + latency_ms
            ) / count

    def get_metrics(self) -> dict[str, Any]:
        """Get current routing metrics.

        Returns:
            Dictionary of routing metrics
        """
        return {
            "total_requests": self.metrics.total_requests,
            "strategy_distribution": self.metrics.strategy_counts,
            "average_complexity_score": round(self.metrics.avg_complexity_score, 3),
            "average_latency_by_strategy_ms": {
                k: round(v, 2) for k, v in (self.metrics.avg_latency_by_strategy or {}).items()
            },
            "cache_hit_rate": self.metrics.cache_hit_rate,
        }

    def _load_strategy_config(self) -> dict:
        """Load strategy configuration from settings.

        Returns:
            Strategy configuration dictionary
        """
        # This could be extended to load from a config file or database
        return {
            "performance_thresholds": {
                "low_latency": 50,  # ms
                "medium_latency": 500,  # ms
                "high_latency": 2000,  # ms
            },
            "complexity_overrides": {
                # Map specific patterns to strategies
            },
        }

    async def _check_experiments(
        self,
        user_id: str,
        session_id: str | None,
        user_context: dict[str, Any] | None,
        messages: list[Message],
        complexity_score: ComplexityScore,
    ) -> tuple[DetectionStrategy, str, str, str] | None:
        """Check if user is part of any active routing experiments.

        Args:
            user_id: User identifier
            session_id: Session identifier
            user_context: User context attributes
            messages: Messages being analyzed
            complexity_score: Complexity analysis results

        Returns:
            Tuple of (strategy, reasoning, experiment_id, variant_id) or None
        """
        if not self.experiment_manager:
            return None

        # Check for active routing strategy experiments
        active_experiments = await self.experiment_manager.list_experiments(
            status_filter=None  # Will be filtered by active status in the method
        )

        for experiment_summary in active_experiments:
            experiment_id = experiment_summary["id"]
            if not experiment_summary.get("is_active", False):
                continue

            # Only process strategy experiments for routing
            if experiment_summary.get("type") != "strategy":
                continue

            # Create assignment context
            context = AssignmentContext(
                user_id=user_id, session_id=session_id, attributes=user_context or {}
            )

            # Get user assignment for this experiment
            assignment = await self.experiment_manager.assign_user(user_id, experiment_id, context)

            if assignment:
                # Get variant configuration
                variant_config = await self.experiment_manager.get_variant_config(
                    user_id, experiment_id
                )

                if variant_config and "strategy" in variant_config:
                    strategy_name = variant_config["strategy"]
                    try:
                        strategy = DetectionStrategy(strategy_name)
                        reasoning = f"Experiment {experiment_id}: {strategy_name}"
                        return strategy, reasoning, experiment_id, assignment.variant_id
                    except ValueError:
                        logger.warning(
                            "Invalid strategy in experiment variant",
                            experiment_id=experiment_id,
                            variant_id=assignment.variant_id,
                            strategy=strategy_name,
                        )

        return None

    async def _record_experiment_metrics(
        self,
        experiment_id: str,
        variant_id: str,
        user_id: str,
        response: DetectionResponse,
        complexity_score: ComplexityScore,
        strategy: DetectionStrategy,
        total_duration_seconds: float,
    ):
        """Record routing metrics for experiment analysis.

        Args:
            experiment_id: Experiment identifier
            variant_id: Variant identifier
            user_id: User identifier
            response: Detection response
            complexity_score: Complexity analysis
            strategy: Strategy used
            total_duration_seconds: Total processing time
        """
        if not self.experiment_manager:
            return

        try:
            # Record basic routing metrics
            await self.experiment_manager.record_metric(
                experiment_id, user_id, "routing_time_ms", total_duration_seconds * 1000
            )

            await self.experiment_manager.record_metric(
                experiment_id, user_id, "complexity_score", complexity_score.score
            )

            await self.experiment_manager.record_metric(
                experiment_id,
                user_id,
                "strategy_latency_target",
                float(self.latency_targets.get(strategy, 0)),
            )

            # Record detection results
            await self.experiment_manager.record_detection_result(
                experiment_id,
                user_id,
                response,
                {
                    "strategy": strategy.value,
                    "complexity_level": complexity_score.level.value,
                    "routing_latency_ms": total_duration_seconds * 1000,
                },
            )

            logger.debug(
                "Experiment metrics recorded",
                experiment_id=experiment_id,
                variant_id=variant_id,
                strategy=strategy.value,
            )

        except Exception as e:
            logger.error(
                "Failed to record experiment metrics", experiment_id=experiment_id, error=str(e)
            )

    def set_experiment_manager(self, experiment_manager: ExperimentManager):
        """Set or update the experiment manager.

        Args:
            experiment_manager: Experiment manager instance
        """
        self.experiment_manager = experiment_manager
        logger.info("Experiment manager set for intelligent router")

    async def get_experiment_routing_stats(self) -> dict[str, Any]:
        """Get routing statistics related to experiments.

        Returns:
            Experiment routing statistics
        """
        base_metrics = self.get_metrics()

        if not self.experiment_manager:
            return {**base_metrics, "experiments_enabled": False, "active_experiments": 0}

        # Get active experiment count
        experiments = await self.experiment_manager.list_experiments()
        active_count = sum(1 if exp.get("is_active", False) else 0 for exp in experiments)

        return {
            **base_metrics,
            "experiments_enabled": True,
            "active_experiments": active_count,
            "experiment_overrides": sum(
                1 for key in self.metrics.strategy_counts.keys() if "experiment" in key.lower()
            ),
        }
