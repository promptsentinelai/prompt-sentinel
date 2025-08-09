"""Tests for LLM provider failover mechanisms."""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timedelta

from prompt_sentinel.providers.base import LLMProvider, ProviderError
from prompt_sentinel.providers.anthropic_provider import AnthropicProvider
from prompt_sentinel.providers.openai_provider import OpenAIProvider
from prompt_sentinel.providers.gemini_provider import GeminiProvider
from prompt_sentinel.detection.llm_classifier import LLMClassifier
from prompt_sentinel.models.schemas import Message, Role, Verdict


class TestProviderFailover:
    """Test provider failover functionality."""

    @pytest.fixture
    def messages(self):
        """Create test messages."""
        return [
            Message(role=Role.USER, content="Test prompt for classification")
        ]

    @pytest.mark.asyncio
    async def test_primary_provider_success(self, messages):
        """Test successful primary provider call."""
        classifier = LLMClassifier(
            provider_order=["anthropic", "openai", "gemini"]
        )
        
        with patch.object(AnthropicProvider, "classify") as mock_classify:
            mock_classify.return_value = (Verdict.ALLOW, 0.95)
            
            verdict, confidence = await classifier.classify(messages)
            
            assert verdict == Verdict.ALLOW
            assert confidence == 0.95
            mock_classify.assert_called_once()

    @pytest.mark.asyncio
    async def test_failover_to_secondary(self, messages):
        """Test failover to secondary provider on primary failure."""
        classifier = LLMClassifier(
            provider_order=["anthropic", "openai", "gemini"]
        )
        
        with patch.object(AnthropicProvider, "classify") as mock_anthropic, \
             patch.object(OpenAIProvider, "classify") as mock_openai:
            
            # Primary fails
            mock_anthropic.side_effect = ProviderError("API error")
            # Secondary succeeds
            mock_openai.return_value = (Verdict.FLAG, 0.75)
            
            verdict, confidence = await classifier.classify(messages)
            
            assert verdict == Verdict.FLAG
            assert confidence == 0.75
            mock_anthropic.assert_called_once()
            mock_openai.assert_called_once()

    @pytest.mark.asyncio
    async def test_all_providers_fail(self, messages):
        """Test behavior when all providers fail."""
        classifier = LLMClassifier(
            provider_order=["anthropic", "openai", "gemini"]
        )
        
        with patch.object(AnthropicProvider, "classify") as mock_anthropic, \
             patch.object(OpenAIProvider, "classify") as mock_openai, \
             patch.object(GeminiProvider, "classify") as mock_gemini:
            
            # All providers fail
            mock_anthropic.side_effect = ProviderError("API error")
            mock_openai.side_effect = ProviderError("API error")
            mock_gemini.side_effect = ProviderError("API error")
            
            # Should fall back to heuristics or default
            verdict, confidence = await classifier.classify(messages)
            
            # Should return a safe default
            assert verdict in [Verdict.FLAG, Verdict.BLOCK]
            assert confidence <= 0.5

    @pytest.mark.asyncio
    async def test_provider_timeout_failover(self, messages):
        """Test failover on provider timeout."""
        classifier = LLMClassifier(
            provider_order=["anthropic", "openai"],
            timeout=1.0
        )
        
        async def slow_classify(*args):
            await asyncio.sleep(2.0)  # Longer than timeout
            return (Verdict.ALLOW, 0.9)
        
        with patch.object(AnthropicProvider, "classify") as mock_anthropic, \
             patch.object(OpenAIProvider, "classify") as mock_openai:
            
            mock_anthropic.side_effect = slow_classify
            mock_openai.return_value = (Verdict.ALLOW, 0.85)
            
            verdict, confidence = await classifier.classify(messages)
            
            # Should use secondary due to timeout
            assert verdict == Verdict.ALLOW
            assert confidence == 0.85

    @pytest.mark.asyncio
    async def test_provider_retry_logic(self, messages):
        """Test provider retry logic before failover."""
        classifier = LLMClassifier(
            provider_order=["anthropic"],
            max_retries=3,
            retry_delay=0.1
        )
        
        call_count = 0
        
        async def flaky_classify(*args):
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ProviderError("Temporary error")
            return (Verdict.ALLOW, 0.9)
        
        with patch.object(AnthropicProvider, "classify") as mock_classify:
            mock_classify.side_effect = flaky_classify
            
            verdict, confidence = await classifier.classify(messages)
            
            assert verdict == Verdict.ALLOW
            assert call_count == 3  # Failed twice, succeeded on third


class TestProviderHealthChecks:
    """Test provider health monitoring."""

    @pytest.mark.asyncio
    async def test_health_check_all_providers(self):
        """Test health checks for all providers."""
        providers = {
            "anthropic": AnthropicProvider(api_key="test"),
            "openai": OpenAIProvider(api_key="test"),
            "gemini": GeminiProvider(api_key="test")
        }
        
        for name, provider in providers.items():
            with patch.object(provider, "health_check") as mock_health:
                mock_health.return_value = True
                
                is_healthy = await provider.health_check()
                assert is_healthy is True

    @pytest.mark.asyncio
    async def test_unhealthy_provider_skipped(self):
        """Test that unhealthy providers are skipped."""
        classifier = LLMClassifier(
            provider_order=["anthropic", "openai"]
        )
        
        with patch.object(AnthropicProvider, "health_check") as mock_health, \
             patch.object(AnthropicProvider, "classify") as mock_classify, \
             patch.object(OpenAIProvider, "classify") as mock_openai:
            
            # First provider unhealthy
            mock_health.return_value = False
            mock_openai.return_value = (Verdict.ALLOW, 0.8)
            
            messages = [Message(role=Role.USER, content="Test")]
            verdict, confidence = await classifier.classify(messages)
            
            # Should skip unhealthy provider
            mock_classify.assert_not_called()
            mock_openai.assert_called_once()

    @pytest.mark.asyncio
    async def test_provider_recovery(self):
        """Test provider recovery after being unhealthy."""
        classifier = LLMClassifier(
            provider_order=["anthropic"],
            health_check_interval=1
        )
        
        health_status = False
        
        async def dynamic_health_check():
            return health_status
        
        with patch.object(AnthropicProvider, "health_check") as mock_health, \
             patch.object(AnthropicProvider, "classify") as mock_classify:
            
            mock_health.side_effect = dynamic_health_check
            mock_classify.return_value = (Verdict.ALLOW, 0.9)
            
            # Initially unhealthy
            health_status = False
            messages = [Message(role=Role.USER, content="Test")]
            
            # Should fail with unhealthy provider
            verdict, confidence = await classifier.classify(messages)
            mock_classify.assert_not_called()
            
            # Provider recovers
            health_status = True
            await asyncio.sleep(1.1)  # Wait for health check interval
            
            # Should work now
            verdict, confidence = await classifier.classify(messages)
            assert verdict == Verdict.ALLOW


class TestProviderLoadBalancing:
    """Test load balancing across providers."""

    @pytest.mark.asyncio
    async def test_round_robin_balancing(self):
        """Test round-robin load balancing."""
        classifier = LLMClassifier(
            provider_order=["anthropic", "openai"],
            load_balance_mode="round_robin"
        )
        
        call_counts = {"anthropic": 0, "openai": 0}
        
        async def count_anthropic(*args):
            call_counts["anthropic"] += 1
            return (Verdict.ALLOW, 0.9)
        
        async def count_openai(*args):
            call_counts["openai"] += 1
            return (Verdict.ALLOW, 0.85)
        
        with patch.object(AnthropicProvider, "classify", side_effect=count_anthropic), \
             patch.object(OpenAIProvider, "classify", side_effect=count_openai):
            
            messages = [Message(role=Role.USER, content="Test")]
            
            # Make multiple calls
            for _ in range(4):
                await classifier.classify(messages)
            
            # Should distribute evenly
            assert call_counts["anthropic"] == 2
            assert call_counts["openai"] == 2

    @pytest.mark.asyncio
    async def test_weighted_load_balancing(self):
        """Test weighted load balancing."""
        classifier = LLMClassifier(
            provider_order=["anthropic", "openai"],
            load_balance_mode="weighted",
            provider_weights={"anthropic": 3, "openai": 1}
        )
        
        call_counts = {"anthropic": 0, "openai": 0}
        
        async def count_calls(provider_name):
            async def counter(*args):
                call_counts[provider_name] += 1
                return (Verdict.ALLOW, 0.9)
            return counter
        
        with patch.object(AnthropicProvider, "classify") as mock_anthropic, \
             patch.object(OpenAIProvider, "classify") as mock_openai:
            
            mock_anthropic.side_effect = await count_calls("anthropic")
            mock_openai.side_effect = await count_calls("openai")
            
            messages = [Message(role=Role.USER, content="Test")]
            
            # Make multiple calls
            for _ in range(8):
                await classifier.classify(messages)
            
            # Should respect weights (approximately 3:1 ratio)
            assert call_counts["anthropic"] >= 5
            assert call_counts["openai"] <= 3


class TestProviderCostOptimization:
    """Test cost optimization strategies."""

    @pytest.mark.asyncio
    async def test_cost_aware_routing(self):
        """Test routing based on provider costs."""
        classifier = LLMClassifier(
            provider_order=["anthropic", "openai", "gemini"],
            optimize_for="cost",
            provider_costs={
                "anthropic": 0.01,
                "openai": 0.02,
                "gemini": 0.005
            }
        )
        
        with patch.object(GeminiProvider, "classify") as mock_gemini:
            mock_gemini.return_value = (Verdict.ALLOW, 0.85)
            
            messages = [Message(role=Role.USER, content="Simple test")]
            verdict, confidence = await classifier.classify(messages)
            
            # Should use cheapest provider for simple queries
            mock_gemini.assert_called_once()

    @pytest.mark.asyncio
    async def test_quality_vs_cost_tradeoff(self):
        """Test balancing quality and cost."""
        classifier = LLMClassifier(
            provider_order=["anthropic", "gemini"],
            optimize_for="balanced",
            min_confidence_threshold=0.8
        )
        
        with patch.object(GeminiProvider, "classify") as mock_gemini, \
             patch.object(AnthropicProvider, "classify") as mock_anthropic:
            
            # Cheap provider gives low confidence
            mock_gemini.return_value = (Verdict.ALLOW, 0.6)
            # Expensive provider gives high confidence
            mock_anthropic.return_value = (Verdict.ALLOW, 0.95)
            
            messages = [Message(role=Role.USER, content="Complex test")]
            verdict, confidence = await classifier.classify(messages)
            
            # Should escalate to better provider for confidence
            assert confidence >= 0.8
            mock_anthropic.assert_called_once()


class TestProviderCircuitBreaker:
    """Test circuit breaker pattern for providers."""

    @pytest.mark.asyncio
    async def test_circuit_breaker_opens(self):
        """Test circuit breaker opening on failures."""
        classifier = LLMClassifier(
            provider_order=["anthropic"],
            circuit_breaker_threshold=3,
            circuit_breaker_timeout=60
        )
        
        with patch.object(AnthropicProvider, "classify") as mock_classify:
            mock_classify.side_effect = ProviderError("API error")
            
            messages = [Message(role=Role.USER, content="Test")]
            
            # Fail multiple times
            for _ in range(3):
                try:
                    await classifier.classify(messages)
                except:
                    pass
            
            # Circuit should be open, no more calls
            try:
                await classifier.classify(messages)
            except:
                pass
            
            # Should not exceed threshold calls
            assert mock_classify.call_count == 3

    @pytest.mark.asyncio
    async def test_circuit_breaker_recovery(self):
        """Test circuit breaker recovery."""
        classifier = LLMClassifier(
            provider_order=["anthropic"],
            circuit_breaker_threshold=2,
            circuit_breaker_timeout=1  # 1 second timeout
        )
        
        call_count = 0
        
        async def flaky_provider(*args):
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                raise ProviderError("Error")
            return (Verdict.ALLOW, 0.9)
        
        with patch.object(AnthropicProvider, "classify") as mock_classify:
            mock_classify.side_effect = flaky_provider
            
            messages = [Message(role=Role.USER, content="Test")]
            
            # Trip the circuit breaker
            for _ in range(2):
                try:
                    await classifier.classify(messages)
                except:
                    pass
            
            # Wait for recovery
            await asyncio.sleep(1.5)
            
            # Should work now
            verdict, confidence = await classifier.classify(messages)
            assert verdict == Verdict.ALLOW


if __name__ == "__main__":
    pytest.main([__file__, "-v"])