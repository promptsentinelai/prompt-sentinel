"""Comprehensive tests for usage tracking module."""

import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from prompt_sentinel.monitoring.usage_tracker import (
    ApiCall,
    Provider,
    TokenUsage,
    UsageMetrics,
    UsageTracker,
)


class TestProvider:
    """Test suite for Provider enum."""

    def test_provider_values(self):
        """Test provider enum values."""
        assert Provider.ANTHROPIC.value == "anthropic"
        assert Provider.OPENAI.value == "openai"
        assert Provider.GEMINI.value == "gemini"
        assert Provider.HEURISTIC.value == "heuristic"
        assert Provider.CACHE.value == "cache"


class TestTokenUsage:
    """Test suite for TokenUsage dataclass."""

    def test_initialization_with_values(self):
        """Test token usage initialization with explicit values."""
        tokens = TokenUsage(prompt_tokens=100, completion_tokens=50, total_tokens=150)
        
        assert tokens.prompt_tokens == 100
        assert tokens.completion_tokens == 50
        assert tokens.total_tokens == 150

    def test_initialization_with_auto_total(self):
        """Test token usage initialization with auto-calculated total."""
        tokens = TokenUsage(prompt_tokens=100, completion_tokens=50)
        
        assert tokens.prompt_tokens == 100
        assert tokens.completion_tokens == 50
        assert tokens.total_tokens == 150

    def test_initialization_defaults(self):
        """Test token usage initialization with defaults."""
        tokens = TokenUsage()
        
        assert tokens.prompt_tokens == 0
        assert tokens.completion_tokens == 0
        assert tokens.total_tokens == 0


class TestApiCall:
    """Test suite for ApiCall dataclass."""

    def test_initialization(self):
        """Test API call initialization."""
        tokens = TokenUsage(prompt_tokens=100, completion_tokens=50)
        timestamp = datetime.now()
        
        call = ApiCall(
            provider=Provider.ANTHROPIC,
            model="claude-3-haiku-20240307",
            timestamp=timestamp,
            tokens=tokens,
            latency_ms=150.5,
            cost_usd=0.025,
            success=True,
            endpoint="/v1/messages",
            metadata={"request_id": "req_123"}
        )
        
        assert call.provider == Provider.ANTHROPIC
        assert call.model == "claude-3-haiku-20240307"
        assert call.timestamp == timestamp
        assert call.tokens == tokens
        assert call.latency_ms == 150.5
        assert call.cost_usd == 0.025
        assert call.success is True
        assert call.endpoint == "/v1/messages"
        assert call.metadata["request_id"] == "req_123"


class TestUsageMetrics:
    """Test suite for UsageMetrics dataclass."""

    def test_default_initialization(self):
        """Test usage metrics default initialization."""
        metrics = UsageMetrics()
        
        assert metrics.total_requests == 0
        assert metrics.successful_requests == 0
        assert metrics.failed_requests == 0
        assert metrics.total_tokens == 0
        assert metrics.total_cost_usd == 0.0
        assert metrics.avg_latency_ms == 0.0
        assert metrics.cache_hits == 0
        assert metrics.cache_hit_rate == 0.0
        assert isinstance(metrics.by_provider, dict)
        assert len(metrics.by_provider) == 0

    def test_custom_initialization(self):
        """Test usage metrics with custom values."""
        metrics = UsageMetrics(
            total_requests=100,
            successful_requests=95,
            failed_requests=5,
            total_tokens=10000,
            total_cost_usd=15.50,
            avg_latency_ms=125.5,
            cache_hits=20,
            cache_hit_rate=0.2,
            by_provider={"anthropic": {"requests": 50}},
            requests_per_minute=5.0,
            tokens_per_minute=500.0,
            cost_per_hour=7.75,
            current_minute_requests=5,
            current_hour_cost=1.5,
            current_day_cost=12.25,
            current_month_cost=150.0
        )
        
        assert metrics.total_requests == 100
        assert metrics.successful_requests == 95
        assert metrics.failed_requests == 5
        assert metrics.total_tokens == 10000
        assert metrics.total_cost_usd == 15.50
        assert metrics.avg_latency_ms == 125.5
        assert metrics.cache_hits == 20
        assert metrics.cache_hit_rate == 0.2
        assert metrics.by_provider["anthropic"]["requests"] == 50
        assert metrics.requests_per_minute == 5.0
        assert metrics.tokens_per_minute == 500.0
        assert metrics.cost_per_hour == 7.75
        assert metrics.current_minute_requests == 5
        assert metrics.current_hour_cost == 1.5
        assert metrics.current_day_cost == 12.25
        assert metrics.current_month_cost == 150.0


class TestUsageTracker:
    """Test suite for UsageTracker."""

    @pytest.fixture
    def tracker(self):
        """Create usage tracker instance."""
        with patch('prompt_sentinel.monitoring.usage_tracker.cache_manager') as mock_cache:
            mock_cache.connected = False
            tracker = UsageTracker(persist_to_cache=False)
            return tracker

    def test_initialization(self, tracker):
        """Test usage tracker initialization."""
        assert tracker.persist_to_cache is False
        assert tracker.retention_hours == 24 * 7
        assert isinstance(tracker.api_calls, list)
        assert len(tracker.api_calls) == 0
        assert isinstance(tracker.metrics, UsageMetrics)
        assert isinstance(tracker.provider_metrics, dict)
        assert tracker.current_minute is not None
        assert tracker.current_hour is not None
        assert tracker.current_day is not None
        assert tracker.current_month is not None

    def test_initialization_with_custom_params(self):
        """Test initialization with custom parameters."""
        with patch('prompt_sentinel.monitoring.usage_tracker.cache_manager') as mock_cache:
            mock_cache.connected = False
            tracker = UsageTracker(persist_to_cache=True, retention_hours=48)
            
            assert tracker.persist_to_cache is True
            assert tracker.retention_hours == 48

    def test_cost_calculation_anthropic(self, tracker):
        """Test cost calculation for Anthropic models."""
        tokens = TokenUsage(prompt_tokens=1000, completion_tokens=500)
        
        # Test known model
        cost = tracker._calculate_cost(
            Provider.ANTHROPIC, 
            "claude-3-haiku-20240307", 
            tokens
        )
        
        # Expected: (1000/1000 * 0.00025) + (500/1000 * 0.00125) = 0.00025 + 0.000625 = 0.000875
        expected_cost = (1.0 * 0.00025) + (0.5 * 0.00125)
        assert cost == pytest.approx(expected_cost, rel=1e-6)

    def test_cost_calculation_openai(self, tracker):
        """Test cost calculation for OpenAI models."""
        tokens = TokenUsage(prompt_tokens=1000, completion_tokens=500)
        
        cost = tracker._calculate_cost(
            Provider.OPENAI,
            "gpt-3.5-turbo",
            tokens
        )
        
        # Expected: (1000/1000 * 0.0005) + (500/1000 * 0.0015) = 0.0005 + 0.00075 = 0.00125
        expected_cost = (1.0 * 0.0005) + (0.5 * 0.0015)
        assert cost == pytest.approx(expected_cost, rel=1e-6)

    def test_cost_calculation_unknown_model(self, tracker):
        """Test cost calculation for unknown model (should use defaults)."""
        tokens = TokenUsage(prompt_tokens=1000, completion_tokens=500)
        
        cost = tracker._calculate_cost(
            Provider.ANTHROPIC,
            "unknown-model",
            tokens
        )
        
        # Should use default pricing: input=0.001, output=0.002
        expected_cost = (1.0 * 0.001) + (0.5 * 0.002)
        assert cost == pytest.approx(expected_cost, rel=1e-6)

    def test_cost_calculation_heuristic(self, tracker):
        """Test cost calculation for heuristic (should be zero)."""
        tokens = TokenUsage(prompt_tokens=1000, completion_tokens=500)
        
        cost = tracker._calculate_cost(Provider.HEURISTIC, "heuristic", tokens)
        assert cost == 0.0

    def test_cost_calculation_cache(self, tracker):
        """Test cost calculation for cache (should be zero)."""
        tokens = TokenUsage(prompt_tokens=0, completion_tokens=0)
        
        cost = tracker._calculate_cost(Provider.CACHE, "cache", tokens)
        assert cost == 0.0

    @pytest.mark.asyncio
    async def test_track_api_call_success(self, tracker):
        """Test tracking a successful API call."""
        api_call = await tracker.track_api_call(
            provider="anthropic",
            model="claude-3-haiku-20240307",
            prompt_tokens=100,
            completion_tokens=50,
            latency_ms=150.5,
            success=True,
            endpoint="/v1/messages",
            metadata={"request_id": "req_123"}
        )
        
        assert api_call.provider == Provider.ANTHROPIC
        assert api_call.model == "claude-3-haiku-20240307"
        assert api_call.tokens.prompt_tokens == 100
        assert api_call.tokens.completion_tokens == 50
        assert api_call.tokens.total_tokens == 150
        assert api_call.latency_ms == 150.5
        assert api_call.success is True
        assert api_call.endpoint == "/v1/messages"
        assert api_call.metadata["request_id"] == "req_123"
        assert api_call.cost_usd > 0
        
        # Check metrics updated
        assert tracker.metrics.total_requests == 1
        assert tracker.metrics.successful_requests == 1
        assert tracker.metrics.failed_requests == 0
        assert tracker.metrics.total_tokens == 150
        assert tracker.metrics.total_cost_usd == api_call.cost_usd

    @pytest.mark.asyncio
    async def test_track_api_call_failure(self, tracker):
        """Test tracking a failed API call."""
        await tracker.track_api_call(
            provider="openai",
            model="gpt-4",
            prompt_tokens=100,
            completion_tokens=0,
            latency_ms=500.0,
            success=False
        )
        
        assert tracker.metrics.total_requests == 1
        assert tracker.metrics.successful_requests == 0
        assert tracker.metrics.failed_requests == 1

    @pytest.mark.asyncio
    async def test_track_api_call_unknown_provider(self, tracker):
        """Test tracking API call with unknown provider."""
        api_call = await tracker.track_api_call(
            provider="unknown",
            model="unknown-model",
            prompt_tokens=100,
            completion_tokens=50,
            latency_ms=100.0
        )
        
        assert api_call.provider == Provider.HEURISTIC
        assert api_call.cost_usd == 0.0

    @pytest.mark.asyncio
    async def test_track_cache_hit(self, tracker):
        """Test tracking cache hits."""
        await tracker.track_cache_hit(endpoint="/v1/detect", latency_ms=5.0)
        
        assert len(tracker.api_calls) == 1
        api_call = tracker.api_calls[0]
        assert api_call.provider == Provider.CACHE
        assert api_call.model == "cache"
        assert api_call.cost_usd == 0.0
        assert api_call.success is True
        assert api_call.latency_ms == 5.0
        assert api_call.metadata["cache_hit"] is True
        
        # Check cache metrics
        assert tracker.metrics.cache_hits == 1
        assert tracker.metrics.total_requests == 1
        assert tracker.metrics.cache_hit_rate == 1.0

    @pytest.mark.asyncio
    async def test_update_metrics_time_windows(self, tracker):
        """Test metrics update with different time windows."""
        # Track multiple calls to test time window logic
        for i in range(5):
            await tracker.track_api_call(
                provider="anthropic",
                model="claude-3-haiku-20240307",
                prompt_tokens=100,
                completion_tokens=50,
                latency_ms=100.0
            )
        
        assert tracker.metrics.current_minute_requests == 5
        assert tracker.metrics.current_hour_cost > 0
        assert tracker.metrics.current_day_cost > 0
        assert tracker.metrics.current_month_cost > 0

    @pytest.mark.asyncio
    async def test_provider_metrics_aggregation(self, tracker):
        """Test per-provider metrics aggregation."""
        # Track calls to different providers
        await tracker.track_api_call(
            provider="anthropic",
            model="claude-3-haiku-20240307",
            prompt_tokens=100,
            completion_tokens=50,
            latency_ms=100.0
        )
        
        await tracker.track_api_call(
            provider="openai",
            model="gpt-3.5-turbo",
            prompt_tokens=200,
            completion_tokens=100,
            latency_ms=200.0
        )
        
        # Check provider metrics
        provider_metrics = tracker.get_provider_breakdown()
        
        assert "anthropic" in provider_metrics
        assert "openai" in provider_metrics
        
        anthropic_metrics = provider_metrics["anthropic"]
        assert anthropic_metrics["requests"] == 1
        assert anthropic_metrics["tokens"] == 150
        assert anthropic_metrics["cost"] > 0
        assert anthropic_metrics["avg_latency"] == 100.0
        assert anthropic_metrics["success_rate"] == 1.0
        
        openai_metrics = provider_metrics["openai"]
        assert openai_metrics["requests"] == 1
        assert openai_metrics["tokens"] == 300
        assert openai_metrics["avg_latency"] == 200.0

    @pytest.mark.asyncio
    async def test_metrics_with_cache_hits(self, tracker):
        """Test metrics calculation with cache hits."""
        # Track API call
        await tracker.track_api_call(
            provider="anthropic",
            model="claude-3-haiku-20240307",
            prompt_tokens=100,
            completion_tokens=50,
            latency_ms=100.0
        )
        
        # Track cache hit
        await tracker.track_cache_hit(endpoint="/v1/detect", latency_ms=5.0)
        
        assert tracker.metrics.total_requests == 2
        assert tracker.metrics.cache_hits == 1
        assert tracker.metrics.cache_hit_rate == 0.5

    def test_get_metrics_all_time(self, tracker):
        """Test getting all-time metrics."""
        metrics = tracker.get_metrics()
        
        assert isinstance(metrics, UsageMetrics)
        assert metrics.total_requests == 0
        assert metrics.total_cost_usd == 0.0

    @pytest.mark.asyncio
    async def test_get_metrics_time_window(self, tracker):
        """Test getting metrics for specific time window."""
        # Track some calls
        await tracker.track_api_call(
            provider="anthropic",
            model="claude-3-haiku-20240307",
            prompt_tokens=100,
            completion_tokens=50,
            latency_ms=100.0
        )
        
        # Get recent metrics (last hour)
        metrics = tracker.get_metrics(time_window=timedelta(hours=1))
        
        assert metrics.total_requests == 1
        assert metrics.total_tokens == 150
        assert metrics.total_cost_usd > 0

    def test_get_metrics_empty_time_window(self, tracker):
        """Test getting metrics for empty time window."""
        # Get metrics for last second (should be empty)
        metrics = tracker.get_metrics(time_window=timedelta(seconds=1))
        
        assert metrics.total_requests == 0
        assert metrics.total_cost_usd == 0.0

    @pytest.mark.asyncio
    async def test_get_cost_breakdown_by_provider(self, tracker):
        """Test cost breakdown by provider."""
        await tracker.track_api_call(
            provider="anthropic",
            model="claude-3-haiku-20240307",
            prompt_tokens=100,
            completion_tokens=50,
            latency_ms=100.0
        )
        
        await tracker.track_api_call(
            provider="openai",
            model="gpt-3.5-turbo",
            prompt_tokens=100,
            completion_tokens=50,
            latency_ms=100.0
        )
        
        breakdown = tracker.get_cost_breakdown(group_by="provider")
        
        assert "anthropic" in breakdown
        assert "openai" in breakdown
        assert breakdown["anthropic"] > 0
        assert breakdown["openai"] > 0

    @pytest.mark.asyncio
    async def test_get_cost_breakdown_by_model(self, tracker):
        """Test cost breakdown by model."""
        await tracker.track_api_call(
            provider="anthropic",
            model="claude-3-haiku-20240307",
            prompt_tokens=100,
            completion_tokens=50,
            latency_ms=100.0
        )
        
        breakdown = tracker.get_cost_breakdown(group_by="model")
        
        assert "anthropic/claude-3-haiku-20240307" in breakdown
        assert breakdown["anthropic/claude-3-haiku-20240307"] > 0

    def test_get_cost_breakdown_invalid_group(self, tracker):
        """Test cost breakdown with invalid group parameter."""
        breakdown = tracker.get_cost_breakdown(group_by="invalid")
        
        # Should return empty dict for no calls
        assert isinstance(breakdown, dict)

    @pytest.mark.asyncio
    async def test_get_usage_trend_empty(self, tracker):
        """Test usage trend with no data."""
        trend = tracker.get_usage_trend()
        
        assert isinstance(trend, list)
        assert len(trend) == 0

    @pytest.mark.asyncio
    async def test_get_usage_trend_by_hour(self, tracker):
        """Test usage trend grouped by hour."""
        # Track some calls
        await tracker.track_api_call(
            provider="anthropic",
            model="claude-3-haiku-20240307",
            prompt_tokens=100,
            completion_tokens=50,
            latency_ms=100.0
        )
        
        trend = tracker.get_usage_trend(period="hour", limit=1)
        
        assert len(trend) == 1
        assert "period" in trend[0]
        assert trend[0]["requests"] == 1
        assert trend[0]["tokens"] == 150
        assert trend[0]["cost"] > 0

    @pytest.mark.asyncio
    async def test_get_usage_trend_by_day(self, tracker):
        """Test usage trend grouped by day."""
        await tracker.track_api_call(
            provider="anthropic",
            model="claude-3-haiku-20240307",
            prompt_tokens=100,
            completion_tokens=50,
            latency_ms=100.0
        )
        
        trend = tracker.get_usage_trend(period="day", limit=1)
        
        assert len(trend) == 1
        assert trend[0]["requests"] == 1

    @pytest.mark.asyncio
    async def test_get_usage_trend_invalid_period(self, tracker):
        """Test usage trend with invalid period."""
        await tracker.track_api_call(
            provider="anthropic",
            model="claude-3-haiku-20240307",
            prompt_tokens=100,
            completion_tokens=50,
            latency_ms=100.0
        )
        
        trend = tracker.get_usage_trend(period="invalid")
        
        assert len(trend) == 0

    @pytest.mark.asyncio
    async def test_clear_old_data(self, tracker):
        """Test clearing old data."""
        # Track some calls
        await tracker.track_api_call(
            provider="anthropic",
            model="claude-3-haiku-20240307",
            prompt_tokens=100,
            completion_tokens=50,
            latency_ms=100.0
        )
        
        # Manually set old timestamp for testing
        tracker.api_calls[0].timestamp = datetime.now() - timedelta(hours=25)
        
        # Clear data older than 24 hours
        tracker.clear_old_data(retention_hours=24)
        
        # Should have no calls left
        assert len(tracker.api_calls) == 0

    @pytest.mark.asyncio
    async def test_clear_old_data_keep_recent(self, tracker):
        """Test clearing old data keeps recent calls."""
        # Track some calls
        await tracker.track_api_call(
            provider="anthropic",
            model="claude-3-haiku-20240307",
            prompt_tokens=100,
            completion_tokens=50,
            latency_ms=100.0
        )
        
        # Clear data older than 1 hour (should keep recent call)
        tracker.clear_old_data(retention_hours=1)
        
        assert len(tracker.api_calls) == 1

    def test_clear_old_data_default_retention(self, tracker):
        """Test clearing old data with default retention."""
        # Use default retention period
        tracker.clear_old_data()
        
        # Should not error and use instance retention_hours
        assert len(tracker.api_calls) == 0

    @pytest.mark.asyncio
    async def test_high_cost_warning_logging(self, tracker):
        """Test logging for high-cost API calls."""
        with patch('prompt_sentinel.monitoring.usage_tracker.logger') as mock_logger:
            # Track high-cost call (> $0.10)
            await tracker.track_api_call(
                provider="openai",
                model="gpt-4",
                prompt_tokens=5000,  # Large number to trigger high cost
                completion_tokens=2500,
                latency_ms=1000.0
            )
            
            # Should have logged a warning for high cost
            mock_logger.warning.assert_called_once()
            call_args = mock_logger.warning.call_args
            assert "High cost API call" in call_args[0][0]

    @pytest.mark.asyncio
    async def test_persist_call_disabled(self, tracker):
        """Test persistence when disabled."""
        # Persistence is disabled in fixture
        api_call = await tracker.track_api_call(
            provider="anthropic",
            model="claude-3-haiku-20240307",
            prompt_tokens=100,
            completion_tokens=50,
            latency_ms=100.0
        )
        
        # Should succeed without persistence
        assert api_call is not None

    @pytest.mark.asyncio
    async def test_persist_call_enabled(self):
        """Test persistence when enabled."""
        with patch('prompt_sentinel.monitoring.usage_tracker.cache_manager') as mock_cache:
            mock_cache.connected = True
            mock_cache.set = AsyncMock()
            mock_cache.get = AsyncMock(return_value=None)
            
            tracker = UsageTracker(persist_to_cache=True)
            
            await tracker.track_api_call(
                provider="anthropic",
                model="claude-3-haiku-20240307",
                prompt_tokens=100,
                completion_tokens=50,
                latency_ms=100.0
            )
            
            # Should have called cache set methods
            assert mock_cache.set.call_count >= 1

    @pytest.mark.asyncio
    async def test_load_persisted_metrics_no_cache(self, tracker):
        """Test loading persisted metrics when cache not connected."""
        # Should not error
        await tracker._load_persisted_metrics()

    @pytest.mark.asyncio
    async def test_load_persisted_metrics_with_data(self):
        """Test loading persisted metrics with cached data."""
        with patch('prompt_sentinel.monitoring.usage_tracker.cache_manager') as mock_cache:
            mock_cache.connected = True
            mock_cache.get = AsyncMock(side_effect=[
                {"requests": 100, "tokens": 10000, "cost": 5.0},  # Daily metrics
                {"cost": 150.0}  # Monthly metrics
            ])
            
            tracker = UsageTracker(persist_to_cache=True)
            await tracker._load_persisted_metrics()
            
            assert tracker.metrics.current_day_cost == 5.0
            assert tracker.metrics.current_month_cost == 150.0

    @pytest.mark.asyncio
    async def test_load_persisted_metrics_error_handling(self):
        """Test error handling in loading persisted metrics."""
        with patch('prompt_sentinel.monitoring.usage_tracker.cache_manager') as mock_cache:
            mock_cache.connected = True
            mock_cache.get = AsyncMock(side_effect=Exception("Cache error"))
            
            with patch('prompt_sentinel.monitoring.usage_tracker.logger') as mock_logger:
                tracker = UsageTracker(persist_to_cache=True)
                await tracker._load_persisted_metrics()
                
                # Should have logged error
                mock_logger.error.assert_called()

    @pytest.mark.asyncio
    async def test_latency_calculation(self, tracker):
        """Test latency metrics calculation."""
        # Track multiple calls with different latencies
        await tracker.track_api_call(
            provider="anthropic",
            model="claude-3-haiku-20240307",
            prompt_tokens=100,
            completion_tokens=50,
            latency_ms=100.0
        )
        
        await tracker.track_api_call(
            provider="anthropic",
            model="claude-3-haiku-20240307",
            prompt_tokens=100,
            completion_tokens=50,
            latency_ms=200.0
        )
        
        # Average latency should be 150ms
        assert tracker.metrics.avg_latency_ms == 150.0

    @pytest.mark.asyncio
    async def test_rate_metrics_calculation(self, tracker):
        """Test rate metrics calculation."""
        await tracker.track_api_call(
            provider="anthropic",
            model="claude-3-haiku-20240307",
            prompt_tokens=100,
            completion_tokens=50,
            latency_ms=100.0
        )
        
        # Should have positive rates
        assert tracker.metrics.requests_per_minute >= 0
        assert tracker.metrics.tokens_per_minute >= 0
        assert tracker.metrics.cost_per_hour >= 0

    @pytest.mark.asyncio
    async def test_success_rate_calculation(self, tracker):
        """Test success rate calculation in provider metrics."""
        # Track successful call
        await tracker.track_api_call(
            provider="anthropic",
            model="claude-3-haiku-20240307",
            prompt_tokens=100,
            completion_tokens=50,
            latency_ms=100.0,
            success=True
        )
        
        # Track failed call
        await tracker.track_api_call(
            provider="anthropic",
            model="claude-3-haiku-20240307",
            prompt_tokens=100,
            completion_tokens=0,
            latency_ms=100.0,
            success=False
        )
        
        provider_metrics = tracker.get_provider_breakdown()
        anthropic_metrics = provider_metrics["anthropic"]
        
        # Success rate should be 50% (1 success out of 2 calls)
        assert anthropic_metrics["success_rate"] == pytest.approx(0.5, rel=0.01)

    @pytest.mark.asyncio
    async def test_cache_not_included_in_provider_metrics(self, tracker):
        """Test that cache hits are not included in provider metrics."""
        await tracker.track_cache_hit(endpoint="/v1/detect", latency_ms=5.0)
        
        provider_metrics = tracker.get_provider_breakdown()
        
        # Cache should not appear in provider metrics
        assert "cache" not in provider_metrics
        
        # But should appear in general metrics
        assert tracker.metrics.cache_hits == 1

    @pytest.mark.asyncio
    async def test_metrics_window_filtering(self, tracker):
        """Test metrics filtering by time window."""
        # Track call
        await tracker.track_api_call(
            provider="anthropic",
            model="claude-3-haiku-20240307",
            prompt_tokens=100,
            completion_tokens=50,
            latency_ms=100.0
        )
        
        # Manually set old timestamp
        tracker.api_calls[0].timestamp = datetime.now() - timedelta(hours=2)
        
        # Get metrics for last hour (should be empty)
        recent_metrics = tracker.get_metrics(time_window=timedelta(hours=1))
        assert recent_metrics.total_requests == 0
        
        # Get metrics for last 3 hours (should include call)
        older_metrics = tracker.get_metrics(time_window=timedelta(hours=3))
        assert older_metrics.total_requests == 1


class TestUsageTrackerIntegration:
    """Integration test scenarios for usage tracker."""

    @pytest.mark.asyncio
    async def test_mixed_provider_usage(self):
        """Test tracking calls across multiple providers."""
        with patch('prompt_sentinel.monitoring.usage_tracker.cache_manager') as mock_cache:
            mock_cache.connected = False
            tracker = UsageTracker(persist_to_cache=False)
        
        # Track calls to different providers
        providers = ["anthropic", "openai", "gemini"]
        models = ["claude-3-haiku-20240307", "gpt-3.5-turbo", "gemini-1.5-flash"]
        
        for provider, model in zip(providers, models):
            await tracker.track_api_call(
                provider=provider,
                model=model,
                prompt_tokens=100,
                completion_tokens=50,
                latency_ms=100.0 + len(provider) * 10  # Vary latency
            )
        
        # Add cache hits
        await tracker.track_cache_hit("/v1/detect", 5.0)
        await tracker.track_cache_hit("/v1/analyze", 3.0)
        
        # Verify aggregated metrics
        assert tracker.metrics.total_requests == 5  # 3 API + 2 cache
        assert tracker.metrics.successful_requests == 5
        assert tracker.metrics.cache_hits == 2
        assert tracker.metrics.cache_hit_rate == 0.4
        assert tracker.metrics.total_cost_usd > 0
        
        # Verify per-provider breakdown
        provider_breakdown = tracker.get_provider_breakdown()
        assert len(provider_breakdown) == 3  # Excludes cache
        
        for provider in providers:
            assert provider in provider_breakdown
            assert provider_breakdown[provider]["requests"] == 1
            assert provider_breakdown[provider]["success_rate"] == 1.0

    @pytest.mark.asyncio
    async def test_usage_lifecycle_simulation(self):
        """Test simulating realistic usage patterns over time."""
        with patch('prompt_sentinel.monitoring.usage_tracker.cache_manager') as mock_cache:
            mock_cache.connected = False
            tracker = UsageTracker(persist_to_cache=False)
        
        # Simulate burst of requests
        for i in range(10):
            await tracker.track_api_call(
                provider="anthropic",
                model="claude-3-haiku-20240307",
                prompt_tokens=100 + i * 10,  # Varying token usage
                completion_tokens=50 + i * 5,
                latency_ms=100.0 + i * 10,  # Increasing latency
                success=i < 8  # 2 failures out of 10
            )
        
        # Verify final state
        assert tracker.metrics.total_requests == 10
        assert tracker.metrics.successful_requests == 8
        assert tracker.metrics.failed_requests == 2
        
        # Cost should increase with larger token counts
        cost_breakdown = tracker.get_cost_breakdown()
        assert cost_breakdown["anthropic"] > 0
        
        # Get hourly trend
        trend = tracker.get_usage_trend(period="hour", limit=1)
        assert len(trend) == 1
        assert trend[0]["requests"] == 10
        
        # Clear old data and verify cleanup
        original_calls = len(tracker.api_calls)
        
        # Manually set old timestamps to test cleanup
        for call in tracker.api_calls:
            call.timestamp = datetime.now() - timedelta(hours=25)
        
        tracker.clear_old_data(retention_hours=24)  # Clear calls older than 24 hours
        assert len(tracker.api_calls) == 0