"""Comprehensive tests for budget management module."""

import asyncio
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

from prompt_sentinel.monitoring.budget_manager import (
    AlertLevel,
    BudgetAlert,
    BudgetConfig,
    BudgetManager,
    BudgetPeriod,
    BudgetStatus,
)
from prompt_sentinel.monitoring.usage_tracker import UsageMetrics, UsageTracker


def create_usage_metrics(
    total_requests=100,
    successful_requests=95,
    failed_requests=5,
    total_tokens=10000,
    total_cost_usd=10.0,
    cache_hits=30,
    cache_hit_rate=0.3,
    current_hour_cost=1.0,
    current_day_cost=5.0,
    current_month_cost=10.0,
):
    """Helper to create UsageMetrics with correct fields."""
    return UsageMetrics(
        total_requests=total_requests,
        successful_requests=successful_requests,
        failed_requests=failed_requests,
        total_tokens=total_tokens,
        total_cost_usd=total_cost_usd,
        avg_latency_ms=100.0,
        cache_hits=cache_hits,
        cache_hit_rate=cache_hit_rate,
        by_provider={
            "openai": {"requests": 50, "tokens": 5000, "cost": total_cost_usd / 2},
            "anthropic": {"requests": 50, "tokens": 5000, "cost": total_cost_usd / 2},
        },
        requests_per_minute=10.0,
        tokens_per_minute=1000.0,
        cost_per_hour=10.0,
        current_minute_requests=10,
        current_hour_cost=current_hour_cost,
        current_day_cost=current_day_cost,
        current_month_cost=current_month_cost,
    )


class TestBudgetPeriod:
    """Test suite for BudgetPeriod enum."""

    def test_budget_period_values(self):
        """Test budget period enum values."""
        assert BudgetPeriod.HOURLY.value == "hourly"
        assert BudgetPeriod.DAILY.value == "daily"
        assert BudgetPeriod.WEEKLY.value == "weekly"
        assert BudgetPeriod.MONTHLY.value == "monthly"


class TestAlertLevel:
    """Test suite for AlertLevel enum."""

    def test_alert_level_values(self):
        """Test alert level enum values."""
        assert AlertLevel.INFO.value == "info"
        assert AlertLevel.WARNING.value == "warning"
        assert AlertLevel.CRITICAL.value == "critical"
        assert AlertLevel.EXCEEDED.value == "exceeded"


class TestBudgetConfig:
    """Test suite for BudgetConfig."""

    def test_default_config(self):
        """Test default budget configuration."""
        config = BudgetConfig()

        # Cost limits should be None by default
        assert config.hourly_limit is None
        assert config.daily_limit is None
        assert config.monthly_limit is None

        # Token limits should be None by default
        assert config.hourly_tokens is None
        assert config.daily_tokens is None
        assert config.monthly_tokens is None

        # Alert thresholds
        assert config.warning_threshold == 0.75
        assert config.critical_threshold == 0.90

        # Actions
        assert config.block_on_exceeded is True
        assert config.throttle_on_warning is False

        # Optimization
        assert config.prefer_cache is True
        assert config.prefer_cheap_models is False

        # Provider limits
        assert config.provider_limits == {}

    def test_custom_config(self):
        """Test custom budget configuration."""
        config = BudgetConfig(
            hourly_limit=10.0,  # Test value
            daily_limit=100.0,  # Test value
            monthly_limit=1000.0,  # Test value
            warning_threshold=0.8,
            critical_threshold=0.95,
            block_on_exceeded=False,
            throttle_on_warning=True,
            provider_limits={"openai": 500.0, "anthropic": 300.0},
        )

        assert config.hourly_limit == 10.0  # Test value
        assert config.daily_limit == 100.0  # Test value
        assert config.monthly_limit == 1000.0  # Test value
        assert config.warning_threshold == 0.8
        assert config.critical_threshold == 0.95
        assert config.block_on_exceeded is False
        assert config.throttle_on_warning is True
        assert config.provider_limits["openai"] == 500.0
        assert config.provider_limits["anthropic"] == 300.0


class TestBudgetAlert:
    """Test suite for BudgetAlert."""

    def test_budget_alert_creation(self):
        """Test creating budget alert."""
        alert = BudgetAlert(
            level=AlertLevel.WARNING,
            period=BudgetPeriod.DAILY,
            current_value=75.0,
            limit_value=100.0,
            percentage=75.0,
            message="Daily budget warning",
            timestamp=datetime.now(),
            recommendations=["Reduce usage", "Switch to cache"],
        )

        assert alert.level == AlertLevel.WARNING
        assert alert.period == BudgetPeriod.DAILY
        assert alert.current_value == 75.0
        assert alert.limit_value == 100.0
        assert alert.percentage == 75.0
        assert alert.message == "Daily budget warning"
        assert len(alert.recommendations) == 2


class TestBudgetStatus:
    """Test suite for BudgetStatus."""

    def test_budget_status_creation(self):
        """Test creating budget status."""
        alert = BudgetAlert(
            level=AlertLevel.INFO,
            period=BudgetPeriod.HOURLY,
            current_value=5.0,
            limit_value=10.0,
            percentage=50.0,
            message="Info",
            timestamp=datetime.now(),
        )

        status = BudgetStatus(
            within_budget=True,
            alerts=[alert],
            hourly_cost=5.0,
            daily_cost=50.0,
            monthly_cost=500.0,
            hourly_remaining=5.0,
            daily_remaining=50.0,
            monthly_remaining=500.0,
            projected_daily=75.0,
            projected_monthly=750.0,
            recommendations=["Monitor usage"],
        )

        assert status.within_budget is True
        assert len(status.alerts) == 1
        assert status.hourly_cost == 5.0
        assert status.daily_cost == 50.0
        assert status.monthly_cost == 500.0
        assert status.hourly_remaining == 5.0
        assert status.daily_remaining == 50.0
        assert status.monthly_remaining == 500.0
        assert status.projected_daily == 75.0
        assert status.projected_monthly == 750.0
        assert len(status.recommendations) == 1


class TestBudgetManager:
    """Test suite for BudgetManager."""

    @pytest.fixture
    def mock_usage_tracker(self):
        """Create mock usage tracker."""
        tracker = MagicMock(spec=UsageTracker)
        tracker.get_metrics.return_value = create_usage_metrics()
        tracker.get_provider_breakdown.return_value = {
            "openai": {"requests": 50, "tokens": 5000, "cost": 5.0},
            "anthropic": {"requests": 50, "tokens": 5000, "cost": 5.0},
        }
        return tracker

    @pytest.fixture
    def budget_config(self):
        """Create test budget configuration."""
        return BudgetConfig(
            hourly_limit=10.0,  # Test value
            daily_limit=100.0,  # Test value
            monthly_limit=1000.0,  # Test value
            warning_threshold=0.75,
            critical_threshold=0.90,
            block_on_exceeded=True,
            throttle_on_warning=True,
        )

    @pytest.fixture
    def budget_manager(self, budget_config, mock_usage_tracker):
        """Create budget manager instance."""
        return BudgetManager(
            config=budget_config, usage_tracker=mock_usage_tracker, alert_callback=None
        )

    def test_initialization(self, budget_manager, budget_config, mock_usage_tracker):
        """Test budget manager initialization."""
        assert budget_manager.config == budget_config
        assert budget_manager.usage_tracker == mock_usage_tracker
        assert budget_manager.alert_callback is None
        assert len(budget_manager.alerts) == 0
        assert budget_manager.is_throttled is False
        assert budget_manager.throttle_until is None

    @pytest.mark.asyncio
    async def test_check_budget_within_limits(self, budget_manager):
        """Test checking budget when within limits."""
        status = await budget_manager.check_budget(estimated_cost=0.5)

        assert status.within_budget is True
        assert len(status.alerts) == 0
        assert status.hourly_cost == 1.0
        assert status.daily_cost == 5.0
        assert status.monthly_cost == 10.0
        assert status.hourly_remaining == 9.0
        assert status.daily_remaining == 95.0
        assert status.monthly_remaining == 990.0

    @pytest.mark.asyncio
    async def test_check_budget_warning(self, budget_manager, mock_usage_tracker):
        """Test budget warning alert."""
        # Set usage to 75% of daily limit
        mock_usage_tracker.get_metrics.return_value = create_usage_metrics(
            current_hour_cost=1.0,
            current_day_cost=75.0,
            current_month_cost=75.0,
            total_cost_usd=75.0,
        )

        status = await budget_manager.check_budget(estimated_cost=1.0)

        assert status.within_budget is True
        assert len(status.alerts) == 1
        assert status.alerts[0].level == AlertLevel.WARNING
        assert status.alerts[0].period == BudgetPeriod.DAILY
        assert len(status.recommendations) > 0

    @pytest.mark.asyncio
    async def test_check_budget_critical(self, budget_manager, mock_usage_tracker):
        """Test budget critical alert."""
        # Set usage to 90% of daily limit
        mock_usage_tracker.get_metrics.return_value = create_usage_metrics(
            current_hour_cost=1.0,
            current_day_cost=90.0,
            current_month_cost=90.0,
            total_cost_usd=90.0,
        )

        status = await budget_manager.check_budget(estimated_cost=1.0)

        assert status.within_budget is True
        assert len(status.alerts) == 1
        assert status.alerts[0].level == AlertLevel.CRITICAL
        assert status.alerts[0].period == BudgetPeriod.DAILY

    @pytest.mark.asyncio
    async def test_check_budget_exceeded(self, budget_manager, mock_usage_tracker):
        """Test budget exceeded alert."""
        # Set usage over daily limit
        mock_usage_tracker.get_metrics.return_value = create_usage_metrics(
            current_hour_cost=1.0,
            current_day_cost=101.0,
            current_month_cost=101.0,
            total_cost_usd=101.0,
        )

        status = await budget_manager.check_budget(estimated_cost=0.0)

        assert status.within_budget is False
        assert len(status.alerts) == 1
        assert status.alerts[0].level == AlertLevel.EXCEEDED
        assert status.alerts[0].period == BudgetPeriod.DAILY
        assert "Budget exceeded" in status.recommendations[0]

    def test_check_limit_none(self, budget_manager):
        """Test checking limit when limit is None."""
        alert = budget_manager._check_limit(
            BudgetPeriod.HOURLY, current=10.0, limit=None, estimated=1.0
        )
        assert alert is None

    def test_check_limit_under_threshold(self, budget_manager):
        """Test checking limit when under threshold."""
        alert = budget_manager._check_limit(
            BudgetPeriod.HOURLY, current=5.0, limit=10.0, estimated=1.0
        )
        assert alert is None

    def test_check_limit_warning_threshold(self, budget_manager):
        """Test checking limit at warning threshold."""
        alert = budget_manager._check_limit(
            BudgetPeriod.HOURLY, current=7.0, limit=10.0, estimated=1.0
        )
        assert alert is not None
        assert alert.level == AlertLevel.WARNING
        assert alert.percentage == 80.0

    def test_check_limit_critical_threshold(self, budget_manager):
        """Test checking limit at critical threshold."""
        alert = budget_manager._check_limit(
            BudgetPeriod.HOURLY, current=8.5, limit=10.0, estimated=1.0
        )
        assert alert is not None
        assert alert.level == AlertLevel.CRITICAL
        assert alert.percentage == 95.0

    def test_check_limit_exceeded(self, budget_manager):
        """Test checking limit when exceeded."""
        alert = budget_manager._check_limit(
            BudgetPeriod.HOURLY, current=10.0, limit=10.0, estimated=1.0
        )
        assert alert is not None
        assert alert.level == AlertLevel.EXCEEDED
        assert alert.percentage == pytest.approx(110.0, rel=0.01)

    @pytest.mark.asyncio
    async def test_process_alert_callback(self, budget_config, mock_usage_tracker):
        """Test processing alert with callback."""
        callback_called = False
        received_alert = None

        async def alert_callback(alert):
            nonlocal callback_called, received_alert
            callback_called = True
            received_alert = alert

        manager = BudgetManager(
            config=budget_config, usage_tracker=mock_usage_tracker, alert_callback=alert_callback
        )

        alert = BudgetAlert(
            level=AlertLevel.WARNING,
            period=BudgetPeriod.DAILY,
            current_value=75.0,
            limit_value=100.0,
            percentage=75.0,
            message="Test alert",
            timestamp=datetime.now(),
        )

        await manager._process_alert(alert)

        assert callback_called is True
        assert received_alert == alert

    @pytest.mark.asyncio
    async def test_process_alert_throttling(self, budget_manager):
        """Test alert triggers throttling."""
        alert = BudgetAlert(
            level=AlertLevel.WARNING,
            period=BudgetPeriod.DAILY,
            current_value=75.0,
            limit_value=100.0,
            percentage=75.0,
            message="Test alert",
            timestamp=datetime.now(),
        )

        await budget_manager._process_alert(alert)

        assert budget_manager.is_throttled is True
        assert budget_manager.throttle_until is not None

    @pytest.mark.asyncio
    async def test_process_alert_rate_limiting(self, budget_manager):
        """Test alert rate limiting."""
        alert = BudgetAlert(
            level=AlertLevel.WARNING,
            period=BudgetPeriod.DAILY,
            current_value=75.0,
            limit_value=100.0,
            percentage=75.0,
            message="Test alert",
            timestamp=datetime.now(),
        )

        # Process first alert
        await budget_manager._process_alert(alert)
        assert len(budget_manager.alerts) == 1

        # Process same alert again (should be rate limited)
        await budget_manager._process_alert(alert)
        assert len(budget_manager.alerts) == 1  # Not added again

    def test_should_block_no_blocking(self, budget_manager):
        """Test should_block when blocking disabled."""
        budget_manager.config.block_on_exceeded = False
        assert budget_manager.should_block(100.0) is False

    def test_should_block_within_limits(self, budget_manager):
        """Test should_block when within limits."""
        assert budget_manager.should_block(0.5) is False

    def test_should_block_exceeds_hourly(self, budget_manager):
        """Test should_block when exceeds hourly limit."""
        assert budget_manager.should_block(10.0) is True

    def test_should_block_exceeds_daily(self, budget_manager, mock_usage_tracker):
        """Test should_block when exceeds daily limit."""
        mock_usage_tracker.get_metrics.return_value = create_usage_metrics(
            current_hour_cost=1.0,
            current_day_cost=99.0,
            current_month_cost=99.0,
            total_cost_usd=99.0,
        )

        assert budget_manager.should_block(2.0) is True

    def test_should_throttle_not_throttled(self, budget_manager):
        """Test should_throttle when not throttled."""
        assert budget_manager.should_throttle() is False

    def test_should_throttle_active(self, budget_manager):
        """Test should_throttle when throttling active."""
        budget_manager.is_throttled = True
        budget_manager.throttle_until = datetime.now() + timedelta(minutes=5)
        assert budget_manager.should_throttle() is True

    def test_should_throttle_expired(self, budget_manager):
        """Test should_throttle when throttling expired."""
        budget_manager.is_throttled = True
        budget_manager.throttle_until = datetime.now() - timedelta(minutes=1)
        assert budget_manager.should_throttle() is False
        assert budget_manager.is_throttled is False

    def test_get_optimization_suggestions(self, budget_manager, mock_usage_tracker):
        """Test getting optimization suggestions with low cache hit rate."""
        # Set cache hit rate below 30% to trigger suggestion
        mock_usage_tracker.get_metrics.return_value = create_usage_metrics(
            cache_hit_rate=0.25  # Below 30% threshold
        )

        suggestions = budget_manager.get_optimization_suggestions()

        assert isinstance(suggestions, list)
        assert len(suggestions) > 0
        # Should have cache suggestion
        assert any("cache" in s.lower() for s in suggestions)

    def test_get_optimization_suggestions_high_failure(self, budget_manager, mock_usage_tracker):
        """Test optimization suggestions with high failure rate."""
        mock_usage_tracker.get_metrics.return_value = create_usage_metrics(
            successful_requests=80, failed_requests=20
        )

        suggestions = budget_manager.get_optimization_suggestions()
        assert any("failure rate" in s.lower() for s in suggestions)

    def test_get_optimization_suggestions_high_tokens(self, budget_manager, mock_usage_tracker):
        """Test optimization suggestions with high token usage."""
        mock_usage_tracker.get_metrics.return_value = create_usage_metrics(
            total_requests=10,
            successful_requests=10,
            failed_requests=0,
            total_tokens=20000,
            cache_hits=3,
            cache_hit_rate=0.3,
        )

        suggestions = budget_manager.get_optimization_suggestions()
        assert any("token usage" in s.lower() for s in suggestions)

    def test_get_budget_summary(self, budget_manager):
        """Test getting budget summary."""
        summary = budget_manager.get_budget_summary()

        assert "current_usage" in summary
        assert "limits" in summary
        assert "status" in summary
        assert "optimization" in summary

        assert summary["current_usage"]["hourly"] == 1.0
        assert summary["current_usage"]["daily"] == 5.0
        assert summary["current_usage"]["monthly"] == 10.0

        assert summary["limits"]["hourly"] == 10.0
        assert summary["limits"]["daily"] == 100.0
        assert summary["limits"]["monthly"] == 1000.0

        assert summary["status"]["throttled"] is False
        assert summary["status"]["recent_alerts"] == 0

    @pytest.mark.asyncio
    async def test_budget_manager_with_alert_callback_error(
        self, budget_config, mock_usage_tracker
    ):
        """Test budget manager handles callback errors gracefully."""

        async def failing_callback(alert):
            raise Exception("Callback failed")

        manager = BudgetManager(
            config=budget_config, usage_tracker=mock_usage_tracker, alert_callback=failing_callback
        )

        alert = BudgetAlert(
            level=AlertLevel.WARNING,
            period=BudgetPeriod.DAILY,
            current_value=75.0,
            limit_value=100.0,
            percentage=75.0,
            message="Test alert",
            timestamp=datetime.now(),
        )

        # Should not raise exception
        await manager._process_alert(alert)
        assert len(manager.alerts) == 1

    def test_budget_projections(self, budget_manager):
        """Test budget projections calculation."""
        with patch("prompt_sentinel.monitoring.budget_manager.datetime") as mock_datetime:
            mock_datetime.now.return_value = datetime(2024, 1, 15, 12, 0, 0)
            mock_datetime.side_effect = lambda *args, **kwargs: datetime(*args, **kwargs)

            status = asyncio.run(budget_manager.check_budget())

            # Projected daily = current_day + (hourly * remaining_hours)
            # At noon, 12 hours remaining: 5.0 + (1.0 * 12) = 17.0
            assert status.projected_daily == 17.0

            # Projected monthly = current_month + (daily * remaining_days)
            # On 15th, ~15 days remaining: 10.0 + (5.0 * 15) = 85.0
            assert status.projected_monthly == 85.0


class TestIntegrationScenarios:
    """Test integration scenarios for budget management."""

    @pytest.mark.asyncio
    async def test_budget_lifecycle(self):
        """Test complete budget lifecycle."""
        # Create tracker and manager
        tracker = MagicMock(spec=UsageTracker)
        tracker.get_metrics.return_value = create_usage_metrics(
            total_requests=0,
            successful_requests=0,
            failed_requests=0,
            total_tokens=0,
            total_cost_usd=0.0,
            cache_hits=0,
            cache_hit_rate=0.0,
            current_hour_cost=0.0,
            current_day_cost=0.0,
            current_month_cost=0.0,
        )
        tracker.get_provider_breakdown.return_value = {}

        config = BudgetConfig(
            hourly_limit=10.0,
            daily_limit=100.0,
            warning_threshold=0.75,
            critical_threshold=0.90,
            throttle_on_warning=True,
        )

        manager = BudgetManager(config, tracker)

        # Initially within budget
        status = await manager.check_budget()
        assert status.within_budget is True
        assert len(status.alerts) == 0

        # Simulate increasing usage
        for cost in [50.0, 75.0, 90.0, 101.0]:
            tracker.get_metrics.return_value = create_usage_metrics(
                current_hour_cost=cost / 10,
                current_day_cost=cost,
                current_month_cost=cost,
                total_cost_usd=cost,
            )

            status = await manager.check_budget()

            if cost == 75.0:
                # Should have warning (might be multiple periods)
                assert len(status.alerts) >= 1
                assert any(a.level == AlertLevel.WARNING for a in status.alerts)
                assert manager.is_throttled is True
            elif cost == 90.0:
                # Should have critical (might be multiple periods)
                assert len(status.alerts) >= 1
                assert any(a.level == AlertLevel.CRITICAL for a in status.alerts)
            elif cost == 101.0:
                # Should be exceeded
                assert status.within_budget is False
                assert status.alerts[0].level == AlertLevel.EXCEEDED
                assert manager.should_block(1.0) is True

    @pytest.mark.asyncio
    async def test_multiple_period_alerts(self):
        """Test alerts for multiple periods simultaneously."""
        tracker = MagicMock(spec=UsageTracker)
        tracker.get_metrics.return_value = create_usage_metrics(
            current_hour_cost=8.0,  # 80% of hourly limit
            current_day_cost=80.0,  # 80% of daily limit
            current_month_cost=800.0,  # 80% of monthly limit
            total_cost_usd=800.0,
        )
        tracker.get_provider_breakdown.return_value = {}

        config = BudgetConfig(
            hourly_limit=10.0,  # Test value
            daily_limit=100.0,  # Test value
            monthly_limit=1000.0,  # Test value
            warning_threshold=0.75,
        )

        manager = BudgetManager(config, tracker)
        status = await manager.check_budget()

        # Should have warnings for all three periods
        assert len(status.alerts) == 3
        assert all(a.level == AlertLevel.WARNING for a in status.alerts)
        periods = {a.period for a in status.alerts}
        assert periods == {BudgetPeriod.HOURLY, BudgetPeriod.DAILY, BudgetPeriod.MONTHLY}
