"""Budget management and cost control for API usage.

This module provides budget tracking and enforcement including:
- Cost limits per time period
- Budget alerts and notifications
- Automatic throttling when approaching limits
- Cost optimization recommendations
"""

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum

import structlog

from .usage_tracker import UsageTracker

logger = structlog.get_logger()


class BudgetPeriod(Enum):
    """Budget period enumeration."""

    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"


class AlertLevel(Enum):
    """Budget alert severity levels."""

    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    EXCEEDED = "exceeded"


@dataclass
class BudgetConfig:
    """Budget configuration."""

    # Cost limits
    hourly_limit: float | None = None
    daily_limit: float | None = None
    monthly_limit: float | None = None

    # Token limits
    hourly_tokens: int | None = None
    daily_tokens: int | None = None
    monthly_tokens: int | None = None

    # Alert thresholds (percentage of limit)
    warning_threshold: float = 0.75  # 75%
    critical_threshold: float = 0.90  # 90%

    # Actions
    block_on_exceeded: bool = True
    throttle_on_warning: bool = False

    # Optimization
    prefer_cache: bool = True
    prefer_cheap_models: bool = False

    # Per-provider limits
    provider_limits: dict[str, float] = field(default_factory=dict)


@dataclass
class BudgetAlert:
    """Budget alert notification."""

    level: AlertLevel
    period: BudgetPeriod
    current_value: float
    limit_value: float
    percentage: float
    message: str
    timestamp: datetime
    recommendations: list[str] = field(default_factory=list)


@dataclass
class BudgetStatus:
    """Current budget status."""

    within_budget: bool
    alerts: list[BudgetAlert]

    # Current usage
    hourly_cost: float
    daily_cost: float
    monthly_cost: float

    # Remaining budget
    hourly_remaining: float | None
    daily_remaining: float | None
    monthly_remaining: float | None

    # Projections
    projected_daily: float
    projected_monthly: float

    # Recommendations
    recommendations: list[str]


class BudgetManager:
    """Manage API usage budgets and cost controls.

    Monitors usage against configured budgets, generates alerts,
    and can automatically throttle or block requests when limits
    are approached or exceeded.
    """

    def __init__(
        self,
        config: BudgetConfig,
        usage_tracker: UsageTracker,
        alert_callback: Callable | None = None,
    ):
        """Initialize budget manager.

        Args:
            config: Budget configuration
            usage_tracker: Usage tracking instance
            alert_callback: Optional callback for budget alerts
        """
        self.config = config
        self.usage_tracker = usage_tracker
        self.alert_callback = alert_callback

        # Alert history
        self.alerts: list[BudgetAlert] = []
        self.last_alert_time: dict[str, datetime] = {}

        # Throttling state
        self.is_throttled = False
        self.throttle_until: datetime | None = None

        # Start monitoring task
        self.monitoring_task = asyncio.create_task(self._monitor_budget())

    async def check_budget(self, estimated_cost: float = 0.0) -> BudgetStatus:
        """Check current budget status.

        Args:
            estimated_cost: Estimated cost of next operation

        Returns:
            BudgetStatus with current state and recommendations
        """
        metrics = self.usage_tracker.get_metrics()
        alerts = []
        recommendations = []

        # Get current usage
        hourly_cost = metrics.current_hour_cost
        daily_cost = metrics.current_day_cost
        monthly_cost = metrics.current_month_cost

        # Check hourly budget
        if self.config.hourly_limit:
            hourly_remaining = self.config.hourly_limit - hourly_cost
            hourly_cost / self.config.hourly_limit

            alert = self._check_limit(
                BudgetPeriod.HOURLY, hourly_cost, self.config.hourly_limit, estimated_cost
            )
            if alert:
                alerts.append(alert)
        else:
            hourly_remaining = None

        # Check daily budget
        if self.config.daily_limit:
            daily_remaining = self.config.daily_limit - daily_cost
            daily_cost / self.config.daily_limit

            alert = self._check_limit(
                BudgetPeriod.DAILY, daily_cost, self.config.daily_limit, estimated_cost
            )
            if alert:
                alerts.append(alert)
        else:
            daily_remaining = None

        # Check monthly budget
        if self.config.monthly_limit:
            monthly_remaining = self.config.monthly_limit - monthly_cost
            monthly_cost / self.config.monthly_limit

            alert = self._check_limit(
                BudgetPeriod.MONTHLY, monthly_cost, self.config.monthly_limit, estimated_cost
            )
            if alert:
                alerts.append(alert)
        else:
            monthly_remaining = None

        # Calculate projections
        current_hour = datetime.now().hour
        hours_remaining_today = 24 - current_hour
        projected_daily = daily_cost + (hourly_cost * hours_remaining_today)

        current_day = datetime.now().day
        days_in_month = 30  # Approximate
        days_remaining = days_in_month - current_day
        projected_monthly = monthly_cost + (daily_cost * days_remaining)

        # Generate recommendations
        if any(a.level in [AlertLevel.WARNING, AlertLevel.CRITICAL] for a in alerts):
            recommendations.extend(
                [
                    "Consider using cached responses when possible",
                    "Switch to lighter detection strategies for simple prompts",
                    "Review and optimize high-cost API calls",
                ]
            )

        if any(a.level == AlertLevel.EXCEEDED for a in alerts):
            recommendations.append("Budget exceeded - new requests may be blocked")

        if self.config.prefer_cheap_models:
            recommendations.append("Using economy models to reduce costs")

        # Check if within budget
        within_budget = not any(a.level == AlertLevel.EXCEEDED for a in alerts)

        # Process alerts
        for alert in alerts:
            await self._process_alert(alert)

        return BudgetStatus(
            within_budget=within_budget,
            alerts=alerts,
            hourly_cost=hourly_cost,
            daily_cost=daily_cost,
            monthly_cost=monthly_cost,
            hourly_remaining=hourly_remaining,
            daily_remaining=daily_remaining,
            monthly_remaining=monthly_remaining,
            projected_daily=projected_daily,
            projected_monthly=projected_monthly,
            recommendations=recommendations,
        )

    def _check_limit(
        self, period: BudgetPeriod, current: float, limit: float, estimated: float
    ) -> BudgetAlert | None:
        """Check a specific budget limit.

        Args:
            period: Budget period
            current: Current usage
            limit: Budget limit
            estimated: Estimated next cost

        Returns:
            BudgetAlert if threshold exceeded, None otherwise
        """
        if not limit:
            return None

        # Calculate percentage including estimated cost
        total = current + estimated
        percentage = total / limit

        # Determine alert level
        if percentage >= 1.0:
            level = AlertLevel.EXCEEDED
            message = f"{period.value.capitalize()} budget exceeded"
        elif percentage >= self.config.critical_threshold:
            level = AlertLevel.CRITICAL
            message = f"{period.value.capitalize()} budget critical ({percentage:.0%})"
        elif percentage >= self.config.warning_threshold:
            level = AlertLevel.WARNING
            message = f"{period.value.capitalize()} budget warning ({percentage:.0%})"
        else:
            return None

        # Generate recommendations
        recommendations = []
        if level == AlertLevel.EXCEEDED:
            recommendations.append(f"Reduce usage or increase {period.value} budget")
        elif level == AlertLevel.CRITICAL:
            recommendations.append("Consider switching to cached/heuristic detection")
        elif level == AlertLevel.WARNING:
            recommendations.append("Monitor usage closely")

        return BudgetAlert(
            level=level,
            period=period,
            current_value=current,
            limit_value=limit,
            percentage=percentage * 100,
            message=message,
            timestamp=datetime.now(),
            recommendations=recommendations,
        )

    async def _process_alert(self, alert: BudgetAlert):
        """Process a budget alert.

        Args:
            alert: Alert to process
        """
        # Check if we should send this alert (rate limiting)
        alert_key = f"{alert.period.value}_{alert.level.value}"
        last_sent = self.last_alert_time.get(alert_key)

        # Only send same alert once per hour
        if last_sent and (datetime.now() - last_sent).seconds < 3600:
            return

        # Store alert
        self.alerts.append(alert)
        self.last_alert_time[alert_key] = datetime.now()

        # Log alert
        log_method = {
            AlertLevel.INFO: logger.info,
            AlertLevel.WARNING: logger.warning,
            AlertLevel.CRITICAL: logger.error,
            AlertLevel.EXCEEDED: logger.critical,
        }.get(alert.level, logger.warning)

        log_method(
            alert.message,
            period=alert.period.value,
            current=alert.current_value,
            limit=alert.limit_value,
            percentage=alert.percentage,
        )

        # Call alert callback if configured
        if self.alert_callback:
            try:
                await self.alert_callback(alert)
            except Exception as e:
                logger.error("Alert callback failed", error=str(e))

        # Take action based on alert level
        if alert.level == AlertLevel.EXCEEDED and self.config.block_on_exceeded:
            logger.critical("Budget exceeded - blocking new API requests")

        elif alert.level == AlertLevel.WARNING and self.config.throttle_on_warning:
            # Enable throttling for 5 minutes
            self.is_throttled = True
            self.throttle_until = datetime.now() + timedelta(minutes=5)
            logger.warning("Throttling enabled due to budget warning")

    async def _monitor_budget(self):
        """Background task to monitor budget status."""
        while True:
            try:
                # Check budget every minute
                await asyncio.sleep(60)

                # Check current status
                status = await self.check_budget()

                # Clear throttling if budget is healthy
                if status.within_budget and self.is_throttled:
                    if self.throttle_until and datetime.now() > self.throttle_until:
                        self.is_throttled = False
                        self.throttle_until = None
                        logger.info("Throttling disabled - budget healthy")

                # Clear old alerts (keep last 24 hours)
                cutoff = datetime.now() - timedelta(hours=24)
                self.alerts = [a for a in self.alerts if a.timestamp > cutoff]

            except Exception as e:
                logger.error("Budget monitoring error", error=str(e))

    def should_block(self, estimated_cost: float = 0.0) -> bool:
        """Check if request should be blocked due to budget.

        Args:
            estimated_cost: Estimated cost of request

        Returns:
            True if request should be blocked
        """
        if not self.config.block_on_exceeded:
            return False

        metrics = self.usage_tracker.get_metrics()

        # Check each limit
        if self.config.hourly_limit:
            if metrics.current_hour_cost + estimated_cost > self.config.hourly_limit:
                return True

        if self.config.daily_limit:
            if metrics.current_day_cost + estimated_cost > self.config.daily_limit:
                return True

        if self.config.monthly_limit:
            if metrics.current_month_cost + estimated_cost > self.config.monthly_limit:
                return True

        return False

    def should_throttle(self) -> bool:
        """Check if requests should be throttled.

        Returns:
            True if throttling is active
        """
        if not self.is_throttled:
            return False

        # Check if throttling period has expired
        if self.throttle_until and datetime.now() > self.throttle_until:
            self.is_throttled = False
            self.throttle_until = None
            return False

        return True

    def get_optimization_suggestions(self) -> list[str]:
        """Get cost optimization suggestions.

        Returns:
            List of optimization suggestions
        """
        suggestions = []
        metrics = self.usage_tracker.get_metrics()
        provider_breakdown = self.usage_tracker.get_provider_breakdown()

        # Check cache hit rate
        if metrics.cache_hit_rate < 0.3:
            suggestions.append(
                f"Low cache hit rate ({metrics.cache_hit_rate:.1%}) - "
                "Consider caching more responses"
            )

        # Check expensive providers
        for provider, stats in provider_breakdown.items():
            if stats["cost"] > metrics.total_cost_usd * 0.5:
                suggestions.append(
                    f"{provider} accounts for {stats['cost']/metrics.total_cost_usd:.0%} "
                    "of costs - consider using cheaper alternatives"
                )

        # Check failure rate
        if metrics.failed_requests > metrics.successful_requests * 0.1:
            suggestions.append(
                f"High failure rate ({metrics.failed_requests}/{metrics.total_requests}) - "
                "Investigate and fix errors to reduce wasted API calls"
            )

        # Check token usage
        if metrics.total_tokens > 0:
            avg_tokens = metrics.total_tokens / max(metrics.total_requests, 1)
            if avg_tokens > 1000:
                suggestions.append(
                    f"High average token usage ({avg_tokens:.0f}) - " "Consider optimizing prompts"
                )

        return suggestions

    def get_budget_summary(self) -> dict:
        """Get budget summary.

        Returns:
            Dictionary with budget overview
        """
        metrics = self.usage_tracker.get_metrics()

        summary = {
            "current_usage": {
                "hourly": metrics.current_hour_cost,
                "daily": metrics.current_day_cost,
                "monthly": metrics.current_month_cost,
            },
            "limits": {
                "hourly": self.config.hourly_limit,
                "daily": self.config.daily_limit,
                "monthly": self.config.monthly_limit,
            },
            "status": {
                "throttled": self.is_throttled,
                "recent_alerts": len(
                    [a for a in self.alerts if (datetime.now() - a.timestamp).seconds < 3600]
                ),
            },
            "optimization": self.get_optimization_suggestions(),
        }

        return summary
