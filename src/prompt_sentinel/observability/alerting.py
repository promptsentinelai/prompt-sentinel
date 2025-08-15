# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Alerting system for observability."""

import asyncio
import time
from collections import defaultdict
from collections.abc import Callable
from enum import Enum
from typing import Any


class AlertSeverity(str, Enum):
    """Alert severity levels."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class Alert:
    """Individual alert."""

    def __init__(
        self,
        name: str,
        message: str,
        severity: AlertSeverity,
        metadata: dict[str, Any] | None = None,
    ):
        """Initialize alert."""
        self.alert_id = f"{name}_{int(time.time() * 1000)}"
        self.name = name
        self.message = message
        self.severity = severity
        self.metadata = metadata or {}
        self.timestamp = time.time()
        self.acknowledged = False
        self.resolved = False


class AlertRule:
    """Alert rule definition."""

    def __init__(
        self, name: str, condition: Callable, severity: AlertSeverity, message_template: str
    ):
        """Initialize alert rule."""
        self.name = name
        self.condition = condition
        self.severity = severity
        self.message_template = message_template
        self.last_fired: float | None = None
        self.fire_count = 0


class AlertManager:
    """Manage alerts and alerting rules."""

    def __init__(self):
        """Initialize alert manager."""
        self.rules: dict[str, AlertRule] = {}
        self.active_alerts: dict[str, Alert] = {}
        self.alert_history: list[Alert] = []
        self.deduplication_window = 300  # 5 minutes
        self.escalation_policies = {}

    def add_rule(
        self, name: str, condition: Callable, severity: AlertSeverity, message_template: str
    ) -> None:
        """Add an alert rule."""
        self.rules[name] = AlertRule(name, condition, severity, message_template)

    async def evaluate_rules(self, metrics: dict[str, Any]) -> list[Alert]:
        """Evaluate alert rules against metrics."""
        new_alerts = []

        for _rule_name, rule in self.rules.items():
            try:
                # Evaluate condition
                should_fire = (
                    await rule.condition(metrics)
                    if asyncio.iscoroutinefunction(rule.condition)
                    else rule.condition(metrics)
                )

                if should_fire:
                    # Check deduplication
                    if not self._should_deduplicate(rule):
                        alert = self._create_alert(rule, metrics)
                        new_alerts.append(alert)
                        self.active_alerts[alert.alert_id] = alert
                        self.alert_history.append(alert)
                        rule.last_fired = time.time()
                        rule.fire_count += 1

            except Exception:
                # Log error evaluating rule
                pass

        return new_alerts

    def _should_deduplicate(self, rule: AlertRule) -> bool:
        """Check if alert should be deduplicated."""
        if rule.last_fired is None:
            return False

        time_since_last = time.time() - rule.last_fired
        return time_since_last < self.deduplication_window

    def _create_alert(self, rule: AlertRule, metrics: dict[str, Any]) -> Alert:
        """Create alert from rule."""
        message = rule.message_template.format(**metrics)
        return Alert(
            name=rule.name, message=message, severity=rule.severity, metadata={"metrics": metrics}
        )

    def acknowledge_alert(self, alert_id: str) -> bool:
        """Acknowledge an alert."""
        if alert_id in self.active_alerts:
            self.active_alerts[alert_id].acknowledged = True
            return True
        return False

    def resolve_alert(self, alert_id: str) -> bool:
        """Resolve an alert."""
        if alert_id in self.active_alerts:
            alert = self.active_alerts[alert_id]
            alert.resolved = True
            del self.active_alerts[alert_id]
            return True
        return False

    def escalate_alert(self, alert_id: str) -> bool:
        """Escalate an alert."""
        if alert_id in self.active_alerts:
            alert = self.active_alerts[alert_id]

            # Upgrade severity
            severity_order = [
                AlertSeverity.INFO,
                AlertSeverity.WARNING,
                AlertSeverity.ERROR,
                AlertSeverity.CRITICAL,
            ]

            current_index = severity_order.index(alert.severity)
            if current_index < len(severity_order) - 1:
                alert.severity = severity_order[current_index + 1]
                return True

        return False

    def get_active_alerts(self) -> list[Alert]:
        """Get all active alerts."""
        return list(self.active_alerts.values())

    def get_alert_summary(self) -> dict[str, Any]:
        """Get alert summary."""
        active_by_severity: defaultdict[str, int] = defaultdict(int)
        for alert in self.active_alerts.values():
            active_by_severity[alert.severity] += 1

        return {
            "total_active": len(self.active_alerts),
            "by_severity": dict(active_by_severity),
            "total_fired": len(self.alert_history),
            "rules_count": len(self.rules),
        }
