"""Safety controls and guardrails for A/B testing experiments.

This module provides comprehensive safety mechanisms to ensure experiments
don't negatively impact system performance or user experience.
"""

import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass
from enum import Enum

import structlog
from prompt_sentinel.cache.cache_manager import cache_manager

from .config import ExperimentConfig, ExperimentStatus, GuardrailConfig


logger = structlog.get_logger()


class GuardrailSeverity(Enum):
    """Severity levels for guardrail violations."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class GuardrailAction(Enum):
    """Actions to take when guardrails are triggered."""

    LOG_ONLY = "log_only"
    ALERT = "alert"
    REDUCE_TRAFFIC = "reduce_traffic"
    PAUSE_EXPERIMENT = "pause_experiment"
    TERMINATE_EXPERIMENT = "terminate_experiment"


@dataclass
class GuardrailViolation:
    """Record of a guardrail violation."""

    experiment_id: str
    guardrail_name: str
    metric_name: str
    threshold_value: float
    actual_value: float
    severity: GuardrailSeverity
    action_taken: GuardrailAction
    timestamp: datetime
    message: str
    metadata: Dict[str, Any]


@dataclass
class SafetyMetrics:
    """Safety-related metrics for monitoring."""

    experiment_id: str
    total_violations: int
    violations_by_severity: Dict[GuardrailSeverity, int]
    last_violation: Optional[datetime]
    experiment_health_score: float  # 0.0 to 1.0
    auto_actions_taken: int
    manual_interventions: int


class SafetyControls:
    """Safety control system for A/B testing experiments.

    Monitors experiment performance and automatically takes corrective
    actions when safety thresholds are violated.
    """

    def __init__(self):
        """Initialize safety controls."""
        self.active_experiments: Dict[str, ExperimentConfig] = {}
        self.guardrail_violations: List[GuardrailViolation] = []
        self.safety_metrics: Dict[str, SafetyMetrics] = {}
        self.monitoring_tasks: Dict[str, asyncio.Task] = {}

        # Safety callbacks
        self.violation_callbacks: List[Callable] = []

        # Default safety thresholds
        self.default_guardrails = self._create_default_guardrails()

    async def register_experiment(
        self,
        experiment: ExperimentConfig,
        custom_guardrails: Optional[List[GuardrailConfig]] = None,
    ):
        """Register experiment for safety monitoring.

        Args:
            experiment: Experiment configuration
            custom_guardrails: Custom safety guardrails
        """
        self.active_experiments[experiment.id] = experiment

        # Initialize safety metrics
        self.safety_metrics[experiment.id] = SafetyMetrics(
            experiment_id=experiment.id,
            total_violations=0,
            violations_by_severity={severity: 0 for severity in GuardrailSeverity},
            last_violation=None,
            experiment_health_score=1.0,
            auto_actions_taken=0,
            manual_interventions=0,
        )

        # Combine default and custom guardrails
        guardrails = list(self.default_guardrails)
        if custom_guardrails:
            guardrails.extend(custom_guardrails)
        if experiment.guardrails:
            guardrails.extend(experiment.guardrails)

        # Start monitoring task
        self.monitoring_tasks[experiment.id] = asyncio.create_task(
            self._monitor_experiment(experiment.id, guardrails)
        )

        logger.info(
            "Experiment registered for safety monitoring",
            experiment_id=experiment.id,
            guardrails_count=len(guardrails),
        )

    async def unregister_experiment(self, experiment_id: str):
        """Unregister experiment from safety monitoring.

        Args:
            experiment_id: Experiment identifier
        """
        # Cancel monitoring task
        if experiment_id in self.monitoring_tasks:
            self.monitoring_tasks[experiment_id].cancel()
            try:
                await self.monitoring_tasks[experiment_id]
            except asyncio.CancelledError:
                pass
            del self.monitoring_tasks[experiment_id]

        # Clean up
        if experiment_id in self.active_experiments:
            del self.active_experiments[experiment_id]

        logger.info("Experiment unregistered from safety monitoring", experiment_id=experiment_id)

    async def check_experiment_safety(
        self, experiment_id: str, metric_data: Dict[str, float]
    ) -> List[GuardrailViolation]:
        """Check experiment metrics against safety guardrails.

        Args:
            experiment_id: Experiment identifier
            metric_data: Current metric values

        Returns:
            List of guardrail violations
        """
        if experiment_id not in self.active_experiments:
            return []

        experiment = self.active_experiments[experiment_id]
        violations = []

        # Check each guardrail
        for guardrail in experiment.guardrails:
            if guardrail.metric_name not in metric_data:
                continue

            actual_value = metric_data[guardrail.metric_name]
            violation = self._check_guardrail(experiment_id, guardrail, actual_value)

            if violation:
                violations.append(violation)
                await self._handle_violation(violation)

        # Check default safety guardrails
        for guardrail in self.default_guardrails:
            if guardrail.metric_name not in metric_data:
                continue

            actual_value = metric_data[guardrail.metric_name]
            violation = self._check_guardrail(experiment_id, guardrail, actual_value)

            if violation:
                violations.append(violation)
                await self._handle_violation(violation)

        return violations

    async def emergency_stop(self, experiment_id: str, reason: str):
        """Immediately stop experiment due to safety concerns.

        Args:
            experiment_id: Experiment identifier
            reason: Reason for emergency stop
        """
        if experiment_id not in self.active_experiments:
            logger.warning("Cannot emergency stop unknown experiment", experiment_id=experiment_id)
            return

        # Update experiment status
        experiment = self.active_experiments[experiment_id]
        experiment.status = ExperimentStatus.TERMINATED

        # Record critical violation
        violation = GuardrailViolation(
            experiment_id=experiment_id,
            guardrail_name="emergency_stop",
            metric_name="safety_override",
            threshold_value=0.0,
            actual_value=1.0,
            severity=GuardrailSeverity.CRITICAL,
            action_taken=GuardrailAction.TERMINATE_EXPERIMENT,
            timestamp=datetime.utcnow(),
            message=f"Emergency stop: {reason}",
            metadata={"manual_intervention": True},
        )

        self.guardrail_violations.append(violation)

        # Update safety metrics
        if experiment_id in self.safety_metrics:
            metrics = self.safety_metrics[experiment_id]
            metrics.manual_interventions += 1
            metrics.experiment_health_score = 0.0

        # Notify callbacks
        for callback in self.violation_callbacks:
            try:
                await callback(violation)
            except Exception as e:
                logger.error("Violation callback failed", error=str(e))

        logger.critical("Emergency experiment stop", experiment_id=experiment_id, reason=reason)

    def get_safety_report(self, experiment_id: str) -> Dict[str, Any]:
        """Get safety report for experiment.

        Args:
            experiment_id: Experiment identifier

        Returns:
            Safety report
        """
        if experiment_id not in self.safety_metrics:
            return {"error": "Experiment not found"}

        metrics = self.safety_metrics[experiment_id]
        recent_violations = [
            v
            for v in self.guardrail_violations
            if v.experiment_id == experiment_id
            and v.timestamp > datetime.utcnow() - timedelta(hours=24)
        ]

        return {
            "experiment_id": experiment_id,
            "health_score": metrics.experiment_health_score,
            "total_violations": metrics.total_violations,
            "violations_by_severity": {
                sev.value: count for sev, count in metrics.violations_by_severity.items()
            },
            "recent_violations_24h": len(recent_violations),
            "last_violation": (
                metrics.last_violation.isoformat() if metrics.last_violation else None
            ),
            "auto_actions_taken": metrics.auto_actions_taken,
            "manual_interventions": metrics.manual_interventions,
            "monitoring_active": experiment_id in self.monitoring_tasks,
            "recent_violations": [
                {
                    "guardrail": v.guardrail_name,
                    "metric": v.metric_name,
                    "severity": v.severity.value,
                    "action": v.action_taken.value,
                    "timestamp": v.timestamp.isoformat(),
                    "message": v.message,
                }
                for v in recent_violations[-10:]  # Last 10 violations
            ],
        }

    def add_violation_callback(self, callback: Callable):
        """Add callback for guardrail violations.

        Args:
            callback: Async callback function
        """
        self.violation_callbacks.append(callback)

    async def _monitor_experiment(self, experiment_id: str, guardrails: List[GuardrailConfig]):
        """Background monitoring task for experiment.

        Args:
            experiment_id: Experiment identifier
            guardrails: List of guardrails to monitor
        """
        logger.info("Started experiment monitoring", experiment_id=experiment_id)

        try:
            while experiment_id in self.active_experiments:
                experiment = self.active_experiments[experiment_id]

                # Skip if experiment is not running
                if experiment.status != ExperimentStatus.RUNNING:
                    await asyncio.sleep(60)  # Check every minute
                    continue

                # Collect current metrics
                metric_data = await self._collect_experiment_metrics(experiment_id)

                # Check guardrails
                violations = await self.check_experiment_safety(experiment_id, metric_data)

                # Update health score
                await self._update_health_score(experiment_id, violations)

                # Sleep before next check
                await asyncio.sleep(30)  # Check every 30 seconds

        except asyncio.CancelledError:
            logger.info("Experiment monitoring cancelled", experiment_id=experiment_id)
        except Exception as e:
            logger.error("Experiment monitoring failed", experiment_id=experiment_id, error=str(e))

    async def _collect_experiment_metrics(self, experiment_id: str) -> Dict[str, float]:
        """Collect current metrics for experiment.

        Args:
            experiment_id: Experiment identifier

        Returns:
            Current metric values
        """
        # This would integrate with the monitoring system
        # For now, return mock data
        return {
            "error_rate": 0.01,
            "response_time_p95": 150.0,
            "success_rate": 0.995,
            "cpu_usage": 0.65,
            "memory_usage": 0.70,
            "cache_hit_rate": 0.85,
        }

    def _check_guardrail(
        self, experiment_id: str, guardrail: GuardrailConfig, actual_value: float
    ) -> Optional[GuardrailViolation]:
        """Check if a guardrail is violated.

        Args:
            experiment_id: Experiment identifier
            guardrail: Guardrail configuration
            actual_value: Actual metric value

        Returns:
            Violation if guardrail is violated
        """
        violated = False

        if guardrail.threshold_type == "max":
            violated = actual_value > guardrail.threshold_value
        elif guardrail.threshold_type == "min":
            violated = actual_value < guardrail.threshold_value

        if not violated:
            return None

        # Determine severity
        severity = self._determine_severity(guardrail, actual_value)

        # Determine action
        action = GuardrailAction(guardrail.action)

        return GuardrailViolation(
            experiment_id=experiment_id,
            guardrail_name=f"{guardrail.metric_name}_{guardrail.threshold_type}",
            metric_name=guardrail.metric_name,
            threshold_value=guardrail.threshold_value,
            actual_value=actual_value,
            severity=severity,
            action_taken=action,
            timestamp=datetime.utcnow(),
            message=f"{guardrail.metric_name} {guardrail.threshold_type} threshold violated: "
            f"{actual_value} vs {guardrail.threshold_value}",
            metadata={},
        )

    def _determine_severity(
        self, guardrail: GuardrailConfig, actual_value: float
    ) -> GuardrailSeverity:
        """Determine severity of guardrail violation.

        Args:
            guardrail: Guardrail configuration
            actual_value: Actual metric value

        Returns:
            Violation severity
        """
        threshold = guardrail.threshold_value

        if guardrail.threshold_type == "max":
            if actual_value > threshold * 2:
                return GuardrailSeverity.CRITICAL
            elif actual_value > threshold * 1.5:
                return GuardrailSeverity.HIGH
            elif actual_value > threshold * 1.2:
                return GuardrailSeverity.MEDIUM
            else:
                return GuardrailSeverity.LOW

        else:  # min threshold
            if actual_value < threshold * 0.5:
                return GuardrailSeverity.CRITICAL
            elif actual_value < threshold * 0.7:
                return GuardrailSeverity.HIGH
            elif actual_value < threshold * 0.8:
                return GuardrailSeverity.MEDIUM
            else:
                return GuardrailSeverity.LOW

    async def _handle_violation(self, violation: GuardrailViolation):
        """Handle a guardrail violation.

        Args:
            violation: Guardrail violation
        """
        # Record violation
        self.guardrail_violations.append(violation)

        # Update safety metrics
        experiment_id = violation.experiment_id
        if experiment_id in self.safety_metrics:
            metrics = self.safety_metrics[experiment_id]
            metrics.total_violations += 1
            metrics.violations_by_severity[violation.severity] += 1
            metrics.last_violation = violation.timestamp

        # Take action based on severity and configuration
        if violation.action_taken == GuardrailAction.PAUSE_EXPERIMENT:
            await self._pause_experiment(experiment_id, violation.message)

        elif violation.action_taken == GuardrailAction.TERMINATE_EXPERIMENT:
            await self._terminate_experiment(experiment_id, violation.message)

        elif violation.action_taken == GuardrailAction.REDUCE_TRAFFIC:
            await self._reduce_experiment_traffic(experiment_id)

        # Notify callbacks
        for callback in self.violation_callbacks:
            try:
                await callback(violation)
            except Exception as e:
                logger.error("Violation callback failed", error=str(e))

        # Log violation
        logger.warning(
            "Guardrail violation",
            experiment_id=experiment_id,
            guardrail=violation.guardrail_name,
            severity=violation.severity.value,
            action=violation.action_taken.value,
            message=violation.message,
        )

    async def _pause_experiment(self, experiment_id: str, reason: str):
        """Pause experiment due to safety violation.

        Args:
            experiment_id: Experiment identifier
            reason: Reason for pausing
        """
        if experiment_id not in self.active_experiments:
            return

        experiment = self.active_experiments[experiment_id]
        experiment.status = ExperimentStatus.PAUSED

        # Update safety metrics
        if experiment_id in self.safety_metrics:
            self.safety_metrics[experiment_id].auto_actions_taken += 1

        logger.warning(
            "Experiment paused due to safety violation", experiment_id=experiment_id, reason=reason
        )

    async def _terminate_experiment(self, experiment_id: str, reason: str):
        """Terminate experiment due to safety violation.

        Args:
            experiment_id: Experiment identifier
            reason: Reason for termination
        """
        if experiment_id not in self.active_experiments:
            return

        experiment = self.active_experiments[experiment_id]
        experiment.status = ExperimentStatus.TERMINATED

        # Update safety metrics
        if experiment_id in self.safety_metrics:
            metrics = self.safety_metrics[experiment_id]
            metrics.auto_actions_taken += 1
            metrics.experiment_health_score = 0.0

        logger.error(
            "Experiment terminated due to safety violation",
            experiment_id=experiment_id,
            reason=reason,
        )

    async def _reduce_experiment_traffic(self, experiment_id: str):
        """Reduce experiment traffic allocation.

        Args:
            experiment_id: Experiment identifier
        """
        if experiment_id not in self.active_experiments:
            return

        experiment = self.active_experiments[experiment_id]

        # Reduce traffic by 50%
        new_percentage = experiment.target_percentage * 0.5
        experiment.target_percentage = max(0.01, new_percentage)

        # Update safety metrics
        if experiment_id in self.safety_metrics:
            self.safety_metrics[experiment_id].auto_actions_taken += 1

        logger.warning(
            "Reduced experiment traffic",
            experiment_id=experiment_id,
            new_percentage=experiment.target_percentage,
        )

    async def _update_health_score(self, experiment_id: str, violations: List[GuardrailViolation]):
        """Update experiment health score based on recent violations.

        Args:
            experiment_id: Experiment identifier
            violations: Recent violations
        """
        if experiment_id not in self.safety_metrics:
            return

        metrics = self.safety_metrics[experiment_id]

        # Calculate health score based on recent violations
        recent_violations = [
            v
            for v in self.guardrail_violations
            if v.experiment_id == experiment_id
            and v.timestamp > datetime.utcnow() - timedelta(hours=1)
        ]

        if not recent_violations:
            metrics.experiment_health_score = min(1.0, metrics.experiment_health_score + 0.1)
        else:
            # Reduce health score based on violations
            penalty = 0
            for violation in recent_violations:
                if violation.severity == GuardrailSeverity.CRITICAL:
                    penalty += 0.5
                elif violation.severity == GuardrailSeverity.HIGH:
                    penalty += 0.3
                elif violation.severity == GuardrailSeverity.MEDIUM:
                    penalty += 0.2
                else:
                    penalty += 0.1

            metrics.experiment_health_score = max(0.0, metrics.experiment_health_score - penalty)

    def _create_default_guardrails(self) -> List[GuardrailConfig]:
        """Create default safety guardrails.

        Returns:
            List of default guardrails
        """
        return [
            GuardrailConfig(
                metric_name="error_rate",
                threshold_type="max",
                threshold_value=0.05,  # 5% error rate
                window_minutes=5,
                action="pause",
            ),
            GuardrailConfig(
                metric_name="response_time_p95",
                threshold_type="max",
                threshold_value=2000.0,  # 2000ms
                window_minutes=5,
                action="pause",
            ),
            GuardrailConfig(
                metric_name="success_rate",
                threshold_type="min",
                threshold_value=0.95,  # 95% success rate
                window_minutes=5,
                action="pause",
            ),
            GuardrailConfig(
                metric_name="cpu_usage",
                threshold_type="max",
                threshold_value=0.9,  # 90% CPU
                window_minutes=10,
                action="terminate",
            ),
            GuardrailConfig(
                metric_name="memory_usage",
                threshold_type="max",
                threshold_value=0.9,  # 90% memory
                window_minutes=10,
                action="terminate",
            ),
        ]
