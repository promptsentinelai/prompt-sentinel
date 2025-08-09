"""Experiment manager for coordinating A/B testing experiments.

This module provides the central coordination for all A/B testing functionality,
including experiment lifecycle management, metric collection, and integration
with the detection routing system.
"""

import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Callable
from dataclasses import dataclass, field
import json

import structlog
from prompt_sentinel.cache.cache_manager import cache_manager
from prompt_sentinel.models.schemas import Message, DetectionResponse

from .config import (
    ExperimentConfig,
    ExperimentVariant,
    ExperimentStatus,
    ExperimentAssignment,
    ExperimentMetadata,
    ExperimentType,
)
from .assignments import AssignmentService, AssignmentContext, BucketingStrategy
from .analyzer import StatisticalAnalyzer, ExperimentResult, MetricData
from .safety import SafetyControls, GuardrailViolation
from .collectors import MetricsCollector
from .database import ExperimentDatabase


logger = structlog.get_logger()


@dataclass
class ExperimentExecution:
    """Runtime state for experiment execution."""

    experiment_id: str
    variant_configs: Dict[str, Dict[str, Any]]
    assignment_cache: Dict[str, str]  # user_id -> variant_id
    metrics_buffer: List[Dict[str, Any]] = field(default_factory=list)
    last_analysis: Optional[datetime] = None
    active_assignments: int = 0


class ExperimentError(Exception):
    """Exception raised during experiment operations."""

    pass


class ExperimentManager:
    """Central manager for A/B testing experiments.

    Coordinates all aspects of experiment execution including:
    - Experiment lifecycle management
    - User assignment and bucketing
    - Metric collection and analysis
    - Safety monitoring and controls
    - Integration with detection routing
    """

    def __init__(
        self,
        database: Optional[ExperimentDatabase] = None,
        assignment_service: Optional[AssignmentService] = None,
        analyzer: Optional[StatisticalAnalyzer] = None,
        safety_controls: Optional[SafetyControls] = None,
        metrics_collector: Optional[MetricsCollector] = None,
    ):
        """Initialize experiment manager.

        Args:
            database: Experiment database backend
            assignment_service: User assignment service
            analyzer: Statistical analysis engine
            safety_controls: Safety monitoring system
            metrics_collector: Metrics collection service
        """
        self.database = database or ExperimentDatabase()
        self.assignment_service = assignment_service or AssignmentService()
        self.analyzer = analyzer or StatisticalAnalyzer()
        self.safety_controls = safety_controls or SafetyControls()
        self.metrics_collector = metrics_collector or MetricsCollector()

        # Runtime state
        self.active_experiments: Dict[str, ExperimentExecution] = {}
        self.experiment_configs: Dict[str, ExperimentConfig] = {}

        # Background tasks
        self.analysis_task: Optional[asyncio.Task] = None
        self.metrics_flush_task: Optional[asyncio.Task] = None

        # Event handlers
        self.experiment_started_handlers: List[Callable] = []
        self.experiment_completed_handlers: List[Callable] = []
        self.assignment_handlers: List[Callable] = []

    async def initialize(self):
        """Initialize the experiment manager."""
        # Initialize components
        await self.database.initialize()

        # Load active experiments
        await self._load_active_experiments()

        # Setup safety monitoring callbacks
        self.safety_controls.add_violation_callback(self._handle_safety_violation)

        # Start background tasks
        self.analysis_task = asyncio.create_task(self._analysis_loop())
        self.metrics_flush_task = asyncio.create_task(self._metrics_flush_loop())

        logger.info(
            "Experiment manager initialized", active_experiments=len(self.active_experiments)
        )

    async def shutdown(self):
        """Shutdown the experiment manager."""
        # Cancel background tasks
        if self.analysis_task:
            self.analysis_task.cancel()
        if self.metrics_flush_task:
            self.metrics_flush_task.cancel()

        # Flush remaining metrics
        for execution in self.active_experiments.values():
            await self._flush_metrics(execution)

        # Shutdown components
        await self.database.close()

        logger.info("Experiment manager shutdown complete")

    async def create_experiment(
        self, config: ExperimentConfig, start_immediately: bool = False
    ) -> str:
        """Create a new experiment.

        Args:
            config: Experiment configuration
            start_immediately: Whether to start immediately

        Returns:
            Experiment ID
        """
        # Validate configuration
        self._validate_experiment_config(config)

        # Save to database
        await self.database.save_experiment(config)

        # Register with safety controls
        await self.safety_controls.register_experiment(config)

        # Cache configuration
        self.experiment_configs[config.id] = config

        if start_immediately:
            await self.start_experiment(config.id)

        logger.info(
            "Experiment created",
            experiment_id=config.id,
            type=config.type.value,
            variants=len(config.variants),
        )

        return config.id

    async def start_experiment(self, experiment_id: str) -> bool:
        """Start an experiment.

        Args:
            experiment_id: Experiment identifier

        Returns:
            True if started successfully
        """
        if experiment_id not in self.experiment_configs:
            config = await self.database.get_experiment(experiment_id)
            if not config:
                raise ExperimentError(f"Experiment not found: {experiment_id}")
            self.experiment_configs[experiment_id] = config

        config = self.experiment_configs[experiment_id]

        # Validate experiment can be started
        if config.status not in [ExperimentStatus.DRAFT, ExperimentStatus.SCHEDULED]:
            raise ExperimentError(f"Cannot start experiment in status: {config.status}")

        # Update status
        config.status = ExperimentStatus.RUNNING
        config.start_time = datetime.utcnow()
        await self.database.update_experiment(config)

        # Create execution state
        execution = ExperimentExecution(
            experiment_id=experiment_id,
            variant_configs={variant.id: variant.config for variant in config.variants},
            assignment_cache={},
        )
        self.active_experiments[experiment_id] = execution

        # Notify handlers
        for handler in self.experiment_started_handlers:
            try:
                await handler(config)
            except Exception as e:
                logger.error("Experiment started handler failed", error=str(e))

        logger.info("Experiment started", experiment_id=experiment_id)

        return True

    async def stop_experiment(self, experiment_id: str, reason: str = "Manual stop") -> bool:
        """Stop an experiment.

        Args:
            experiment_id: Experiment identifier
            reason: Reason for stopping

        Returns:
            True if stopped successfully
        """
        if experiment_id not in self.experiment_configs:
            return False

        config = self.experiment_configs[experiment_id]

        # Update status
        config.status = ExperimentStatus.COMPLETED
        config.end_time = datetime.utcnow()
        await self.database.update_experiment(config)

        # Flush remaining metrics
        if experiment_id in self.active_experiments:
            execution = self.active_experiments[experiment_id]
            await self._flush_metrics(execution)
            del self.active_experiments[experiment_id]

        # Unregister from safety controls
        await self.safety_controls.unregister_experiment(experiment_id)

        # Perform final analysis
        await self._analyze_experiment(experiment_id)

        # Notify handlers
        for handler in self.experiment_completed_handlers:
            try:
                await handler(config, reason)
            except Exception as e:
                logger.error("Experiment completed handler failed", error=str(e))

        logger.info("Experiment stopped", experiment_id=experiment_id, reason=reason)

        return True

    async def assign_user(
        self, user_id: str, experiment_id: str, context: Optional[AssignmentContext] = None
    ) -> Optional[ExperimentAssignment]:
        """Assign user to experiment variant.

        Args:
            user_id: User identifier
            experiment_id: Experiment identifier
            context: Assignment context

        Returns:
            Assignment if user should participate
        """
        if experiment_id not in self.experiment_configs:
            return None

        config = self.experiment_configs[experiment_id]

        # Check if experiment is active
        if not config.is_active():
            return None

        # Create context if not provided
        if not context:
            context = AssignmentContext(user_id=user_id)

        # Get assignment
        assignment = await self.assignment_service.assign_user(
            context, config, BucketingStrategy.HASH_BASED
        )

        if assignment:
            # Update execution state
            if experiment_id in self.active_experiments:
                execution = self.active_experiments[experiment_id]
                execution.assignment_cache[user_id] = assignment.variant_id
                execution.active_assignments += 1

            # Record assignment event
            await self.record_assignment_event(assignment, context)

            # Notify handlers
            for handler in self.assignment_handlers:
                try:
                    await handler(assignment, context)
                except Exception as e:
                    logger.error("Assignment handler failed", error=str(e))

        return assignment

    async def get_variant_config(
        self, user_id: str, experiment_id: str
    ) -> Optional[Dict[str, Any]]:
        """Get variant configuration for user.

        Args:
            user_id: User identifier
            experiment_id: Experiment identifier

        Returns:
            Variant configuration if user is assigned
        """
        assignment = await self.assignment_service.get_assignment(user_id, experiment_id)

        if not assignment:
            return None

        if experiment_id in self.active_experiments:
            execution = self.active_experiments[experiment_id]
            return execution.variant_configs.get(assignment.variant_id)

        return None

    async def record_metric(
        self,
        experiment_id: str,
        user_id: str,
        metric_name: str,
        value: float,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Record a metric value for an experiment.

        Args:
            experiment_id: Experiment identifier
            user_id: User identifier
            metric_name: Name of the metric
            value: Metric value
            metadata: Additional metadata
        """
        if experiment_id not in self.active_experiments:
            return

        # Get user's variant assignment
        assignment = await self.assignment_service.get_assignment(user_id, experiment_id)
        if not assignment:
            return

        # Record metric
        metric_event = {
            "experiment_id": experiment_id,
            "user_id": user_id,
            "variant_id": assignment.variant_id,
            "metric_name": metric_name,
            "value": value,
            "timestamp": datetime.utcnow().isoformat(),
            "metadata": metadata or {},
        }

        # Add to buffer
        execution = self.active_experiments[experiment_id]
        execution.metrics_buffer.append(metric_event)

        # Also record with metrics collector
        await self.metrics_collector.record_experiment_metric(
            experiment_id, assignment.variant_id, metric_name, value
        )

    async def record_detection_result(
        self,
        experiment_id: str,
        user_id: str,
        detection_response: DetectionResponse,
        routing_metadata: Optional[Dict[str, Any]] = None,
    ):
        """Record detection result for experiment analysis.

        Args:
            experiment_id: Experiment identifier
            user_id: User identifier
            detection_response: Detection result
            routing_metadata: Routing metadata
        """
        # Extract key metrics from detection response
        await self.record_metric(
            experiment_id, user_id, "response_time_ms", detection_response.processing_time_ms
        )

        await self.record_metric(
            experiment_id, user_id, "confidence", detection_response.confidence
        )

        # Record binary metrics
        await self.record_metric(
            experiment_id, user_id, "blocked", 1.0 if detection_response.verdict == "block" else 0.0
        )

        await self.record_metric(
            experiment_id, user_id, "pii_detected", 1.0 if detection_response.pii_detected else 0.0
        )

        # Record routing metadata if available
        if routing_metadata:
            if "strategy" in routing_metadata:
                await self.record_metric(
                    experiment_id,
                    user_id,
                    "strategy_latency",
                    routing_metadata.get("routing_latency_ms", 0),
                )

    async def get_experiment_results(self, experiment_id: str) -> List[ExperimentResult]:
        """Get statistical analysis results for experiment.

        Args:
            experiment_id: Experiment identifier

        Returns:
            List of analysis results
        """
        # Get metric data from database
        metric_data = await self.database.get_experiment_metrics(experiment_id)

        if not metric_data:
            return []

        # Get experiment config
        config = self.experiment_configs.get(experiment_id)
        if not config:
            config = await self.database.get_experiment(experiment_id)
            if not config:
                return []

        # Prepare metric configurations
        metric_configs = {
            metric: {"type": "continuous", "min_effect_size": 0.05}
            for metric in config.primary_metrics + config.secondary_metrics
        }

        # Analyze experiment
        results = await self.analyzer.analyze_experiment(
            experiment_id,
            metric_data,
            metric_configs,
            min_sample_size=config.min_sample_size,
            confidence_level=config.confidence_level,
        )

        return results

    async def get_experiment_status(self, experiment_id: str) -> Optional[Dict[str, Any]]:
        """Get comprehensive experiment status.

        Args:
            experiment_id: Experiment identifier

        Returns:
            Experiment status and metrics
        """
        config = self.experiment_configs.get(experiment_id)
        if not config:
            config = await self.database.get_experiment(experiment_id)
            if not config:
                return None

        # Get assignment statistics
        assignment_stats = await self.assignment_service.get_assignment_stats(experiment_id)

        # Get safety report
        safety_report = self.safety_controls.get_safety_report(experiment_id)

        # Get latest analysis results
        results = await self.get_experiment_results(experiment_id)

        # Calculate runtime metrics
        runtime_metrics = {}
        if experiment_id in self.active_experiments:
            execution = self.active_experiments[experiment_id]
            runtime_metrics = {
                "active_assignments": execution.active_assignments,
                "buffered_metrics": len(execution.metrics_buffer),
                "last_analysis": (
                    execution.last_analysis.isoformat() if execution.last_analysis else None
                ),
            }

        return {
            "experiment_id": experiment_id,
            "name": config.name,
            "type": config.type.value,
            "status": config.status.value,
            "start_time": config.start_time.isoformat() if config.start_time else None,
            "end_time": config.end_time.isoformat() if config.end_time else None,
            "is_active": config.is_active(),
            "variants": [
                {
                    "id": v.id,
                    "name": v.name,
                    "traffic_percentage": v.traffic_percentage,
                    "is_control": v.is_control,
                }
                for v in config.variants
            ],
            "assignment_stats": assignment_stats,
            "safety_report": safety_report,
            "runtime_metrics": runtime_metrics,
            "analysis_results": [result.get_summary() for result in results],
            "primary_metrics": config.primary_metrics,
            "secondary_metrics": config.secondary_metrics,
        }

    async def list_experiments(
        self,
        status_filter: Optional[ExperimentStatus] = None,
        type_filter: Optional[ExperimentType] = None,
    ) -> List[Dict[str, Any]]:
        """List experiments with optional filtering.

        Args:
            status_filter: Filter by experiment status
            type_filter: Filter by experiment type

        Returns:
            List of experiment summaries
        """
        experiments = await self.database.list_experiments(status_filter, type_filter)

        summaries = []
        for config in experiments:
            summary = {
                "id": config.id,
                "name": config.name,
                "type": config.type.value,
                "status": config.status.value,
                "created_at": config.created_at.isoformat(),
                "start_time": config.start_time.isoformat() if config.start_time else None,
                "variants_count": len(config.variants),
                "is_active": config.is_active(),
            }
            summaries.append(summary)

        return summaries

    async def record_assignment_event(
        self, assignment: ExperimentAssignment, context: AssignmentContext
    ):
        """Record assignment event for analytics.

        Args:
            assignment: User assignment
            context: Assignment context
        """
        event = {
            "event_type": "assignment",
            "experiment_id": assignment.experiment_id,
            "user_id": assignment.user_id,
            "variant_id": assignment.variant_id,
            "timestamp": assignment.assigned_at.isoformat(),
            "context": {
                "session_id": context.session_id,
                "ip_address": context.ip_address,
                "user_agent": context.user_agent,
                "attributes": context.attributes,
            },
        }

        await self.database.save_assignment_event(event)

    def add_experiment_started_handler(self, handler: Callable):
        """Add handler for experiment started events."""
        self.experiment_started_handlers.append(handler)

    def add_experiment_completed_handler(self, handler: Callable):
        """Add handler for experiment completed events."""
        self.experiment_completed_handlers.append(handler)

    def add_assignment_handler(self, handler: Callable):
        """Add handler for user assignment events."""
        self.assignment_handlers.append(handler)

    # Private methods

    def _validate_experiment_config(self, config: ExperimentConfig):
        """Validate experiment configuration."""
        # This will trigger Pydantic validation
        # Additional custom validation can be added here
        pass

    async def _load_active_experiments(self):
        """Load active experiments from database."""
        active_experiments = await self.database.list_experiments(
            status_filter=ExperimentStatus.RUNNING
        )

        for config in active_experiments:
            self.experiment_configs[config.id] = config

            # Create execution state
            execution = ExperimentExecution(
                experiment_id=config.id,
                variant_configs={variant.id: variant.config for variant in config.variants},
                assignment_cache={},
            )
            self.active_experiments[config.id] = execution

            # Register with safety controls
            await self.safety_controls.register_experiment(config)

    async def _analysis_loop(self):
        """Background task for periodic analysis."""
        while True:
            try:
                await asyncio.sleep(300)  # Analyze every 5 minutes

                for experiment_id in list(self.active_experiments.keys()):
                    await self._analyze_experiment(experiment_id)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Analysis loop error", error=str(e))

    async def _metrics_flush_loop(self):
        """Background task for flushing metrics."""
        while True:
            try:
                await asyncio.sleep(60)  # Flush every minute

                for execution in self.active_experiments.values():
                    await self._flush_metrics(execution)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Metrics flush loop error", error=str(e))

    async def _flush_metrics(self, execution: ExperimentExecution):
        """Flush buffered metrics to database."""
        if not execution.metrics_buffer:
            return

        try:
            await self.database.save_metrics_batch(execution.metrics_buffer)
            execution.metrics_buffer.clear()

        except Exception as e:
            logger.error(
                "Failed to flush metrics", experiment_id=execution.experiment_id, error=str(e)
            )

    async def _analyze_experiment(self, experiment_id: str):
        """Perform analysis for a single experiment."""
        try:
            results = await self.get_experiment_results(experiment_id)

            if results:
                # Save analysis results
                await self.database.save_analysis_results(experiment_id, results)

                # Update execution state
                if experiment_id in self.active_experiments:
                    self.active_experiments[experiment_id].last_analysis = datetime.utcnow()

                # Check for auto-promotion
                config = self.experiment_configs.get(experiment_id)
                if config and config.auto_promote:
                    await self._check_auto_promotion(experiment_id, results)

        except Exception as e:
            logger.error("Failed to analyze experiment", experiment_id=experiment_id, error=str(e))

    async def _check_auto_promotion(self, experiment_id: str, results: List[ExperimentResult]):
        """Check if winning variant should be auto-promoted."""
        # Find significant results with positive effect
        significant_improvements = [
            r
            for r in results
            if r.is_significant and r.practical_significance and r.effect_size > 0
        ]

        if significant_improvements:
            # For now, just log - actual promotion would need more sophisticated logic
            logger.info(
                "Experiment has significant improvements",
                experiment_id=experiment_id,
                improvements=len(significant_improvements),
            )

    async def _handle_safety_violation(self, violation: GuardrailViolation):
        """Handle safety violations from safety controls."""
        logger.warning(
            "Safety violation in experiment",
            experiment_id=violation.experiment_id,
            guardrail=violation.guardrail_name,
            severity=violation.severity.value,
        )

        # Record violation event
        await self.database.save_safety_violation(violation)
