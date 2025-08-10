"""Comprehensive tests for experiments manager module."""

import pytest

# Mark entire module as skip - experiments feature is partially implemented
pytestmark = pytest.mark.skip(reason="Experiments feature is partially implemented")

from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

from prompt_sentinel.experiments.analyzer import ExperimentResult, StatisticalAnalyzer
from prompt_sentinel.experiments.assignments import AssignmentContext, AssignmentService
from prompt_sentinel.experiments.collectors import MetricsCollector
from prompt_sentinel.experiments.config import (
    ExperimentAssignment,
    ExperimentConfig,
    ExperimentStatus,
    ExperimentType,
    ExperimentVariant,
    GuardrailConfig,
    TrafficAllocation,
)
from prompt_sentinel.experiments.database import ExperimentDatabase
from prompt_sentinel.experiments.manager import (
    ExperimentError,
    ExperimentExecution,
    ExperimentManager,
)
from prompt_sentinel.experiments.safety import GuardrailViolation, SafetyControls
from prompt_sentinel.models.schemas import DetectionResponse, Verdict


class TestExperimentExecution:
    """Test suite for ExperimentExecution dataclass."""

    def test_initialization(self):
        """Test ExperimentExecution initialization."""
        execution = ExperimentExecution(
            experiment_id="exp_001",
            variant_configs={
                "control": {"threshold": 0.5},
                "treatment": {"threshold": 0.7},
            },
            assignment_cache={"user_001": "control"},
        )

        assert execution.experiment_id == "exp_001"
        assert len(execution.variant_configs) == 2
        assert execution.assignment_cache["user_001"] == "control"
        assert execution.metrics_buffer == []
        assert execution.last_analysis is None
        assert execution.active_assignments == 0

    def test_metrics_buffer(self):
        """Test metrics buffer management."""
        execution = ExperimentExecution(
            experiment_id="exp_001",
            variant_configs={},
            assignment_cache={},
        )

        # Add metrics to buffer
        metric = {"metric_name": "accuracy", "value": 0.95}
        execution.metrics_buffer.append(metric)

        assert len(execution.metrics_buffer) == 1
        assert execution.metrics_buffer[0]["value"] == 0.95


class TestExperimentManager:
    """Test suite for ExperimentManager."""

    @pytest.fixture
    def mock_database(self):
        """Create mock database."""
        db = MagicMock(spec=ExperimentDatabase)
        db.initialize = AsyncMock()
        db.save_experiment = AsyncMock(return_value=True)
        db.get_experiment = AsyncMock()
        db.list_experiments = AsyncMock(return_value=[])
        db.update_experiment = AsyncMock(return_value=True)
        db.save_metrics_batch = AsyncMock(return_value=True)
        db.save_analysis_results = AsyncMock(return_value=True)
        return db

    @pytest.fixture
    def mock_assignment_service(self):
        """Create mock assignment service."""
        service = MagicMock(spec=AssignmentService)
        service.get_assignment = AsyncMock()
        service.save_assignment = AsyncMock()
        return service

    @pytest.fixture
    def mock_analyzer(self):
        """Create mock statistical analyzer."""
        analyzer = MagicMock(spec=StatisticalAnalyzer)
        analyzer.analyze = AsyncMock()
        return analyzer

    @pytest.fixture
    def mock_safety_controls(self):
        """Create mock safety controls."""
        controls = MagicMock(spec=SafetyControls)
        controls.check_guardrails = AsyncMock(return_value=[])
        controls.monitor_experiment = AsyncMock()
        return controls

    @pytest.fixture
    def mock_metrics_collector(self):
        """Create mock metrics collector."""
        collector = MagicMock(spec=MetricsCollector)
        collector.collect = AsyncMock()
        collector.get_buffer = MagicMock(return_value=[])
        collector.clear_buffer = MagicMock()
        return collector

    @pytest.fixture
    def manager(
        self,
        mock_database,
        mock_assignment_service,
        mock_analyzer,
        mock_safety_controls,
        mock_metrics_collector,
    ):
        """Create experiment manager with mocks."""
        return ExperimentManager(
            database=mock_database,
            assignment_service=mock_assignment_service,
            analyzer=mock_analyzer,
            safety_controls=mock_safety_controls,
            metrics_collector=mock_metrics_collector,
        )

    @pytest.fixture
    def sample_experiment_config(self):
        """Create sample experiment configuration."""
        return ExperimentConfig(
            id="exp_001",
            name="Test Experiment",
            description="Testing detection strategies",
            type=ExperimentType.STRATEGY,
            status=ExperimentStatus.DRAFT,
            start_time=datetime.utcnow(),
            end_time=datetime.utcnow() + timedelta(days=7),
            variants=[
                ExperimentVariant(
                    id="control",
                    name="Control",
                    description="Current strategy",
                    config={"strategy": "heuristic"},
                    traffic_percentage=0.5,
                    is_control=True,
                ),
                ExperimentVariant(
                    id="treatment",
                    name="Treatment",
                    description="ML-enhanced strategy",
                    config={"strategy": "ml_enhanced"},
                    traffic_percentage=0.5,
                    is_control=False,
                ),
            ],
            traffic_allocation=TrafficAllocation(control=0.5, treatment=0.5),
            guardrails=GuardrailConfig(
                max_false_positive_rate=0.1,
                min_true_positive_rate=0.9,
                auto_stop_on_violation=True,
            ),
            metadata={"owner": "test_user"},
        )

    def test_initialization(self, manager):
        """Test manager initialization."""
        assert manager.database is not None
        assert manager.assignment_service is not None
        assert manager.analyzer is not None
        assert manager.safety_controls is not None
        assert manager.metrics_collector is not None
        assert len(manager.active_experiments) == 0
        assert len(manager.experiment_configs) == 0
        assert manager.analysis_task is None
        assert manager.metrics_flush_task is None

    def test_initialization_with_defaults(self):
        """Test manager initialization with default components."""
        manager = ExperimentManager()
        assert isinstance(manager.database, ExperimentDatabase)
        assert isinstance(manager.assignment_service, AssignmentService)
        assert isinstance(manager.analyzer, StatisticalAnalyzer)
        assert isinstance(manager.safety_controls, SafetyControls)
        assert isinstance(manager.metrics_collector, MetricsCollector)

    @pytest.mark.asyncio
    async def test_initialize(self, manager):
        """Test manager initialization."""
        await manager.initialize()

        # Verify components initialized
        manager.database.initialize.assert_called_once()

        # Verify background tasks started
        assert manager.analysis_task is not None
        assert manager.metrics_flush_task is not None

    @pytest.mark.asyncio
    async def test_shutdown(self, manager):
        """Test manager shutdown."""
        # Initialize first
        await manager.initialize()

        # Shutdown
        await manager.shutdown()

        # Verify tasks cancelled
        assert manager.analysis_task is None
        assert manager.metrics_flush_task is None

    @pytest.mark.asyncio
    async def test_create_experiment(self, manager, sample_experiment_config):
        """Test creating a new experiment."""
        result = await manager.create_experiment(sample_experiment_config)

        assert result is True
        manager.database.save_experiment.assert_called_once_with(sample_experiment_config)
        assert sample_experiment_config.id in manager.experiment_configs

    @pytest.mark.asyncio
    async def test_create_experiment_duplicate(self, manager, sample_experiment_config):
        """Test creating duplicate experiment."""
        # First creation succeeds
        await manager.create_experiment(sample_experiment_config)

        # Second creation should fail
        with pytest.raises(ExperimentError, match="already exists"):
            await manager.create_experiment(sample_experiment_config)

    @pytest.mark.asyncio
    async def test_start_experiment(self, manager, sample_experiment_config):
        """Test starting an experiment."""
        # Create experiment first
        await manager.create_experiment(sample_experiment_config)

        # Start experiment
        result = await manager.start_experiment(sample_experiment_config.id)

        assert result is True
        assert sample_experiment_config.id in manager.active_experiments

        # Verify execution state
        execution = manager.active_experiments[sample_experiment_config.id]
        assert execution.experiment_id == sample_experiment_config.id
        assert len(execution.variant_configs) == 2

    @pytest.mark.asyncio
    async def test_start_experiment_not_found(self, manager):
        """Test starting non-existent experiment."""
        with pytest.raises(ExperimentError, match="not found"):
            await manager.start_experiment("non_existent")

    @pytest.mark.asyncio
    async def test_start_experiment_already_running(self, manager, sample_experiment_config):
        """Test starting already running experiment."""
        await manager.create_experiment(sample_experiment_config)
        await manager.start_experiment(sample_experiment_config.id)

        # Starting again should fail
        with pytest.raises(ExperimentError, match="already running"):
            await manager.start_experiment(sample_experiment_config.id)

    @pytest.mark.asyncio
    async def test_stop_experiment(self, manager, sample_experiment_config):
        """Test stopping an experiment."""
        await manager.create_experiment(sample_experiment_config)
        await manager.start_experiment(sample_experiment_config.id)

        # Stop experiment
        result = await manager.stop_experiment(sample_experiment_config.id)

        assert result is True
        assert sample_experiment_config.id not in manager.active_experiments

        # Verify status updated
        manager.database.update_experiment.assert_called()

    @pytest.mark.asyncio
    async def test_pause_experiment(self, manager, sample_experiment_config):
        """Test pausing an experiment."""
        await manager.create_experiment(sample_experiment_config)
        await manager.start_experiment(sample_experiment_config.id)

        # Pause experiment
        result = await manager.pause_experiment(sample_experiment_config.id)

        assert result is True
        assert sample_experiment_config.status == ExperimentStatus.PAUSED

    @pytest.mark.asyncio
    async def test_resume_experiment(self, manager, sample_experiment_config):
        """Test resuming a paused experiment."""
        await manager.create_experiment(sample_experiment_config)
        await manager.start_experiment(sample_experiment_config.id)
        await manager.pause_experiment(sample_experiment_config.id)

        # Resume experiment
        result = await manager.resume_experiment(sample_experiment_config.id)

        assert result is True
        assert sample_experiment_config.status == ExperimentStatus.RUNNING

    @pytest.mark.asyncio
    async def test_get_assignment(self, manager, sample_experiment_config):
        """Test getting user assignment."""
        await manager.create_experiment(sample_experiment_config)
        await manager.start_experiment(sample_experiment_config.id)

        # Mock assignment service response
        manager.assignment_service.get_assignment.return_value = ExperimentAssignment(
            experiment_id=sample_experiment_config.id,
            user_id="user_001",
            variant_id="control",
            assigned_at=datetime.utcnow(),
            context={},
        )

        # Get assignment
        context = AssignmentContext(
            user_id="user_001",
            attributes={"device": "mobile"},
        )
        assignment = await manager.get_assignment(sample_experiment_config.id, context)

        assert assignment is not None
        assert assignment.variant_id == "control"

        # Check cache
        execution = manager.active_experiments[sample_experiment_config.id]
        assert execution.assignment_cache["user_001"] == "control"

    @pytest.mark.asyncio
    async def test_get_assignment_cached(self, manager, sample_experiment_config):
        """Test getting cached assignment."""
        await manager.create_experiment(sample_experiment_config)
        await manager.start_experiment(sample_experiment_config.id)

        # Pre-populate cache
        execution = manager.active_experiments[sample_experiment_config.id]
        execution.assignment_cache["user_001"] = "treatment"

        # Get assignment (should use cache)
        context = AssignmentContext(user_id="user_001", attributes={})
        assignment = await manager.get_assignment(sample_experiment_config.id, context)

        assert assignment.variant_id == "treatment"
        # Assignment service should not be called
        manager.assignment_service.get_assignment.assert_not_called()

    @pytest.mark.asyncio
    async def test_record_metric(self, manager, sample_experiment_config):
        """Test recording experiment metric."""
        await manager.create_experiment(sample_experiment_config)
        await manager.start_experiment(sample_experiment_config.id)

        # Record metric
        await manager.record_metric(
            experiment_id=sample_experiment_config.id,
            user_id="user_001",
            metric_name="accuracy",
            value=0.95,
            variant_id="control",
        )

        # Verify metric in buffer
        execution = manager.active_experiments[sample_experiment_config.id]
        assert len(execution.metrics_buffer) == 1
        assert execution.metrics_buffer[0]["metric_name"] == "accuracy"

    @pytest.mark.asyncio
    async def test_record_detection_result(self, manager, sample_experiment_config):
        """Test recording detection result as metric."""
        await manager.create_experiment(sample_experiment_config)
        await manager.start_experiment(sample_experiment_config.id)

        # Create detection result
        detection_result = DetectionResponse(
            verdict=Verdict.BLOCK,
            confidence=0.9,
            reasons=[],
            processing_time_ms=100.0,
            metadata={},
        )

        # Record result
        await manager.record_detection_result(
            experiment_id=sample_experiment_config.id,
            user_id="user_001",
            variant_id="treatment",
            result=detection_result,
        )

        # Verify metrics recorded
        execution = manager.active_experiments[sample_experiment_config.id]
        assert len(execution.metrics_buffer) > 0

        # Should record multiple metrics from result
        metric_names = [m["metric_name"] for m in execution.metrics_buffer]
        assert "verdict" in metric_names
        assert "confidence" in metric_names
        assert "processing_time_ms" in metric_names

    @pytest.mark.asyncio
    async def test_analyze_experiment(self, manager, sample_experiment_config):
        """Test analyzing experiment results."""
        await manager.create_experiment(sample_experiment_config)
        await manager.start_experiment(sample_experiment_config.id)

        # Mock analyzer response
        mock_result = ExperimentResult(
            experiment_id=sample_experiment_config.id,
            control_metrics={"accuracy": 0.9},
            treatment_metrics={"accuracy": 0.95},
            statistical_significance=0.03,
            effect_size=0.2,
            confidence_interval=(0.02, 0.08),
            recommendation="Continue experiment",
            analysis_timestamp=datetime.utcnow(),
        )
        manager.analyzer.analyze.return_value = mock_result

        # Analyze
        result = await manager.analyze_experiment(sample_experiment_config.id)

        assert result is not None
        assert result.statistical_significance == 0.03
        assert result.recommendation == "Continue experiment"

        # Verify saved
        manager.database.save_analysis_results.assert_called_once()

    @pytest.mark.asyncio
    async def test_check_guardrails(self, manager, sample_experiment_config):
        """Test checking experiment guardrails."""
        await manager.create_experiment(sample_experiment_config)
        await manager.start_experiment(sample_experiment_config.id)

        # Mock guardrail violation
        violation = GuardrailViolation(
            experiment_id=sample_experiment_config.id,
            variant_id="treatment",
            guardrail_name="max_false_positive_rate",
            expected_value=0.1,
            actual_value=0.15,
            severity="high",
            timestamp=datetime.utcnow(),
            auto_stopped=True,
        )
        manager.safety_controls.check_guardrails.return_value = [violation]

        # Check guardrails
        violations = await manager.check_guardrails(sample_experiment_config.id)

        assert len(violations) == 1
        assert violations[0].guardrail_name == "max_false_positive_rate"

        # Should auto-stop if configured
        if sample_experiment_config.guardrails.auto_stop_on_violation:
            assert sample_experiment_config.id not in manager.active_experiments

    @pytest.mark.asyncio
    async def test_list_experiments(self, manager, sample_experiment_config):
        """Test listing experiments."""
        # Mock database response
        manager.database.list_experiments.return_value = [sample_experiment_config]

        # List all experiments
        experiments = await manager.list_experiments()

        assert len(experiments) == 1
        assert experiments[0].id == sample_experiment_config.id

        # List by status
        experiments = await manager.list_experiments(status=ExperimentStatus.DRAFT)
        manager.database.list_experiments.assert_called_with(status=ExperimentStatus.DRAFT)

    @pytest.mark.asyncio
    async def test_get_experiment_status(self, manager, sample_experiment_config):
        """Test getting experiment status."""
        await manager.create_experiment(sample_experiment_config)

        status = await manager.get_experiment_status(sample_experiment_config.id)

        assert status["id"] == sample_experiment_config.id
        assert status["status"] == sample_experiment_config.status.value
        assert status["is_running"] is False

        # Start experiment
        await manager.start_experiment(sample_experiment_config.id)
        status = await manager.get_experiment_status(sample_experiment_config.id)
        assert status["is_running"] is True

    @pytest.mark.asyncio
    async def test_flush_metrics(self, manager, sample_experiment_config):
        """Test flushing metrics to database."""
        await manager.create_experiment(sample_experiment_config)
        await manager.start_experiment(sample_experiment_config.id)

        # Add metrics to buffer
        execution = manager.active_experiments[sample_experiment_config.id]
        execution.metrics_buffer = [
            {"metric_name": "accuracy", "value": 0.9},
            {"metric_name": "latency", "value": 100},
        ]

        # Flush metrics
        await manager._flush_metrics()

        # Verify saved
        manager.database.save_metrics_batch.assert_called_once()
        assert len(execution.metrics_buffer) == 0

    @pytest.mark.asyncio
    async def test_periodic_analysis(self, manager, sample_experiment_config):
        """Test periodic analysis task."""
        await manager.create_experiment(sample_experiment_config)
        await manager.start_experiment(sample_experiment_config.id)

        # Mock analyzer
        mock_result = MagicMock()
        manager.analyzer.analyze.return_value = mock_result

        # Run periodic analysis
        await manager._run_periodic_analysis()

        # Verify analysis performed
        manager.analyzer.analyze.assert_called()

        # Verify last analysis time updated
        execution = manager.active_experiments[sample_experiment_config.id]
        assert execution.last_analysis is not None

    @pytest.mark.asyncio
    async def test_event_handlers(self, manager, sample_experiment_config):
        """Test event handler registration and execution."""
        # Register handlers
        started_called = False
        completed_called = False

        async def on_started(exp_id):
            nonlocal started_called
            started_called = True

        async def on_completed(exp_id):
            nonlocal completed_called
            completed_called = True

        manager.on_experiment_started(on_started)
        manager.on_experiment_completed(on_completed)

        # Start experiment (should trigger handler)
        await manager.create_experiment(sample_experiment_config)
        await manager.start_experiment(sample_experiment_config.id)
        assert started_called

        # Stop experiment (should trigger handler)
        await manager.stop_experiment(sample_experiment_config.id)
        assert completed_called

    @pytest.mark.asyncio
    async def test_experiment_error_handling(self, manager):
        """Test error handling in experiment operations."""
        # Database error
        manager.database.save_experiment.side_effect = Exception("Database error")

        with pytest.raises(ExperimentError):
            await manager.create_experiment(MagicMock())

        # Assignment error
        manager.assignment_service.get_assignment.side_effect = Exception("Assignment error")

        with pytest.raises(ExperimentError):
            await manager.get_assignment("exp_001", MagicMock())

    @pytest.mark.asyncio
    async def test_concurrent_experiments(self, manager):
        """Test managing multiple concurrent experiments."""
        # Create multiple experiments
        experiments = []
        for i in range(3):
            config = ExperimentConfig(
                id=f"exp_{i}",
                name=f"Experiment {i}",
                description=f"Test {i}",
                type=ExperimentType.STRATEGY,
                status=ExperimentStatus.DRAFT,
                start_time=datetime.utcnow(),
                end_time=datetime.utcnow() + timedelta(days=1),
                variants=[],
                traffic_allocation=TrafficAllocation(control=1.0, treatment=0.0),
                guardrails=GuardrailConfig(),
                metadata={},
            )
            experiments.append(config)
            await manager.create_experiment(config)

        # Start all experiments
        for exp in experiments:
            await manager.start_experiment(exp.id)

        # Verify all running
        assert len(manager.active_experiments) == 3

        # Stop one experiment
        await manager.stop_experiment("exp_1")
        assert len(manager.active_experiments) == 2
        assert "exp_1" not in manager.active_experiments

    @pytest.mark.asyncio
    async def test_experiment_lifecycle(self, manager, sample_experiment_config):
        """Test complete experiment lifecycle."""
        # Create
        await manager.create_experiment(sample_experiment_config)
        assert sample_experiment_config.status == ExperimentStatus.DRAFT

        # Start
        await manager.start_experiment(sample_experiment_config.id)
        assert sample_experiment_config.status == ExperimentStatus.RUNNING

        # Pause
        await manager.pause_experiment(sample_experiment_config.id)
        assert sample_experiment_config.status == ExperimentStatus.PAUSED

        # Resume
        await manager.resume_experiment(sample_experiment_config.id)
        assert sample_experiment_config.status == ExperimentStatus.RUNNING

        # Complete
        await manager.complete_experiment(sample_experiment_config.id)
        assert sample_experiment_config.status == ExperimentStatus.COMPLETED
        assert sample_experiment_config.id not in manager.active_experiments

    def test_validate_experiment_config(self, manager, sample_experiment_config):
        """Test experiment configuration validation."""
        # Valid config should pass
        assert manager._validate_config(sample_experiment_config) is True

        # Invalid traffic allocation
        sample_experiment_config.traffic_allocation.control = 0.6
        sample_experiment_config.traffic_allocation.treatment = 0.6
        assert manager._validate_config(sample_experiment_config) is False

        # No variants
        sample_experiment_config.variants = []
        assert manager._validate_config(sample_experiment_config) is False
