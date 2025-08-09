"""Comprehensive tests for experiments database module."""

import asyncio
import json
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import aiosqlite
import pytest

from prompt_sentinel.experiments.analyzer import ExperimentResult
from prompt_sentinel.experiments.config import (
    ExperimentConfig,
    ExperimentStatus,
    ExperimentType,
    ExperimentVariant,
    GuardrailConfig,
    TrafficAllocation,
)
from prompt_sentinel.experiments.database import DatabaseError, ExperimentDatabase
from prompt_sentinel.experiments.safety import GuardrailViolation


class TestExperimentDatabase:
    """Test suite for ExperimentDatabase."""

    @pytest.fixture
    async def temp_db(self):
        """Create a temporary database for testing."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            db_path = tmp.name
        
        db = ExperimentDatabase(db_path)
        await db.initialize()
        yield db
        
        # Cleanup
        Path(db_path).unlink(missing_ok=True)

    @pytest.fixture
    def sample_experiment_config(self):
        """Create a sample experiment configuration."""
        return ExperimentConfig(
            id="exp_001",
            name="Test Experiment",
            description="Testing new detection algorithm",
            type=ExperimentType.STRATEGY,
            status=ExperimentStatus.DRAFT,
            start_time=datetime.utcnow(),
            end_time=datetime.utcnow() + timedelta(days=7),
            variants=[
                ExperimentVariant(
                    id="control",
                    name="Control",
                    description="Current algorithm",
                    config={"threshold": 0.5},
                    traffic_percentage=0.5,
                    is_control=True,
                ),
                ExperimentVariant(
                    id="treatment",
                    name="Treatment",
                    description="New algorithm",
                    config={"threshold": 0.7},
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
            metadata={"owner": "test_user", "tags": ["detection", "ml"]},
        )

    @pytest.mark.asyncio
    async def test_database_initialization(self):
        """Test database initialization."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            db_path = tmp.name
        
        db = ExperimentDatabase(db_path)
        assert not db.initialized
        
        await db.initialize()
        assert db.initialized
        
        # Should not reinitialize
        await db.initialize()
        assert db.initialized
        
        # Check tables exist
        async with aiosqlite.connect(db_path) as conn:
            cursor = await conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
            tables = await cursor.fetchall()
            table_names = [t[0] for t in tables]
            
            assert "experiments" in table_names
            assert "experiment_metrics" in table_names
            assert "experiment_assignments" in table_names
            assert "experiment_results" in table_names
            assert "guardrail_violations" in table_names
        
        Path(db_path).unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_save_experiment(self, temp_db, sample_experiment_config):
        """Test saving an experiment configuration."""
        await temp_db.save_experiment(sample_experiment_config)
        
        # Verify saved data
        async with aiosqlite.connect(temp_db.db_path) as conn:
            cursor = await conn.execute(
                "SELECT * FROM experiments WHERE id = ?",
                (sample_experiment_config.id,)
            )
            row = await cursor.fetchone()
            
            assert row is not None
            assert row[0] == sample_experiment_config.id
            assert row[1] == sample_experiment_config.name
            assert row[2] == sample_experiment_config.description
            assert row[3] == sample_experiment_config.type.value
            assert row[4] == sample_experiment_config.status.value

    @pytest.mark.asyncio
    async def test_save_experiment_duplicate(self, temp_db, sample_experiment_config):
        """Test saving duplicate experiment raises error."""
        await temp_db.save_experiment(sample_experiment_config)
        
        # Saving again should update
        sample_experiment_config.status = ExperimentStatus.RUNNING
        await temp_db.save_experiment(sample_experiment_config)
        
        # Verify updated
        experiment = await temp_db.get_experiment(sample_experiment_config.id)
        assert experiment.status == ExperimentStatus.RUNNING

    @pytest.mark.asyncio
    async def test_get_experiment(self, temp_db, sample_experiment_config):
        """Test retrieving an experiment."""
        await temp_db.save_experiment(sample_experiment_config)
        
        experiment = await temp_db.get_experiment(sample_experiment_config.id)
        
        assert experiment is not None
        assert experiment.id == sample_experiment_config.id
        assert experiment.name == sample_experiment_config.name
        assert experiment.type == sample_experiment_config.type
        assert experiment.status == sample_experiment_config.status
        assert len(experiment.variants) == 2

    @pytest.mark.asyncio
    async def test_get_experiment_not_found(self, temp_db):
        """Test retrieving non-existent experiment."""
        experiment = await temp_db.get_experiment("non_existent")
        assert experiment is None

    @pytest.mark.asyncio
    async def test_update_experiment_status(self, temp_db, sample_experiment_config):
        """Test updating experiment status."""
        await temp_db.save_experiment(sample_experiment_config)
        
        # Update status
        await temp_db.update_experiment_status(
            sample_experiment_config.id,
            ExperimentStatus.RUNNING
        )
        
        # Verify update
        experiment = await temp_db.get_experiment(sample_experiment_config.id)
        assert experiment.status == ExperimentStatus.RUNNING

    @pytest.mark.asyncio
    async def test_list_experiments(self, temp_db, sample_experiment_config):
        """Test listing experiments."""
        # Save multiple experiments
        await temp_db.save_experiment(sample_experiment_config)
        
        config2 = sample_experiment_config.model_copy()
        config2.id = "exp_002"
        config2.name = "Second Experiment"
        config2.status = ExperimentStatus.COMPLETED
        await temp_db.save_experiment(config2)
        
        # List all
        experiments = await temp_db.list_experiments()
        assert len(experiments) == 2
        
        # List by status
        running = await temp_db.list_experiments(status=ExperimentStatus.DRAFT)
        assert len(running) == 1
        assert running[0].id == sample_experiment_config.id
        
        completed = await temp_db.list_experiments(status=ExperimentStatus.COMPLETED)
        assert len(completed) == 1
        assert completed[0].id == "exp_002"

    @pytest.mark.asyncio
    async def test_record_metric(self, temp_db, sample_experiment_config):
        """Test recording experiment metrics."""
        await temp_db.save_experiment(sample_experiment_config)
        
        # Record metrics
        await temp_db.record_metric(
            experiment_id=sample_experiment_config.id,
            variant_id="control",
            user_id="user_001",
            metric_name="false_positive_rate",
            value=0.05,
            metadata={"session_id": "sess_001"}
        )
        
        await temp_db.record_metric(
            experiment_id=sample_experiment_config.id,
            variant_id="treatment",
            user_id="user_002",
            metric_name="false_positive_rate",
            value=0.08,
        )
        
        # Verify metrics recorded
        async with aiosqlite.connect(temp_db.db_path) as conn:
            cursor = await conn.execute(
                "SELECT COUNT(*) FROM experiment_metrics WHERE experiment_id = ?",
                (sample_experiment_config.id,)
            )
            count = await cursor.fetchone()
            assert count[0] == 2

    @pytest.mark.asyncio
    async def test_get_metrics(self, temp_db, sample_experiment_config):
        """Test retrieving experiment metrics."""
        await temp_db.save_experiment(sample_experiment_config)
        
        # Record multiple metrics
        for i in range(10):
            await temp_db.record_metric(
                experiment_id=sample_experiment_config.id,
                variant_id="control" if i % 2 == 0 else "treatment",
                user_id=f"user_{i}",
                metric_name="detection_accuracy",
                value=0.9 + (i * 0.01),
            )
        
        # Get all metrics
        metrics = await temp_db.get_metrics(sample_experiment_config.id)
        assert len(metrics) == 10
        
        # Get metrics for specific variant
        control_metrics = await temp_db.get_metrics(
            sample_experiment_config.id,
            variant_id="control"
        )
        assert len(control_metrics) == 5
        
        # Get specific metric
        accuracy_metrics = await temp_db.get_metrics(
            sample_experiment_config.id,
            metric_name="detection_accuracy"
        )
        assert len(accuracy_metrics) == 10
        assert all(m["metric_name"] == "detection_accuracy" for m in accuracy_metrics)

    @pytest.mark.asyncio
    async def test_record_assignment(self, temp_db, sample_experiment_config):
        """Test recording user assignments."""
        await temp_db.save_experiment(sample_experiment_config)
        
        # Record assignment
        await temp_db.record_assignment(
            experiment_id=sample_experiment_config.id,
            user_id="user_001",
            variant_id="control",
            context={"ip": "192.168.1.1", "device": "mobile"}
        )
        
        # Verify assignment recorded
        async with aiosqlite.connect(temp_db.db_path) as conn:
            cursor = await conn.execute(
                "SELECT * FROM experiment_assignments WHERE user_id = ?",
                ("user_001",)
            )
            row = await cursor.fetchone()
            assert row is not None
            assert row[2] == "user_001"
            assert row[3] == "control"

    @pytest.mark.asyncio
    async def test_get_assignment(self, temp_db, sample_experiment_config):
        """Test retrieving user assignment."""
        await temp_db.save_experiment(sample_experiment_config)
        
        # No assignment initially
        assignment = await temp_db.get_assignment(
            sample_experiment_config.id,
            "user_001"
        )
        assert assignment is None
        
        # Record assignment
        await temp_db.record_assignment(
            experiment_id=sample_experiment_config.id,
            user_id="user_001",
            variant_id="treatment",
        )
        
        # Get assignment
        assignment = await temp_db.get_assignment(
            sample_experiment_config.id,
            "user_001"
        )
        assert assignment is not None
        assert assignment["variant_id"] == "treatment"
        assert assignment["user_id"] == "user_001"

    @pytest.mark.asyncio
    async def test_save_experiment_result(self, temp_db, sample_experiment_config):
        """Test saving experiment analysis results."""
        await temp_db.save_experiment(sample_experiment_config)
        
        # Create result
        result = ExperimentResult(
            experiment_id=sample_experiment_config.id,
            control_metrics={
                "false_positive_rate": 0.05,
                "true_positive_rate": 0.92,
                "sample_size": 1000,
            },
            treatment_metrics={
                "false_positive_rate": 0.08,
                "true_positive_rate": 0.95,
                "sample_size": 1000,
            },
            statistical_significance=0.03,
            effect_size=0.15,
            confidence_interval=(0.05, 0.25),
            recommendation="Continue experiment",
            analysis_timestamp=datetime.utcnow(),
        )
        
        await temp_db.save_experiment_result(result)
        
        # Verify saved
        async with aiosqlite.connect(temp_db.db_path) as conn:
            cursor = await conn.execute(
                "SELECT * FROM experiment_results WHERE experiment_id = ?",
                (sample_experiment_config.id,)
            )
            row = await cursor.fetchone()
            assert row is not None
            assert row[1] == sample_experiment_config.id

    @pytest.mark.asyncio
    async def test_get_experiment_results(self, temp_db, sample_experiment_config):
        """Test retrieving experiment results."""
        await temp_db.save_experiment(sample_experiment_config)
        
        # No results initially
        results = await temp_db.get_experiment_results(sample_experiment_config.id)
        assert len(results) == 0
        
        # Save multiple results
        for i in range(3):
            result = ExperimentResult(
                experiment_id=sample_experiment_config.id,
                control_metrics={"metric": i},
                treatment_metrics={"metric": i + 1},
                statistical_significance=0.05,
                effect_size=0.1 * i,
                confidence_interval=(0.0, 0.2),
                recommendation=f"Result {i}",
                analysis_timestamp=datetime.utcnow() + timedelta(hours=i),
            )
            await temp_db.save_experiment_result(result)
        
        # Get all results
        results = await temp_db.get_experiment_results(sample_experiment_config.id)
        assert len(results) == 3
        
        # Results should be ordered by timestamp
        for i in range(1, len(results)):
            assert results[i]["analysis_timestamp"] > results[i-1]["analysis_timestamp"]

    @pytest.mark.asyncio
    async def test_record_guardrail_violation(self, temp_db, sample_experiment_config):
        """Test recording guardrail violations."""
        await temp_db.save_experiment(sample_experiment_config)
        
        # Create violation
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
        
        await temp_db.record_guardrail_violation(violation)
        
        # Verify recorded
        violations = await temp_db.get_guardrail_violations(sample_experiment_config.id)
        assert len(violations) == 1
        assert violations[0]["guardrail_name"] == "max_false_positive_rate"
        assert violations[0]["actual_value"] == 0.15
        assert violations[0]["auto_stopped"] is True

    @pytest.mark.asyncio
    async def test_get_guardrail_violations(self, temp_db, sample_experiment_config):
        """Test retrieving guardrail violations."""
        await temp_db.save_experiment(sample_experiment_config)
        
        # Record multiple violations
        for i in range(3):
            violation = GuardrailViolation(
                experiment_id=sample_experiment_config.id,
                variant_id="treatment",
                guardrail_name=f"metric_{i}",
                expected_value=0.1,
                actual_value=0.1 + (i * 0.05),
                severity="medium" if i < 2 else "high",
                timestamp=datetime.utcnow(),
                auto_stopped=i == 2,
            )
            await temp_db.record_guardrail_violation(violation)
        
        # Get all violations
        violations = await temp_db.get_guardrail_violations(sample_experiment_config.id)
        assert len(violations) == 3
        
        # Check high severity violation
        high_severity = [v for v in violations if v["severity"] == "high"]
        assert len(high_severity) == 1
        assert high_severity[0]["auto_stopped"] is True

    @pytest.mark.asyncio
    async def test_delete_experiment(self, temp_db, sample_experiment_config):
        """Test deleting an experiment and its data."""
        await temp_db.save_experiment(sample_experiment_config)
        
        # Add some data
        await temp_db.record_metric(
            experiment_id=sample_experiment_config.id,
            variant_id="control",
            user_id="user_001",
            metric_name="test",
            value=1.0,
        )
        await temp_db.record_assignment(
            experiment_id=sample_experiment_config.id,
            user_id="user_001",
            variant_id="control",
        )
        
        # Delete experiment
        await temp_db.delete_experiment(sample_experiment_config.id)
        
        # Verify deleted
        experiment = await temp_db.get_experiment(sample_experiment_config.id)
        assert experiment is None
        
        # Verify cascaded deletes
        metrics = await temp_db.get_metrics(sample_experiment_config.id)
        assert len(metrics) == 0

    @pytest.mark.asyncio
    async def test_database_error_handling(self, temp_db):
        """Test database error handling."""
        # Test with invalid experiment ID
        with pytest.raises(DatabaseError):
            await temp_db.update_experiment_status("non_existent", ExperimentStatus.RUNNING)
        
        # Test with corrupted database connection
        temp_db.db_path = "/invalid/path/to/db.db"
        with pytest.raises(DatabaseError):
            await temp_db.save_experiment(MagicMock())

    @pytest.mark.asyncio
    async def test_concurrent_operations(self, temp_db, sample_experiment_config):
        """Test concurrent database operations."""
        await temp_db.save_experiment(sample_experiment_config)
        
        # Simulate concurrent metric recording
        async def record_metrics(variant_id, start_idx):
            for i in range(10):
                await temp_db.record_metric(
                    experiment_id=sample_experiment_config.id,
                    variant_id=variant_id,
                    user_id=f"user_{start_idx + i}",
                    metric_name="concurrent_test",
                    value=float(i),
                )
        
        # Run concurrent operations
        await asyncio.gather(
            record_metrics("control", 0),
            record_metrics("treatment", 100),
            record_metrics("control", 200),
        )
        
        # Verify all metrics recorded
        metrics = await temp_db.get_metrics(sample_experiment_config.id)
        assert len(metrics) == 30

    @pytest.mark.asyncio
    async def test_transaction_rollback(self, temp_db, sample_experiment_config):
        """Test transaction rollback on error."""
        await temp_db.save_experiment(sample_experiment_config)
        
        # Mock a failure during transaction
        with patch("aiosqlite.connect") as mock_connect:
            mock_db = AsyncMock()
            mock_db.__aenter__.side_effect = Exception("Database error")
            mock_connect.return_value = mock_db
            
            with pytest.raises(DatabaseError):
                await temp_db.record_metric(
                    experiment_id=sample_experiment_config.id,
                    variant_id="control",
                    user_id="user_001",
                    metric_name="test",
                    value=1.0,
                )

    @pytest.mark.asyncio
    async def test_get_active_experiments(self, temp_db):
        """Test retrieving active experiments."""
        # Create experiments with different statuses
        for i, status in enumerate([
            ExperimentStatus.DRAFT,
            ExperimentStatus.RUNNING,
            ExperimentStatus.PAUSED,
            ExperimentStatus.COMPLETED,
            ExperimentStatus.TERMINATED,
        ]):
            config = ExperimentConfig(
                id=f"exp_{i}",
                name=f"Experiment {i}",
                description=f"Test {status.value}",
                type=ExperimentType.STRATEGY,
                status=status,
                start_time=datetime.utcnow() - timedelta(days=1) if status == ExperimentStatus.RUNNING else None,
                end_time=datetime.utcnow() + timedelta(days=1) if status == ExperimentStatus.RUNNING else None,
                variants=[],
                traffic_allocation=TrafficAllocation(control=1.0, treatment=0.0),
                guardrails=GuardrailConfig(),
                metadata={},
            )
            await temp_db.save_experiment(config)
        
        # Get active experiments
        active = await temp_db.get_active_experiments()
        assert len(active) == 1
        assert active[0].status == ExperimentStatus.RUNNING

    @pytest.mark.asyncio
    async def test_cleanup_old_data(self, temp_db, sample_experiment_config):
        """Test cleanup of old experiment data."""
        await temp_db.save_experiment(sample_experiment_config)
        
        # Add old metrics
        for i in range(10):
            await temp_db.record_metric(
                experiment_id=sample_experiment_config.id,
                variant_id="control",
                user_id=f"user_{i}",
                metric_name="old_metric",
                value=float(i),
                timestamp=datetime.utcnow() - timedelta(days=90),
            )
        
        # Add recent metrics
        for i in range(5):
            await temp_db.record_metric(
                experiment_id=sample_experiment_config.id,
                variant_id="control",
                user_id=f"user_new_{i}",
                metric_name="new_metric",
                value=float(i),
            )
        
        # Cleanup old data (older than 60 days)
        await temp_db.cleanup_old_data(days=60)
        
        # Verify only recent metrics remain
        metrics = await temp_db.get_metrics(sample_experiment_config.id)
        assert len(metrics) == 5
        assert all(m["metric_name"] == "new_metric" for m in metrics)