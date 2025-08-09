"""Detailed tests for experiment tracking and A/B testing."""

import pytest
import asyncio
import numpy as np
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from scipy import stats

from prompt_sentinel.experiments.manager import ExperimentManager
from prompt_sentinel.experiments.analyzer import ExperimentAnalyzer
from prompt_sentinel.experiments.assignments import AssignmentStrategy
from prompt_sentinel.models.schemas import Message, Role, Verdict


class TestExperimentManager:
    """Test experiment management functionality."""

    @pytest.fixture
    async def experiment_manager(self):
        """Create experiment manager."""
        manager = ExperimentManager()
        await manager.initialize()
        yield manager
        await manager.cleanup()

    @pytest.mark.asyncio
    async def test_create_experiment(self, experiment_manager):
        """Test creating an experiment."""
        experiment = await experiment_manager.create_experiment(
            name="detection_threshold_test",
            description="Test different detection thresholds",
            hypothesis="Lower threshold increases detection rate without increasing false positives",
            variants={
                "control": {
                    "threshold": 0.5,
                    "allocation": 0.5
                },
                "treatment": {
                    "threshold": 0.3,
                    "allocation": 0.5
                }
            },
            metrics=["detection_rate", "false_positive_rate", "latency"],
            duration_days=7,
            minimum_sample_size=1000
        )
        
        assert experiment.id is not None
        assert experiment.status == "active"
        assert len(experiment.variants) == 2
        assert experiment.start_time is not None

    @pytest.mark.asyncio
    async def test_variant_assignment(self, experiment_manager):
        """Test assigning users to variants."""
        experiment = await experiment_manager.create_experiment(
            name="assignment_test",
            variants={
                "A": {"allocation": 0.33},
                "B": {"allocation": 0.33},
                "C": {"allocation": 0.34}
            }
        )
        
        assignments = {}
        for i in range(1000):
            user_id = f"user_{i}"
            variant = await experiment_manager.assign_variant(
                experiment_id=experiment.id,
                user_id=user_id
            )
            assignments[variant] = assignments.get(variant, 0) + 1
        
        # Check allocation ratios
        assert 300 < assignments["A"] < 370  # ~33%
        assert 300 < assignments["B"] < 370  # ~33%
        assert 310 < assignments["C"] < 380  # ~34%
        
        # Check consistency (same user gets same variant)
        variant1 = await experiment_manager.assign_variant(experiment.id, "user_1")
        variant2 = await experiment_manager.assign_variant(experiment.id, "user_1")
        assert variant1 == variant2

    @pytest.mark.asyncio
    async def test_record_experiment_event(self, experiment_manager):
        """Test recording experiment events."""
        experiment = await experiment_manager.create_experiment(
            name="event_test",
            variants={"control": {}, "treatment": {}}
        )
        
        # Record events
        events = [
            {"user_id": "user_1", "variant": "control", "event": "detection", "value": True},
            {"user_id": "user_2", "variant": "treatment", "event": "detection", "value": True},
            {"user_id": "user_3", "variant": "control", "event": "detection", "value": False},
            {"user_id": "user_4", "variant": "treatment", "event": "false_positive", "value": True},
        ]
        
        for event in events:
            await experiment_manager.record_event(
                experiment_id=experiment.id,
                **event
            )
        
        # Get events
        recorded = await experiment_manager.get_events(experiment.id)
        assert len(recorded) == 4
        assert all(e["experiment_id"] == experiment.id for e in recorded)

    @pytest.mark.asyncio
    async def test_experiment_guardrails(self, experiment_manager):
        """Test experiment safety guardrails."""
        experiment = await experiment_manager.create_experiment(
            name="guardrail_test",
            variants={"control": {}, "risky": {"threshold": 0.9}},
            guardrails={
                "max_false_negative_rate": 0.1,
                "max_latency_ms": 100,
                "min_detection_rate": 0.8
            }
        )
        
        # Simulate metrics that violate guardrails
        await experiment_manager.record_metric(
            experiment_id=experiment.id,
            variant="risky",
            metric="false_negative_rate",
            value=0.15  # Exceeds max
        )
        
        # Check if experiment should be stopped
        should_stop = await experiment_manager.check_guardrails(experiment.id)
        assert should_stop is True
        
        # Experiment should be paused
        status = await experiment_manager.get_experiment_status(experiment.id)
        assert status == "paused"

    @pytest.mark.asyncio
    async def test_experiment_power_analysis(self, experiment_manager):
        """Test statistical power analysis."""
        # Calculate required sample size
        sample_size = await experiment_manager.calculate_sample_size(
            baseline_rate=0.1,  # 10% baseline
            minimum_detectable_effect=0.02,  # 2% absolute difference
            power=0.8,  # 80% power
            significance_level=0.05
        )
        
        # Should recommend reasonable sample size
        assert 1000 < sample_size < 10000

    @pytest.mark.asyncio
    async def test_experiment_early_stopping(self, experiment_manager):
        """Test early stopping for conclusive results."""
        experiment = await experiment_manager.create_experiment(
            name="early_stop_test",
            variants={"control": {}, "treatment": {}},
            enable_early_stopping=True,
            confidence_threshold=0.95
        )
        
        # Simulate clear winner
        for i in range(100):
            # Treatment clearly better
            await experiment_manager.record_event(
                experiment_id=experiment.id,
                user_id=f"user_{i}",
                variant="control" if i % 2 == 0 else "treatment",
                event="success",
                value=i % 2 == 1  # Treatment always succeeds
            )
        
        # Check if we can stop early
        can_stop = await experiment_manager.check_early_stopping(experiment.id)
        assert can_stop is True
        
        # Get winner
        winner = await experiment_manager.get_winner(experiment.id)
        assert winner == "treatment"


class TestExperimentAnalyzer:
    """Test experiment analysis functionality."""

    @pytest.fixture
    def analyzer(self):
        """Create experiment analyzer."""
        return ExperimentAnalyzer()

    @pytest.mark.asyncio
    async def test_statistical_significance(self, analyzer):
        """Test statistical significance calculation."""
        # Control: 100 conversions out of 1000 (10%)
        # Treatment: 120 conversions out of 1000 (12%)
        
        result = await analyzer.calculate_significance(
            control_successes=100,
            control_trials=1000,
            treatment_successes=120,
            treatment_trials=1000
        )
        
        assert "p_value" in result
        assert "confidence" in result
        assert "significant" in result
        
        # Should be significant at 95% confidence
        assert result["p_value"] < 0.05
        assert result["confidence"] > 0.95
        assert result["significant"] is True

    @pytest.mark.asyncio
    async def test_confidence_intervals(self, analyzer):
        """Test confidence interval calculation."""
        # Calculate CI for conversion rate
        ci = await analyzer.calculate_confidence_interval(
            successes=50,
            trials=500,
            confidence_level=0.95
        )
        
        assert "lower" in ci
        assert "upper" in ci
        assert "point_estimate" in ci
        
        # Point estimate should be 10%
        assert abs(ci["point_estimate"] - 0.1) < 0.01
        
        # CI should contain true value
        assert ci["lower"] < 0.1 < ci["upper"]

    @pytest.mark.asyncio
    async def test_sequential_testing(self, analyzer):
        """Test sequential testing for continuous monitoring."""
        # Initialize sequential test
        test = await analyzer.create_sequential_test(
            alpha=0.05,  # Type I error
            beta=0.2,    # Type II error (80% power)
            effect_size=0.02
        )
        
        # Simulate data collection
        for day in range(30):
            # Add daily results
            control_data = np.random.binomial(100, 0.1)  # 10% rate
            treatment_data = np.random.binomial(100, 0.12)  # 12% rate
            
            decision = await analyzer.update_sequential_test(
                test,
                control_successes=control_data,
                control_trials=100,
                treatment_successes=treatment_data,
                treatment_trials=100
            )
            
            if decision != "continue":
                break
        
        # Should reach decision
        assert decision in ["control", "treatment", "no_difference"]

    @pytest.mark.asyncio
    async def test_bayesian_analysis(self, analyzer):
        """Test Bayesian analysis of experiments."""
        # Prior: Beta(1, 1) - uniform
        # Data: 45/500 control, 55/500 treatment
        
        result = await analyzer.bayesian_analysis(
            control_successes=45,
            control_trials=500,
            treatment_successes=55,
            treatment_trials=500,
            prior_alpha=1,
            prior_beta=1
        )
        
        assert "probability_treatment_better" in result
        assert "expected_lift" in result
        assert "credible_interval" in result
        
        # Treatment should be better
        assert result["probability_treatment_better"] > 0.5

    @pytest.mark.asyncio
    async def test_segmentation_analysis(self, analyzer):
        """Test segment-based analysis."""
        # Analyze by user segments
        segments = {
            "new_users": {
                "control": {"successes": 20, "trials": 200},
                "treatment": {"successes": 30, "trials": 200}
            },
            "power_users": {
                "control": {"successes": 80, "trials": 300},
                "treatment": {"successes": 85, "trials": 300}
            }
        }
        
        results = await analyzer.analyze_segments(segments)
        
        # Should show different effects per segment
        assert results["new_users"]["lift"] > results["power_users"]["lift"]
        assert results["new_users"]["significant"] is True

    @pytest.mark.asyncio
    async def test_metric_correlation(self, analyzer):
        """Test correlation between metrics."""
        # Generate correlated metrics
        np.random.seed(42)
        detection_rate = np.random.uniform(0.8, 0.95, 100)
        # False positives inversely correlated
        false_positive_rate = 0.2 - 0.15 * detection_rate + np.random.normal(0, 0.02, 100)
        
        correlation = await analyzer.calculate_correlation(
            metric1=detection_rate,
            metric2=false_positive_rate
        )
        
        assert "correlation" in correlation
        assert "p_value" in correlation
        
        # Should be negatively correlated
        assert correlation["correlation"] < -0.5


class TestAssignmentStrategies:
    """Test different assignment strategies."""

    @pytest.fixture
    def assignment_strategy(self):
        """Create assignment strategy."""
        return AssignmentStrategy()

    @pytest.mark.asyncio
    async def test_random_assignment(self, assignment_strategy):
        """Test random assignment strategy."""
        strategy = assignment_strategy.create_strategy(
            type="random",
            variants=["A", "B", "C"],
            weights=[0.5, 0.3, 0.2]
        )
        
        assignments = []
        for i in range(1000):
            variant = await strategy.assign(f"user_{i}")
            assignments.append(variant)
        
        # Check distribution
        counts = {v: assignments.count(v) for v in ["A", "B", "C"]}
        assert 450 < counts["A"] < 550  # ~50%
        assert 250 < counts["B"] < 350  # ~30%
        assert 150 < counts["C"] < 250  # ~20%

    @pytest.mark.asyncio
    async def test_deterministic_assignment(self, assignment_strategy):
        """Test deterministic assignment (consistent hashing)."""
        strategy = assignment_strategy.create_strategy(
            type="deterministic",
            variants=["A", "B"],
            seed="experiment_123"
        )
        
        # Same user should always get same variant
        user_id = "test_user"
        assignments = []
        for _ in range(10):
            variant = await strategy.assign(user_id)
            assignments.append(variant)
        
        assert len(set(assignments)) == 1  # All same

    @pytest.mark.asyncio
    async def test_stratified_assignment(self, assignment_strategy):
        """Test stratified assignment by user attributes."""
        strategy = assignment_strategy.create_strategy(
            type="stratified",
            variants=["A", "B"],
            strata=["country", "user_type"]
        )
        
        # Assign users with different attributes
        users = [
            {"id": "1", "country": "US", "user_type": "free"},
            {"id": "2", "country": "US", "user_type": "pro"},
            {"id": "3", "country": "UK", "user_type": "free"},
            {"id": "4", "country": "UK", "user_type": "pro"},
        ]
        
        assignments = {}
        for user in users * 25:  # 100 users total
            key = f"{user['country']}_{user['user_type']}"
            variant = await strategy.assign(user["id"], attributes=user)
            
            if key not in assignments:
                assignments[key] = {"A": 0, "B": 0}
            assignments[key][variant] += 1
        
        # Each stratum should be balanced
        for stratum, counts in assignments.items():
            total = counts["A"] + counts["B"]
            ratio = counts["A"] / total
            assert 0.4 < ratio < 0.6  # Roughly 50/50

    @pytest.mark.asyncio
    async def test_bandits_assignment(self, assignment_strategy):
        """Test multi-armed bandit assignment."""
        strategy = assignment_strategy.create_strategy(
            type="thompson_sampling",
            variants=["A", "B", "C"],
            exploration_rate=0.1
        )
        
        # Simulate rewards
        rewards = {"A": 0.1, "B": 0.15, "C": 0.12}
        
        for i in range(1000):
            # Get assignment
            variant = await strategy.assign(f"user_{i}")
            
            # Simulate outcome
            success = np.random.random() < rewards[variant]
            
            # Update strategy
            await strategy.update(variant, reward=1 if success else 0)
        
        # Should converge to best variant (B)
        final_probs = await strategy.get_selection_probabilities()
        assert final_probs["B"] > final_probs["A"]
        assert final_probs["B"] > final_probs["C"]


class TestExperimentMonitoring:
    """Test experiment monitoring and alerting."""

    @pytest.mark.asyncio
    async def test_sample_ratio_mismatch(self):
        """Test detection of sample ratio mismatch."""
        from prompt_sentinel.experiments.monitoring import ExperimentMonitor
        
        monitor = ExperimentMonitor()
        
        # Expected 50/50 split, got 45/55
        is_mismatch = await monitor.detect_sample_ratio_mismatch(
            expected_ratio=0.5,
            observed_control=450,
            observed_treatment=550,
            confidence_level=0.95
        )
        
        # Small deviation, should be OK
        assert is_mismatch is False
        
        # Large deviation: 40/60
        is_mismatch = await monitor.detect_sample_ratio_mismatch(
            expected_ratio=0.5,
            observed_control=400,
            observed_treatment=600,
            confidence_level=0.95
        )
        
        assert is_mismatch is True

    @pytest.mark.asyncio
    async def test_novelty_detection(self):
        """Test detection of novel patterns in treatment."""
        from prompt_sentinel.experiments.monitoring import ExperimentMonitor
        
        monitor = ExperimentMonitor()
        
        # Normal behavior in control
        control_metrics = np.random.normal(0.1, 0.01, 100)
        
        # Anomalous behavior in treatment
        treatment_metrics = np.concatenate([
            np.random.normal(0.1, 0.01, 90),  # Normal
            np.random.normal(0.3, 0.05, 10)   # Anomalies
        ])
        
        anomalies = await monitor.detect_anomalies(
            control_data=control_metrics,
            treatment_data=treatment_metrics
        )
        
        assert len(anomalies) > 0
        assert anomalies[0]["severity"] == "high"

    @pytest.mark.asyncio
    async def test_interaction_effects(self):
        """Test detection of interaction effects."""
        from prompt_sentinel.experiments.analyzer import ExperimentAnalyzer
        
        analyzer = ExperimentAnalyzer()
        
        # Simulate interaction: Treatment works better for segment A
        data = {
            "segment_A": {
                "control": {"successes": 10, "trials": 100},
                "treatment": {"successes": 25, "trials": 100}  # Big lift
            },
            "segment_B": {
                "control": {"successes": 15, "trials": 100},
                "treatment": {"successes": 16, "trials": 100}  # Small lift
            }
        }
        
        interaction = await analyzer.test_interaction_effect(data)
        
        assert interaction["significant"] is True
        assert interaction["interaction_strength"] > 0.5


class TestExperimentReporting:
    """Test experiment reporting and visualization."""

    @pytest.mark.asyncio
    async def test_generate_experiment_report(self):
        """Test generating experiment report."""
        from prompt_sentinel.experiments.reporting import ExperimentReporter
        
        reporter = ExperimentReporter()
        
        experiment_data = {
            "name": "Detection Threshold Test",
            "duration_days": 14,
            "variants": {
                "control": {
                    "users": 5000,
                    "detections": 450,
                    "false_positives": 50
                },
                "treatment": {
                    "users": 5000,
                    "detections": 520,
                    "false_positives": 65
                }
            }
        }
        
        report = await reporter.generate_report(experiment_data)
        
        assert "summary" in report
        assert "metrics" in report
        assert "recommendations" in report
        assert "statistical_analysis" in report
        
        # Check lift calculation
        assert report["metrics"]["detection_lift"] > 0.1  # ~15% lift

    @pytest.mark.asyncio
    async def test_experiment_dashboard_data(self):
        """Test data preparation for experiment dashboard."""
        from prompt_sentinel.experiments.reporting import ExperimentReporter
        
        reporter = ExperimentReporter()
        
        # Prepare time series data
        time_series = await reporter.prepare_time_series(
            experiment_id="exp_123",
            metrics=["conversion_rate", "latency"],
            granularity="hourly"
        )
        
        assert "timestamps" in time_series
        assert "control" in time_series
        assert "treatment" in time_series
        assert len(time_series["timestamps"]) > 0


class TestExperimentCompliance:
    """Test experiment compliance and ethics."""

    @pytest.mark.asyncio
    async def test_user_opt_out(self):
        """Test user opt-out from experiments."""
        from prompt_sentinel.experiments.compliance import ComplianceManager
        
        compliance = ComplianceManager()
        
        # User opts out
        await compliance.opt_out_user("user_123")
        
        # Check if user is excluded
        is_excluded = await compliance.is_user_excluded("user_123")
        assert is_excluded is True
        
        # User should get control variant
        variant = await compliance.get_safe_variant("user_123")
        assert variant == "control"

    @pytest.mark.asyncio
    async def test_data_retention_policy(self):
        """Test experiment data retention."""
        from prompt_sentinel.experiments.compliance import ComplianceManager
        
        compliance = ComplianceManager()
        
        # Set retention policy
        await compliance.set_retention_policy(
            experiment_data_days=90,
            user_identifiers_days=30
        )
        
        # Check data for deletion
        data_to_delete = await compliance.get_expired_data(
            cutoff_date=datetime.utcnow() - timedelta(days=91)
        )
        
        assert "experiment_results" in data_to_delete
        assert "user_assignments" in data_to_delete


if __name__ == "__main__":
    pytest.main([__file__, "-v"])