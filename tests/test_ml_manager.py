"""Tests for ML pattern manager module."""

import json
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from prompt_sentinel.ml.manager import (
    ManagedPattern,
    PatternManager,
    PatternPerformance,
    PatternStatus,
)
from prompt_sentinel.ml.patterns import ExtractedPattern


class TestPatternStatus:
    """Test suite for PatternStatus enum."""

    def test_pattern_status_values(self):
        """Test pattern status enum values."""
        assert PatternStatus.CANDIDATE.value == "candidate"
        assert PatternStatus.TESTING.value == "testing"
        assert PatternStatus.ACTIVE.value == "active"
        assert PatternStatus.RETIRED.value == "retired"
        assert PatternStatus.REJECTED.value == "rejected"

    def test_all_statuses_defined(self):
        """Test that all expected statuses are defined."""
        expected_statuses = {"CANDIDATE", "TESTING", "ACTIVE", "RETIRED", "REJECTED"}
        actual_statuses = {status.name for status in PatternStatus}
        assert expected_statuses == actual_statuses


class TestPatternPerformance:
    """Test suite for PatternPerformance dataclass."""

    @pytest.fixture
    def empty_performance(self):
        """Create empty performance metrics."""
        return PatternPerformance()

    @pytest.fixture
    def sample_performance(self):
        """Create sample performance metrics."""
        return PatternPerformance(
            true_positives=80,
            false_positives=20,
            true_negatives=150,
            false_negatives=10,
            total_matches=100,
            last_match=datetime.utcnow()
        )

    def test_initialization(self, empty_performance):
        """Test performance initialization."""
        assert empty_performance.true_positives == 0
        assert empty_performance.false_positives == 0
        assert empty_performance.true_negatives == 0
        assert empty_performance.false_negatives == 0
        assert empty_performance.total_matches == 0
        assert empty_performance.last_match is None

    def test_precision_calculation(self, sample_performance):
        """Test precision calculation."""
        # Precision = TP / (TP + FP) = 80 / (80 + 20) = 0.8
        assert sample_performance.precision == 0.8

    def test_precision_zero_division(self, empty_performance):
        """Test precision with zero division."""
        assert empty_performance.precision == 0.0

    def test_recall_calculation(self, sample_performance):
        """Test recall calculation."""
        # Recall = TP / (TP + FN) = 80 / (80 + 10) ≈ 0.889
        assert pytest.approx(sample_performance.recall, 0.001) == 0.889

    def test_recall_zero_division(self, empty_performance):
        """Test recall with zero division."""
        assert empty_performance.recall == 0.0

    def test_f1_score_calculation(self, sample_performance):
        """Test F1 score calculation."""
        # F1 = 2 * (precision * recall) / (precision + recall)
        precision = sample_performance.precision
        recall = sample_performance.recall
        expected_f1 = 2 * (precision * recall) / (precision + recall)
        assert pytest.approx(sample_performance.f1_score, 0.001) == expected_f1

    def test_f1_score_zero_division(self, empty_performance):
        """Test F1 score with zero division."""
        assert empty_performance.f1_score == 0.0

    def test_accuracy_calculation(self, sample_performance):
        """Test accuracy calculation."""
        # Accuracy = (TP + TN) / (TP + FP + TN + FN) = (80 + 150) / 260 ≈ 0.885
        assert pytest.approx(sample_performance.accuracy, 0.001) == 0.885

    def test_accuracy_zero_division(self, empty_performance):
        """Test accuracy with zero division."""
        assert empty_performance.accuracy == 0.0

    def test_performance_with_only_true_positives(self):
        """Test performance with only true positives."""
        perf = PatternPerformance(true_positives=100)
        assert perf.precision == 1.0
        assert perf.recall == 1.0
        assert perf.f1_score == 1.0
        assert perf.accuracy == 1.0

    def test_performance_with_only_false_positives(self):
        """Test performance with only false positives."""
        perf = PatternPerformance(false_positives=100)
        assert perf.precision == 0.0
        assert perf.recall == 0.0
        assert perf.f1_score == 0.0
        assert perf.accuracy == 0.0


class TestManagedPattern:
    """Test suite for ManagedPattern dataclass."""

    @pytest.fixture
    def sample_pattern(self):
        """Create a sample extracted pattern."""
        return ExtractedPattern(
            pattern_id="pat_001",
            regex="test.*pattern",
            confidence=0.85,
            support=10,
            cluster_id=1,
            category="injection",
            description="Test pattern",
            examples=["test pattern 1"],
            created_at=datetime.utcnow(),
            metadata={}
        )

    @pytest.fixture
    def managed_pattern(self, sample_pattern):
        """Create a managed pattern."""
        return ManagedPattern(
            pattern=sample_pattern,
            status=PatternStatus.TESTING,
            performance=PatternPerformance(true_positives=5, false_positives=1),
            promoted_at=None,
            retired_at=None,
            version=1,
            metadata={"source": "test"}
        )

    def test_initialization(self, managed_pattern):
        """Test managed pattern initialization."""
        assert managed_pattern.pattern.pattern_id == "pat_001"
        assert managed_pattern.status == PatternStatus.TESTING
        assert managed_pattern.performance.true_positives == 5
        assert managed_pattern.promoted_at is None
        assert managed_pattern.retired_at is None
        assert managed_pattern.version == 1
        assert managed_pattern.metadata["source"] == "test"

    def test_to_dict(self, managed_pattern):
        """Test conversion to dictionary."""
        result = managed_pattern.to_dict()
        
        assert "pattern" in result
        assert result["pattern"]["pattern_id"] == "pat_001"
        assert result["status"] == "testing"
        assert "performance" in result
        assert result["performance"]["true_positives"] == 5
        assert result["promoted_at"] is None
        assert result["retired_at"] is None
        assert result["version"] == 1
        assert result["metadata"]["source"] == "test"

    def test_to_dict_with_dates(self, sample_pattern):
        """Test to_dict with promoted and retired dates."""
        now = datetime.utcnow()
        later = now + timedelta(days=30)
        
        managed = ManagedPattern(
            pattern=sample_pattern,
            status=PatternStatus.RETIRED,
            performance=PatternPerformance(),
            promoted_at=now,
            retired_at=later,
            version=2,
            metadata={}
        )
        
        result = managed.to_dict()
        assert result["promoted_at"] == now.isoformat()
        assert result["retired_at"] == later.isoformat()
        assert result["version"] == 2

    def test_different_statuses(self, sample_pattern):
        """Test managed pattern with different statuses."""
        for status in PatternStatus:
            managed = ManagedPattern(
                pattern=sample_pattern,
                status=status,
                performance=PatternPerformance(),
                metadata={}
            )
            assert managed.status == status
            assert managed.to_dict()["status"] == status.value


class TestPatternManager:
    """Test suite for PatternManager."""

    @pytest.fixture
    def manager(self):
        """Create a pattern manager."""
        return PatternManager(
            min_precision=0.8,
            min_recall=0.5,
            min_samples_for_promotion=10,
            evaluation_period_hours=24,
            max_active_patterns=100
        )

    def test_initialization(self, manager):
        """Test manager initialization."""
        assert manager.min_precision == 0.8
        assert manager.min_recall == 0.5
        assert manager.min_samples_for_promotion == 10
        assert manager.evaluation_period_hours == 24
        assert manager.max_active_patterns == 100
        assert len(manager.patterns) == 0
        assert manager.collector is not None
        assert manager.pattern_extractor is not None
        assert manager.clustering_engine is not None
        assert manager.feature_extractor is not None

    def test_default_initialization(self):
        """Test manager with default parameters."""
        manager = PatternManager()
        assert manager.min_precision == 0.9
        assert manager.min_recall == 0.5
        assert manager.min_samples_for_promotion == 100
        assert manager.evaluation_period_hours == 24
        assert manager.max_active_patterns == 1000

    def test_get_active_patterns(self, manager):
        """Test getting active patterns."""
        # Initially no patterns
        patterns = manager.get_active_patterns()
        assert patterns == []
        
        # Add some patterns to patterns_by_status
        pattern1 = ExtractedPattern(
            pattern_id="active_1",
            regex="test1",
            confidence=0.9,
            support=10,
            cluster_id=1,
            category="test",
            description="Active pattern 1",
            examples=["ex1"],
            created_at=datetime.utcnow(),
            metadata={}
        )
        
        pattern2 = ExtractedPattern(
            pattern_id="active_2",
            regex="test2",
            confidence=0.85,
            support=8,
            cluster_id=2,
            category="test",
            description="Active pattern 2",
            examples=["ex2"],
            created_at=datetime.utcnow(),
            metadata={}
        )
        
        # Add to manager's storage
        manager.patterns["active_1"] = ManagedPattern(
            pattern=pattern1,
            status=PatternStatus.ACTIVE,
            performance=PatternPerformance(),
            metadata={}
        )
        manager.patterns["active_2"] = ManagedPattern(
            pattern=pattern2,
            status=PatternStatus.ACTIVE,
            performance=PatternPerformance(),
            metadata={}
        )
        manager.patterns_by_status[PatternStatus.ACTIVE] = ["active_1", "active_2"]
        
        # Get active patterns
        active = manager.get_active_patterns()
        assert len(active) == 2
        assert all(p.pattern_id in ["active_1", "active_2"] for p in active)

    def test_discovery_stats(self, manager):
        """Test discovery statistics initialization."""
        assert manager.discovery_stats["total_discovered"] == 0
        assert manager.discovery_stats["total_promoted"] == 0
        assert manager.discovery_stats["total_retired"] == 0
        assert manager.discovery_stats["last_discovery"] is None

    def test_patterns_by_status_storage(self, manager):
        """Test patterns_by_status defaultdict."""
        # Should be empty initially
        assert len(manager.patterns_by_status[PatternStatus.ACTIVE]) == 0
        assert len(manager.patterns_by_status[PatternStatus.TESTING]) == 0
        
        # Add pattern IDs
        manager.patterns_by_status[PatternStatus.ACTIVE].append("pattern_1")
        manager.patterns_by_status[PatternStatus.TESTING].extend(["pattern_2", "pattern_3"])
        
        assert len(manager.patterns_by_status[PatternStatus.ACTIVE]) == 1
        assert len(manager.patterns_by_status[PatternStatus.TESTING]) == 2


class TestPatternManagerAsync:
    """Test suite for async methods of PatternManager."""

    @pytest.mark.asyncio
    async def test_initialize(self):
        """Test async initialization."""
        manager = PatternManager()
        
        # Mock the collector
        manager.collector = MagicMock()
        manager.collector.initialize = AsyncMock()
        
        # Mock internal methods
        with patch.object(manager, '_load_patterns', AsyncMock()):
            with patch('asyncio.create_task') as mock_create_task:
                mock_create_task.return_value = MagicMock()
                
                await manager.initialize()
                
                assert manager._running is True
                assert len(manager._tasks) == 3  # Three background tasks
                manager.collector.initialize.assert_called_once()

    @pytest.mark.asyncio
    async def test_shutdown(self):
        """Test async shutdown."""
        manager = PatternManager()
        manager._running = True
        
        # Mock components
        manager.collector = MagicMock()
        manager.collector.shutdown = AsyncMock()
        
        # Create mock tasks
        mock_task = MagicMock()
        mock_task.cancel = MagicMock()
        manager._tasks = [mock_task, mock_task]
        
        # Mock save patterns
        with patch.object(manager, '_save_patterns', AsyncMock()):
            await manager.shutdown()
            
            assert manager._running is False
            assert mock_task.cancel.call_count == 2
            manager.collector.shutdown.assert_called_once()

    @pytest.mark.asyncio
    async def test_promote_pattern(self):
        """Test pattern promotion."""
        manager = PatternManager()
        
        # Create a pattern to promote
        pattern = ExtractedPattern(
            pattern_id="promote_me",
            regex="test",
            confidence=0.9,
            support=10,
            cluster_id=1,
            category="test",
            description="Pattern to promote",
            examples=["ex"],
            created_at=datetime.utcnow(),
            metadata={}
        )
        
        # Add as testing pattern
        managed = ManagedPattern(
            pattern=pattern,
            status=PatternStatus.TESTING,
            performance=PatternPerformance(
                true_positives=90,
                false_positives=5,
                true_negatives=100,
                false_negatives=5
            ),
            metadata={}
        )
        manager.patterns["promote_me"] = managed
        manager.patterns_by_status[PatternStatus.TESTING] = ["promote_me"]
        
        # Promote
        result = await manager.promote_pattern("promote_me")
        
        assert result is True
        assert managed.status == PatternStatus.ACTIVE
        assert managed.promoted_at is not None

    @pytest.mark.asyncio
    async def test_retire_pattern(self):
        """Test pattern retirement."""
        manager = PatternManager()
        
        # Create an active pattern
        pattern = ExtractedPattern(
            pattern_id="retire_me",
            regex="test",
            confidence=0.9,
            support=10,
            cluster_id=1,
            category="test",
            description="Pattern to retire",
            examples=["ex"],
            created_at=datetime.utcnow(),
            metadata={}
        )
        
        # Add as active pattern
        managed = ManagedPattern(
            pattern=pattern,
            status=PatternStatus.ACTIVE,
            performance=PatternPerformance(),
            promoted_at=datetime.utcnow(),
            metadata={}
        )
        manager.patterns["retire_me"] = managed
        manager.patterns_by_status[PatternStatus.ACTIVE] = ["retire_me"]
        
        # Retire
        result = await manager.retire_pattern("retire_me", reason="Poor performance")
        
        assert result is True
        assert managed.status == PatternStatus.RETIRED
        assert managed.retired_at is not None
        assert managed.metadata["retirement_reason"] == "Poor performance"