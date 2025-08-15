# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Comprehensive tests for ML manager module."""

import asyncio
import json
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import numpy as np
import pytest

from prompt_sentinel.ml.collector import DetectionEvent, EventType, PatternCollector
from prompt_sentinel.ml.manager import (
    ManagedPattern,
    PatternManager,
    PatternPerformance,
    PatternStatus,
)
from prompt_sentinel.ml.patterns import ExtractedPattern
from prompt_sentinel.models.schemas import Verdict


class TestPatternStatus:
    """Test suite for PatternStatus enum."""

    def test_pattern_status_values(self):
        """Test PatternStatus enum values."""
        assert PatternStatus.CANDIDATE.value == "candidate"
        assert PatternStatus.TESTING.value == "testing"
        assert PatternStatus.ACTIVE.value == "active"
        assert PatternStatus.RETIRED.value == "retired"
        assert PatternStatus.REJECTED.value == "rejected"


class TestPatternPerformance:
    """Test suite for PatternPerformance dataclass."""

    @pytest.fixture
    def performance(self):
        """Create a sample performance instance."""
        return PatternPerformance(
            true_positives=80,
            false_positives=10,
            true_negatives=100,
            false_negatives=20,
            total_matches=90,
            last_match=datetime.utcnow(),
        )

    def test_initialization(self):
        """Test PatternPerformance initialization."""
        perf = PatternPerformance()

        assert perf.true_positives == 0
        assert perf.false_positives == 0
        assert perf.true_negatives == 0
        assert perf.false_negatives == 0
        assert perf.total_matches == 0
        assert perf.last_match is None

    def test_precision_calculation(self, performance):
        """Test precision calculation."""
        # TP=80, FP=10, so precision = 80/(80+10) = 0.889
        assert performance.precision == pytest.approx(0.889, abs=0.01)

        # Edge case: no positives
        empty_perf = PatternPerformance()
        assert empty_perf.precision == 0.0

    def test_recall_calculation(self, performance):
        """Test recall calculation."""
        # TP=80, FN=20, so recall = 80/(80+20) = 0.8
        assert performance.recall == 0.8

        # Edge case: no true positives or false negatives
        empty_perf = PatternPerformance()
        assert empty_perf.recall == 0.0

    def test_f1_score_calculation(self, performance):
        """Test F1 score calculation."""
        # F1 = 2 * (precision * recall) / (precision + recall)
        precision = performance.precision
        recall = performance.recall
        expected_f1 = 2 * (precision * recall) / (precision + recall)
        assert performance.f1_score == pytest.approx(expected_f1, abs=0.01)

        # Edge case: zero precision and recall
        empty_perf = PatternPerformance()
        assert empty_perf.f1_score == 0.0

    def test_accuracy_calculation(self, performance):
        """Test accuracy calculation."""
        # Accuracy = (TP + TN) / (TP + FP + TN + FN) = (80 + 100) / 210
        assert performance.accuracy == pytest.approx(180 / 210, abs=0.01)

        # Edge case: no samples
        empty_perf = PatternPerformance()
        assert empty_perf.accuracy == 0.0


class TestManagedPattern:
    """Test suite for ManagedPattern dataclass."""

    @pytest.fixture
    def sample_pattern(self):
        """Create a sample ExtractedPattern."""
        return ExtractedPattern(
            pattern_id="pat_123",
            regex="test.*pattern",
            confidence=0.9,
            support=10,
            cluster_id=1,
            category="injection",
            description="Test pattern",
            examples=["test 1", "test 2"],
            created_at=datetime.utcnow(),
        )

    @pytest.fixture
    def managed_pattern(self, sample_pattern):
        """Create a sample ManagedPattern."""
        return ManagedPattern(
            pattern=sample_pattern,
            status=PatternStatus.TESTING,
            performance=PatternPerformance(true_positives=5, false_positives=1),
            promoted_at=datetime.utcnow(),
            version=2,
            metadata={"source": "test"},
        )

    def test_initialization(self, sample_pattern):
        """Test ManagedPattern initialization."""
        managed = ManagedPattern(
            pattern=sample_pattern, status=PatternStatus.CANDIDATE, performance=PatternPerformance()
        )

        assert managed.pattern == sample_pattern
        assert managed.status == PatternStatus.CANDIDATE
        assert managed.promoted_at is None
        assert managed.retired_at is None
        assert managed.version == 1
        assert managed.metadata == {}

    def test_to_dict(self, managed_pattern):
        """Test conversion to dictionary."""
        data = managed_pattern.to_dict()

        assert isinstance(data, dict)
        assert "pattern" in data
        assert data["status"] == "testing"
        assert "performance" in data
        assert data["version"] == 2
        assert data["metadata"] == {"source": "test"}
        assert data["promoted_at"] is not None

    def test_to_dict_with_none_dates(self, sample_pattern):
        """Test to_dict with None dates."""
        managed = ManagedPattern(
            pattern=sample_pattern, status=PatternStatus.ACTIVE, performance=PatternPerformance()
        )

        data = managed.to_dict()
        assert data["promoted_at"] is None
        assert data["retired_at"] is None


class TestPatternManager:
    """Test suite for PatternManager class."""

    @pytest.fixture
    def mock_collector(self):
        """Create a mock PatternCollector."""
        collector = MagicMock(spec=PatternCollector)
        collector.initialize = AsyncMock()
        collector.shutdown = AsyncMock()
        collector.get_events_for_clustering = MagicMock(return_value=[])
        collector.get_statistics = MagicMock(
            return_value={"ready_for_clustering": False, "total_events": 0}
        )
        return collector

    @pytest.fixture
    def manager(self, mock_collector):
        """Create a PatternManager instance."""
        return PatternManager(
            collector=mock_collector,
            min_precision=0.9,
            min_recall=0.5,
            min_samples_for_promotion=10,
            evaluation_period_hours=1,
            max_active_patterns=100,
        )

    @pytest.fixture
    def sample_pattern(self):
        """Create a sample ExtractedPattern."""
        return ExtractedPattern(
            pattern_id="test_001",
            regex="test.*pattern",
            confidence=0.85,
            support=15,
            cluster_id=1,
            category="injection",
            description="Test pattern",
            examples=["test pattern 1", "test pattern 2"],
            created_at=datetime.utcnow(),
        )

    @pytest.fixture
    def sample_events(self):
        """Create sample detection events."""
        return [
            DetectionEvent(
                event_id=f"evt_{i}",
                timestamp=datetime.utcnow(),
                event_type=EventType.DETECTION,
                prompt=f"Test prompt {i}",
                verdict=Verdict.BLOCK,
                confidence=0.8,
                categories=["injection"],
                patterns_matched=[],
                provider_used="test",
                processing_time_ms=10.0,
            )
            for i in range(20)
        ]

    def test_initialization(self):
        """Test PatternManager initialization."""
        manager = PatternManager(
            min_precision=0.85,
            min_recall=0.6,
            min_samples_for_promotion=50,
            evaluation_period_hours=12,
            max_active_patterns=500,
        )

        assert manager.min_precision == 0.85
        assert manager.min_recall == 0.6
        assert manager.min_samples_for_promotion == 50
        assert manager.evaluation_period_hours == 12
        assert manager.max_active_patterns == 500
        assert isinstance(manager.collector, PatternCollector)
        assert len(manager.patterns) == 0

    def test_initialization_with_collector(self, mock_collector):
        """Test initialization with provided collector."""
        manager = PatternManager(collector=mock_collector)
        assert manager.collector == mock_collector

    @pytest.mark.asyncio
    async def test_initialize(self, manager, mock_collector):
        """Test manager initialization."""
        with patch.object(manager, "_load_patterns", new_callable=AsyncMock) as mock_load:
            with patch("asyncio.create_task") as mock_create_task:
                mock_create_task.return_value = MagicMock()

                await manager.initialize()

                assert manager._running is True
                mock_collector.initialize.assert_called_once()
                mock_load.assert_called_once()
                assert mock_create_task.call_count == 3  # 3 background tasks

    @pytest.mark.asyncio
    async def test_shutdown(self, manager, mock_collector):
        """Test manager shutdown."""
        manager._running = True
        task1 = MagicMock()
        task2 = MagicMock()
        manager._tasks = [task1, task2]

        with patch.object(manager, "_save_patterns", new_callable=AsyncMock) as mock_save:
            await manager.shutdown()

            assert manager._running is False
            task1.cancel.assert_called_once()
            task2.cancel.assert_called_once()
            mock_save.assert_called_once()
            mock_collector.shutdown.assert_called_once()

    @pytest.mark.asyncio
    async def test_discover_patterns_insufficient_events(self, manager, mock_collector):
        """Test pattern discovery with insufficient events."""
        mock_collector.get_events_for_clustering.return_value = []
        manager.clustering_engine.min_cluster_size = 10

        patterns = await manager.discover_patterns()

        assert patterns == []

    @pytest.mark.asyncio
    async def test_discover_patterns_success(self, manager, mock_collector, sample_events):
        """Test successful pattern discovery."""
        mock_collector.get_events_for_clustering.return_value = sample_events
        manager.clustering_engine.min_cluster_size = 5

        # Mock feature extraction
        mock_features = [
            MagicMock(to_array=MagicMock(return_value=np.random.rand(38))) for _ in sample_events
        ]
        manager.feature_extractor.extract_batch = MagicMock(return_value=mock_features)

        # Mock clustering
        mock_clusters = [MagicMock(), MagicMock()]
        manager.clustering_engine.cluster_events = AsyncMock(return_value=mock_clusters)

        # Mock pattern extraction
        mock_patterns = [
            ExtractedPattern(
                pattern_id=f"pat_{i}",
                regex=f"pattern_{i}",
                confidence=0.8,
                support=10,
                cluster_id=1,
                category="test",
                description=f"Pattern {i}",
                examples=["ex1", "ex2"],
                created_at=datetime.utcnow(),
            )
            for i in range(3)
        ]
        manager.pattern_extractor.extract_patterns = AsyncMock(return_value=mock_patterns[:2])
        manager.pattern_extractor.merge_similar_patterns = MagicMock(return_value=mock_patterns)

        patterns = await manager.discover_patterns()

        assert len(patterns) == 3
        assert len(manager.patterns) == 3
        assert all(p.pattern_id in manager.patterns for p in patterns)
        assert manager.discovery_stats["total_discovered"] == 3

    @pytest.mark.asyncio
    async def test_evaluate_pattern_true_positive(self, manager, sample_pattern):
        """Test pattern evaluation with true positive."""
        # Add pattern to manager
        managed = ManagedPattern(
            pattern=sample_pattern, status=PatternStatus.TESTING, performance=PatternPerformance()
        )
        manager.patterns[sample_pattern.pattern_id] = managed

        # Mock pattern test
        sample_pattern.test = MagicMock(return_value=True)

        # Create event
        event = DetectionEvent(
            event_id="evt_1",
            timestamp=datetime.utcnow(),
            event_type=EventType.DETECTION,
            prompt="test pattern match",
            verdict=Verdict.BLOCK,
            confidence=0.9,
            categories=["test"],
            patterns_matched=[],
            provider_used="test",
            processing_time_ms=10.0,
        )

        with patch.object(manager, "_check_pattern_status", new_callable=AsyncMock):
            await manager.evaluate_pattern(sample_pattern.pattern_id, event, was_correct=True)

        assert managed.performance.true_positives == 1
        assert managed.performance.total_matches == 1

    @pytest.mark.asyncio
    async def test_evaluate_pattern_false_positive(self, manager, sample_pattern):
        """Test pattern evaluation with false positive."""
        managed = ManagedPattern(
            pattern=sample_pattern, status=PatternStatus.TESTING, performance=PatternPerformance()
        )
        manager.patterns[sample_pattern.pattern_id] = managed
        sample_pattern.test = MagicMock(return_value=True)

        event = DetectionEvent(
            event_id="evt_1",
            timestamp=datetime.utcnow(),
            event_type=EventType.DETECTION,
            prompt="test",
            verdict=Verdict.BLOCK,
            confidence=0.9,
            categories=["test"],
            patterns_matched=[],
            provider_used="test",
            processing_time_ms=10.0,
        )

        with patch.object(manager, "_check_pattern_status", new_callable=AsyncMock):
            await manager.evaluate_pattern(sample_pattern.pattern_id, event, was_correct=False)

        assert managed.performance.false_positives == 1

    @pytest.mark.asyncio
    async def test_evaluate_pattern_not_found(self, manager):
        """Test evaluating non-existent pattern."""
        event = MagicMock()
        # Should not raise error
        await manager.evaluate_pattern("non_existent", event, True)

    @pytest.mark.asyncio
    async def test_promote_pattern_success(self, manager, sample_pattern):
        """Test successful pattern promotion."""
        managed = ManagedPattern(
            pattern=sample_pattern,
            status=PatternStatus.TESTING,
            performance=PatternPerformance(true_positives=10, false_positives=1),
        )
        manager.patterns[sample_pattern.pattern_id] = managed
        manager.patterns_by_status[PatternStatus.TESTING].append(sample_pattern.pattern_id)

        result = await manager.promote_pattern(sample_pattern.pattern_id)

        assert result is True
        assert managed.status == PatternStatus.ACTIVE
        assert managed.promoted_at is not None
        assert sample_pattern.pattern_id in manager.patterns_by_status[PatternStatus.ACTIVE]
        assert sample_pattern.pattern_id not in manager.patterns_by_status[PatternStatus.TESTING]

    @pytest.mark.asyncio
    async def test_promote_pattern_not_found(self, manager):
        """Test promoting non-existent pattern."""
        result = await manager.promote_pattern("non_existent")
        assert result is False

    @pytest.mark.asyncio
    async def test_promote_pattern_retired(self, manager, sample_pattern):
        """Test promoting retired pattern."""
        managed = ManagedPattern(
            pattern=sample_pattern, status=PatternStatus.RETIRED, performance=PatternPerformance()
        )
        manager.patterns[sample_pattern.pattern_id] = managed

        result = await manager.promote_pattern(sample_pattern.pattern_id)
        assert result is False

    @pytest.mark.asyncio
    async def test_retire_pattern_success(self, manager, sample_pattern):
        """Test successful pattern retirement."""
        managed = ManagedPattern(
            pattern=sample_pattern, status=PatternStatus.ACTIVE, performance=PatternPerformance()
        )
        manager.patterns[sample_pattern.pattern_id] = managed
        manager.patterns_by_status[PatternStatus.ACTIVE].append(sample_pattern.pattern_id)

        result = await manager.retire_pattern(sample_pattern.pattern_id, "Poor performance")

        assert result is True
        assert managed.status == PatternStatus.RETIRED
        assert managed.retired_at is not None
        assert managed.metadata["retirement_reason"] == "Poor performance"
        assert sample_pattern.pattern_id in manager.patterns_by_status[PatternStatus.RETIRED]

    @pytest.mark.asyncio
    async def test_retire_pattern_not_found(self, manager):
        """Test retiring non-existent pattern."""
        result = await manager.retire_pattern("non_existent")
        assert result is False

    def test_get_active_patterns(self, manager, sample_pattern):
        """Test getting active patterns."""
        # Add active pattern
        managed1 = ManagedPattern(
            pattern=sample_pattern, status=PatternStatus.ACTIVE, performance=PatternPerformance()
        )
        manager.patterns[sample_pattern.pattern_id] = managed1
        manager.patterns_by_status[PatternStatus.ACTIVE].append(sample_pattern.pattern_id)

        # Add non-active pattern
        pattern2 = ExtractedPattern(
            pattern_id="test_002",
            regex=".*other.*",
            confidence=0.7,
            support=5,
            cluster_id=2,
            category="test",
            description="Other pattern",
            examples=["other"],
            created_at=datetime.utcnow(),
        )
        managed2 = ManagedPattern(
            pattern=pattern2, status=PatternStatus.TESTING, performance=PatternPerformance()
        )
        manager.patterns[pattern2.pattern_id] = managed2

        active = manager.get_active_patterns()

        assert len(active) == 1
        assert active[0] == sample_pattern

    def test_get_pattern_statistics(self, manager, sample_pattern):
        """Test getting pattern statistics."""
        # Add patterns with different statuses
        for i, status in enumerate(PatternStatus):
            pattern = ExtractedPattern(
                pattern_id=f"pat_{status.value}",
                regex=f"pattern_{i}",
                confidence=0.8,
                support=10,
                cluster_id=i,
                category="test",
                description=f"Pattern {i}",
                examples=["ex"],
                created_at=datetime.utcnow(),
            )
            managed = ManagedPattern(
                pattern=pattern,
                status=status,
                performance=PatternPerformance(
                    true_positives=10, false_positives=2, true_negatives=20, false_negatives=3
                ),
            )
            manager.patterns[pattern.pattern_id] = managed
            manager.patterns_by_status[status].append(pattern.pattern_id)

        manager.discovery_stats["total_discovered"] = 5

        stats = manager.get_pattern_statistics()

        assert stats["total_patterns"] == 5
        assert all(status.value in stats["status_distribution"] for status in PatternStatus)
        assert "discovery_stats" in stats
        assert "active_pattern_performance" in stats
        assert "collector_stats" in stats

    @pytest.mark.asyncio
    async def test_check_pattern_status_promote_to_testing(self, manager, sample_pattern):
        """Test promoting candidate to testing."""
        managed = ManagedPattern(
            pattern=sample_pattern,
            status=PatternStatus.CANDIDATE,
            performance=PatternPerformance(
                true_positives=9, false_positives=1, true_negatives=5, false_negatives=1
            ),
        )
        manager.patterns[sample_pattern.pattern_id] = managed
        manager.patterns_by_status[PatternStatus.CANDIDATE].append(sample_pattern.pattern_id)
        manager.min_samples_for_promotion = 10

        await manager._check_pattern_status(managed)

        assert managed.status == PatternStatus.TESTING
        assert sample_pattern.pattern_id in manager.patterns_by_status[PatternStatus.TESTING]

    @pytest.mark.asyncio
    async def test_check_pattern_status_promote_to_active(self, manager, sample_pattern):
        """Test promoting testing to active."""
        sample_pattern.created_at = datetime.utcnow() - timedelta(hours=2)
        managed = ManagedPattern(
            pattern=sample_pattern,
            status=PatternStatus.TESTING,
            performance=PatternPerformance(
                true_positives=90, false_positives=5, true_negatives=100, false_negatives=10
            ),
        )
        manager.patterns[sample_pattern.pattern_id] = managed
        manager.patterns_by_status[PatternStatus.TESTING].append(sample_pattern.pattern_id)
        manager.evaluation_period_hours = 1

        with patch.object(manager, "promote_pattern", new_callable=AsyncMock):
            await manager._check_pattern_status(managed)
            manager.promote_pattern.assert_called_once_with(sample_pattern.pattern_id)

    @pytest.mark.asyncio
    async def test_check_pattern_status_reject(self, manager, sample_pattern):
        """Test rejecting testing pattern."""
        sample_pattern.created_at = datetime.utcnow() - timedelta(hours=2)
        managed = ManagedPattern(
            pattern=sample_pattern,
            status=PatternStatus.TESTING,
            performance=PatternPerformance(
                true_positives=5,
                false_positives=20,  # Poor precision
                true_negatives=100,
                false_negatives=10,
            ),
        )
        manager.patterns[sample_pattern.pattern_id] = managed
        manager.patterns_by_status[PatternStatus.TESTING].append(sample_pattern.pattern_id)

        await manager._check_pattern_status(managed)

        assert managed.status == PatternStatus.REJECTED
        assert sample_pattern.pattern_id in manager.patterns_by_status[PatternStatus.REJECTED]

    @pytest.mark.asyncio
    async def test_check_pattern_status_retire_active(self, manager, sample_pattern):
        """Test retiring active pattern with poor performance."""
        managed = ManagedPattern(
            pattern=sample_pattern,
            status=PatternStatus.ACTIVE,
            performance=PatternPerformance(
                true_positives=100,
                false_positives=300,  # Too many false positives
                true_negatives=500,
                false_negatives=101,
            ),
        )
        manager.patterns[sample_pattern.pattern_id] = managed

        with patch.object(manager, "retire_pattern", new_callable=AsyncMock):
            await manager._check_pattern_status(managed)
            manager.retire_pattern.assert_called_once()

    @pytest.mark.asyncio
    async def test_periodic_discovery(self, manager, mock_collector):
        """Test periodic discovery task."""
        manager._running = True
        mock_collector.get_statistics.return_value = {"ready_for_clustering": True}

        with patch.object(manager, "discover_patterns", new_callable=AsyncMock) as mock_discover:
            with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
                mock_sleep.side_effect = [None, asyncio.CancelledError()]

                try:
                    await manager._periodic_discovery()
                except asyncio.CancelledError:
                    pass

                mock_discover.assert_called_once()

    @pytest.mark.asyncio
    async def test_periodic_evaluation(self, manager, sample_pattern):
        """Test periodic evaluation task."""
        manager._running = True
        managed = ManagedPattern(
            pattern=sample_pattern, status=PatternStatus.TESTING, performance=PatternPerformance()
        )
        manager.patterns[sample_pattern.pattern_id] = managed
        manager.patterns_by_status[PatternStatus.TESTING].append(sample_pattern.pattern_id)

        with patch.object(manager, "_check_pattern_status", new_callable=AsyncMock) as mock_check:
            with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
                mock_sleep.side_effect = [None, asyncio.CancelledError()]

                try:
                    await manager._periodic_evaluation()
                except asyncio.CancelledError:
                    pass

                mock_check.assert_called_once_with(managed)

    @pytest.mark.asyncio
    async def test_periodic_cleanup(self, manager):
        """Test periodic cleanup task."""
        manager._running = True

        # Add old rejected pattern
        old_pattern = ExtractedPattern(
            pattern_id="old_pat",
            regex="old",
            confidence=0.5,
            support=2,
            cluster_id=1,
            category="test",
            description="Old pattern",
            examples=["old"],
            created_at=datetime.utcnow() - timedelta(days=40),
        )
        managed = ManagedPattern(
            pattern=old_pattern, status=PatternStatus.REJECTED, performance=PatternPerformance()
        )
        manager.patterns[old_pattern.pattern_id] = managed
        manager.patterns_by_status[PatternStatus.REJECTED].append(old_pattern.pattern_id)

        with patch("asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
            mock_sleep.side_effect = [None, asyncio.CancelledError()]

            try:
                await manager._periodic_cleanup()
            except asyncio.CancelledError:
                pass

            # Old pattern should be removed
            assert old_pattern.pattern_id not in manager.patterns

    @pytest.mark.asyncio
    async def test_load_patterns_success(self, manager):
        """Test loading patterns from cache."""
        patterns_data = [
            {
                "pattern": {
                    "pattern_id": "loaded_001",
                    "regex": "loaded.*pattern",
                    "confidence": 0.85,
                    "support": 20,
                    "cluster_id": 1,
                    "category": "test",
                    "description": "Loaded pattern",
                    "examples": ["loaded pattern"],
                    "created_at": datetime.utcnow().isoformat(),
                    "metadata": {},
                },
                "status": "active",
                "performance": {
                    "true_positives": 50,
                    "false_positives": 5,
                    "true_negatives": 100,
                    "false_negatives": 10,
                    "total_matches": 55,
                    "last_match": None,
                },
                "promoted_at": None,
                "retired_at": None,
                "version": 1,
                "metadata": {},
            }
        ]

        with patch("prompt_sentinel.ml.manager.cache_manager") as mock_cache:
            mock_cache.connected = True
            mock_cache.get = AsyncMock(return_value=json.dumps(patterns_data))

            await manager._load_patterns()

            assert len(manager.patterns) == 1
            assert "loaded_001" in manager.patterns
            assert manager.patterns["loaded_001"].status == PatternStatus.ACTIVE

    @pytest.mark.asyncio
    async def test_load_patterns_not_connected(self, manager):
        """Test load patterns when cache not connected."""
        with patch("prompt_sentinel.ml.manager.cache_manager") as mock_cache:
            mock_cache.connected = False

            await manager._load_patterns()

            # Should return early without loading
            assert len(manager.patterns) == 0

    @pytest.mark.asyncio
    async def test_save_patterns_success(self, manager, sample_pattern):
        """Test saving patterns to cache."""
        managed = ManagedPattern(
            pattern=sample_pattern, status=PatternStatus.ACTIVE, performance=PatternPerformance()
        )
        manager.patterns[sample_pattern.pattern_id] = managed

        with patch("prompt_sentinel.ml.manager.cache_manager") as mock_cache:
            mock_cache.connected = True
            mock_cache.set = AsyncMock()

            await manager._save_patterns()

            mock_cache.set.assert_called_once()
            call_args = mock_cache.set.call_args
            assert call_args[0][0] == "ml:managed_patterns"
            assert isinstance(call_args[0][1], str)  # JSON string

    @pytest.mark.asyncio
    async def test_save_patterns_not_connected(self, manager):
        """Test save patterns when cache not connected."""
        with patch("prompt_sentinel.ml.manager.cache_manager") as mock_cache:
            mock_cache.connected = False
            mock_cache.set = AsyncMock()

            await manager._save_patterns()

            # Should not attempt to save
            mock_cache.set.assert_not_called()


class TestPatternManagerIntegration:
    """Integration tests for PatternManager."""

    @pytest.mark.asyncio
    async def test_full_pattern_lifecycle(self):
        """Test complete pattern lifecycle from discovery to retirement."""
        manager = PatternManager(
            min_precision=0.8,
            min_recall=0.4,
            min_samples_for_promotion=5,
            evaluation_period_hours=0,  # Immediate for testing
        )

        # Create a test pattern
        pattern = ExtractedPattern(
            pattern_id="lifecycle_test",
            regex="test.*lifecycle",
            confidence=0.9,
            support=20,
            cluster_id=1,
            category="test",
            description="Lifecycle test pattern",
            examples=["test lifecycle"],
            created_at=datetime.utcnow() - timedelta(hours=1),  # Make it old enough
        )

        # Add as candidate
        managed = ManagedPattern(
            pattern=pattern, status=PatternStatus.CANDIDATE, performance=PatternPerformance()
        )
        manager.patterns[pattern.pattern_id] = managed
        manager.patterns_by_status[PatternStatus.CANDIDATE].append(pattern.pattern_id)

        # Simulate evaluations to promote to testing
        managed.performance.true_positives = 5
        managed.performance.false_positives = 0

        await manager._check_pattern_status(managed)
        assert managed.status == PatternStatus.TESTING

        # Promote to active (pattern is old enough now)
        managed.performance.true_positives = 10
        managed.performance.false_positives = 1

        await manager._check_pattern_status(managed)
        # Should call promote_pattern internally

        # Simulate poor performance and retire (need >1000 total evaluations)
        managed.status = PatternStatus.ACTIVE
        managed.performance.true_positives = 400
        managed.performance.false_positives = 900  # >2x true positives and >1000 total

        with patch.object(manager, "retire_pattern", new_callable=AsyncMock) as mock_retire:
            await manager._check_pattern_status(managed)
            mock_retire.assert_called_once()

    @pytest.mark.asyncio
    async def test_concurrent_pattern_operations(self):
        """Test concurrent pattern operations."""
        manager = PatternManager()

        # Create multiple patterns
        patterns = []
        for i in range(10):
            pattern = ExtractedPattern(
                pattern_id=f"concurrent_{i}",
                regex=f"pattern_{i}",
                confidence=0.8,
                support=10,
                cluster_id=i,
                category="test",
                description=f"Concurrent pattern {i}",
                examples=[f"ex_{i}"],
                created_at=datetime.utcnow(),
            )
            patterns.append(pattern)

            managed = ManagedPattern(
                pattern=pattern,
                status=PatternStatus.TESTING,
                performance=PatternPerformance(true_positives=8, false_positives=1),
            )
            manager.patterns[pattern.pattern_id] = managed
            manager.patterns_by_status[PatternStatus.TESTING].append(pattern.pattern_id)

        # Concurrently promote patterns
        tasks = [manager.promote_pattern(p.pattern_id) for p in patterns]
        results = await asyncio.gather(*tasks)

        assert all(results)
        assert len(manager.patterns_by_status[PatternStatus.ACTIVE]) == 10
        assert len(manager.patterns_by_status[PatternStatus.TESTING]) == 0
