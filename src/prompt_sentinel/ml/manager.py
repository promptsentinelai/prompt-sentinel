"""Pattern management system.

Manages the lifecycle of discovered patterns including storage, evaluation,
promotion, and retirement based on performance metrics.
"""

import asyncio
import json
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any

import structlog

from prompt_sentinel.cache.cache_manager import cache_manager
from prompt_sentinel.ml.clustering import ClusteringEngine
from prompt_sentinel.ml.collector import DetectionEvent, PatternCollector
from prompt_sentinel.ml.features import FeatureExtractor
from prompt_sentinel.ml.patterns import ExtractedPattern, PatternExtractor

logger = structlog.get_logger()


class PatternStatus(Enum):
    """Pattern lifecycle status."""

    CANDIDATE = "candidate"  # Newly discovered
    TESTING = "testing"  # Being evaluated
    ACTIVE = "active"  # In production
    RETIRED = "retired"  # Removed from use
    REJECTED = "rejected"  # Failed evaluation


@dataclass
class PatternPerformance:
    """Performance metrics for a pattern."""

    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    total_matches: int = 0
    last_match: datetime | None = None

    @property
    def precision(self) -> float:
        """Calculate precision."""
        if self.true_positives + self.false_positives == 0:
            return 0.0
        return self.true_positives / (self.true_positives + self.false_positives)

    @property
    def recall(self) -> float:
        """Calculate recall."""
        if self.true_positives + self.false_negatives == 0:
            return 0.0
        return self.true_positives / (self.true_positives + self.false_negatives)

    @property
    def f1_score(self) -> float:
        """Calculate F1 score."""
        if self.precision + self.recall == 0:
            return 0.0
        return 2 * (self.precision * self.recall) / (self.precision + self.recall)

    @property
    def accuracy(self) -> float:
        """Calculate accuracy."""
        total = (
            self.true_positives + self.false_positives + self.true_negatives + self.false_negatives
        )
        if total == 0:
            return 0.0
        return (self.true_positives + self.true_negatives) / total


@dataclass
class ManagedPattern:
    """A pattern under management."""

    pattern: ExtractedPattern
    status: PatternStatus
    performance: PatternPerformance
    promoted_at: datetime | None = None
    retired_at: datetime | None = None
    version: int = 1
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "pattern": self.pattern.to_dict(),
            "status": self.status.value,
            "performance": asdict(self.performance),
            "promoted_at": self.promoted_at.isoformat() if self.promoted_at else None,
            "retired_at": self.retired_at.isoformat() if self.retired_at else None,
            "version": self.version,
            "metadata": self.metadata,
        }


class PatternManager:
    """Manages the lifecycle of discovered patterns."""

    def __init__(
        self,
        collector: PatternCollector | None = None,
        min_precision: float = 0.9,
        min_recall: float = 0.5,
        min_samples_for_promotion: int = 100,
        evaluation_period_hours: int = 24,
        max_active_patterns: int = 1000,
    ):
        """Initialize pattern manager.

        Args:
            collector: Pattern collector instance
            min_precision: Minimum precision for promotion
            min_recall: Minimum recall for promotion
            min_samples_for_promotion: Minimum evaluations before promotion
            evaluation_period_hours: Hours to test patterns
            max_active_patterns: Maximum active patterns
        """
        self.collector = collector or PatternCollector()
        self.min_precision = min_precision
        self.min_recall = min_recall
        self.min_samples_for_promotion = min_samples_for_promotion
        self.evaluation_period_hours = evaluation_period_hours
        self.max_active_patterns = max_active_patterns

        # Pattern storage
        self.patterns: dict[str, ManagedPattern] = {}
        self.patterns_by_status: dict[PatternStatus, list[str]] = defaultdict(list)

        # Components
        self.feature_extractor = FeatureExtractor()
        self.clustering_engine = ClusteringEngine()
        self.pattern_extractor = PatternExtractor()

        # Statistics
        self.discovery_stats = {
            "total_discovered": 0,
            "total_promoted": 0,
            "total_retired": 0,
            "last_discovery": None,
        }

        # Background tasks
        self._tasks: list[asyncio.Task] = []
        self._running = False

    async def initialize(self):
        """Initialize the pattern manager."""
        self._running = True

        # Initialize components
        await self.collector.initialize()

        # Load existing patterns
        await self._load_patterns()

        # Start background tasks
        self._tasks.append(asyncio.create_task(self._periodic_discovery()))
        self._tasks.append(asyncio.create_task(self._periodic_evaluation()))
        self._tasks.append(asyncio.create_task(self._periodic_cleanup()))

        logger.info(
            "Pattern manager initialized",
            active_patterns=len(self.patterns_by_status[PatternStatus.ACTIVE]),
        )

    async def shutdown(self):
        """Shutdown the pattern manager."""
        self._running = False

        # Cancel tasks
        for task in self._tasks:
            task.cancel()

        # Save patterns
        await self._save_patterns()

        # Shutdown collector
        await self.collector.shutdown()

        logger.info("Pattern manager shutdown")

    async def discover_patterns(self) -> list[ExtractedPattern]:
        """Run pattern discovery on collected events."""
        # Get events for clustering
        events = self.collector.get_events_for_clustering()

        if len(events) < self.clustering_engine.min_cluster_size:
            logger.info("Not enough events for clustering", event_count=len(events))
            return []

        logger.info("Starting pattern discovery", event_count=len(events))

        # Extract features
        prompts = [event.prompt for event in events]
        feature_vectors = self.feature_extractor.extract_batch(prompts)

        # Convert to numpy array
        import numpy as np

        feature_matrix = np.array([f.to_array() for f in feature_vectors])

        # Run clustering
        clusters = await self.clustering_engine.cluster_events(feature_matrix, events)

        logger.info("Clustering complete", n_clusters=len(clusters))

        # Extract patterns from each cluster
        all_patterns = []

        for cluster in clusters:
            patterns = await self.pattern_extractor.extract_patterns(cluster, events)
            all_patterns.extend(patterns)

        # Merge similar patterns
        merged_patterns = self.pattern_extractor.merge_similar_patterns(all_patterns)

        # Add to management
        new_patterns = []
        for pattern in merged_patterns:
            if pattern.pattern_id not in self.patterns:
                managed = ManagedPattern(
                    pattern=pattern,
                    status=PatternStatus.CANDIDATE,
                    performance=PatternPerformance(),
                )
                self.patterns[pattern.pattern_id] = managed
                self.patterns_by_status[PatternStatus.CANDIDATE].append(pattern.pattern_id)
                new_patterns.append(pattern)

                self.discovery_stats["total_discovered"] += 1

        self.discovery_stats["last_discovery"] = datetime.utcnow()

        logger.info(
            "Pattern discovery complete",
            new_patterns=len(new_patterns),
            total_patterns=len(all_patterns),
        )

        return new_patterns

    async def evaluate_pattern(self, pattern_id: str, event: DetectionEvent, was_correct: bool):
        """Evaluate a pattern's performance.

        Args:
            pattern_id: Pattern to evaluate
            event: Detection event
            was_correct: Whether detection was correct
        """
        if pattern_id not in self.patterns:
            return

        managed = self.patterns[pattern_id]
        pattern = managed.pattern

        # Test pattern
        matches = pattern.test(event.prompt)

        # Update performance metrics
        if matches and was_correct:
            managed.performance.true_positives += 1
        elif matches and not was_correct:
            managed.performance.false_positives += 1
        elif not matches and not was_correct:
            managed.performance.true_negatives += 1
        elif not matches and was_correct:
            managed.performance.false_negatives += 1

        if matches:
            managed.performance.total_matches += 1
            managed.performance.last_match = datetime.utcnow()

        # Check for promotion/demotion
        await self._check_pattern_status(managed)

    async def promote_pattern(self, pattern_id: str) -> bool:
        """Manually promote a pattern to active status.

        Args:
            pattern_id: Pattern to promote

        Returns:
            True if promoted successfully
        """
        if pattern_id not in self.patterns:
            return False

        managed = self.patterns[pattern_id]

        # Check if can be promoted
        if managed.status in [PatternStatus.RETIRED, PatternStatus.REJECTED]:
            logger.warning(
                "Cannot promote pattern", pattern_id=pattern_id, status=managed.status.value
            )
            return False

        # Update status
        old_status = managed.status
        managed.status = PatternStatus.ACTIVE
        managed.promoted_at = datetime.utcnow()

        # Update indexes
        if pattern_id in self.patterns_by_status[old_status]:
            self.patterns_by_status[old_status].remove(pattern_id)
        self.patterns_by_status[PatternStatus.ACTIVE].append(pattern_id)

        self.discovery_stats["total_promoted"] += 1

        logger.info(
            "Pattern promoted",
            pattern_id=pattern_id,
            precision=managed.performance.precision,
            recall=managed.performance.recall,
        )

        return True

    async def retire_pattern(self, pattern_id: str, reason: str = "") -> bool:
        """Retire a pattern from active use.

        Args:
            pattern_id: Pattern to retire
            reason: Reason for retirement

        Returns:
            True if retired successfully
        """
        if pattern_id not in self.patterns:
            return False

        managed = self.patterns[pattern_id]

        # Update status
        old_status = managed.status
        managed.status = PatternStatus.RETIRED
        managed.retired_at = datetime.utcnow()
        managed.metadata["retirement_reason"] = reason

        # Update indexes
        if pattern_id in self.patterns_by_status[old_status]:
            self.patterns_by_status[old_status].remove(pattern_id)
        self.patterns_by_status[PatternStatus.RETIRED].append(pattern_id)

        self.discovery_stats["total_retired"] += 1

        logger.info("Pattern retired", pattern_id=pattern_id, reason=reason)

        return True

    def get_active_patterns(self) -> list[ExtractedPattern]:
        """Get all active patterns for detection.

        Returns:
            List of active patterns
        """
        active_patterns = []

        for pattern_id in self.patterns_by_status[PatternStatus.ACTIVE]:
            if pattern_id in self.patterns:
                active_patterns.append(self.patterns[pattern_id].pattern)

        return active_patterns

    def get_pattern_statistics(self) -> dict[str, Any]:
        """Get pattern management statistics.

        Returns:
            Dictionary of statistics
        """
        status_counts = {
            status.value: len(self.patterns_by_status[status]) for status in PatternStatus
        }

        # Calculate average performance
        active_patterns = [
            self.patterns[pid]
            for pid in self.patterns_by_status[PatternStatus.ACTIVE]
            if pid in self.patterns
        ]

        if active_patterns:
            avg_precision = sum(p.performance.precision for p in active_patterns) / len(
                active_patterns
            )
            avg_recall = sum(p.performance.recall for p in active_patterns) / len(active_patterns)
            avg_f1 = sum(p.performance.f1_score for p in active_patterns) / len(active_patterns)
        else:
            avg_precision = avg_recall = avg_f1 = 0.0

        return {
            "total_patterns": len(self.patterns),
            "status_distribution": status_counts,
            "discovery_stats": self.discovery_stats,
            "active_pattern_performance": {
                "avg_precision": avg_precision,
                "avg_recall": avg_recall,
                "avg_f1_score": avg_f1,
            },
            "collector_stats": self.collector.get_statistics(),
        }

    async def _check_pattern_status(self, managed: ManagedPattern):
        """Check if pattern should be promoted or demoted."""
        perf = managed.performance
        total_evaluations = (
            perf.true_positives + perf.false_positives + perf.true_negatives + perf.false_negatives
        )

        # Check for promotion
        if (
            managed.status == PatternStatus.CANDIDATE
            and total_evaluations >= self.min_samples_for_promotion
        ):

            if perf.precision >= self.min_precision and perf.recall >= self.min_recall:
                # Promote to testing
                managed.status = PatternStatus.TESTING
                self.patterns_by_status[PatternStatus.CANDIDATE].remove(managed.pattern.pattern_id)
                self.patterns_by_status[PatternStatus.TESTING].append(managed.pattern.pattern_id)
                logger.info("Pattern promoted to testing", pattern_id=managed.pattern.pattern_id)

        # Check testing patterns
        elif managed.status == PatternStatus.TESTING:
            # Check if evaluation period complete
            time_in_testing = datetime.utcnow() - managed.pattern.created_at

            if time_in_testing > timedelta(hours=self.evaluation_period_hours):
                if perf.precision >= self.min_precision and perf.recall >= self.min_recall:
                    # Promote to active
                    await self.promote_pattern(managed.pattern.pattern_id)
                else:
                    # Reject pattern
                    managed.status = PatternStatus.REJECTED
                    self.patterns_by_status[PatternStatus.TESTING].remove(
                        managed.pattern.pattern_id
                    )
                    self.patterns_by_status[PatternStatus.REJECTED].append(
                        managed.pattern.pattern_id
                    )
                    logger.info(
                        "Pattern rejected",
                        pattern_id=managed.pattern.pattern_id,
                        precision=perf.precision,
                        recall=perf.recall,
                    )

        # Check active patterns for retirement
        elif managed.status == PatternStatus.ACTIVE:
            # Retire if performance degrades
            if total_evaluations > 1000 and (
                perf.precision < self.min_precision * 0.8
                or perf.false_positives > perf.true_positives * 2
            ):
                await self.retire_pattern(
                    managed.pattern.pattern_id,
                    f"Performance degraded: precision={perf.precision:.2f}",
                )

    async def _periodic_discovery(self):
        """Periodically run pattern discovery."""
        while self._running:
            try:
                await asyncio.sleep(3600)  # Every hour

                # Check if enough new events
                stats = self.collector.get_statistics()
                if stats["ready_for_clustering"]:
                    await self.discover_patterns()

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Error in periodic discovery", error=str(e))

    async def _periodic_evaluation(self):
        """Periodically evaluate patterns."""
        while self._running:
            try:
                await asyncio.sleep(600)  # Every 10 minutes

                # Evaluate testing patterns
                for pattern_id in list(self.patterns_by_status[PatternStatus.TESTING]):
                    if pattern_id in self.patterns:
                        await self._check_pattern_status(self.patterns[pattern_id])

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Error in periodic evaluation", error=str(e))

    async def _periodic_cleanup(self):
        """Periodically clean up old patterns."""
        while self._running:
            try:
                await asyncio.sleep(86400)  # Daily

                # Remove old rejected patterns
                cutoff = datetime.utcnow() - timedelta(days=30)

                for pattern_id in list(self.patterns_by_status[PatternStatus.REJECTED]):
                    if pattern_id in self.patterns:
                        pattern = self.patterns[pattern_id]
                        if pattern.pattern.created_at < cutoff:
                            del self.patterns[pattern_id]
                            self.patterns_by_status[PatternStatus.REJECTED].remove(pattern_id)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Error in periodic cleanup", error=str(e))

    async def _load_patterns(self):
        """Load patterns from cache."""
        if not cache_manager.connected:
            return

        try:
            data = await cache_manager.get("ml:managed_patterns")
            if data:
                patterns_data = json.loads(data)

                for pattern_dict in patterns_data:
                    # Reconstruct pattern
                    pattern = ExtractedPattern(**pattern_dict["pattern"])
                    performance = PatternPerformance(**pattern_dict["performance"])

                    managed = ManagedPattern(
                        pattern=pattern,
                        status=PatternStatus(pattern_dict["status"]),
                        performance=performance,
                        version=pattern_dict.get("version", 1),
                        metadata=pattern_dict.get("metadata", {}),
                    )

                    self.patterns[pattern.pattern_id] = managed
                    self.patterns_by_status[managed.status].append(pattern.pattern_id)

                logger.info("Loaded patterns from cache", count=len(self.patterns))

        except Exception as e:
            logger.error("Failed to load patterns", error=str(e))

    async def _save_patterns(self):
        """Save patterns to cache."""
        if not cache_manager.connected:
            return

        try:
            patterns_data = [managed.to_dict() for managed in self.patterns.values()]

            await cache_manager.set(
                "ml:managed_patterns", json.dumps(patterns_data), ttl=86400 * 30  # 30 days
            )

            logger.info("Saved patterns to cache", count=len(patterns_data))

        except Exception as e:
            logger.error("Failed to save patterns", error=str(e))
