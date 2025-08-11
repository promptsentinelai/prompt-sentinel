# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Event collector for pattern discovery.

Captures detection events and maintains a sliding window buffer
for ML analysis and pattern extraction.
"""

import asyncio
import hashlib
import json
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any

import structlog

from prompt_sentinel.cache.cache_manager import cache_manager
from prompt_sentinel.models.schemas import Verdict

logger = structlog.get_logger()


class EventType(Enum):
    """Types of detection events."""

    DETECTION = "detection"
    FEEDBACK = "feedback"
    PATTERN_MATCH = "pattern_match"
    FALSE_POSITIVE = "false_positive"
    FALSE_NEGATIVE = "false_negative"


@dataclass
class DetectionEvent:
    """A single detection event for ML analysis."""

    event_id: str
    timestamp: datetime
    event_type: EventType
    prompt: str
    verdict: Verdict
    confidence: float
    categories: list[str]
    patterns_matched: list[str]
    provider_used: str
    processing_time_ms: float
    metadata: dict[str, Any] = field(default_factory=dict)

    # Feedback fields
    user_label: str | None = None
    is_false_positive: bool = False
    is_false_negative: bool = False

    # Feature cache
    features: dict[str, Any] | None = None
    embedding: list[float] | None = None

    def to_dict(self) -> dict:
        """Convert to dictionary for storage."""
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat()
        data["event_type"] = self.event_type.value
        data["verdict"] = self.verdict.value if isinstance(self.verdict, Verdict) else self.verdict
        return data

    @classmethod
    def from_dict(cls, data: dict) -> "DetectionEvent":
        """Create from dictionary."""
        data["timestamp"] = datetime.fromisoformat(data["timestamp"])
        data["event_type"] = EventType(data["event_type"])
        if isinstance(data["verdict"], str):
            data["verdict"] = Verdict(data["verdict"])
        return cls(**data)

    def get_hash(self) -> str:
        """Get hash of the prompt for deduplication."""
        return hashlib.sha256(self.prompt.encode()).hexdigest()[:16]


class PatternCollector:
    """Collects and manages detection events for pattern discovery."""

    def __init__(
        self,
        buffer_size: int = 10000,
        persist_to_cache: bool = True,
        min_events_for_clustering: int = 100,
    ):
        """Initialize the pattern collector.

        Args:
            buffer_size: Maximum events to keep in memory
            persist_to_cache: Whether to persist events to Redis
            min_events_for_clustering: Minimum events needed for clustering
        """
        self.buffer_size = buffer_size
        self.persist_to_cache = persist_to_cache
        self.min_events_for_clustering = min_events_for_clustering

        # Circular buffer for recent events
        self.event_buffer = deque(maxlen=buffer_size)

        # Indexes for fast lookup
        self.events_by_verdict: dict[str, list[DetectionEvent]] = {
            verdict.value: [] for verdict in Verdict
        }
        self.events_by_category: dict[str, list[DetectionEvent]] = {}
        self.prompt_hashes: set[str] = set()

        # Statistics
        self.total_events = 0
        self.unique_prompts = 0
        self.false_positives = 0
        self.false_negatives = 0

        # Background tasks
        self._tasks: list[asyncio.Task] = []
        self._running = False

    async def initialize(self):
        """Initialize the collector and load persisted events."""
        self._running = True

        # Load persisted events from cache
        if self.persist_to_cache and cache_manager.enabled:
            await self._load_from_cache()

        # Start background tasks
        self._tasks.append(asyncio.create_task(self._periodic_persistence()))
        self._tasks.append(asyncio.create_task(self._periodic_cleanup()))

        logger.info(
            "Pattern collector initialized",
            buffer_size=self.buffer_size,
            events_loaded=len(self.event_buffer),
        )

    async def shutdown(self):
        """Shutdown the collector and save state."""
        self._running = False

        # Cancel background tasks
        for task in self._tasks:
            task.cancel()

        # Save current state
        if self.persist_to_cache:
            await self._save_to_cache()

        logger.info("Pattern collector shutdown", total_events=self.total_events)

    async def collect_event(
        self,
        prompt: str,
        verdict: Verdict,
        confidence: float,
        categories: list[str],
        patterns_matched: list[str],
        provider_used: str,
        processing_time_ms: float,
        metadata: dict[str, Any] | None = None,
    ) -> DetectionEvent:
        """Collect a new detection event.

        Args:
            prompt: The prompt that was analyzed
            verdict: Detection verdict
            confidence: Confidence score
            categories: Detection categories
            patterns_matched: Patterns that matched
            provider_used: Provider used for detection
            processing_time_ms: Processing time
            metadata: Additional metadata

        Returns:
            The created detection event
        """
        # Create event
        event = DetectionEvent(
            event_id=f"evt_{datetime.utcnow().timestamp()}_{len(self.event_buffer)}",
            timestamp=datetime.utcnow(),
            event_type=EventType.DETECTION,
            prompt=prompt,
            verdict=verdict,
            confidence=confidence,
            categories=categories,
            patterns_matched=patterns_matched,
            provider_used=provider_used,
            processing_time_ms=processing_time_ms,
            metadata=metadata or {},
        )

        # Add to buffer
        self._add_event(event)

        # Track statistics
        self.total_events += 1
        prompt_hash = event.get_hash()
        if prompt_hash not in self.prompt_hashes:
            self.prompt_hashes.add(prompt_hash)
            self.unique_prompts += 1

        logger.debug(
            "Detection event collected",
            event_id=event.event_id,
            verdict=verdict.value,
            categories=categories,
        )

        return event

    async def add_feedback(
        self,
        event_id: str,
        user_label: str,
        is_false_positive: bool = False,
        is_false_negative: bool = False,
    ) -> bool:
        """Add user feedback to an event.

        Args:
            event_id: Event to update
            user_label: User's label for the event
            is_false_positive: Whether this was a false positive
            is_false_negative: Whether this was a false negative

        Returns:
            True if event was found and updated
        """
        # Find event in buffer
        for event in self.event_buffer:
            if event.event_id == event_id:
                event.user_label = user_label
                event.is_false_positive = is_false_positive
                event.is_false_negative = is_false_negative
                event.event_type = EventType.FEEDBACK

                # Update statistics
                if is_false_positive:
                    self.false_positives += 1
                if is_false_negative:
                    self.false_negatives += 1

                logger.info("Feedback added to event", event_id=event_id, label=user_label)
                return True

        return False

    def get_events_for_clustering(
        self,
        min_confidence: float = 0.5,
        verdicts: list[Verdict] | None = None,
        limit: int | None = None,
    ) -> list[DetectionEvent]:
        """Get events suitable for clustering.

        Args:
            min_confidence: Minimum confidence threshold
            verdicts: Filter by specific verdicts
            limit: Maximum number of events

        Returns:
            List of events for clustering
        """
        events = []
        verdicts_to_check = verdicts or [Verdict.BLOCK, Verdict.FLAG]

        for event in self.event_buffer:
            # Skip events with user feedback marking them as false positives
            if event.is_false_positive:
                continue

            # Check criteria
            if event.confidence >= min_confidence and event.verdict in verdicts_to_check:
                events.append(event)

            if limit and len(events) >= limit:
                break

        return events

    def get_statistics(self) -> dict[str, Any]:
        """Get collector statistics.

        Returns:
            Dictionary of statistics
        """
        verdict_counts = {}
        for verdict in Verdict:
            verdict_counts[verdict.value] = len(self.events_by_verdict.get(verdict.value, []))

        category_counts = {
            category: len(events) for category, events in self.events_by_category.items()
        }

        return {
            "total_events": self.total_events,
            "buffer_size": len(self.event_buffer),
            "unique_prompts": self.unique_prompts,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "verdict_distribution": verdict_counts,
            "category_distribution": category_counts,
            "ready_for_clustering": len(self.event_buffer) >= self.min_events_for_clustering,
        }

    def _add_event(self, event: DetectionEvent):
        """Add event to internal indexes."""
        # Add to buffer (circular, will remove oldest if full)
        self.event_buffer.append(event)

        # Update verdict index
        verdict_key = event.verdict.value if isinstance(event.verdict, Verdict) else event.verdict
        if verdict_key not in self.events_by_verdict:
            self.events_by_verdict[verdict_key] = []
        self.events_by_verdict[verdict_key].append(event)

        # Maintain verdict index size
        if len(self.events_by_verdict[verdict_key]) > self.buffer_size // 10:
            self.events_by_verdict[verdict_key].pop(0)

        # Update category index
        for category in event.categories:
            if category not in self.events_by_category:
                self.events_by_category[category] = []
            self.events_by_category[category].append(event)

            # Maintain category index size
            if len(self.events_by_category[category]) > self.buffer_size // 20:
                self.events_by_category[category].pop(0)

    async def _load_from_cache(self):
        """Load persisted events from cache."""
        if not cache_manager.connected:
            return

        try:
            # Load events from cache
            events_data = await cache_manager.get("ml:pattern_events")
            if events_data:
                events = json.loads(events_data)
                for event_dict in events[-self.buffer_size :]:  # Load up to buffer_size
                    try:
                        event = DetectionEvent.from_dict(event_dict)
                        self._add_event(event)
                    except Exception as e:
                        logger.warning("Failed to load event from cache", error=str(e))

                logger.info("Loaded events from cache", count=len(self.event_buffer))
        except Exception as e:
            logger.error("Failed to load events from cache", error=str(e))

    async def _save_to_cache(self):
        """Save events to cache for persistence."""
        if not cache_manager.connected or not self.event_buffer:
            return

        try:
            # Convert events to dict
            events_data = [event.to_dict() for event in self.event_buffer]

            # Save to cache with TTL
            await cache_manager.set(
                "ml:pattern_events", json.dumps(events_data), ttl=86400 * 7  # Keep for 7 days
            )

            # Save statistics
            stats = self.get_statistics()
            await cache_manager.set("ml:pattern_stats", json.dumps(stats), ttl=3600)  # 1 hour

            logger.debug("Saved events to cache", count=len(events_data))
        except Exception as e:
            logger.error("Failed to save events to cache", error=str(e))

    async def _periodic_persistence(self):
        """Periodically save events to cache."""
        while self._running:
            try:
                await asyncio.sleep(300)  # Every 5 minutes
                if self.persist_to_cache:
                    await self._save_to_cache()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Error in periodic persistence", error=str(e))

    async def _periodic_cleanup(self):
        """Periodically clean up old events."""
        while self._running:
            try:
                await asyncio.sleep(3600)  # Every hour

                # Remove events older than 24 hours
                cutoff = datetime.utcnow() - timedelta(hours=24)
                initial_size = len(self.event_buffer)

                # Filter old events
                self.event_buffer = deque(
                    (e for e in self.event_buffer if e.timestamp > cutoff), maxlen=self.buffer_size
                )

                removed = initial_size - len(self.event_buffer)
                if removed > 0:
                    logger.info("Cleaned up old events", removed=removed)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Error in periodic cleanup", error=str(e))


# Global collector instance
pattern_collector = PatternCollector()
