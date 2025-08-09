"""Tests for ML event collector module."""

import hashlib
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from prompt_sentinel.ml.collector import DetectionEvent, EventType, PatternCollector
from prompt_sentinel.models.schemas import Verdict


class TestEventType:
    """Test suite for EventType enum."""

    def test_event_type_values(self):
        """Test event type enum values."""
        assert EventType.DETECTION.value == "detection"
        assert EventType.FEEDBACK.value == "feedback"
        assert EventType.PATTERN_MATCH.value == "pattern_match"
        assert EventType.FALSE_POSITIVE.value == "false_positive"
        assert EventType.FALSE_NEGATIVE.value == "false_negative"

    def test_all_event_types_defined(self):
        """Test that all expected event types are defined."""
        expected_types = {"DETECTION", "FEEDBACK", "PATTERN_MATCH", "FALSE_POSITIVE", "FALSE_NEGATIVE"}
        actual_types = {event.name for event in EventType}
        assert expected_types == actual_types


class TestDetectionEvent:
    """Test suite for DetectionEvent dataclass."""

    @pytest.fixture
    def sample_event(self):
        """Create a sample detection event."""
        return DetectionEvent(
            event_id="evt_001",
            timestamp=datetime.utcnow(),
            event_type=EventType.DETECTION,
            prompt="Test prompt for injection detection",
            verdict=Verdict.BLOCK,
            confidence=0.85,
            categories=["injection", "role_manipulation"],
            patterns_matched=["pattern_1", "pattern_2"],
            provider_used="anthropic",
            processing_time_ms=150.5,
            metadata={"source": "api", "version": "v2"}
        )

    @pytest.fixture
    def feedback_event(self):
        """Create a feedback event."""
        return DetectionEvent(
            event_id="evt_002",
            timestamp=datetime.utcnow(),
            event_type=EventType.FEEDBACK,
            prompt="This was incorrectly flagged",
            verdict=Verdict.FLAG,
            confidence=0.6,
            categories=["suspicious"],
            patterns_matched=[],
            provider_used="openai",
            processing_time_ms=200.0,
            user_label="safe",
            is_false_positive=True,
            is_false_negative=False
        )

    def test_initialization(self, sample_event):
        """Test event initialization."""
        assert sample_event.event_id == "evt_001"
        assert sample_event.event_type == EventType.DETECTION
        assert sample_event.prompt == "Test prompt for injection detection"
        assert sample_event.verdict == Verdict.BLOCK
        assert sample_event.confidence == 0.85
        assert len(sample_event.categories) == 2
        assert len(sample_event.patterns_matched) == 2
        assert sample_event.provider_used == "anthropic"
        assert sample_event.processing_time_ms == 150.5
        assert sample_event.metadata["source"] == "api"
        assert sample_event.user_label is None
        assert sample_event.is_false_positive is False
        assert sample_event.is_false_negative is False
        assert sample_event.features is None
        assert sample_event.embedding is None

    def test_feedback_fields(self, feedback_event):
        """Test feedback-specific fields."""
        assert feedback_event.event_type == EventType.FEEDBACK
        assert feedback_event.user_label == "safe"
        assert feedback_event.is_false_positive is True
        assert feedback_event.is_false_negative is False

    def test_to_dict(self, sample_event):
        """Test conversion to dictionary."""
        event_dict = sample_event.to_dict()
        
        assert event_dict["event_id"] == "evt_001"
        assert isinstance(event_dict["timestamp"], str)  # Should be ISO format
        assert event_dict["event_type"] == "detection"
        assert event_dict["verdict"] == "BLOCK"
        assert event_dict["confidence"] == 0.85
        assert event_dict["categories"] == ["injection", "role_manipulation"]
        assert event_dict["patterns_matched"] == ["pattern_1", "pattern_2"]
        assert event_dict["provider_used"] == "anthropic"
        assert event_dict["processing_time_ms"] == 150.5
        assert event_dict["metadata"]["source"] == "api"

    def test_from_dict(self):
        """Test creating event from dictionary."""
        now = datetime.utcnow()
        data = {
            "event_id": "evt_003",
            "timestamp": now.isoformat(),
            "event_type": "detection",
            "prompt": "Test prompt",
            "verdict": "ALLOW",
            "confidence": 0.3,
            "categories": ["benign"],
            "patterns_matched": [],
            "provider_used": "gemini",
            "processing_time_ms": 100.0,
            "metadata": {},
            "user_label": None,
            "is_false_positive": False,
            "is_false_negative": False,
            "features": None,
            "embedding": None
        }
        
        event = DetectionEvent.from_dict(data)
        
        assert event.event_id == "evt_003"
        assert event.event_type == EventType.DETECTION
        assert event.verdict == Verdict.ALLOW
        assert event.confidence == 0.3
        assert event.provider_used == "gemini"

    def test_get_hash(self, sample_event):
        """Test hash generation for deduplication."""
        hash_value = sample_event.get_hash()
        
        # Should be consistent for same prompt
        expected_hash = hashlib.sha256(sample_event.prompt.encode()).hexdigest()[:16]
        assert hash_value == expected_hash
        
        # Should be deterministic
        assert sample_event.get_hash() == hash_value

    def test_get_hash_different_prompts(self):
        """Test that different prompts produce different hashes."""
        event1 = DetectionEvent(
            event_id="evt_004",
            timestamp=datetime.utcnow(),
            event_type=EventType.DETECTION,
            prompt="First prompt",
            verdict=Verdict.ALLOW,
            confidence=0.5,
            categories=[],
            patterns_matched=[],
            provider_used="test",
            processing_time_ms=50.0
        )
        
        event2 = DetectionEvent(
            event_id="evt_005",
            timestamp=datetime.utcnow(),
            event_type=EventType.DETECTION,
            prompt="Second prompt",
            verdict=Verdict.ALLOW,
            confidence=0.5,
            categories=[],
            patterns_matched=[],
            provider_used="test",
            processing_time_ms=50.0
        )
        
        assert event1.get_hash() != event2.get_hash()

    def test_with_features_and_embeddings(self):
        """Test event with features and embeddings."""
        event = DetectionEvent(
            event_id="evt_006",
            timestamp=datetime.utcnow(),
            event_type=EventType.PATTERN_MATCH,
            prompt="Test",
            verdict=Verdict.FLAG,
            confidence=0.7,
            categories=["suspicious"],
            patterns_matched=["pat_1"],
            provider_used="test",
            processing_time_ms=75.0,
            features={"length": 100, "entropy": 4.5},
            embedding=[0.1, 0.2, 0.3, 0.4, 0.5]
        )
        
        assert event.features["length"] == 100
        assert event.features["entropy"] == 4.5
        assert len(event.embedding) == 5
        assert event.embedding[0] == 0.1


class TestPatternCollector:
    """Test suite for PatternCollector."""

    @pytest.fixture
    def collector(self):
        """Create a pattern collector."""
        return PatternCollector(
            buffer_size=100,
            persist_to_cache=False,
            min_events_for_clustering=10
        )

    @pytest.fixture
    def collector_with_cache(self):
        """Create a collector with caching enabled."""
        return PatternCollector(
            buffer_size=50,
            persist_to_cache=True,
            min_events_for_clustering=5
        )

    def test_initialization(self, collector):
        """Test collector initialization."""
        assert collector.buffer_size == 100
        assert collector.persist_to_cache is False
        assert collector.min_events_for_clustering == 10
        assert hasattr(collector, 'events')
        assert hasattr(collector, 'event_hashes')
        assert hasattr(collector, 'stats')

    def test_default_initialization(self):
        """Test collector with default parameters."""
        collector = PatternCollector()
        assert collector.buffer_size == 10000
        assert collector.persist_to_cache is True
        assert collector.min_events_for_clustering == 100

    @pytest.mark.asyncio
    async def test_add_event(self, collector):
        """Test adding an event to the collector."""
        event = DetectionEvent(
            event_id="test_001",
            timestamp=datetime.utcnow(),
            event_type=EventType.DETECTION,
            prompt="Test prompt",
            verdict=Verdict.ALLOW,
            confidence=0.5,
            categories=["benign"],
            patterns_matched=[],
            provider_used="test",
            processing_time_ms=50.0
        )
        
        await collector.add_event(event)
        
        assert len(collector.events) == 1
        assert collector.events[0].event_id == "test_001"
        assert event.get_hash() in collector.event_hashes

    @pytest.mark.asyncio
    async def test_add_duplicate_event(self, collector):
        """Test that duplicate events are not added."""
        event1 = DetectionEvent(
            event_id="dup_001",
            timestamp=datetime.utcnow(),
            event_type=EventType.DETECTION,
            prompt="Duplicate prompt",
            verdict=Verdict.BLOCK,
            confidence=0.8,
            categories=["injection"],
            patterns_matched=[],
            provider_used="test",
            processing_time_ms=60.0
        )
        
        event2 = DetectionEvent(
            event_id="dup_002",
            timestamp=datetime.utcnow() + timedelta(seconds=1),
            event_type=EventType.DETECTION,
            prompt="Duplicate prompt",  # Same prompt
            verdict=Verdict.FLAG,
            confidence=0.7,
            categories=["suspicious"],
            patterns_matched=[],
            provider_used="test",
            processing_time_ms=65.0
        )
        
        await collector.add_event(event1)
        await collector.add_event(event2)
        
        # Should only have one event due to duplicate detection
        assert len(collector.events) == 1
        assert collector.events[0].event_id == "dup_001"

    @pytest.mark.asyncio
    async def test_buffer_size_limit(self, collector):
        """Test that buffer size is respected."""
        # Add more events than buffer size
        for i in range(150):
            event = DetectionEvent(
                event_id=f"evt_{i}",
                timestamp=datetime.utcnow(),
                event_type=EventType.DETECTION,
                prompt=f"Prompt {i}",  # Unique prompts
                verdict=Verdict.ALLOW,
                confidence=0.5,
                categories=[],
                patterns_matched=[],
                provider_used="test",
                processing_time_ms=50.0
            )
            await collector.add_event(event)
        
        # Should only keep buffer_size events
        assert len(collector.events) <= collector.buffer_size

    def test_get_events_for_clustering(self, collector):
        """Test getting events for clustering."""
        # Initially no events
        events = collector.get_events_for_clustering()
        assert events == []
        
        # Add some events (not enough for clustering)
        for i in range(5):
            collector.events.append(DetectionEvent(
                event_id=f"cluster_{i}",
                timestamp=datetime.utcnow(),
                event_type=EventType.DETECTION,
                prompt=f"Prompt {i}",
                verdict=Verdict.ALLOW,
                confidence=0.5,
                categories=[],
                patterns_matched=[],
                provider_used="test",
                processing_time_ms=50.0
            ))
        
        # Still not enough for clustering
        events = collector.get_events_for_clustering()
        assert events == []
        
        # Add more events to meet threshold
        for i in range(5, 15):
            collector.events.append(DetectionEvent(
                event_id=f"cluster_{i}",
                timestamp=datetime.utcnow(),
                event_type=EventType.DETECTION,
                prompt=f"Prompt {i}",
                verdict=Verdict.ALLOW,
                confidence=0.5,
                categories=[],
                patterns_matched=[],
                provider_used="test",
                processing_time_ms=50.0
            ))
        
        # Now should return events
        events = collector.get_events_for_clustering()
        assert len(events) == 15

    def test_get_events_for_clustering_with_max_events(self, collector):
        """Test getting limited events for clustering."""
        # Add many events
        for i in range(50):
            collector.events.append(DetectionEvent(
                event_id=f"evt_{i}",
                timestamp=datetime.utcnow(),
                event_type=EventType.DETECTION,
                prompt=f"Prompt {i}",
                verdict=Verdict.ALLOW,
                confidence=0.5,
                categories=[],
                patterns_matched=[],
                provider_used="test",
                processing_time_ms=50.0
            ))
        
        # Get limited events
        events = collector.get_events_for_clustering(max_events=20)
        assert len(events) == 20

    def test_get_feedback_events(self, collector):
        """Test getting feedback events."""
        # Add mixed events
        for i in range(10):
            event_type = EventType.FEEDBACK if i % 3 == 0 else EventType.DETECTION
            collector.events.append(DetectionEvent(
                event_id=f"evt_{i}",
                timestamp=datetime.utcnow(),
                event_type=event_type,
                prompt=f"Prompt {i}",
                verdict=Verdict.ALLOW,
                confidence=0.5,
                categories=[],
                patterns_matched=[],
                provider_used="test",
                processing_time_ms=50.0,
                is_false_positive=(i % 3 == 0)
            ))
        
        feedback_events = collector.get_feedback_events()
        
        # Should only return feedback events
        assert all(e.event_type == EventType.FEEDBACK for e in feedback_events)
        assert len(feedback_events) == 4  # Events 0, 3, 6, 9

    def test_clear_old_events(self, collector):
        """Test clearing old events."""
        now = datetime.utcnow()
        
        # Add events with different timestamps
        for i in range(10):
            timestamp = now - timedelta(hours=i * 5)
            collector.events.append(DetectionEvent(
                event_id=f"evt_{i}",
                timestamp=timestamp,
                event_type=EventType.DETECTION,
                prompt=f"Prompt {i}",
                verdict=Verdict.ALLOW,
                confidence=0.5,
                categories=[],
                patterns_matched=[],
                provider_used="test",
                processing_time_ms=50.0
            ))
        
        # Clear events older than 24 hours
        collector.clear_old_events(max_age_hours=24)
        
        # Should keep only recent events
        remaining_events = [e for e in collector.events if (now - e.timestamp).total_seconds() < 24 * 3600]
        assert len(collector.events) == len(remaining_events)

    def test_get_statistics(self, collector):
        """Test getting collector statistics."""
        # Add various events
        for i in range(20):
            verdict = [Verdict.ALLOW, Verdict.FLAG, Verdict.BLOCK][i % 3]
            event_type = EventType.FEEDBACK if i == 5 else EventType.DETECTION
            
            collector.events.append(DetectionEvent(
                event_id=f"evt_{i}",
                timestamp=datetime.utcnow(),
                event_type=event_type,
                prompt=f"Prompt {i}",
                verdict=verdict,
                confidence=0.5 + (i * 0.02),
                categories=["test"],
                patterns_matched=[],
                provider_used="test",
                processing_time_ms=50.0 + i,
                is_false_positive=(i == 5)
            ))
        
        stats = collector.get_statistics()
        
        assert stats["total_events"] == 20
        assert stats["unique_prompts"] <= 20
        assert "verdicts" in stats
        assert "event_types" in stats
        assert stats["feedback_events"] > 0
        assert stats["false_positives"] > 0


class TestPatternCollectorIntegration:
    """Integration tests for PatternCollector."""

    @pytest.mark.asyncio
    async def test_event_lifecycle(self):
        """Test complete event lifecycle."""
        collector = PatternCollector(buffer_size=50, persist_to_cache=False)
        
        # Add detection event
        detection = DetectionEvent(
            event_id="lifecycle_001",
            timestamp=datetime.utcnow(),
            event_type=EventType.DETECTION,
            prompt="Test injection attempt",
            verdict=Verdict.BLOCK,
            confidence=0.9,
            categories=["injection"],
            patterns_matched=["pat_1"],
            provider_used="anthropic",
            processing_time_ms=120.0
        )
        
        await collector.add_event(detection)
        assert len(collector.events) == 1
        
        # Add feedback event
        feedback = DetectionEvent(
            event_id="lifecycle_002",
            timestamp=datetime.utcnow(),
            event_type=EventType.FEEDBACK,
            prompt="Test injection attempt",  # Same prompt
            verdict=Verdict.BLOCK,
            confidence=0.9,
            categories=["injection"],
            patterns_matched=["pat_1"],
            provider_used="anthropic",
            processing_time_ms=120.0,
            user_label="correct",
            is_false_positive=False
        )
        
        # Should not add duplicate
        await collector.add_event(feedback)
        assert len(collector.events) == 1
        
        # Get statistics
        stats = collector.get_statistics()
        assert stats["total_events"] == 1

    @pytest.mark.asyncio
    async def test_concurrent_additions(self):
        """Test concurrent event additions."""
        collector = PatternCollector(buffer_size=100)
        
        async def add_events(start_id, count):
            for i in range(count):
                event = DetectionEvent(
                    event_id=f"concurrent_{start_id}_{i}",
                    timestamp=datetime.utcnow(),
                    event_type=EventType.DETECTION,
                    prompt=f"Prompt {start_id}_{i}",
                    verdict=Verdict.ALLOW,
                    confidence=0.5,
                    categories=[],
                    patterns_matched=[],
                    provider_used="test",
                    processing_time_ms=50.0
                )
                await collector.add_event(event)
        
        # Add events concurrently
        import asyncio
        await asyncio.gather(
            add_events(0, 10),
            add_events(100, 10),
            add_events(200, 10)
        )
        
        # Should have all unique events
        assert len(collector.events) == 30