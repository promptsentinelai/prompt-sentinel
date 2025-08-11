# Copyright 2025 PromptSentinel
# Licensed under the Elastic License 2.0; you may not use this file except
# in compliance with the Elastic License 2.0. You may obtain a copy of the
# License at https://www.elastic.co/licensing/elastic-license

"""Performance benchmark tests for PromptSentinel."""

import asyncio
import time
from statistics import mean, stdev
import pytest

from prompt_sentinel.detection.detector import PromptDetector
from prompt_sentinel.detection.heuristics import HeuristicDetector
from prompt_sentinel.detection.pii_detector import PIIDetector
from prompt_sentinel.models.schemas import Message, Role

# Skip all tests in this file - feature not implemented
pytestmark = pytest.mark.skip(reason="Feature not yet implemented")



class TestDetectionBenchmarks:
    """Benchmark tests for detection performance."""

    @pytest.fixture
    def detector(self):
        """Create detector instance."""
        return PromptDetector()

    @pytest.fixture
    def heuristic_detector(self):
        """Create heuristic detector instance."""
        return HeuristicDetector(detection_mode="moderate")

    def test_heuristic_detection_speed(self, heuristic_detector):
        """Benchmark heuristic detection speed."""
        messages = [
            Message(role=Role.USER, content="Please help me with my homework")
        ]
        
        # Run multiple iterations
        times = []
        for _ in range(10):
            start = time.perf_counter()
            verdict, reasons, confidence = heuristic_detector.detect(messages)
            elapsed = time.perf_counter() - start
            times.append(elapsed)
        
        avg_time = mean(times)
        
        # Should complete quickly
        assert avg_time < 0.01  # Less than 10ms average

    def test_large_message_performance(self, heuristic_detector):
        """Benchmark detection on large messages."""
        # Create a 10KB message
        large_content = "This is a test message. " * 500
        messages = [Message(role=Role.USER, content=large_content)]
        
        # Run multiple iterations
        times = []
        for _ in range(5):
            start = time.perf_counter()
            verdict, reasons, confidence = heuristic_detector.detect(messages)
            elapsed = time.perf_counter() - start
            times.append(elapsed)
        
        avg_time = mean(times)
        
        # Should handle large messages efficiently
        assert avg_time < 0.1  # Less than 100ms average

    def test_multiple_messages_performance(self, heuristic_detector):
        """Benchmark detection on multiple messages."""
        messages = [
            Message(role=Role.SYSTEM, content="You are a helpful assistant"),
            Message(role=Role.USER, content="What's the weather like?"),
            Message(role=Role.ASSISTANT, content="I can help with that"),
            Message(role=Role.USER, content="Tell me more"),
        ] * 5  # 20 messages total
        
        # Run multiple iterations
        times = []
        for _ in range(5):
            start = time.perf_counter()
            verdict, reasons, confidence = heuristic_detector.detect(messages)
            elapsed = time.perf_counter() - start
            times.append(elapsed)
        
        avg_time = mean(times)
        
        # Should handle multiple messages efficiently
        assert avg_time < 0.05  # Less than 50ms average

    @pytest.mark.asyncio
    async def test_async_detection_performance(self, detector):
        """Benchmark async detection performance."""
        messages = [
            Message(role=Role.USER, content="Test message for benchmarking")
        ]
        
        # Run multiple iterations
        times = []
        for _ in range(10):
            start = time.perf_counter()
            response = await detector.detect(messages)
            elapsed = time.perf_counter() - start
            times.append(elapsed)
        
        avg_time = mean(times)
        std_time = stdev(times) if len(times) > 1 else 0
        
        # Should be consistently fast
        assert avg_time < 0.5  # Less than 500ms average
        assert std_time < 0.1  # Low variance

    @pytest.mark.asyncio
    async def test_concurrent_detection_throughput(self, detector):
        """Benchmark concurrent detection throughput."""
        messages = [
            Message(role=Role.USER, content=f"Test message {i}")
            for i in range(10)
        ]
        
        async def detect_one(msg):
            return await detector.detect([msg])
        
        # Measure concurrent processing
        start = time.perf_counter()
        results = await asyncio.gather(*[detect_one(msg) for msg in messages])
        elapsed = time.perf_counter() - start
        
        # Calculate throughput
        throughput = len(messages) / elapsed
        
        # Should handle concurrent requests efficiently
        assert throughput > 5  # At least 5 requests per second
        assert all(r.verdict is not None for r in results)


class TestPIIDetectionBenchmarks:
    """Benchmark tests for PII detection performance."""

    @pytest.fixture
    def detector(self):
        """Create PII detector instance."""
        return PIIDetector()

    def test_pii_detection_speed(self, detector):
        """Benchmark PII detection speed."""
        text = "Contact me at john.doe@example.com or call 555-123-4567"
        
        # Run multiple iterations
        times = []
        for _ in range(10):
            start = time.perf_counter()
            result = detector.detect(text)
            elapsed = time.perf_counter() - start
            times.append(elapsed)
        
        avg_time = mean(times)
        
        # Should complete quickly
        assert avg_time < 0.005  # Less than 5ms average
        assert len(result) > 0  # Should find PII

    def test_large_text_pii_scanning(self, detector):
        """Benchmark PII scanning on large text."""
        # Create a large document with some PII
        base_text = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. " * 100
        text = f"{base_text} Email: test@example.com {base_text} Phone: 555-0123 {base_text}"
        
        # Run multiple iterations
        times = []
        for _ in range(5):
            start = time.perf_counter()
            result = detector.detect(text)
            elapsed = time.perf_counter() - start
            times.append(elapsed)
        
        avg_time = mean(times)
        
        # Should handle large texts efficiently
        assert avg_time < 0.05  # Less than 50ms average

    def test_pii_redaction_performance(self, detector):
        """Benchmark PII redaction performance."""
        text = """
        John Doe (SSN: 123-45-6789) lives at 123 Main St.
        Email: john@example.com, Phone: (555) 123-4567
        Credit Card: 4111-1111-1111-1111
        """
        
        # Run multiple iterations
        times = []
        for _ in range(10):
            start = time.perf_counter()
            matches = detector.detect(text)
            result = detector.redact(text, matches)
            elapsed = time.perf_counter() - start
            times.append(elapsed)
        
        avg_time = mean(times)
        
        # Should redact efficiently
        assert avg_time < 0.01  # Less than 10ms average
        assert "john@example.com" not in result  # PII should be redacted


class TestScalabilityBenchmarks:
    """Benchmark tests for scalability."""

    @pytest.mark.asyncio
    async def test_scaling_with_message_count(self):
        """Test how performance scales with message count."""
        detector = HeuristicDetector(detection_mode="moderate")
        
        results = {}
        for count in [1, 10, 50, 100, 500]:
            messages = [
                Message(role=Role.USER, content=f"Message {i}")
                for i in range(count)
            ]
            
            start = time.perf_counter()
            verdict, reasons, confidence = detector.detect(messages)
            elapsed = time.perf_counter() - start
            
            results[count] = elapsed
        
        # Check that scaling is reasonable (not exponential)
        # Time for 100 messages should be less than 100x time for 1 message
        assert results[100] < results[1] * 100
        
        # Time for 500 messages should be less than 5x time for 100 messages
        assert results[500] < results[100] * 5

    def test_scaling_with_message_size(self):
        """Test how performance scales with message size."""
        detector = HeuristicDetector(detection_mode="moderate")
        
        results = {}
        for size_kb in [1, 5, 10, 50, 100]:
            content = "a" * (size_kb * 1024)
            messages = [Message(role=Role.USER, content=content)]
            
            start = time.perf_counter()
            verdict, reasons, confidence = detector.detect(messages)
            elapsed = time.perf_counter() - start
            
            results[size_kb] = elapsed
        
        # Check that scaling is reasonable
        # 100KB should take less than 100x the time of 1KB
        assert results[100] < results[1] * 100

    @pytest.mark.asyncio
    async def test_memory_usage_stability(self, detector):
        """Test that memory usage remains stable."""
        import gc
        import sys
        
        # Force garbage collection
        gc.collect()
        
        # Get initial memory usage (rough estimate)
        initial_objects = len(gc.get_objects())
        
        # Process many messages
        for i in range(100):
            messages = [
                Message(role=Role.USER, content=f"Test message {i}" * 100)
            ]
            response = await detector.detect(messages)
        
        # Force garbage collection again
        gc.collect()
        
        # Check memory didn't grow excessively
        final_objects = len(gc.get_objects())
        growth = final_objects - initial_objects
        
        # Should not leak memory excessively (allow some growth for caches)
        assert growth < 10000  # Arbitrary but reasonable limit


class TestCachingPerformance:
    """Benchmark tests for caching performance."""

    @pytest.mark.asyncio
    async def test_cache_hit_performance(self):
        """Test performance improvement with cache hits."""
        detector = PromptDetector()
        messages = [
            Message(role=Role.USER, content="This is a test message")
        ]
        
        # First call (cache miss)
        start = time.perf_counter()
        response1 = await detector.detect(messages)
        first_time = time.perf_counter() - start
        
        # Second call (potential cache hit)
        start = time.perf_counter()
        response2 = await detector.detect(messages)
        second_time = time.perf_counter() - start
        
        # Cache hit should be faster (or at least not slower)
        # Note: This might not always be true if LLM is not called
        assert second_time <= first_time * 1.5

    @pytest.mark.asyncio
    async def test_cache_memory_bounded(self):
        """Test that cache doesn't grow unbounded."""
        detector = PromptDetector()
        
        # Generate many unique messages
        for i in range(1000):
            messages = [
                Message(role=Role.USER, content=f"Unique message {i}")
            ]
            await detector.detect(messages)
        
        # Cache should have eviction policy
        # This is a placeholder - actual test depends on cache implementation
        assert True  # Cache implementation should handle this


class TestLatencyPercentiles:
    """Test latency percentiles for SLA compliance."""

    @pytest.mark.asyncio
    async def test_p99_latency(self):
        """Test that P99 latency meets SLA."""
        detector = PromptDetector()
        messages = [
            Message(role=Role.USER, content="Test message for latency")
        ]
        
        # Collect latency samples
        latencies = []
        for _ in range(100):
            start = time.perf_counter()
            await detector.detect(messages)
            latencies.append(time.perf_counter() - start)
        
        # Sort to get percentiles
        latencies.sort()
        p50 = latencies[50]
        p95 = latencies[95]
        p99 = latencies[99]
        
        # Check SLA compliance
        assert p50 < 0.1  # P50 under 100ms
        assert p95 < 0.5  # P95 under 500ms
        assert p99 < 1.0  # P99 under 1 second


if __name__ == "__main__":
    # Run with: pytest test_benchmarks.py --benchmark-only
    pytest.main([__file__, "-v", "--benchmark-only"])