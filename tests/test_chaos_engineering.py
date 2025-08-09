"""Chaos engineering tests for PromptSentinel."""

import pytest
import asyncio
import random
import time
import os
import signal
from datetime import datetime, timedelta
from typing import Dict, List, Any
from unittest.mock import AsyncMock, MagicMock, patch
import aiohttp
import psutil

from prompt_sentinel.models.schemas import Message, Role, Verdict


class TestChaosMonkey:
    """Test chaos monkey fault injection."""

    @pytest.fixture
    def chaos_monkey(self):
        """Create chaos monkey instance."""
        from prompt_sentinel.chaos.monkey import ChaosMonkey
        return ChaosMonkey(
            failure_probability=0.1,
            latency_probability=0.2,
            exception_probability=0.05
        )

    @pytest.mark.asyncio
    async def test_random_failure_injection(self, chaos_monkey):
        """Test random failure injection."""
        success_count = 0
        failure_count = 0
        
        async def operation():
            return "success"
        
        # Run operations with chaos
        for _ in range(1000):
            wrapped = chaos_monkey.wrap(operation)
            try:
                result = await wrapped()
                if result == "success":
                    success_count += 1
            except Exception:
                failure_count += 1
        
        # Should have injected failures
        assert failure_count > 50  # At least 5% failures
        assert failure_count < 200  # Not more than 20%
        assert success_count + failure_count == 1000

    @pytest.mark.asyncio
    async def test_latency_injection(self, chaos_monkey):
        """Test latency injection."""
        latencies = []
        
        async def fast_operation():
            return "fast"
        
        # Measure latencies
        for _ in range(100):
            wrapped = chaos_monkey.wrap(fast_operation)
            start = time.perf_counter()
            
            try:
                await wrapped()
            except:
                pass
            
            latencies.append(time.perf_counter() - start)
        
        # Some operations should be slow
        slow_operations = [l for l in latencies if l > 0.1]
        assert len(slow_operations) > 10  # At least 10% slow
        assert len(slow_operations) < 40  # Not more than 40%

    @pytest.mark.asyncio
    async def test_exception_type_injection(self, chaos_monkey):
        """Test different exception type injection."""
        exceptions_seen = set()
        
        chaos_monkey.set_exception_types([
            TimeoutError,
            ConnectionError,
            ValueError,
            RuntimeError
        ])
        
        async def operation():
            return "result"
        
        # Collect exception types
        for _ in range(500):
            wrapped = chaos_monkey.wrap(operation)
            try:
                await wrapped()
            except Exception as e:
                exceptions_seen.add(type(e).__name__)
        
        # Should see variety of exceptions
        assert len(exceptions_seen) >= 3


class TestNetworkChaos:
    """Test network chaos scenarios."""

    @pytest.fixture
    def network_chaos(self):
        """Create network chaos controller."""
        from prompt_sentinel.chaos.network import NetworkChaos
        return NetworkChaos()

    @pytest.mark.asyncio
    async def test_network_partition(self, network_chaos):
        """Test network partition simulation."""
        # Create partition
        await network_chaos.create_partition(
            source="api_service",
            target="database",
            duration_seconds=2
        )
        
        # Check partition active
        assert network_chaos.is_partitioned("api_service", "database")
        
        # Wait for healing
        await asyncio.sleep(2.5)
        
        # Partition should be healed
        assert not network_chaos.is_partitioned("api_service", "database")

    @pytest.mark.asyncio
    async def test_packet_loss(self, network_chaos):
        """Test packet loss simulation."""
        await network_chaos.add_packet_loss(
            service="api",
            loss_percentage=20
        )
        
        success_count = 0
        failure_count = 0
        
        # Simulate requests
        for _ in range(100):
            if await network_chaos.should_drop_packet("api"):
                failure_count += 1
            else:
                success_count += 1
        
        # Should have ~20% packet loss
        assert 15 < failure_count < 25

    @pytest.mark.asyncio
    async def test_network_delay(self, network_chaos):
        """Test network delay injection."""
        await network_chaos.add_delay(
            service="cache",
            min_delay_ms=50,
            max_delay_ms=200,
            distribution="normal"
        )
        
        delays = []
        
        # Measure delays
        for _ in range(100):
            delay = await network_chaos.get_delay("cache")
            delays.append(delay)
        
        # Check delay distribution
        avg_delay = sum(delays) / len(delays)
        assert 50 <= avg_delay <= 200
        
        # Should have variation
        assert min(delays) >= 50
        assert max(delays) <= 200

    @pytest.mark.asyncio
    async def test_bandwidth_throttling(self, network_chaos):
        """Test bandwidth throttling."""
        await network_chaos.throttle_bandwidth(
            service="upload",
            bandwidth_mbps=1.0
        )
        
        # Simulate data transfer
        data_size_mb = 10
        start = time.time()
        
        await network_chaos.simulate_transfer(
            service="upload",
            size_mb=data_size_mb
        )
        
        duration = time.time() - start
        
        # Should take approximately 10 seconds (10MB at 1MB/s)
        assert 9 < duration < 12


class TestResourceChaos:
    """Test resource exhaustion scenarios."""

    @pytest.fixture
    def resource_chaos(self):
        """Create resource chaos controller."""
        from prompt_sentinel.chaos.resources import ResourceChaos
        return ResourceChaos()

    @pytest.mark.asyncio
    async def test_cpu_stress(self, resource_chaos):
        """Test CPU stress injection."""
        initial_cpu = psutil.cpu_percent(interval=1)
        
        # Start CPU stress
        stress_task = asyncio.create_task(
            resource_chaos.stress_cpu(
                cpu_percent=50,
                duration_seconds=3
            )
        )
        
        await asyncio.sleep(1)
        
        # Check CPU usage increased
        stressed_cpu = psutil.cpu_percent(interval=1)
        assert stressed_cpu > initial_cpu
        
        # Wait for stress to end
        await stress_task
        
        await asyncio.sleep(1)
        
        # CPU should return to normal
        final_cpu = psutil.cpu_percent(interval=1)
        assert final_cpu < stressed_cpu

    @pytest.mark.asyncio
    async def test_memory_stress(self, resource_chaos):
        """Test memory stress injection."""
        process = psutil.Process()
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Allocate memory
        memory_holder = await resource_chaos.allocate_memory(
            size_mb=100
        )
        
        # Check memory increased
        stressed_memory = process.memory_info().rss / 1024 / 1024
        assert stressed_memory > initial_memory + 50  # At least 50MB increase
        
        # Release memory
        await resource_chaos.release_memory(memory_holder)
        
        # Force garbage collection
        import gc
        gc.collect()
        
        # Memory should decrease
        final_memory = process.memory_info().rss / 1024 / 1024
        assert final_memory < stressed_memory

    @pytest.mark.asyncio
    async def test_disk_io_stress(self, resource_chaos):
        """Test disk I/O stress."""
        # Start disk stress
        stress_task = asyncio.create_task(
            resource_chaos.stress_disk_io(
                operations_per_second=100,
                duration_seconds=2
            )
        )
        
        # Monitor disk I/O
        initial_io = psutil.disk_io_counters()
        await asyncio.sleep(2)
        final_io = psutil.disk_io_counters()
        
        # Should see increased I/O
        read_increase = final_io.read_count - initial_io.read_count
        write_increase = final_io.write_count - initial_io.write_count
        
        assert read_increase > 0 or write_increase > 0
        
        await stress_task

    @pytest.mark.asyncio
    async def test_file_descriptor_exhaustion(self, resource_chaos):
        """Test file descriptor exhaustion."""
        # Get current limit
        import resource
        soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
        
        # Try to exhaust file descriptors
        fds = await resource_chaos.exhaust_file_descriptors(
            percentage=0.8  # Use 80% of available
        )
        
        # Should have opened many file descriptors
        assert len(fds) > 0
        assert len(fds) < soft_limit
        
        # Clean up
        await resource_chaos.release_file_descriptors(fds)


class TestApplicationChaos:
    """Test application-level chaos."""

    @pytest.mark.asyncio
    async def test_database_chaos(self):
        """Test database chaos scenarios."""
        from prompt_sentinel.chaos.application import DatabaseChaos
        
        db_chaos = DatabaseChaos()
        
        # Simulate connection pool exhaustion
        await db_chaos.exhaust_connections(percentage=0.9)
        
        # Try to get connection
        try:
            conn = await db_chaos.get_connection(timeout=1)
            assert False, "Should have failed to get connection"
        except TimeoutError:
            pass
        
        # Release connections
        await db_chaos.release_connections()
        
        # Should work now
        conn = await db_chaos.get_connection()
        assert conn is not None

    @pytest.mark.asyncio
    async def test_cache_chaos(self):
        """Test cache chaos scenarios."""
        from prompt_sentinel.chaos.application import CacheChaos
        
        cache_chaos = CacheChaos()
        
        # Add cache corruption
        await cache_chaos.corrupt_cache_entries(
            percentage=0.1,
            corruption_type="bit_flip"
        )
        
        # Test cache reads
        corrupted_count = 0
        for i in range(100):
            value = await cache_chaos.get(f"key_{i}")
            if value and value.get("corrupted"):
                corrupted_count += 1
        
        # Should have some corrupted entries
        assert 5 < corrupted_count < 15

    @pytest.mark.asyncio
    async def test_api_chaos(self):
        """Test API chaos scenarios."""
        from prompt_sentinel.chaos.application import APIChaos
        
        api_chaos = APIChaos()
        
        # Add response mutations
        await api_chaos.add_response_mutation(
            endpoint="/v1/detect",
            mutation_type="status_code",
            probability=0.1,
            mutation_value=500
        )
        
        # Test API calls
        error_count = 0
        for _ in range(100):
            response = await api_chaos.make_request("/v1/detect")
            if response["status"] == 500:
                error_count += 1
        
        # Should have some errors
        assert 5 < error_count < 15


class TestChaosOrchestration:
    """Test chaos orchestration and scenarios."""

    @pytest.fixture
    def chaos_orchestrator(self):
        """Create chaos orchestrator."""
        from prompt_sentinel.chaos.orchestrator import ChaosOrchestrator
        return ChaosOrchestrator()

    @pytest.mark.asyncio
    async def test_chaos_scenario_execution(self, chaos_orchestrator):
        """Test executing chaos scenarios."""
        # Define scenario
        scenario = {
            "name": "Black Friday",
            "description": "Simulate Black Friday traffic",
            "steps": [
                {
                    "type": "traffic_spike",
                    "multiplier": 10,
                    "duration": 60
                },
                {
                    "type": "cpu_stress",
                    "cpu_percent": 80,
                    "duration": 30
                },
                {
                    "type": "network_latency",
                    "delay_ms": 100,
                    "duration": 45
                }
            ]
        }
        
        # Execute scenario
        result = await chaos_orchestrator.execute_scenario(scenario)
        
        assert result["status"] == "completed"
        assert len(result["steps_executed"]) == 3
        assert result["errors"] == []

    @pytest.mark.asyncio
    async def test_gradual_degradation(self, chaos_orchestrator):
        """Test gradual system degradation."""
        # Configure gradual degradation
        await chaos_orchestrator.configure_degradation(
            start_level=0,
            end_level=0.9,
            duration_minutes=5,
            step_size=0.1
        )
        
        # Start degradation
        degradation_task = asyncio.create_task(
            chaos_orchestrator.start_degradation()
        )
        
        # Monitor degradation levels
        levels = []
        for _ in range(10):
            await asyncio.sleep(0.5)
            level = chaos_orchestrator.get_degradation_level()
            levels.append(level)
        
        # Should see increasing degradation
        assert levels[0] < levels[-1]
        assert all(0 <= l <= 1 for l in levels)
        
        # Stop degradation
        chaos_orchestrator.stop_degradation()
        await degradation_task

    @pytest.mark.asyncio
    async def test_chaos_scheduling(self, chaos_orchestrator):
        """Test scheduled chaos events."""
        # Schedule chaos events
        events = [
            {
                "time": datetime.utcnow() + timedelta(seconds=1),
                "type": "network_partition",
                "duration": 2
            },
            {
                "time": datetime.utcnow() + timedelta(seconds=3),
                "type": "cpu_spike",
                "duration": 1
            }
        ]
        
        await chaos_orchestrator.schedule_events(events)
        
        # Wait for events to execute
        await asyncio.sleep(5)
        
        # Check event history
        history = chaos_orchestrator.get_event_history()
        assert len(history) == 2
        assert all(e["status"] == "executed" for e in history)


class TestChaosGameDays:
    """Test chaos game day scenarios."""

    @pytest.mark.asyncio
    @pytest.mark.slow
    async def test_cascading_failure(self):
        """Test cascading failure scenario."""
        from prompt_sentinel.chaos.scenarios import CascadingFailure
        
        scenario = CascadingFailure()
        
        # Start with one service failure
        await scenario.fail_service("auth_service")
        
        # Should trigger cascade
        await asyncio.sleep(2)
        
        failed_services = scenario.get_failed_services()
        
        # Multiple services should be affected
        assert len(failed_services) > 1
        assert "auth_service" in failed_services
        
        # System should attempt recovery
        await scenario.start_recovery()
        await asyncio.sleep(3)
        
        # Some services should recover
        recovered = scenario.get_recovered_services()
        assert len(recovered) > 0

    @pytest.mark.asyncio
    @pytest.mark.slow
    async def test_thundering_herd(self):
        """Test thundering herd scenario."""
        from prompt_sentinel.chaos.scenarios import ThunderingHerd
        
        scenario = ThunderingHerd()
        
        # Simulate cache expiry causing thundering herd
        await scenario.expire_cache()
        
        # Generate concurrent requests
        request_tasks = []
        for _ in range(1000):
            request_tasks.append(
                scenario.make_request()
            )
        
        # Execute requests
        results = await asyncio.gather(
            *request_tasks,
            return_exceptions=True
        )
        
        # Many should fail due to overload
        failures = [r for r in results if isinstance(r, Exception)]
        assert len(failures) > 100
        
        # System should stabilize
        await asyncio.sleep(2)
        
        # Retry should work better
        retry_results = await asyncio.gather(
            *[scenario.make_request() for _ in range(100)],
            return_exceptions=True
        )
        
        retry_failures = [r for r in retry_results if isinstance(r, Exception)]
        assert len(retry_failures) < len(failures) / 10

    @pytest.mark.asyncio
    @pytest.mark.slow
    async def test_split_brain(self):
        """Test split-brain scenario."""
        from prompt_sentinel.chaos.scenarios import SplitBrain
        
        scenario = SplitBrain()
        
        # Create network partition
        await scenario.create_partition()
        
        # Both partitions think they're primary
        partition1_state = await scenario.get_partition_state(1)
        partition2_state = await scenario.get_partition_state(2)
        
        assert partition1_state["is_primary"] is True
        assert partition2_state["is_primary"] is True
        
        # Writes to different partitions
        await scenario.write_to_partition(1, "data1")
        await scenario.write_to_partition(2, "data2")
        
        # Heal partition
        await scenario.heal_partition()
        
        # Check for conflicts
        conflicts = await scenario.detect_conflicts()
        assert len(conflicts) > 0
        
        # Resolve conflicts
        resolution = await scenario.resolve_conflicts()
        assert resolution["status"] == "resolved"


class TestChaosObservability:
    """Test chaos observability and metrics."""

    @pytest.fixture
    def chaos_metrics(self):
        """Create chaos metrics collector."""
        from prompt_sentinel.chaos.metrics import ChaosMetrics
        return ChaosMetrics()

    @pytest.mark.asyncio
    async def test_chaos_impact_measurement(self, chaos_metrics):
        """Test measuring chaos impact."""
        # Start baseline measurement
        await chaos_metrics.start_baseline()
        await asyncio.sleep(1)
        baseline = await chaos_metrics.capture_baseline()
        
        # Inject chaos
        await chaos_metrics.start_chaos("network_latency")
        await asyncio.sleep(1)
        
        # Measure impact
        impact = await chaos_metrics.measure_impact()
        
        assert impact["latency_increase"] > 0
        assert impact["error_rate_increase"] >= 0
        assert impact["throughput_decrease"] >= 0

    @pytest.mark.asyncio
    async def test_chaos_blast_radius(self, chaos_metrics):
        """Test blast radius measurement."""
        # Inject localized chaos
        await chaos_metrics.inject_chaos(
            target="service_a",
            chaos_type="failure"
        )
        
        # Measure blast radius
        blast_radius = await chaos_metrics.measure_blast_radius()
        
        assert "service_a" in blast_radius["directly_affected"]
        assert len(blast_radius["indirectly_affected"]) >= 0
        assert blast_radius["total_services_affected"] >= 1

    @pytest.mark.asyncio
    async def test_recovery_time_measurement(self, chaos_metrics):
        """Test recovery time measurement."""
        # Inject failure
        await chaos_metrics.inject_failure("database")
        failure_time = time.time()
        
        # Wait for recovery
        while not await chaos_metrics.is_recovered("database"):
            await asyncio.sleep(0.5)
            if time.time() - failure_time > 10:
                break
        
        recovery_time = time.time() - failure_time
        
        # Record recovery metrics
        metrics = await chaos_metrics.get_recovery_metrics()
        
        assert metrics["recovery_time"] > 0
        assert metrics["recovery_time"] < 10
        assert metrics["recovery_successful"] is True


class TestChaosValidation:
    """Test chaos experiment validation."""

    @pytest.mark.asyncio
    async def test_hypothesis_validation(self):
        """Test validating chaos hypothesis."""
        from prompt_sentinel.chaos.validation import HypothesisValidator
        
        validator = HypothesisValidator()
        
        # Define hypothesis
        hypothesis = {
            "steady_state": {
                "error_rate": {"max": 0.01},
                "latency_p99": {"max": 100},
                "availability": {"min": 0.999}
            },
            "chaos": {
                "type": "network_partition",
                "duration": 60
            },
            "expected_outcome": {
                "error_rate": {"max": 0.05},
                "latency_p99": {"max": 500},
                "availability": {"min": 0.99}
            }
        }
        
        # Validate hypothesis
        result = await validator.validate(hypothesis)
        
        assert result["hypothesis_valid"] in [True, False]
        assert "steady_state_before" in result
        assert "steady_state_after" in result
        assert "outcome_met" in result

    @pytest.mark.asyncio
    async def test_safety_checks(self):
        """Test chaos safety checks."""
        from prompt_sentinel.chaos.safety import SafetyController
        
        safety = SafetyController()
        
        # Configure safety limits
        safety.set_limits({
            "max_error_rate": 0.1,
            "max_latency_ms": 1000,
            "min_availability": 0.95
        })
        
        # Check if safe to proceed
        safe = await safety.is_safe_to_proceed()
        assert isinstance(safe, bool)
        
        # Simulate unsafe condition
        await safety.report_metric("error_rate", 0.15)
        
        # Should trigger abort
        should_abort = await safety.should_abort()
        assert should_abort is True
        
        # Execute abort
        abort_result = await safety.execute_abort()
        assert abort_result["status"] == "aborted"
        assert abort_result["reason"] == "error_rate exceeded limit"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])