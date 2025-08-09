"""Resilience and error recovery tests for PromptSentinel."""

import pytest
import asyncio
import random
import time
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timedelta
import aiohttp

from prompt_sentinel.models.schemas import Message, Role, Verdict


class TestCircuitBreaker:
    """Test circuit breaker pattern implementation."""

    @pytest.fixture
    def circuit_breaker(self):
        """Create circuit breaker instance."""
        from prompt_sentinel.resilience.circuit_breaker import CircuitBreaker
        return CircuitBreaker(
            failure_threshold=5,
            recovery_timeout=60,
            expected_exception=Exception
        )

    @pytest.mark.asyncio
    async def test_circuit_breaker_opens(self, circuit_breaker):
        """Test circuit breaker opening on failures."""
        # Mock failing service
        async def failing_service():
            raise Exception("Service unavailable")
        
        # Should fail and open circuit
        for i in range(5):
            with pytest.raises(Exception):
                await circuit_breaker.call(failing_service)
        
        # Circuit should be open
        assert circuit_breaker.state == "open"
        
        # Further calls should fail immediately
        with pytest.raises(Exception) as exc:
            await circuit_breaker.call(failing_service)
        assert "Circuit breaker is open" in str(exc.value)

    @pytest.mark.asyncio
    async def test_circuit_breaker_half_open(self, circuit_breaker):
        """Test circuit breaker half-open state."""
        # Force circuit open
        circuit_breaker._failure_count = 5
        circuit_breaker._last_failure_time = time.time() - 61  # Past recovery timeout
        circuit_breaker.state = "open"
        
        # Next call should try half-open
        async def working_service():
            return "success"
        
        result = await circuit_breaker.call(working_service)
        assert result == "success"
        assert circuit_breaker.state == "closed"

    @pytest.mark.asyncio
    async def test_circuit_breaker_recovery(self, circuit_breaker):
        """Test circuit breaker recovery."""
        call_count = 0
        
        async def flaky_service():
            nonlocal call_count
            call_count += 1
            if call_count <= 5:
                raise Exception("Temporary failure")
            return "recovered"
        
        # First 5 calls fail
        for i in range(5):
            with pytest.raises(Exception):
                await circuit_breaker.call(flaky_service)
        
        # Circuit is open
        assert circuit_breaker.state == "open"
        
        # Wait for recovery timeout
        await asyncio.sleep(1.5)  # Assuming short timeout for test
        circuit_breaker._recovery_timeout = 1
        
        # Service should recover
        result = await circuit_breaker.call(flaky_service)
        assert result == "recovered"
        assert circuit_breaker.state == "closed"


class TestRetryMechanisms:
    """Test retry mechanisms with backoff."""

    @pytest.mark.asyncio
    async def test_exponential_backoff(self):
        """Test exponential backoff retry."""
        from prompt_sentinel.resilience.retry import RetryWithBackoff
        
        retry = RetryWithBackoff(
            max_retries=3,
            initial_delay=0.1,
            max_delay=2.0,
            exponential_base=2
        )
        
        call_count = 0
        
        async def flaky_operation():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise Exception("Temporary error")
            return "success"
        
        start = time.time()
        result = await retry.execute(flaky_operation)
        duration = time.time() - start
        
        assert result == "success"
        assert call_count == 3
        # Should have delays: 0.1, 0.2, (success)
        assert duration >= 0.3

    @pytest.mark.asyncio
    async def test_retry_with_jitter(self):
        """Test retry with jitter to prevent thundering herd."""
        from prompt_sentinel.resilience.retry import RetryWithBackoff
        
        retry = RetryWithBackoff(
            max_retries=5,
            initial_delay=0.1,
            jitter=True
        )
        
        delays = []
        
        async def track_delays():
            if len(delays) < 4:
                delay = retry._calculate_delay(len(delays))
                delays.append(delay)
                raise Exception("Retry")
            return "done"
        
        await retry.execute(track_delays)
        
        # Delays should have variation due to jitter
        assert len(set(delays)) == len(delays)  # All different

    @pytest.mark.asyncio
    async def test_retry_on_specific_exceptions(self):
        """Test retry only on specific exceptions."""
        from prompt_sentinel.resilience.retry import RetryWithBackoff
        
        retry = RetryWithBackoff(
            max_retries=3,
            retry_on=[TimeoutError, ConnectionError]
        )
        
        async def operation_with_timeout():
            raise TimeoutError("Timeout")
        
        async def operation_with_value_error():
            raise ValueError("Invalid value")
        
        # Should retry on TimeoutError
        with pytest.raises(TimeoutError):
            await retry.execute(operation_with_timeout)
        assert retry._attempt_count == 3
        
        # Should not retry on ValueError
        retry._attempt_count = 0
        with pytest.raises(ValueError):
            await retry.execute(operation_with_value_error)
        assert retry._attempt_count == 1


class TestBulkheadPattern:
    """Test bulkhead isolation pattern."""

    @pytest.mark.asyncio
    async def test_bulkhead_isolation(self):
        """Test bulkhead prevents resource exhaustion."""
        from prompt_sentinel.resilience.bulkhead import Bulkhead
        
        # Create bulkheads for different operations
        detection_bulkhead = Bulkhead(max_concurrent=10)
        analysis_bulkhead = Bulkhead(max_concurrent=5)
        
        # Simulate detection operations
        detection_tasks = []
        for i in range(15):
            async def detect():
                async with detection_bulkhead:
                    await asyncio.sleep(0.1)
                    return f"detection_{i}"
            detection_tasks.append(detect())
        
        # Simulate analysis operations
        analysis_tasks = []
        for i in range(10):
            async def analyze():
                async with analysis_bulkhead:
                    await asyncio.sleep(0.2)
                    return f"analysis_{i}"
            analysis_tasks.append(analyze())
        
        # Run concurrently
        start = time.time()
        results = await asyncio.gather(
            *detection_tasks,
            *analysis_tasks,
            return_exceptions=True
        )
        duration = time.time() - start
        
        # Check bulkhead enforcement
        detection_results = [r for r in results[:15] if not isinstance(r, Exception)]
        analysis_results = [r for r in results[15:] if not isinstance(r, Exception)]
        
        assert len(detection_results) == 15
        assert len(analysis_results) == 10
        
        # Duration should show bulkhead limiting
        # Detection: 15 tasks / 10 concurrent * 0.1s = 0.2s minimum
        # Analysis: 10 tasks / 5 concurrent * 0.2s = 0.4s minimum
        assert duration >= 0.2

    @pytest.mark.asyncio
    async def test_bulkhead_rejection(self):
        """Test bulkhead rejection when full."""
        from prompt_sentinel.resilience.bulkhead import Bulkhead
        
        bulkhead = Bulkhead(
            max_concurrent=5,
            max_queue=2,
            timeout=0.5
        )
        
        # Fill bulkhead and queue
        async def slow_operation():
            async with bulkhead:
                await asyncio.sleep(2)
        
        tasks = [slow_operation() for _ in range(8)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # 5 in bulkhead + 2 in queue = 7 successful, 1 rejected
        exceptions = [r for r in results if isinstance(r, Exception)]
        assert len(exceptions) >= 1
        assert any("Bulkhead queue full" in str(e) for e in exceptions)


class TestTimeoutHandling:
    """Test timeout handling and recovery."""

    @pytest.mark.asyncio
    async def test_operation_timeout(self):
        """Test operation timeout handling."""
        from prompt_sentinel.resilience.timeout import TimeoutManager
        
        timeout_manager = TimeoutManager(default_timeout=1.0)
        
        async def slow_operation():
            await asyncio.sleep(2.0)
            return "completed"
        
        with pytest.raises(asyncio.TimeoutError):
            await timeout_manager.execute(slow_operation)

    @pytest.mark.asyncio
    async def test_adaptive_timeout(self):
        """Test adaptive timeout based on historical data."""
        from prompt_sentinel.resilience.timeout import AdaptiveTimeout
        
        adaptive = AdaptiveTimeout(
            initial_timeout=1.0,
            percentile=95,
            window_size=100
        )
        
        # Record some response times
        for _ in range(50):
            adaptive.record_response_time(0.1)
        for _ in range(40):
            adaptive.record_response_time(0.2)
        for _ in range(10):
            adaptive.record_response_time(0.5)
        
        # Timeout should adapt to P95
        new_timeout = adaptive.get_timeout()
        assert 0.4 < new_timeout < 0.6  # Around P95

    @pytest.mark.asyncio
    async def test_timeout_with_fallback(self):
        """Test timeout with fallback mechanism."""
        from prompt_sentinel.resilience.timeout import TimeoutWithFallback
        
        timeout_handler = TimeoutWithFallback(timeout=0.1)
        
        async def slow_primary():
            await asyncio.sleep(1.0)
            return "primary"
        
        async def fast_fallback():
            return "fallback"
        
        result = await timeout_handler.execute(
            primary=slow_primary,
            fallback=fast_fallback
        )
        
        assert result == "fallback"


class TestHealthMonitoring:
    """Test health monitoring and recovery."""

    @pytest.mark.asyncio
    async def test_health_check_recovery(self):
        """Test automatic recovery based on health checks."""
        from prompt_sentinel.resilience.health_monitor import HealthMonitor
        
        monitor = HealthMonitor(
            check_interval=0.5,
            unhealthy_threshold=3,
            healthy_threshold=2
        )
        
        health_status = {"healthy": False}
        
        async def health_check():
            return health_status["healthy"]
        
        monitor.register_check("service", health_check)
        
        # Start monitoring
        monitoring_task = asyncio.create_task(monitor.start())
        
        # Service starts unhealthy
        await asyncio.sleep(2)
        assert monitor.get_status("service") == "unhealthy"
        
        # Service recovers
        health_status["healthy"] = True
        await asyncio.sleep(1.5)
        assert monitor.get_status("service") == "healthy"
        
        monitoring_task.cancel()

    @pytest.mark.asyncio
    async def test_cascading_health_checks(self):
        """Test cascading health check dependencies."""
        from prompt_sentinel.resilience.health_monitor import HealthMonitor
        
        monitor = HealthMonitor()
        
        # Define health checks with dependencies
        async def database_health():
            return True
        
        async def cache_health():
            # Depends on database
            db_healthy = await database_health()
            return db_healthy
        
        async def api_health():
            # Depends on cache
            cache_healthy = await cache_health()
            return cache_healthy
        
        monitor.register_check("database", database_health)
        monitor.register_check("cache", cache_health, depends_on=["database"])
        monitor.register_check("api", api_health, depends_on=["cache"])
        
        # If database fails, all dependent services should be unhealthy
        with patch.object(monitor, "_checks", {"database": AsyncMock(return_value=False)}):
            statuses = await monitor.check_all()
            assert statuses["database"] == "unhealthy"
            assert statuses["cache"] == "unhealthy"
            assert statuses["api"] == "unhealthy"


class TestGracefulDegradation:
    """Test graceful degradation strategies."""

    @pytest.mark.asyncio
    async def test_feature_degradation(self):
        """Test feature degradation under load."""
        from prompt_sentinel.resilience.degradation import DegradationManager
        
        manager = DegradationManager()
        
        # Define feature priorities
        manager.set_feature_priority({
            "llm_detection": 1,  # Critical
            "pii_detection": 2,  # Important
            "analytics": 3,      # Nice to have
            "experiments": 4     # Optional
        })
        
        # Simulate increasing load
        load_levels = [0.5, 0.7, 0.85, 0.95]
        
        for load in load_levels:
            enabled_features = manager.get_enabled_features(load)
            
            if load < 0.7:
                assert all(f in enabled_features for f in [
                    "llm_detection", "pii_detection", "analytics", "experiments"
                ])
            elif load < 0.85:
                assert "experiments" not in enabled_features
                assert "llm_detection" in enabled_features
            elif load < 0.95:
                assert "analytics" not in enabled_features
                assert "llm_detection" in enabled_features
            else:
                # Only critical features
                assert enabled_features == ["llm_detection"]

    @pytest.mark.asyncio
    async def test_quality_degradation(self):
        """Test quality degradation for performance."""
        from prompt_sentinel.resilience.degradation import QualityDegradation
        
        degradation = QualityDegradation()
        
        # Normal operation
        config = degradation.get_config(load=0.3)
        assert config["sample_rate"] == 1.0
        assert config["model_quality"] == "high"
        assert config["timeout"] == 5.0
        
        # High load - reduce quality
        config = degradation.get_config(load=0.9)
        assert config["sample_rate"] < 1.0  # Sample subset
        assert config["model_quality"] == "low"  # Use faster model
        assert config["timeout"] < 2.0  # Shorter timeout


class TestErrorPropagation:
    """Test error propagation and containment."""

    @pytest.mark.asyncio
    async def test_error_boundary(self):
        """Test error boundary prevents propagation."""
        from prompt_sentinel.resilience.error_boundary import ErrorBoundary
        
        boundary = ErrorBoundary(
            fallback_value={"verdict": "ALLOW", "confidence": 0.5}
        )
        
        async def failing_detection():
            raise Exception("Detection failed")
        
        # Should return fallback instead of propagating error
        result = await boundary.execute(failing_detection)
        assert result["verdict"] == "ALLOW"
        assert result["confidence"] == 0.5
        
        # Should log error
        assert boundary.error_count == 1

    @pytest.mark.asyncio
    async def test_error_aggregation(self):
        """Test error aggregation and reporting."""
        from prompt_sentinel.resilience.error_aggregator import ErrorAggregator
        
        aggregator = ErrorAggregator(
            window_size=60,  # 1 minute
            threshold=10
        )
        
        # Generate various errors
        for i in range(15):
            error_type = ["TimeoutError", "ConnectionError", "ValueError"][i % 3]
            aggregator.record_error(
                error_type=error_type,
                context={"operation": "detect", "user": f"user_{i}"}
            )
        
        # Get error summary
        summary = aggregator.get_summary()
        
        assert summary["total_errors"] == 15
        assert summary["error_rate"] > 0
        assert "TimeoutError" in summary["by_type"]
        assert summary["by_type"]["TimeoutError"] == 5
        
        # Should trigger alert
        alerts = aggregator.get_alerts()
        assert len(alerts) > 0
        assert alerts[0]["severity"] == "high"


class TestResourcePooling:
    """Test resource pooling and management."""

    @pytest.mark.asyncio
    async def test_connection_pool_resilience(self):
        """Test connection pool resilience."""
        from prompt_sentinel.resilience.pool import ResilientPool
        
        pool = ResilientPool(
            min_size=2,
            max_size=10,
            max_idle_time=60,
            health_check_interval=5
        )
        
        await pool.initialize()
        
        # Simulate connection failures
        for i in range(5):
            conn = await pool.acquire()
            if i % 2 == 0:
                # Simulate failure
                conn.mark_unhealthy()
            await pool.release(conn)
        
        # Pool should maintain minimum healthy connections
        healthy_count = pool.get_healthy_count()
        assert healthy_count >= 2
        
        # Pool should create new connections to replace unhealthy
        total_count = pool.get_total_count()
        assert total_count <= 10

    @pytest.mark.asyncio
    async def test_pool_overflow_handling(self):
        """Test pool overflow and queuing."""
        from prompt_sentinel.resilience.pool import ResilientPool
        
        pool = ResilientPool(
            max_size=5,
            queue_size=3,
            acquire_timeout=1.0
        )
        
        await pool.initialize()
        
        # Acquire all connections
        connections = []
        for _ in range(5):
            conn = await pool.acquire()
            connections.append(conn)
        
        # Next acquisitions should queue
        queue_task = asyncio.create_task(pool.acquire())
        await asyncio.sleep(0.1)
        
        # Release one connection
        await pool.release(connections[0])
        
        # Queued task should get connection
        conn = await queue_task
        assert conn is not None


class TestFailoverStrategies:
    """Test failover strategies."""

    @pytest.mark.asyncio
    async def test_primary_backup_failover(self):
        """Test primary-backup failover."""
        from prompt_sentinel.resilience.failover import PrimaryBackupFailover
        
        failover = PrimaryBackupFailover()
        
        primary_healthy = True
        
        async def primary_service():
            if not primary_healthy:
                raise Exception("Primary failed")
            return "primary_result"
        
        async def backup_service():
            return "backup_result"
        
        failover.configure(
            primary=primary_service,
            backup=backup_service
        )
        
        # Primary works
        result = await failover.execute()
        assert result == "primary_result"
        
        # Primary fails, use backup
        primary_healthy = False
        result = await failover.execute()
        assert result == "backup_result"

    @pytest.mark.asyncio
    async def test_active_active_failover(self):
        """Test active-active failover with load balancing."""
        from prompt_sentinel.resilience.failover import ActiveActiveFailover
        
        failover = ActiveActiveFailover(
            strategy="round_robin"
        )
        
        call_counts = {"service1": 0, "service2": 0}
        
        async def service1():
            call_counts["service1"] += 1
            return "service1"
        
        async def service2():
            call_counts["service2"] += 1
            return "service2"
        
        failover.add_service("service1", service1)
        failover.add_service("service2", service2)
        
        # Should distribute calls
        for _ in range(10):
            await failover.execute()
        
        assert call_counts["service1"] == 5
        assert call_counts["service2"] == 5


class TestChaosEngineering:
    """Test chaos engineering scenarios."""

    @pytest.mark.asyncio
    async def test_random_failures(self):
        """Test system behavior with random failures."""
        from prompt_sentinel.resilience.chaos import ChaosMonkey
        
        chaos = ChaosMonkey(
            failure_rate=0.2,
            latency_rate=0.3,
            latency_range=(0.1, 2.0)
        )
        
        successes = 0
        failures = 0
        slow_requests = 0
        
        async def operation():
            return "success"
        
        for _ in range(100):
            wrapped = chaos.wrap(operation)
            start = time.time()
            
            try:
                result = await wrapped()
                if time.time() - start > 0.1:
                    slow_requests += 1
                successes += 1
            except Exception:
                failures += 1
        
        # Should have injected failures and latency
        assert 15 < failures < 25  # ~20%
        assert 25 < slow_requests < 35  # ~30%

    @pytest.mark.asyncio
    async def test_network_partition_simulation(self):
        """Test network partition simulation."""
        from prompt_sentinel.resilience.chaos import NetworkChaos
        
        network_chaos = NetworkChaos()
        
        # Simulate partition between services
        network_chaos.create_partition(
            source="api",
            target="database",
            duration=2.0
        )
        
        async def database_call():
            if network_chaos.is_partitioned("api", "database"):
                raise ConnectionError("Network partition")
            return "data"
        
        # Should fail during partition
        with pytest.raises(ConnectionError):
            await database_call()
        
        # Wait for partition to heal
        await asyncio.sleep(2.5)
        
        # Should work after partition
        result = await database_call()
        assert result == "data"


class TestRecoveryStrategies:
    """Test various recovery strategies."""

    @pytest.mark.asyncio
    async def test_checkpoint_recovery(self):
        """Test recovery from checkpoints."""
        from prompt_sentinel.resilience.recovery import CheckpointRecovery
        
        recovery = CheckpointRecovery()
        
        # Create checkpoints during processing
        data = []
        
        async def process_with_checkpoints():
            for i in range(10):
                data.append(i)
                await recovery.save_checkpoint({"progress": i, "data": data})
                
                # Simulate failure at step 5
                if i == 5:
                    raise Exception("Processing failed")
        
        # First attempt fails
        with pytest.raises(Exception):
            await process_with_checkpoints()
        
        # Recover from checkpoint
        checkpoint = await recovery.load_checkpoint()
        assert checkpoint["progress"] == 5
        
        # Resume from checkpoint
        data = checkpoint["data"]
        for i in range(checkpoint["progress"] + 1, 10):
            data.append(i)
        
        assert len(data) == 10

    @pytest.mark.asyncio
    async def test_compensating_transactions(self):
        """Test compensating transaction pattern."""
        from prompt_sentinel.resilience.recovery import CompensatingTransaction
        
        transaction = CompensatingTransaction()
        
        executed_steps = []
        
        # Define steps with compensations
        @transaction.step(
            name="step1",
            compensation=lambda: executed_steps.remove("step1")
        )
        async def step1():
            executed_steps.append("step1")
            return "result1"
        
        @transaction.step(
            name="step2",
            compensation=lambda: executed_steps.remove("step2")
        )
        async def step2():
            executed_steps.append("step2")
            raise Exception("Step 2 failed")
        
        # Execute transaction
        try:
            await transaction.execute([step1, step2])
        except Exception:
            # Compensations should have run
            pass
        
        # All steps should be rolled back
        assert len(executed_steps) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])