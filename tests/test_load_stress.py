"""Load and stress tests for PromptSentinel."""

import pytest
import asyncio
import aiohttp
import time
import random
from statistics import mean, median, stdev
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any

from prompt_sentinel.models.schemas import Message, Role


class TestLoadTesting:
    """Load testing for sustained traffic."""

    @pytest.mark.asyncio
    @pytest.mark.slow
    async def test_sustained_load(self):
        """Test system under sustained load."""
        # Configuration
        target_rps = 100  # Requests per second
        duration_seconds = 60
        api_url = "http://localhost:8000/v1/detect"
        
        results = {
            "successful": 0,
            "failed": 0,
            "latencies": [],
            "errors": []
        }
        
        async def make_request(session, prompt):
            """Make a single request."""
            start = time.time()
            try:
                async with session.post(
                    api_url,
                    json={"prompt": prompt},
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as response:
                    latency = time.time() - start
                    results["latencies"].append(latency)
                    
                    if response.status == 200:
                        results["successful"] += 1
                    else:
                        results["failed"] += 1
                        results["errors"].append(response.status)
                        
                    return await response.json()
                    
            except Exception as e:
                results["failed"] += 1
                results["errors"].append(str(e))
                return None
        
        # Generate load
        async with aiohttp.ClientSession() as session:
            start_time = time.time()
            request_count = 0
            
            while time.time() - start_time < duration_seconds:
                # Calculate requests to send this iteration
                elapsed = time.time() - start_time
                expected_requests = int(elapsed * target_rps)
                requests_to_send = expected_requests - request_count
                
                # Send batch of requests
                if requests_to_send > 0:
                    prompts = [f"Load test prompt {i}" for i in range(requests_to_send)]
                    tasks = [make_request(session, prompt) for prompt in prompts]
                    await asyncio.gather(*tasks, return_exceptions=True)
                    request_count += requests_to_send
                
                # Small delay to prevent CPU spinning
                await asyncio.sleep(0.1)
        
        # Analyze results
        total_requests = results["successful"] + results["failed"]
        success_rate = results["successful"] / total_requests if total_requests > 0 else 0
        
        # Performance assertions
        assert success_rate > 0.95, f"Success rate {success_rate:.2%} below 95%"
        
        if results["latencies"]:
            p50 = median(results["latencies"])
            p95 = sorted(results["latencies"])[int(len(results["latencies"]) * 0.95)]
            p99 = sorted(results["latencies"])[int(len(results["latencies"]) * 0.99)]
            
            assert p50 < 0.1, f"P50 latency {p50:.3f}s exceeds 100ms"
            assert p95 < 0.5, f"P95 latency {p95:.3f}s exceeds 500ms"
            assert p99 < 1.0, f"P99 latency {p99:.3f}s exceeds 1s"

    @pytest.mark.asyncio
    @pytest.mark.slow
    async def test_ramp_up_load(self):
        """Test system with gradually increasing load."""
        api_url = "http://localhost:8000/v1/detect"
        
        # Ramp configuration
        initial_rps = 10
        final_rps = 200
        ramp_duration = 120  # 2 minutes
        step_duration = 10  # Increase every 10 seconds
        
        metrics = []
        
        async with aiohttp.ClientSession() as session:
            steps = ramp_duration // step_duration
            rps_increment = (final_rps - initial_rps) / steps
            
            for step in range(steps):
                current_rps = initial_rps + (rps_increment * step)
                step_metrics = {
                    "rps": current_rps,
                    "successful": 0,
                    "failed": 0,
                    "latencies": []
                }
                
                # Run at current RPS for step duration
                start_time = time.time()
                while time.time() - start_time < step_duration:
                    # Send requests at current rate
                    tasks = []
                    for _ in range(int(current_rps / 10)):  # Batch size
                        async def request():
                            start = time.time()
                            try:
                                async with session.post(
                                    api_url,
                                    json={"prompt": f"Ramp test {step}"},
                                    timeout=aiohttp.ClientTimeout(total=5)
                                ) as resp:
                                    step_metrics["latencies"].append(time.time() - start)
                                    if resp.status == 200:
                                        step_metrics["successful"] += 1
                                    else:
                                        step_metrics["failed"] += 1
                            except:
                                step_metrics["failed"] += 1
                        
                        tasks.append(request())
                    
                    await asyncio.gather(*tasks, return_exceptions=True)
                    await asyncio.sleep(0.1)
                
                metrics.append(step_metrics)
                
                # Check if system is degrading
                if step_metrics["failed"] > step_metrics["successful"] * 0.1:
                    print(f"System degradation at {current_rps} RPS")
                    break
        
        # Find breaking point
        breaking_point = None
        for metric in metrics:
            success_rate = metric["successful"] / (metric["successful"] + metric["failed"])
            if success_rate < 0.95:
                breaking_point = metric["rps"]
                break
        
        # System should handle at least 100 RPS
        assert breaking_point is None or breaking_point > 100


class TestStressTesting:
    """Stress testing to find breaking points."""

    @pytest.mark.asyncio
    @pytest.mark.slow
    async def test_spike_traffic(self):
        """Test system response to traffic spikes."""
        api_url = "http://localhost:8000/v1/detect"
        
        # Normal load followed by spike
        normal_rps = 50
        spike_rps = 500
        normal_duration = 30
        spike_duration = 10
        
        results = {
            "normal_phase": {"successful": 0, "failed": 0, "latencies": []},
            "spike_phase": {"successful": 0, "failed": 0, "latencies": []},
            "recovery_phase": {"successful": 0, "failed": 0, "latencies": []}
        }
        
        async with aiohttp.ClientSession() as session:
            # Normal phase
            await self._generate_load(
                session, api_url, normal_rps, normal_duration,
                results["normal_phase"]
            )
            
            # Spike phase
            await self._generate_load(
                session, api_url, spike_rps, spike_duration,
                results["spike_phase"]
            )
            
            # Recovery phase
            await self._generate_load(
                session, api_url, normal_rps, normal_duration,
                results["recovery_phase"]
            )
        
        # Analyze behavior
        normal_p95 = self._calculate_percentile(results["normal_phase"]["latencies"], 95)
        spike_p95 = self._calculate_percentile(results["spike_phase"]["latencies"], 95)
        recovery_p95 = self._calculate_percentile(results["recovery_phase"]["latencies"], 95)
        
        # System should handle spike (maybe with degradation)
        spike_success_rate = results["spike_phase"]["successful"] / (
            results["spike_phase"]["successful"] + results["spike_phase"]["failed"]
        )
        assert spike_success_rate > 0.8, "System failed during spike"
        
        # System should recover
        assert recovery_p95 < normal_p95 * 1.5, "System didn't recover after spike"

    @pytest.mark.asyncio
    @pytest.mark.slow
    async def test_memory_stress(self):
        """Test system under memory pressure."""
        api_url = "http://localhost:8000/v1/detect"
        
        # Send increasingly large payloads
        payload_sizes = [1_000, 10_000, 100_000, 1_000_000]  # Characters
        
        results = []
        async with aiohttp.ClientSession() as session:
            for size in payload_sizes:
                # Generate large prompt
                large_prompt = "x" * size
                
                start = time.time()
                try:
                    async with session.post(
                        api_url,
                        json={"prompt": large_prompt},
                        timeout=aiohttp.ClientTimeout(total=30)
                    ) as response:
                        latency = time.time() - start
                        results.append({
                            "size": size,
                            "status": response.status,
                            "latency": latency
                        })
                except Exception as e:
                    results.append({
                        "size": size,
                        "error": str(e)
                    })
        
        # System should handle or gracefully reject large payloads
        for result in results:
            if "error" not in result:
                assert result["status"] in [200, 413], f"Unexpected status for {result['size']} chars"

    @pytest.mark.asyncio
    @pytest.mark.slow
    async def test_connection_pool_exhaustion(self):
        """Test behavior when connection pool is exhausted."""
        api_url = "http://localhost:8000/v1/detect"
        
        # Create many long-running connections
        async def slow_request(session, delay):
            """Make a request that holds connection."""
            try:
                # Simulate slow processing
                prompt = "Analyze this: " + ("complex " * 1000)
                async with session.post(
                    api_url,
                    json={"prompt": prompt},
                    timeout=aiohttp.ClientTimeout(total=delay + 5)
                ) as response:
                    return response.status
            except:
                return None
        
        # Try to exhaust connections
        connector = aiohttp.TCPConnector(limit=100, limit_per_host=100)
        async with aiohttp.ClientSession(connector=connector) as session:
            # Launch many slow requests
            tasks = []
            for i in range(150):  # More than connection limit
                tasks.append(slow_request(session, delay=10))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Count successful requests
        successful = sum(1 for r in results if r == 200)
        
        # Should handle gracefully (queue or reject excess)
        assert successful >= 100, "Too many requests failed"

    async def _generate_load(self, session, url, rps, duration, results):
        """Helper to generate load at specified RPS."""
        start_time = time.time()
        
        while time.time() - start_time < duration:
            tasks = []
            for _ in range(int(rps / 10)):
                async def request():
                    req_start = time.time()
                    try:
                        async with session.post(
                            url,
                            json={"prompt": "Test"},
                            timeout=aiohttp.ClientTimeout(total=5)
                        ) as resp:
                            results["latencies"].append(time.time() - req_start)
                            if resp.status == 200:
                                results["successful"] += 1
                            else:
                                results["failed"] += 1
                    except:
                        results["failed"] += 1
                
                tasks.append(request())
            
            await asyncio.gather(*tasks, return_exceptions=True)
            await asyncio.sleep(0.1)

    def _calculate_percentile(self, values, percentile):
        """Calculate percentile from list of values."""
        if not values:
            return 0
        sorted_values = sorted(values)
        index = int(len(sorted_values) * percentile / 100)
        return sorted_values[min(index, len(sorted_values) - 1)]


class TestConcurrencyLimits:
    """Test system concurrency limits."""

    @pytest.mark.asyncio
    @pytest.mark.slow
    async def test_max_concurrent_requests(self):
        """Test maximum concurrent request handling."""
        api_url = "http://localhost:8000/v1/detect"
        
        # Test different concurrency levels
        concurrency_levels = [10, 50, 100, 200, 500]
        results = []
        
        for level in concurrency_levels:
            async with aiohttp.ClientSession() as session:
                # Launch concurrent requests
                tasks = []
                for i in range(level):
                    async def request(idx):
                        try:
                            async with session.post(
                                api_url,
                                json={"prompt": f"Concurrent {idx}"},
                                timeout=aiohttp.ClientTimeout(total=10)
                            ) as resp:
                                return resp.status
                        except:
                            return None
                    
                    tasks.append(request(i))
                
                start = time.time()
                statuses = await asyncio.gather(*tasks)
                duration = time.time() - start
                
                successful = sum(1 for s in statuses if s == 200)
                results.append({
                    "concurrency": level,
                    "successful": successful,
                    "duration": duration,
                    "success_rate": successful / level
                })
        
        # System should handle reasonable concurrency
        for result in results:
            if result["concurrency"] <= 100:
                assert result["success_rate"] > 0.9, f"Failed at {result['concurrency']} concurrent"

    @pytest.mark.asyncio
    async def test_websocket_connection_limits(self):
        """Test WebSocket connection limits."""
        ws_url = "ws://localhost:8000/ws"
        
        connections = []
        max_connections = 100
        
        try:
            # Open many WebSocket connections
            for i in range(max_connections):
                session = aiohttp.ClientSession()
                ws = await session.ws_connect(ws_url)
                connections.append((session, ws))
                
                # Send initial message
                await ws.send_json({
                    "type": "ping",
                    "client_id": f"stress_test_{i}"
                })
        except Exception as e:
            # Found the limit
            successful_connections = len(connections)
        else:
            successful_connections = max_connections
        finally:
            # Clean up connections
            for session, ws in connections:
                await ws.close()
                await session.close()
        
        # Should support reasonable number of WebSocket connections
        assert successful_connections >= 50, f"Only {successful_connections} WebSocket connections"


class TestResourceUtilization:
    """Test resource utilization under load."""

    @pytest.mark.asyncio
    @pytest.mark.slow
    async def test_cpu_utilization(self):
        """Test CPU utilization under load."""
        import psutil
        
        api_url = "http://localhost:8000/v1/detect"
        
        # Get baseline CPU
        process = psutil.Process()
        baseline_cpu = process.cpu_percent(interval=1)
        
        # Generate CPU-intensive load
        async with aiohttp.ClientSession() as session:
            # Complex prompts that require more processing
            complex_prompts = [
                "Analyze this: " + ("complex pattern " * 100),
                "Detect threats in: " + ("nested [[context]] " * 50),
                "Parse: " + ("A" * 10000)
            ]
            
            tasks = []
            for _ in range(100):
                prompt = random.choice(complex_prompts)
                tasks.append(session.post(api_url, json={"prompt": prompt}))
            
            await asyncio.gather(*tasks, return_exceptions=True)
        
        # Check CPU after load
        peak_cpu = process.cpu_percent(interval=1)
        
        # CPU should not saturate
        assert peak_cpu < 90, f"CPU usage too high: {peak_cpu}%"

    @pytest.mark.asyncio
    @pytest.mark.slow
    async def test_memory_leaks(self):
        """Test for memory leaks under sustained load."""
        import psutil
        import gc
        
        api_url = "http://localhost:8000/v1/detect"
        
        process = psutil.Process()
        
        # Get baseline memory
        gc.collect()
        baseline_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Run sustained load
        async with aiohttp.ClientSession() as session:
            for iteration in range(10):
                # Generate load
                tasks = []
                for _ in range(100):
                    tasks.append(
                        session.post(api_url, json={"prompt": f"Iteration {iteration}"})
                    )
                await asyncio.gather(*tasks, return_exceptions=True)
                
                # Force garbage collection
                gc.collect()
                
                # Check memory growth
                current_memory = process.memory_info().rss / 1024 / 1024
                memory_growth = current_memory - baseline_memory
                
                # Memory growth should stabilize
                if iteration > 5:
                    assert memory_growth < 100, f"Memory leak detected: {memory_growth}MB growth"


class TestFailureScenarios:
    """Test system behavior under failure conditions."""

    @pytest.mark.asyncio
    async def test_backend_service_failure(self):
        """Test behavior when backend services fail."""
        from unittest.mock import patch
        
        api_url = "http://localhost:8000/v1/detect"
        
        # Simulate different backend failures
        with patch("prompt_sentinel.providers.anthropic_provider.AnthropicProvider.classify") as mock:
            mock.side_effect = Exception("Provider unavailable")
            
            async with aiohttp.ClientSession() as session:
                # System should fallback or degrade gracefully
                async with session.post(
                    api_url,
                    json={"prompt": "Test during failure"}
                ) as response:
                    assert response.status in [200, 503]
                    
                    if response.status == 200:
                        # Should use fallback
                        data = await response.json()
                        assert "is_malicious" in data

    @pytest.mark.asyncio
    async def test_database_failure_handling(self):
        """Test handling of database failures."""
        from unittest.mock import patch
        
        api_url = "http://localhost:8000/v1/detect"
        
        with patch("prompt_sentinel.storage.database.save_detection") as mock_save:
            mock_save.side_effect = Exception("Database unavailable")
            
            async with aiohttp.ClientSession() as session:
                # Should still process requests
                async with session.post(
                    api_url,
                    json={"prompt": "Test without database"}
                ) as response:
                    assert response.status == 200
                    data = await response.json()
                    assert "is_malicious" in data

    @pytest.mark.asyncio
    async def test_cascading_failures(self):
        """Test prevention of cascading failures."""
        api_url = "http://localhost:8000/v1/detect"
        
        # Simulate one slow/failing endpoint
        slow_endpoint = "http://localhost:8000/v2/analyze"
        
        async with aiohttp.ClientSession() as session:
            # Send requests to slow endpoint
            slow_tasks = []
            for _ in range(50):
                slow_tasks.append(
                    session.post(
                        slow_endpoint,
                        json={"messages": [{"role": "user", "content": "Slow"}]},
                        timeout=aiohttp.ClientTimeout(total=1)
                    )
                )
            
            # Meanwhile, fast endpoint should still work
            fast_tasks = []
            for _ in range(50):
                fast_tasks.append(
                    session.post(
                        api_url,
                        json={"prompt": "Fast"},
                        timeout=aiohttp.ClientTimeout(total=5)
                    )
                )
            
            # Execute both
            slow_results = await asyncio.gather(*slow_tasks, return_exceptions=True)
            fast_results = await asyncio.gather(*fast_tasks, return_exceptions=True)
            
            # Count successful fast requests
            fast_successful = sum(
                1 for r in fast_results
                if not isinstance(r, Exception) and r.status == 200
            )
            
            # Fast endpoint should not be affected
            assert fast_successful > 40, "Cascading failure detected"


class TestPerformanceBaselines:
    """Test performance against baselines."""

    @pytest.mark.asyncio
    async def test_latency_baseline(self):
        """Test that latency meets baseline requirements."""
        api_url = "http://localhost:8000/v1/detect"
        
        # Baseline requirements (in seconds)
        baselines = {
            "p50": 0.05,
            "p95": 0.2,
            "p99": 0.5
        }
        
        latencies = []
        
        async with aiohttp.ClientSession() as session:
            # Collect latency samples
            for _ in range(1000):
                start = time.time()
                async with session.post(
                    api_url,
                    json={"prompt": "Baseline test"}
                ) as response:
                    if response.status == 200:
                        latencies.append(time.time() - start)
        
        # Calculate percentiles
        latencies.sort()
        p50 = latencies[int(len(latencies) * 0.5)]
        p95 = latencies[int(len(latencies) * 0.95)]
        p99 = latencies[int(len(latencies) * 0.99)]
        
        # Check against baselines
        assert p50 <= baselines["p50"], f"P50 {p50:.3f}s exceeds baseline {baselines['p50']}s"
        assert p95 <= baselines["p95"], f"P95 {p95:.3f}s exceeds baseline {baselines['p95']}s"
        assert p99 <= baselines["p99"], f"P99 {p99:.3f}s exceeds baseline {baselines['p99']}s"

    @pytest.mark.asyncio
    async def test_throughput_baseline(self):
        """Test that throughput meets baseline requirements."""
        api_url = "http://localhost:8000/v1/detect"
        
        # Baseline: Should handle at least 100 RPS
        target_rps = 100
        duration = 10
        
        successful = 0
        start_time = time.time()
        
        async with aiohttp.ClientSession() as session:
            while time.time() - start_time < duration:
                tasks = []
                for _ in range(target_rps // 10):
                    async def request():
                        try:
                            async with session.post(
                                api_url,
                                json={"prompt": "Throughput test"},
                                timeout=aiohttp.ClientTimeout(total=1)
                            ) as resp:
                                if resp.status == 200:
                                    return True
                        except:
                            pass
                        return False
                    
                    tasks.append(request())
                
                results = await asyncio.gather(*tasks)
                successful += sum(results)
                await asyncio.sleep(0.1)
        
        actual_rps = successful / duration
        assert actual_rps >= target_rps * 0.95, f"Throughput {actual_rps:.1f} RPS below target"


if __name__ == "__main__":
    # Run only specific test groups to avoid overwhelming the system
    import sys
    
    if len(sys.argv) > 1:
        test_group = sys.argv[1]
        pytest.main([__file__, f"-k={test_group}", "-v", "--tb=short"])
    else:
        print("Usage: python test_load_stress.py <test_group>")
        print("Groups: load, stress, concurrency, resource, failure, baseline")
        print("Or run: pytest test_load_stress.py -m slow")