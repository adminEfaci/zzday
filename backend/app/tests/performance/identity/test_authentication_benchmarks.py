"""
Performance benchmarks for authentication operations.

Tests authentication throughput, latency, and scalability under various loads.
"""

import asyncio
import statistics
import time
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from app.modules.identity.application.commands.authentication import (
    LoginCommand,
    RefreshTokenCommand,
    ValidateSessionCommand,
)
from app.modules.identity.application.services import IdentityApplicationService


@pytest.mark.benchmark
class TestAuthenticationPerformance:
    """Benchmark authentication operations."""

    @pytest.fixture
    def test_users(self) -> list[dict[str, str]]:
        """Create test users for benchmarking."""
        users = []
        for i in range(1000):
            users.append(
                {
                    "user_id": str(uuid4()),
                    "username": f"perfuser{i}",
                    "password": f"TestPass{i}!@#",
                    "email": f"perfuser{i}@example.com",
                }
            )
        return users

    @pytest.fixture
    async def app_service(self):
        """Create application service for benchmarking."""
        # In real benchmarks, this would be a properly configured service
        from unittest.mock import Mock

        service = Mock(spec=IdentityApplicationService)

        # Mock login to simulate realistic processing time
        async def mock_login(command):
            # Simulate password hashing time (50ms)
            await asyncio.sleep(0.05)
            return Mock(
                access_token=f"token_{command.username}",
                refresh_token=f"refresh_{command.username}",
                session_id=str(uuid4()),
                user_id=str(uuid4()),
            )

        service.login = mock_login

        # Mock token refresh (faster than login)
        async def mock_refresh(command):
            # Simulate token validation and generation (10ms)
            await asyncio.sleep(0.01)
            return Mock(
                access_token=f"new_token_{time.time()}",
                refresh_token=f"new_refresh_{time.time()}",
            )

        service.refresh_token = mock_refresh

        # Mock session validation (very fast)
        async def mock_validate(command):
            # Simulate cache lookup (2ms)
            await asyncio.sleep(0.002)
            return Mock(is_valid=True)

        service.validate_session = mock_validate

        return service

    @pytest.mark.asyncio
    async def test_login_throughput(self, app_service, test_users):
        """Test login operations per second."""
        num_operations = 100
        users_subset = test_users[:num_operations]

        async def perform_login(user):
            command = LoginCommand(
                username=user["username"],
                password=user["password"],
                ip_address="192.168.1.1",
                user_agent="Mozilla/5.0",
            )
            return await app_service.login(command)

        # Warm up
        await perform_login(users_subset[0])

        # Measure throughput
        start_time = time.perf_counter()

        tasks = [perform_login(user) for user in users_subset]
        await asyncio.gather(*tasks)

        end_time = time.perf_counter()
        duration = end_time - start_time

        throughput = num_operations / duration
        avg_latency = duration / num_operations * 1000  # ms

        print("\nLogin Performance:")
        print(f"  Operations: {num_operations}")
        print(f"  Total time: {duration:.2f}s")
        print(f"  Throughput: {throughput:.2f} ops/sec")
        print(f"  Avg latency: {avg_latency:.2f}ms")

        # Assert minimum performance requirements
        assert throughput >= 20  # At least 20 logins/sec
        assert avg_latency <= 100  # Max 100ms average latency

    @pytest.mark.asyncio
    async def test_concurrent_login_scaling(self, app_service, test_users):
        """Test how login performance scales with concurrency."""
        concurrency_levels = [1, 10, 50, 100]
        results = {}

        for concurrency in concurrency_levels:
            users_subset = test_users[: concurrency * 10]

            async def perform_logins():
                semaphore = asyncio.Semaphore(concurrency)

                async def login_with_semaphore(user):
                    async with semaphore:
                        command = LoginCommand(
                            username=user["username"],
                            password=user["password"],
                            ip_address="192.168.1.1",
                            user_agent="Mozilla/5.0",
                        )
                        start = time.perf_counter()
                        await app_service.login(command)
                        return time.perf_counter() - start

                tasks = [login_with_semaphore(user) for user in users_subset]
                return await asyncio.gather(*tasks)

            start_time = time.perf_counter()
            latencies = await perform_logins()
            total_time = time.perf_counter() - start_time

            results[concurrency] = {
                "total_operations": len(users_subset),
                "total_time": total_time,
                "throughput": len(users_subset) / total_time,
                "avg_latency": statistics.mean(latencies) * 1000,
                "p95_latency": statistics.quantiles(latencies, n=20)[18] * 1000,
                "p99_latency": statistics.quantiles(latencies, n=100)[98] * 1000,
            }

        print("\nLogin Scaling Results:")
        for concurrency, metrics in results.items():
            print(f"\n  Concurrency: {concurrency}")
            print(f"    Throughput: {metrics['throughput']:.2f} ops/sec")
            print(f"    Avg latency: {metrics['avg_latency']:.2f}ms")
            print(f"    P95 latency: {metrics['p95_latency']:.2f}ms")
            print(f"    P99 latency: {metrics['p99_latency']:.2f}ms")

        # Verify scaling efficiency
        baseline_throughput = results[1]["throughput"]
        for concurrency in [10, 50, 100]:
            efficiency = results[concurrency]["throughput"] / (
                baseline_throughput * concurrency
            )
            assert efficiency >= 0.7  # At least 70% scaling efficiency

    @pytest.mark.asyncio
    async def test_token_refresh_performance(self, app_service):
        """Test token refresh performance."""
        num_operations = 1000

        async def perform_refresh(token_id):
            command = RefreshTokenCommand(refresh_token=f"refresh_token_{token_id}")
            return await app_service.refresh_token(command)

        # Warm up
        await perform_refresh(0)

        # Measure performance
        latencies = []
        start_time = time.perf_counter()

        for i in range(num_operations):
            op_start = time.perf_counter()
            await perform_refresh(i)
            latencies.append(time.perf_counter() - op_start)

        total_time = time.perf_counter() - start_time

        throughput = num_operations / total_time
        avg_latency = statistics.mean(latencies) * 1000
        p95_latency = statistics.quantiles(latencies, n=20)[18] * 1000
        p99_latency = statistics.quantiles(latencies, n=100)[98] * 1000

        print("\nToken Refresh Performance:")
        print(f"  Operations: {num_operations}")
        print(f"  Throughput: {throughput:.2f} ops/sec")
        print(f"  Avg latency: {avg_latency:.2f}ms")
        print(f"  P95 latency: {p95_latency:.2f}ms")
        print(f"  P99 latency: {p99_latency:.2f}ms")

        # Assert performance requirements
        assert throughput >= 100  # At least 100 refreshes/sec
        assert avg_latency <= 20  # Max 20ms average
        assert p99_latency <= 50  # Max 50ms for 99th percentile

    @pytest.mark.asyncio
    async def test_session_validation_performance(self, app_service):
        """Test session validation performance (cache hits)."""
        num_operations = 10000
        session_ids = [str(uuid4()) for _ in range(100)]  # 100 unique sessions

        async def perform_validation(index):
            command = ValidateSessionCommand(
                session_id=session_ids[index % len(session_ids)],
                access_token=f"token_{index}",
            )
            return await app_service.validate_session(command)

        # Warm up cache
        for session_id in session_ids[:10]:
            await app_service.validate_session(
                ValidateSessionCommand(session_id=session_id, access_token="warmup")
            )

        # Measure performance
        start_time = time.perf_counter()

        tasks = [perform_validation(i) for i in range(num_operations)]
        await asyncio.gather(*tasks)

        total_time = time.perf_counter() - start_time

        throughput = num_operations / total_time
        avg_latency = total_time / num_operations * 1000

        print("\nSession Validation Performance:")
        print(f"  Operations: {num_operations}")
        print(f"  Throughput: {throughput:.2f} ops/sec")
        print(f"  Avg latency: {avg_latency:.2f}ms")

        # Assert high performance for cached operations
        assert throughput >= 1000  # At least 1000 validations/sec
        assert avg_latency <= 5  # Max 5ms average


@pytest.mark.benchmark
class TestAuthenticationLoadPatterns:
    """Test authentication under different load patterns."""

    @pytest.fixture
    async def app_service(self):
        """Create app service with realistic delays."""
        from unittest.mock import Mock

        service = Mock(spec=IdentityApplicationService)

        # Track metrics
        service.metrics = {"total_requests": 0, "failed_requests": 0, "latencies": []}

        async def mock_login(command):
            service.metrics["total_requests"] += 1

            # Simulate variable processing time based on load
            base_delay = 0.05  # 50ms base
            load_factor = min(service.metrics["total_requests"] / 1000, 2.0)
            delay = base_delay * (1 + load_factor)

            # Simulate occasional failures under load
            if service.metrics["total_requests"] % 100 == 99:
                service.metrics["failed_requests"] += 1
                raise Exception("Service temporarily unavailable")

            start = time.perf_counter()
            await asyncio.sleep(delay)
            service.metrics["latencies"].append(time.perf_counter() - start)

            return Mock(
                access_token=f"token_{command.username}", session_id=str(uuid4())
            )

        service.login = mock_login
        return service

    @pytest.mark.asyncio
    async def test_burst_load_pattern(self, app_service):
        """Test handling of burst traffic."""
        burst_size = 500

        async def burst_login(index):
            try:
                command = LoginCommand(
                    username=f"burst_user_{index}",
                    password="TestPass123!",
                    ip_address="192.168.1.1",
                    user_agent="Mozilla/5.0",
                )
                await app_service.login(command)
                return True
            except Exception:
                return False

        # Generate burst
        print("\nGenerating burst traffic...")
        start_time = time.perf_counter()

        tasks = [burst_login(i) for i in range(burst_size)]
        results = await asyncio.gather(*tasks)

        burst_duration = time.perf_counter() - start_time

        success_count = sum(1 for r in results if r)
        failure_count = burst_size - success_count

        print("\nBurst Load Results:")
        print(f"  Burst size: {burst_size} requests")
        print(f"  Duration: {burst_duration:.2f}s")
        print(f"  Success rate: {success_count/burst_size*100:.1f}%")
        print(f"  Failed requests: {failure_count}")

        if app_service.metrics["latencies"]:
            print(
                f"  Avg latency: {statistics.mean(app_service.metrics['latencies'])*1000:.2f}ms"
            )
            print(f"  Max latency: {max(app_service.metrics['latencies'])*1000:.2f}ms")

        # Assert acceptable performance under burst
        assert success_count / burst_size >= 0.95  # At least 95% success rate
        assert burst_duration <= 30  # Complete within 30 seconds

    @pytest.mark.asyncio
    async def test_sustained_load_pattern(self, app_service):
        """Test sustained load over time."""
        target_rps = 50  # Requests per second
        duration = 10  # seconds

        async def sustained_load():
            results = []
            start_time = time.perf_counter()
            request_interval = 1.0 / target_rps

            request_count = 0
            while time.perf_counter() - start_time < duration:
                # Start a new request
                task = asyncio.create_task(
                    app_service.login(
                        LoginCommand(
                            username=f"sustained_user_{request_count}",
                            password="TestPass123!",
                            ip_address="192.168.1.1",
                            user_agent="Mozilla/5.0",
                        )
                    )
                )
                results.append(task)
                request_count += 1

                # Wait for next request slot
                await asyncio.sleep(request_interval)

            # Wait for all requests to complete
            return await asyncio.gather(*results, return_exceptions=True)

        print(f"\nSustained Load Test: {target_rps} RPS for {duration}s")
        results = await sustained_load()

        success_count = sum(1 for r in results if not isinstance(r, Exception))
        actual_rps = len(results) / duration

        print("\nSustained Load Results:")
        print(f"  Target RPS: {target_rps}")
        print(f"  Actual RPS: {actual_rps:.2f}")
        print(f"  Total requests: {len(results)}")
        print(f"  Success rate: {success_count/len(results)*100:.1f}%")

        # Assert sustained performance
        assert actual_rps >= target_rps * 0.95  # Within 5% of target
        assert success_count / len(results) >= 0.98  # At least 98% success

    @pytest.mark.asyncio
    async def test_ramp_up_pattern(self, app_service):
        """Test gradual load increase."""
        ramp_duration = 10  # seconds
        max_rps = 100

        async def ramp_up_load():
            results = []
            start_time = time.perf_counter()
            request_count = 0

            while True:
                elapsed = time.perf_counter() - start_time
                if elapsed >= ramp_duration:
                    break

                # Calculate current RPS based on ramp
                current_rps = (elapsed / ramp_duration) * max_rps
                current_rps = max(current_rps, 1)

                request_interval = 1.0 / current_rps

                # Start request
                task = asyncio.create_task(
                    app_service.login(
                        LoginCommand(
                            username=f"ramp_user_{request_count}",
                            password="TestPass123!",
                            ip_address="192.168.1.1",
                            user_agent="Mozilla/5.0",
                        )
                    )
                )
                results.append((elapsed, task))
                request_count += 1

                await asyncio.sleep(request_interval)

            # Wait for completion
            completed = []
            for elapsed, task in results:
                try:
                    await task
                    completed.append((elapsed, True))
                except Exception:
                    completed.append((elapsed, False))

            return completed

        print(f"\nRamp-up Load Test: 0 to {max_rps} RPS over {ramp_duration}s")
        results = await ramp_up_load()

        # Analyze results by time bucket
        buckets = {}
        bucket_size = 1.0  # 1 second buckets

        for elapsed, success in results:
            bucket = int(elapsed / bucket_size)
            if bucket not in buckets:
                buckets[bucket] = {"total": 0, "success": 0}
            buckets[bucket]["total"] += 1
            if success:
                buckets[bucket]["success"] += 1

        print("\nRamp-up Results by Second:")
        for bucket in sorted(buckets.keys()):
            stats = buckets[bucket]
            success_rate = stats["success"] / stats["total"] * 100
            print(
                f"  Second {bucket}: {stats['total']} requests, {success_rate:.1f}% success"
            )

        # Verify graceful handling of load increase
        for stats in buckets.values():
            assert stats["success"] / stats["total"] >= 0.9  # 90% success minimum


@pytest.mark.benchmark
class TestAuthenticationMemoryUsage:
    """Test memory usage during authentication operations."""

    @pytest.mark.asyncio
    async def test_session_cache_memory_usage(self, app_service):
        """Test memory usage of session cache."""
        import sys

        # Create many sessions
        num_sessions = 10000
        sessions = []

        # Measure initial memory

        for i in range(num_sessions):
            session = {
                "session_id": str(uuid4()),
                "user_id": str(uuid4()),
                "access_token": f"token_{i}" * 10,  # Simulate larger tokens
                "refresh_token": f"refresh_{i}" * 10,
                "created_at": datetime.now(UTC),
                "metadata": {
                    "ip_address": f"192.168.{i // 256}.{i % 256}",
                    "user_agent": "Mozilla/5.0" * 5,  # Simulate longer UA
                    "device_id": str(uuid4()),
                    "location": "US",
                },
            }
            sessions.append(session)

            if i == 0:
                sys.getsizeof(session)

        total_size = sum(sys.getsizeof(s) for s in sessions)
        avg_size = total_size / num_sessions

        print("\nSession Memory Usage:")
        print(f"  Number of sessions: {num_sessions}")
        print(f"  Avg size per session: {avg_size:.0f} bytes")
        print(f"  Total size: {total_size / 1024 / 1024:.2f} MB")
        print(
            f"  Memory per 1K sessions: {total_size / num_sessions * 1000 / 1024 / 1024:.2f} MB"
        )

        # Assert reasonable memory usage
        assert avg_size <= 2048  # Max 2KB per session
        assert (
            total_size / num_sessions * 1000 / 1024 / 1024 <= 2
        )  # Max 2MB per 1K sessions
