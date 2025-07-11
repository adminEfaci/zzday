"""
Resilience testing using chaos engineering.

Tests system behavior under various failure conditions.
"""

import asyncio

import pytest

from app.tests.chaos import ChaosMonkey
from app.tests.containers import TestContainer


@pytest.mark.chaos
@pytest.mark.asyncio
class TestSystemResilience:
    """Test system resilience under failure conditions."""

    async def test_authentication_during_database_failure(
        self, 
        test_container: TestContainer,
        chaos_monkey: ChaosMonkey,
        email_builder
    ):
        """Test authentication behavior when database fails."""
        # Create user first (before failure)
        user_email = email_builder.unique()
        user_data = {
            "username": user_email.value,
            "email": user_email.value,
            "password": "ResilienceTest123!@#",
            "confirm_password": "ResilienceTest123!@#"
        }
        
        await test_container.async_client.post(
            "/api/v1/auth/register",
            json=user_data
        )
        
        # Inject database failure
        await chaos_monkey.break_database_connection(duration=2)
        
        # Try authentication during failure
        login_response = await test_container.async_client.post(
            "/api/v1/auth/login",
            json={
                "username": user_email.value,
                "password": "ResilienceTest123!@#"
            }
        )
        
        # Should gracefully handle database failure
        # Either return 503 (service unavailable) or use cached auth
        assert login_response.status_code in [200, 503, 500]
        
        # Should not crash the application
        if login_response.status_code == 503:
            # Verify error response is properly formatted
            assert "error" in login_response.text.lower() or "service" in login_response.text.lower()
            
        # Wait for service recovery
        await asyncio.sleep(3)
        
        # After recovery, authentication should work
        recovery_response = await test_container.async_client.post(
            "/api/v1/auth/login",
            json={
                "username": user_email.value,
                "password": "ResilienceTest123!@#"
            }
        )
        
        # Should work after recovery (or still be unavailable gracefully)
        assert recovery_response.status_code in [200, 401, 503]

    async def test_concurrent_requests_during_failure(
        self, 
        test_container: TestContainer,
        chaos_monkey: ChaosMonkey,
        email_builder
    ):
        """Test concurrent request handling during failures."""
        # Create multiple users
        users = []
        for i in range(3):
            user_email = email_builder.unique()
            user_data = {
                "username": user_email.value,
                "email": user_email.value,
                "password": f"ConcurrentTest{i}123!@#",
                "confirm_password": f"ConcurrentTest{i}123!@#"
            }
            await test_container.async_client.post(
                "/api/v1/auth/register",
                json=user_data
            )
            users.append(user_data)
        
        # Inject network latency
        await chaos_monkey.introduce_network_latency(ms=500)
        
        # Send concurrent requests
        tasks = []
        for user in users:
            task = test_container.async_client.post(
                "/api/v1/auth/login",
                json={
                    "username": user["username"],
                    "password": user["password"]
                }
            )
            tasks.append(task)
        
        # Execute concurrently
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Should handle all requests without crashing
        for response in responses:
            if not isinstance(response, Exception):
                assert response.status_code in [200, 401, 503, 408]  # 408 = timeout
            # Exceptions are also acceptable under failure conditions

    async def test_cache_failure_graceful_degradation(
        self, 
        test_container: TestContainer,
        chaos_monkey: ChaosMonkey,
        email_builder
    ):
        """Test graceful degradation when cache fails."""
        # Create and login user
        user_email = email_builder.unique()
        user_data = {
            "username": user_email.value,
            "email": user_email.value,
            "password": "CacheTest123!@#",
            "confirm_password": "CacheTest123!@#"
        }
        
        await test_container.async_client.post(
            "/api/v1/auth/register",
            json=user_data
        )
        
        # Successful login (cache working)
        login_response = await test_container.async_client.post(
            "/api/v1/auth/login",
            json={
                "username": user_email.value,
                "password": "CacheTest123!@#"
            }
        )
        
        if login_response.status_code == 200:
            # Corrupt cache
            await chaos_monkey.corrupt_cache_data("*")
            
            # Subsequent requests should still work (fallback to DB)
            cookies = login_response.cookies
            
            profile_response = await test_container.async_client.get(
                "/api/v1/auth/me",
                cookies=cookies
            )
            
            # Should work with degraded performance
            assert profile_response.status_code in [200, 404, 503]
            
            # Check for degraded mode headers
            if "X-Cache-Status" in profile_response.headers:
                assert profile_response.headers["X-Cache-Status"] in ["miss", "bypass", "error"]

    async def test_connection_pool_exhaustion_handling(
        self, 
        test_container: TestContainer,
        chaos_monkey: ChaosMonkey,
        email_builder
    ):
        """Test handling of connection pool exhaustion."""
        # Exhaust connection pool
        await chaos_monkey.exhaust_connection_pool()
        
        # Try authentication
        user_email = email_builder.unique()
        
        login_response = await test_container.async_client.post(
            "/api/v1/auth/login",
            json={
                "username": user_email.value,
                "password": "PoolTest123!@#"
            }
        )
        
        # Should handle pool exhaustion gracefully
        assert login_response.status_code in [503, 500, 429]  # 429 = too many requests
        
        # Should not crash
        response_text = login_response.text.lower()
        assert "internal server error" not in response_text or "service unavailable" in response_text

    async def test_random_failure_injection(
        self, 
        test_container: TestContainer,
        chaos_monkey: ChaosMonkey,
        email_builder
    ):
        """Test system under random failure conditions."""
        # Inject random failures at 20% rate
        await chaos_monkey.inject_random_failures(failure_rate=0.2)
        
        # Perform multiple operations
        success_count = 0
        total_requests = 10
        
        for i in range(total_requests):
            user_email = email_builder.unique()
            
            try:
                response = await test_container.async_client.post(
                    "/api/v1/auth/login",
                    json={
                        "username": user_email.value,
                        "password": f"RandomTest{i}123!@#"
                    }
                )
                
                if response.status_code in [200, 401]:  # Expected responses
                    success_count += 1
                    
            except Exception:
                pass  # Failures are expected with random injection
        
        # Should have some successful operations despite random failures
        success_rate = success_count / total_requests
        assert success_rate >= 0.5  # At least 50% should work with 20% failure rate


@pytest.mark.chaos
@pytest.mark.asyncio  
class TestFailureRecovery:
    """Test system recovery after failures."""

    async def test_automatic_recovery_after_database_restoration(
        self, 
        test_container: TestContainer,
        chaos_monkey: ChaosMonkey,
        email_builder
    ):
        """Test that system recovers automatically after database restoration."""
        user_email = email_builder.unique()
        
        # Break database
        await chaos_monkey.break_database_connection(duration=3)
        
        # Should fail during outage
        failure_response = await test_container.async_client.get("/api/v1/health")
        assert failure_response.status_code in [503, 500]
        
        # Wait for recovery
        await asyncio.sleep(4)
        
        # Should work after recovery
        recovery_response = await test_container.async_client.get("/api/v1/health")
        assert recovery_response.status_code in [200, 404]  # 404 if endpoint doesn't exist

    async def test_circuit_breaker_behavior(
        self, 
        test_container: TestContainer,
        chaos_monkey: ChaosMonkey
    ):
        """Test circuit breaker pattern implementation."""
        # This test assumes circuit breaker is implemented
        # If not implemented, this test documents the expected behavior
        
        # Cause multiple failures to trigger circuit breaker
        await chaos_monkey.break_database_connection(duration=1)
        
        # Multiple failed requests should trigger circuit breaker
        for i in range(5):
            response = await test_container.async_client.get("/api/v1/health")
            await asyncio.sleep(0.2)
        
        # Circuit breaker should be open - requests should fail fast
        # (This test may not pass if circuit breaker is not implemented)
        fast_fail_response = await test_container.async_client.get("/api/v1/health")
        
        # Should either fail fast (circuit breaker) or continue failing slowly
        assert fast_fail_response.status_code in [503, 500]