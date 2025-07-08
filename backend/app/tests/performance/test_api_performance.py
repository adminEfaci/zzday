"""
API Performance Tests

Tests performance of all API endpoints against established baselines.
"""

import pytest
import asyncio
from httpx import AsyncClient
from fastapi.testclient import TestClient

from app.tests.performance.performance_baselines import (
    PerformanceMonitor,
    PerformanceRegistry,
    LoadTestScenario,
    get_load_test_scenario,
)
from app.tests.builders.user_builder import UserBuilder
from app.tests.builders.session_builder import SessionBuilder


@pytest.mark.performance
@pytest.mark.asyncio
class TestAuthenticationPerformance:
    """Test authentication endpoint performance."""
    
    async def test_login_performance_baseline(self, async_client: AsyncClient):
        """Test login endpoint meets performance baseline."""
        monitor = PerformanceMonitor()
        
        # Create test user
        user_builder = UserBuilder()
        user = user_builder.build()
        
        # Test login performance
        with monitor.measure_performance("auth_login"):
            response = await async_client.post(
                "/auth/login",
                json={
                    "email": user.email.value,
                    "password": "test_password123"
                }
            )
        
        assert response.status_code == 200
        
        # Assert performance baseline
        metrics = monitor.get_metrics("auth_login")[0]
        monitor.assert_performance_baseline("auth_login", metrics)
    
    async def test_register_performance_baseline(self, async_client: AsyncClient):
        """Test registration endpoint meets performance baseline."""
        monitor = PerformanceMonitor()
        
        # Test registration performance
        with monitor.measure_performance("auth_register"):
            response = await async_client.post(
                "/auth/register",
                json={
                    "email": "newuser@test.local",
                    "password": "test_password123",
                    "confirm_password": "test_password123"
                }
            )
        
        assert response.status_code == 201
        
        # Assert performance baseline
        metrics = monitor.get_metrics("auth_register")[0]
        monitor.assert_performance_baseline("auth_register", metrics)
    
    async def test_token_refresh_performance_baseline(self, async_client: AsyncClient, auth_headers: dict):
        """Test token refresh endpoint meets performance baseline."""
        monitor = PerformanceMonitor()
        
        # Test token refresh performance
        with monitor.measure_performance("auth_refresh_token"):
            response = await async_client.post(
                "/auth/refresh",
                headers=auth_headers
            )
        
        assert response.status_code == 200
        
        # Assert performance baseline
        metrics = monitor.get_metrics("auth_refresh_token")[0]
        monitor.assert_performance_baseline("auth_refresh_token", metrics)
    
    async def test_login_load_test(self, async_client: AsyncClient):
        """Test login endpoint under load."""
        scenario = get_load_test_scenario("light_load")
        
        # Create test user
        user_builder = UserBuilder()
        user = user_builder.build()
        
        async def login_operation():
            response = await async_client.post(
                "/auth/login",
                json={
                    "email": user.email.value,
                    "password": "test_password123"
                }
            )
            return response.status_code == 200
        
        # Run load test
        await scenario.run_load_test(login_operation)
        
        # Analyze results
        summary = scenario.get_load_test_summary()
        
        # Assert load test meets baseline
        baseline = PerformanceRegistry.get_baseline("auth_login")
        assert summary["requests_per_second"] >= baseline.target_rps * 0.8  # 80% of target
        assert summary["response_time"]["p95"] <= baseline.p95_response_time
        assert summary["response_time"]["p99"] <= baseline.p99_response_time


@pytest.mark.performance
@pytest.mark.asyncio
class TestUserPerformance:
    """Test user endpoint performance."""
    
    async def test_get_profile_performance_baseline(self, async_client: AsyncClient, auth_headers: dict):
        """Test get profile endpoint meets performance baseline."""
        monitor = PerformanceMonitor()
        
        # Test get profile performance
        with monitor.measure_performance("user_get_profile"):
            response = await async_client.get(
                "/users/profile",
                headers=auth_headers
            )
        
        assert response.status_code == 200
        
        # Assert performance baseline
        metrics = monitor.get_metrics("user_get_profile")[0]
        monitor.assert_performance_baseline("user_get_profile", metrics)
    
    async def test_update_profile_performance_baseline(self, async_client: AsyncClient, auth_headers: dict):
        """Test update profile endpoint meets performance baseline."""
        monitor = PerformanceMonitor()
        
        # Test update profile performance
        with monitor.measure_performance("user_update_profile"):
            response = await async_client.patch(
                "/users/profile",
                headers=auth_headers,
                json={
                    "name": "Updated Name",
                    "bio": "Updated bio"
                }
            )
        
        assert response.status_code == 200
        
        # Assert performance baseline
        metrics = monitor.get_metrics("user_update_profile")[0]
        monitor.assert_performance_baseline("user_update_profile", metrics)
    
    async def test_get_profile_load_test(self, async_client: AsyncClient, auth_headers: dict):
        """Test get profile endpoint under load."""
        scenario = get_load_test_scenario("medium_load")
        
        async def get_profile_operation():
            response = await async_client.get(
                "/users/profile",
                headers=auth_headers
            )
            return response.status_code == 200
        
        # Run load test
        await scenario.run_load_test(get_profile_operation)
        
        # Analyze results
        summary = scenario.get_load_test_summary()
        
        # Assert load test meets baseline
        baseline = PerformanceRegistry.get_baseline("user_get_profile")
        assert summary["requests_per_second"] >= baseline.target_rps * 0.8  # 80% of target
        assert summary["response_time"]["p95"] <= baseline.p95_response_time
        assert summary["response_time"]["p99"] <= baseline.p99_response_time


@pytest.mark.performance
@pytest.mark.asyncio
class TestRolePerformance:
    """Test role and permission endpoint performance."""
    
    async def test_permission_check_performance_baseline(self, async_client: AsyncClient, auth_headers: dict):
        """Test permission check endpoint meets performance baseline."""
        monitor = PerformanceMonitor()
        
        # Test permission check performance
        with monitor.measure_performance("permission_check"):
            response = await async_client.get(
                "/users/permissions/user:read",
                headers=auth_headers
            )
        
        assert response.status_code == 200
        
        # Assert performance baseline
        metrics = monitor.get_metrics("permission_check")[0]
        monitor.assert_performance_baseline("permission_check", metrics)
    
    async def test_role_assign_performance_baseline(self, async_client: AsyncClient, admin_auth_headers: dict):
        """Test role assignment endpoint meets performance baseline."""
        monitor = PerformanceMonitor()
        
        # Create test user
        user_builder = UserBuilder()
        user = user_builder.build()
        
        # Test role assignment performance
        with monitor.measure_performance("role_assign"):
            response = await async_client.post(
                f"/users/{user.id}/roles",
                headers=admin_auth_headers,
                json={
                    "role_name": "user"
                }
            )
        
        assert response.status_code == 200
        
        # Assert performance baseline
        metrics = monitor.get_metrics("role_assign")[0]
        monitor.assert_performance_baseline("role_assign", metrics)
    
    async def test_permission_check_load_test(self, async_client: AsyncClient, auth_headers: dict):
        """Test permission check endpoint under heavy load."""
        scenario = get_load_test_scenario("heavy_load")
        
        async def permission_check_operation():
            response = await async_client.get(
                "/users/permissions/user:read",
                headers=auth_headers
            )
            return response.status_code == 200
        
        # Run load test
        await scenario.run_load_test(permission_check_operation)
        
        # Analyze results
        summary = scenario.get_load_test_summary()
        
        # Assert load test meets baseline
        baseline = PerformanceRegistry.get_baseline("permission_check")
        assert summary["requests_per_second"] >= baseline.target_rps * 0.8  # 80% of target
        assert summary["response_time"]["p95"] <= baseline.p95_response_time
        assert summary["response_time"]["p99"] <= baseline.p99_response_time


@pytest.mark.performance
@pytest.mark.asyncio
class TestBatchOperationPerformance:
    """Test batch operation performance."""
    
    async def test_batch_user_import_performance_baseline(self, async_client: AsyncClient, admin_auth_headers: dict):
        """Test batch user import meets performance baseline."""
        monitor = PerformanceMonitor()
        
        # Generate batch of users
        users_data = []
        for i in range(100):
            user_builder = UserBuilder()
            user = user_builder.build()
            users_data.append({
                "email": user.email.value,
                "password": "test_password123",
                "name": f"Test User {i}"
            })
        
        # Test batch import performance
        with monitor.measure_performance("batch_user_import"):
            response = await async_client.post(
                "/admin/users/batch-import",
                headers=admin_auth_headers,
                json={"users": users_data}
            )
        
        assert response.status_code == 200
        
        # Assert performance baseline
        metrics = monitor.get_metrics("batch_user_import")[0]
        monitor.assert_performance_baseline("batch_user_import", metrics)
    
    async def test_batch_permission_check_performance_baseline(self, async_client: AsyncClient, auth_headers: dict):
        """Test batch permission check meets performance baseline."""
        monitor = PerformanceMonitor()
        
        # Generate batch of permissions to check
        permissions = [
            "user:read", "user:write", "user:delete",
            "role:read", "role:write", "role:delete",
            "permission:read", "permission:write", "permission:delete"
        ]
        
        # Test batch permission check performance
        with monitor.measure_performance("batch_permission_check"):
            response = await async_client.post(
                "/users/permissions/batch-check",
                headers=auth_headers,
                json={"permissions": permissions * 11}  # 99 permissions total
            )
        
        assert response.status_code == 200
        
        # Assert performance baseline
        metrics = monitor.get_metrics("batch_permission_check")[0]
        monitor.assert_performance_baseline("batch_permission_check", metrics)


@pytest.mark.performance
@pytest.mark.asyncio
class TestPerformanceRegression:
    """Test for performance regressions across all endpoints."""
    
    async def test_all_endpoints_performance_regression(self, async_client: AsyncClient, auth_headers: dict):
        """Test all endpoints for performance regression."""
        monitor = PerformanceMonitor()
        
        # Test all critical endpoints
        test_cases = [
            ("auth_login", "POST", "/auth/login", {"email": "test@example.com", "password": "test123"}),
            ("user_get_profile", "GET", "/users/profile", None),
            ("permission_check", "GET", "/users/permissions/user:read", None),
        ]
        
        for operation_name, method, endpoint, payload in test_cases:
            with monitor.measure_performance(operation_name):
                if method == "GET":
                    response = await async_client.get(endpoint, headers=auth_headers)
                elif method == "POST":
                    response = await async_client.post(endpoint, json=payload, headers=auth_headers)
                elif method == "PATCH":
                    response = await async_client.patch(endpoint, json=payload, headers=auth_headers)
                else:
                    continue
                
                assert response.status_code in [200, 201, 202]
            
            # Assert performance baseline for each operation
            metrics = monitor.get_metrics(operation_name)[-1]
            monitor.assert_performance_baseline(operation_name, metrics)
    
    async def test_concurrent_mixed_operations(self, async_client: AsyncClient, auth_headers: dict):
        """Test mixed operations under concurrent load."""
        scenario = LoadTestScenario("Mixed Operations", concurrent_users=30, duration_seconds=60)
        
        async def mixed_operations():
            # Simulate realistic user behavior
            operations = [
                ("GET", "/users/profile"),
                ("GET", "/users/permissions/user:read"),
                ("PATCH", "/users/profile", {"name": "Updated Name"}),
                ("GET", "/users/sessions"),
            ]
            
            for method, endpoint, *payload in operations:
                if method == "GET":
                    response = await async_client.get(endpoint, headers=auth_headers)
                elif method == "PATCH":
                    response = await async_client.patch(endpoint, json=payload[0], headers=auth_headers)
                
                # Small delay between operations
                await asyncio.sleep(0.1)
        
        # Run load test
        await scenario.run_load_test(mixed_operations)
        
        # Analyze results
        summary = scenario.get_load_test_summary()
        
        # Assert reasonable performance under mixed load
        assert summary["requests_per_second"] >= 10  # Minimum threshold
        assert summary["response_time"]["p95"] <= 1.0  # 95% under 1 second
        assert summary["response_time"]["p99"] <= 2.0  # 99% under 2 seconds