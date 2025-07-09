"""
Performance Test Suite using Locust for Load Testing.

Comprehensive performance testing for database operations, API endpoints,
and infrastructure components.
"""

import asyncio
import random
import time
from typing import Any, Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta
import json

from locust import HttpUser, task, between, events
from locust.env import Environment
from locust.stats import stats_printer, stats_history
from locust.log import setup_logging

from app.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class PerformanceMetrics:
    """Performance test metrics."""
    total_requests: int
    failed_requests: int
    average_response_time: float
    median_response_time: float
    p95_response_time: float
    p99_response_time: float
    requests_per_second: float
    error_rate: float
    start_time: datetime
    end_time: Optional[datetime] = None


class DatabasePerformanceUser(HttpUser):
    """Database performance test user."""
    
    wait_time = between(0.1, 0.5)
    
    def on_start(self):
        """Setup test data."""
        self.user_ids = []
        self.session_tokens = []
        
        # Create test users
        for i in range(10):
            response = self.client.post("/api/users", json={
                "email": f"test{i}@example.com",
                "password": "Test123!",
                "first_name": f"Test{i}",
                "last_name": "User"
            })
            if response.status_code == 201:
                user_data = response.json()
                self.user_ids.append(user_data["id"])
    
    @task(3)
    def read_user(self):
        """Test user read operations."""
        if self.user_ids:
            user_id = random.choice(self.user_ids)
            with self.client.get(f"/api/users/{user_id}", catch_response=True) as response:
                if response.status_code == 200:
                    response.success()
                else:
                    response.failure(f"Got status {response.status_code}")
    
    @task(2)
    def list_users(self):
        """Test user list operations."""
        params = {
            "limit": random.randint(10, 50),
            "offset": random.randint(0, 100)
        }
        with self.client.get("/api/users", params=params, catch_response=True) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Got status {response.status_code}")
    
    @task(1)
    def update_user(self):
        """Test user update operations."""
        if self.user_ids:
            user_id = random.choice(self.user_ids)
            data = {
                "first_name": f"Updated{random.randint(1, 1000)}",
                "last_name": "User"
            }
            with self.client.patch(f"/api/users/{user_id}", json=data, catch_response=True) as response:
                if response.status_code == 200:
                    response.success()
                else:
                    response.failure(f"Got status {response.status_code}")
    
    @task(1)
    def complex_query(self):
        """Test complex database queries."""
        params = {
            "filter": "active",
            "sort": "created_at",
            "include": "profile,permissions",
            "limit": 20
        }
        with self.client.get("/api/users/search", params=params, catch_response=True) as response:
            if response.status_code == 200:
                response.success()
            else:
                response.failure(f"Got status {response.status_code}")


class AuthenticationPerformanceUser(HttpUser):
    """Authentication performance test user."""
    
    wait_time = between(0.1, 0.3)
    
    def on_start(self):
        """Setup test credentials."""
        self.test_email = f"perf_test_{random.randint(1, 10000)}@example.com"
        self.test_password = "Test123!"
        
        # Create test user
        self.client.post("/api/auth/register", json={
            "email": self.test_email,
            "password": self.test_password,
            "first_name": "Perf",
            "last_name": "Test"
        })
    
    @task(5)
    def login(self):
        """Test login operations."""
        data = {
            "email": self.test_email,
            "password": self.test_password
        }
        with self.client.post("/api/auth/login", json=data, catch_response=True) as response:
            if response.status_code == 200:
                response.success()
                # Store token for other operations
                self.token = response.json().get("access_token")
            else:
                response.failure(f"Login failed with status {response.status_code}")
    
    @task(3)
    def validate_token(self):
        """Test token validation operations."""
        if hasattr(self, 'token'):
            headers = {"Authorization": f"Bearer {self.token}"}
            with self.client.get("/api/auth/me", headers=headers, catch_response=True) as response:
                if response.status_code == 200:
                    response.success()
                else:
                    response.failure(f"Token validation failed with status {response.status_code}")
    
    @task(1)
    def refresh_token(self):
        """Test token refresh operations."""
        if hasattr(self, 'token'):
            headers = {"Authorization": f"Bearer {self.token}"}
            with self.client.post("/api/auth/refresh", headers=headers, catch_response=True) as response:
                if response.status_code == 200:
                    response.success()
                    self.token = response.json().get("access_token")
                else:
                    response.failure(f"Token refresh failed with status {response.status_code}")


class CachePerformanceUser(HttpUser):
    """Cache performance test user."""
    
    wait_time = between(0.05, 0.1)
    
    @task(10)
    def cache_read(self):
        """Test cache read operations."""
        cache_key = f"test_key_{random.randint(1, 1000)}"
        with self.client.get(f"/api/cache/{cache_key}", catch_response=True) as response:
            if response.status_code in [200, 404]:
                response.success()
            else:
                response.failure(f"Cache read failed with status {response.status_code}")
    
    @task(3)
    def cache_write(self):
        """Test cache write operations."""
        cache_key = f"test_key_{random.randint(1, 1000)}"
        data = {
            "value": f"test_value_{random.randint(1, 10000)}",
            "ttl": 300
        }
        with self.client.post(f"/api/cache/{cache_key}", json=data, catch_response=True) as response:
            if response.status_code in [200, 201]:
                response.success()
            else:
                response.failure(f"Cache write failed with status {response.status_code}")
    
    @task(1)
    def cache_invalidate(self):
        """Test cache invalidation operations."""
        pattern = f"test_key_{random.randint(1, 100)}*"
        with self.client.delete(f"/api/cache", params={"pattern": pattern}, catch_response=True) as response:
            if response.status_code in [200, 204]:
                response.success()
            else:
                response.failure(f"Cache invalidation failed with status {response.status_code}")


class IntegrationPerformanceUser(HttpUser):
    """Integration services performance test user."""
    
    wait_time = between(0.2, 0.5)
    
    @task(3)
    def send_email(self):
        """Test email sending operations."""
        data = {
            "to": "test@example.com",
            "subject": f"Test Email {random.randint(1, 1000)}",
            "body": "This is a test email for performance testing.",
            "template": "notification"
        }
        with self.client.post("/api/notifications/email", json=data, catch_response=True) as response:
            if response.status_code in [200, 202]:
                response.success()
            else:
                response.failure(f"Email send failed with status {response.status_code}")
    
    @task(2)
    def send_sms(self):
        """Test SMS sending operations."""
        data = {
            "to": "+1234567890",
            "message": f"Test SMS {random.randint(1, 1000)}",
            "template": "verification"
        }
        with self.client.post("/api/notifications/sms", json=data, catch_response=True) as response:
            if response.status_code in [200, 202]:
                response.success()
            else:
                response.failure(f"SMS send failed with status {response.status_code}")
    
    @task(1)
    def webhook_call(self):
        """Test webhook operations."""
        data = {
            "url": "https://httpbin.org/post",
            "payload": {"test": f"data_{random.randint(1, 1000)}"},
            "headers": {"Content-Type": "application/json"}
        }
        with self.client.post("/api/webhooks/send", json=data, catch_response=True) as response:
            if response.status_code in [200, 202]:
                response.success()
            else:
                response.failure(f"Webhook call failed with status {response.status_code}")


class PerformanceTestRunner:
    """Performance test runner and results analyzer."""
    
    def __init__(self, host: str = "http://localhost:8000"):
        self.host = host
        self.results: Dict[str, PerformanceMetrics] = {}
        
    async def run_test_suite(
        self,
        test_scenarios: List[Dict[str, Any]],
        duration: int = 60,
        spawn_rate: float = 1.0
    ) -> Dict[str, PerformanceMetrics]:
        """Run comprehensive performance test suite."""
        
        setup_logging("INFO")
        
        results = {}
        
        for scenario in test_scenarios:
            logger.info(f"Running performance test: {scenario['name']}")
            
            # Setup environment
            env = Environment(
                user_classes=[scenario['user_class']],
                host=self.host
            )
            
            # Setup event listeners
            self._setup_event_listeners(env, scenario['name'])
            
            # Start test
            env.create_local_runner()
            start_time = datetime.now()
            
            # Spawn users
            env.runner.start(
                user_count=scenario.get('users', 10),
                spawn_rate=spawn_rate
            )
            
            # Wait for test duration
            await asyncio.sleep(duration)
            
            # Stop test
            env.runner.stop()
            end_time = datetime.now()
            
            # Collect results
            stats = env.stats
            results[scenario['name']] = PerformanceMetrics(
                total_requests=stats.total.num_requests,
                failed_requests=stats.total.num_failures,
                average_response_time=stats.total.avg_response_time,
                median_response_time=stats.total.median_response_time,
                p95_response_time=stats.total.get_response_time_percentile(0.95),
                p99_response_time=stats.total.get_response_time_percentile(0.99),
                requests_per_second=stats.total.current_rps,
                error_rate=stats.total.fail_ratio,
                start_time=start_time,
                end_time=end_time
            )
            
            logger.info(f"Test completed: {scenario['name']}")
            
        return results
    
    def _setup_event_listeners(self, env: Environment, test_name: str):
        """Setup event listeners for detailed monitoring."""
        
        @events.request.add_listener
        def on_request(request_type, name, response_time, response_length, exception, context, **kwargs):
            if exception:
                logger.warning(f"Request failed: {name} - {exception}")
        
        @events.user_error.add_listener
        def on_user_error(user_instance, exception, tb, **kwargs):
            logger.error(f"User error in {test_name}: {exception}")
        
        @events.spawning_complete.add_listener
        def on_spawning_complete(user_count, **kwargs):
            logger.info(f"Spawning complete for {test_name}: {user_count} users")
    
    def generate_report(self, results: Dict[str, PerformanceMetrics]) -> str:
        """Generate performance test report."""
        
        report = f"""
# Performance Test Report
Generated: {datetime.now().isoformat()}

## Test Results Summary

"""
        
        for test_name, metrics in results.items():
            duration = (metrics.end_time - metrics.start_time).total_seconds()
            
            report += f"""
### {test_name}
- **Duration**: {duration:.1f}s
- **Total Requests**: {metrics.total_requests:,}
- **Failed Requests**: {metrics.failed_requests:,}
- **Error Rate**: {metrics.error_rate:.2%}
- **Requests/Second**: {metrics.requests_per_second:.2f}
- **Average Response Time**: {metrics.average_response_time:.2f}ms
- **Median Response Time**: {metrics.median_response_time:.2f}ms
- **95th Percentile**: {metrics.p95_response_time:.2f}ms
- **99th Percentile**: {metrics.p99_response_time:.2f}ms

"""
        
        # Add performance analysis
        report += """
## Performance Analysis

"""
        
        for test_name, metrics in results.items():
            if metrics.error_rate > 0.05:  # 5% error rate
                report += f"⚠️ **{test_name}**: High error rate ({metrics.error_rate:.2%})\n"
            
            if metrics.p95_response_time > 1000:  # 1 second
                report += f"⚠️ **{test_name}**: High response time (P95: {metrics.p95_response_time:.2f}ms)\n"
            
            if metrics.requests_per_second < 10:
                report += f"⚠️ **{test_name}**: Low throughput ({metrics.requests_per_second:.2f} req/s)\n"
        
        report += """
## Recommendations

1. **Database Optimization**: Review slow queries and add missing indexes
2. **Cache Optimization**: Implement cache warming for frequently accessed data
3. **Connection Pooling**: Optimize database connection pool settings
4. **Rate Limiting**: Implement rate limiting to prevent abuse
5. **Monitoring**: Add performance monitoring dashboards

"""
        
        return report
    
    async def run_stress_test(
        self,
        user_class,
        max_users: int = 100,
        spawn_rate: float = 2.0,
        duration: int = 300
    ) -> Dict[str, Any]:
        """Run stress test to find breaking point."""
        
        setup_logging("INFO")
        
        env = Environment(user_classes=[user_class], host=self.host)
        env.create_local_runner()
        
        # Gradual load increase
        results = []
        current_users = 1
        
        while current_users <= max_users:
            logger.info(f"Testing with {current_users} users")
            
            # Start users
            env.runner.start(user_count=current_users, spawn_rate=spawn_rate)
            
            # Wait for stabilization
            await asyncio.sleep(30)
            
            # Collect metrics
            stats = env.stats
            results.append({
                "users": current_users,
                "rps": stats.total.current_rps,
                "avg_response_time": stats.total.avg_response_time,
                "error_rate": stats.total.fail_ratio
            })
            
            # Check if system is breaking
            if stats.total.fail_ratio > 0.1 or stats.total.avg_response_time > 5000:
                logger.warning(f"System breaking at {current_users} users")
                break
            
            current_users = min(current_users * 2, max_users)
        
        env.runner.stop()
        
        return {
            "max_stable_users": current_users // 2,
            "breaking_point": current_users,
            "results": results
        }


# Test scenario configurations
DEFAULT_TEST_SCENARIOS = [
    {
        "name": "Database Performance",
        "user_class": DatabasePerformanceUser,
        "users": 20,
        "description": "Test database operations performance"
    },
    {
        "name": "Authentication Performance", 
        "user_class": AuthenticationPerformanceUser,
        "users": 50,
        "description": "Test authentication system performance"
    },
    {
        "name": "Cache Performance",
        "user_class": CachePerformanceUser,
        "users": 30,
        "description": "Test caching system performance"
    },
    {
        "name": "Integration Performance",
        "user_class": IntegrationPerformanceUser,
        "users": 10,
        "description": "Test integration services performance"
    }
]


async def run_performance_tests(
    host: str = "http://localhost:8000",
    duration: int = 60,
    scenarios: Optional[List[Dict[str, Any]]] = None
) -> str:
    """Run performance tests and return report."""
    
    test_scenarios = scenarios or DEFAULT_TEST_SCENARIOS
    runner = PerformanceTestRunner(host)
    
    results = await runner.run_test_suite(test_scenarios, duration)
    report = runner.generate_report(results)
    
    return report


__all__ = [
    "PerformanceTestRunner",
    "DatabasePerformanceUser",
    "AuthenticationPerformanceUser", 
    "CachePerformanceUser",
    "IntegrationPerformanceUser",
    "PerformanceMetrics",
    "DEFAULT_TEST_SCENARIOS",
    "run_performance_tests"
]