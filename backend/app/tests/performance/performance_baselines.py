"""
Performance Baselines and Thresholds

Defines performance baselines for all critical operations and provides
utilities for measuring and asserting performance requirements.
"""

import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Dict, List, Optional, Any, Callable, Generator
from unittest.mock import Mock

import pytest
import psutil
import asyncio
from sqlalchemy.ext.asyncio import AsyncSession


@dataclass
class PerformanceBaseline:
    """Performance baseline for a specific operation."""
    operation_name: str
    max_response_time: float  # seconds
    max_memory_mb: float
    max_cpu_percent: float
    target_rps: float  # requests per second
    p95_response_time: float  # 95th percentile response time
    p99_response_time: float  # 99th percentile response time


class PerformanceRegistry:
    """Registry of performance baselines for different operations."""
    
    BASELINES = {
        # Authentication operations
        "auth_login": PerformanceBaseline(
            operation_name="User Login",
            max_response_time=0.2,
            max_memory_mb=10.0,
            max_cpu_percent=30.0,
            target_rps=100.0,
            p95_response_time=0.15,
            p99_response_time=0.18
        ),
        "auth_register": PerformanceBaseline(
            operation_name="User Registration",
            max_response_time=0.5,
            max_memory_mb=15.0,
            max_cpu_percent=40.0,
            target_rps=50.0,
            p95_response_time=0.4,
            p99_response_time=0.45
        ),
        "auth_refresh_token": PerformanceBaseline(
            operation_name="Token Refresh",
            max_response_time=0.1,
            max_memory_mb=5.0,
            max_cpu_percent=20.0,
            target_rps=500.0,
            p95_response_time=0.08,
            p99_response_time=0.09
        ),
        
        # User operations
        "user_get_profile": PerformanceBaseline(
            operation_name="Get User Profile",
            max_response_time=0.1,
            max_memory_mb=8.0,
            max_cpu_percent=25.0,
            target_rps=200.0,
            p95_response_time=0.08,
            p99_response_time=0.09
        ),
        "user_update_profile": PerformanceBaseline(
            operation_name="Update User Profile",
            max_response_time=0.3,
            max_memory_mb=12.0,
            max_cpu_percent=35.0,
            target_rps=100.0,
            p95_response_time=0.25,
            p99_response_time=0.28
        ),
        "user_delete_account": PerformanceBaseline(
            operation_name="Delete User Account",
            max_response_time=1.0,
            max_memory_mb=20.0,
            max_cpu_percent=50.0,
            target_rps=10.0,
            p95_response_time=0.8,
            p99_response_time=0.9
        ),
        
        # Role and permission operations
        "role_assign": PerformanceBaseline(
            operation_name="Assign Role to User",
            max_response_time=0.2,
            max_memory_mb=10.0,
            max_cpu_percent=30.0,
            target_rps=100.0,
            p95_response_time=0.15,
            p99_response_time=0.18
        ),
        "permission_check": PerformanceBaseline(
            operation_name="Check User Permission",
            max_response_time=0.05,
            max_memory_mb=5.0,
            max_cpu_percent=15.0,
            target_rps=1000.0,
            p95_response_time=0.03,
            p99_response_time=0.04
        ),
        
        # Database operations
        "db_user_query": PerformanceBaseline(
            operation_name="Database User Query",
            max_response_time=0.05,
            max_memory_mb=8.0,
            max_cpu_percent=20.0,
            target_rps=500.0,
            p95_response_time=0.03,
            p99_response_time=0.04
        ),
        "db_user_insert": PerformanceBaseline(
            operation_name="Database User Insert",
            max_response_time=0.1,
            max_memory_mb=10.0,
            max_cpu_percent=25.0,
            target_rps=200.0,
            p95_response_time=0.08,
            p99_response_time=0.09
        ),
        "db_user_update": PerformanceBaseline(
            operation_name="Database User Update",
            max_response_time=0.1,
            max_memory_mb=10.0,
            max_cpu_percent=25.0,
            target_rps=200.0,
            p95_response_time=0.08,
            p99_response_time=0.09
        ),
        "db_user_delete": PerformanceBaseline(
            operation_name="Database User Delete",
            max_response_time=0.1,
            max_memory_mb=10.0,
            max_cpu_percent=25.0,
            target_rps=150.0,
            p95_response_time=0.08,
            p99_response_time=0.09
        ),
        
        # Batch operations
        "batch_user_import": PerformanceBaseline(
            operation_name="Batch User Import (100 users)",
            max_response_time=5.0,
            max_memory_mb=50.0,
            max_cpu_percent=70.0,
            target_rps=1.0,
            p95_response_time=4.0,
            p99_response_time=4.5
        ),
        "batch_permission_check": PerformanceBaseline(
            operation_name="Batch Permission Check (100 permissions)",
            max_response_time=0.5,
            max_memory_mb=20.0,
            max_cpu_percent=40.0,
            target_rps=50.0,
            p95_response_time=0.4,
            p99_response_time=0.45
        ),
    }
    
    @classmethod
    def get_baseline(cls, operation_name: str) -> Optional[PerformanceBaseline]:
        """Get performance baseline for operation."""
        return cls.BASELINES.get(operation_name)
    
    @classmethod
    def get_all_baselines(cls) -> Dict[str, PerformanceBaseline]:
        """Get all performance baselines."""
        return cls.BASELINES.copy()


@dataclass
class PerformanceMetrics:
    """Performance metrics captured during test execution."""
    operation_name: str
    response_time: float
    memory_usage_mb: float
    cpu_percent: float
    timestamp: float
    additional_metrics: Dict[str, Any]


class PerformanceMonitor:
    """Monitor and measure performance metrics during test execution."""
    
    def __init__(self):
        self.metrics: List[PerformanceMetrics] = []
        self.process = psutil.Process()
        
    @contextmanager
    def measure_performance(self, operation_name: str, **additional_metrics) -> Generator[None, None, None]:
        """Context manager to measure performance of an operation."""
        # Initial measurements
        start_time = time.perf_counter()
        start_memory = self.process.memory_info().rss / 1024 / 1024  # MB
        start_cpu = self.process.cpu_percent()
        
        # Let CPU measurement stabilize
        time.sleep(0.1)
        
        try:
            yield
        finally:
            # Final measurements
            end_time = time.perf_counter()
            end_memory = self.process.memory_info().rss / 1024 / 1024  # MB
            end_cpu = self.process.cpu_percent()
            
            # Calculate metrics
            response_time = end_time - start_time
            memory_usage = max(end_memory - start_memory, 0)
            cpu_percent = max(end_cpu, start_cpu)
            
            # Store metrics
            metrics = PerformanceMetrics(
                operation_name=operation_name,
                response_time=response_time,
                memory_usage_mb=memory_usage,
                cpu_percent=cpu_percent,
                timestamp=end_time,
                additional_metrics=additional_metrics
            )
            self.metrics.append(metrics)
    
    def get_metrics(self, operation_name: Optional[str] = None) -> List[PerformanceMetrics]:
        """Get performance metrics, optionally filtered by operation name."""
        if operation_name is None:
            return self.metrics.copy()
        return [m for m in self.metrics if m.operation_name == operation_name]
    
    def clear_metrics(self):
        """Clear all stored metrics."""
        self.metrics.clear()
    
    def assert_performance_baseline(self, operation_name: str, metrics: PerformanceMetrics):
        """Assert that metrics meet the performance baseline."""
        baseline = PerformanceRegistry.get_baseline(operation_name)
        if baseline is None:
            pytest.fail(f"No performance baseline defined for operation: {operation_name}")
        
        # Check response time
        if metrics.response_time > baseline.max_response_time:
            pytest.fail(
                f"Response time {metrics.response_time:.3f}s exceeds baseline "
                f"{baseline.max_response_time:.3f}s for {operation_name}"
            )
        
        # Check memory usage
        if metrics.memory_usage_mb > baseline.max_memory_mb:
            pytest.fail(
                f"Memory usage {metrics.memory_usage_mb:.1f}MB exceeds baseline "
                f"{baseline.max_memory_mb:.1f}MB for {operation_name}"
            )
        
        # Check CPU usage
        if metrics.cpu_percent > baseline.max_cpu_percent:
            pytest.fail(
                f"CPU usage {metrics.cpu_percent:.1f}% exceeds baseline "
                f"{baseline.max_cpu_percent:.1f}% for {operation_name}"
            )


class LoadTestScenario:
    """Defines a load testing scenario with multiple concurrent operations."""
    
    def __init__(self, name: str, concurrent_users: int, duration_seconds: float):
        self.name = name
        self.concurrent_users = concurrent_users
        self.duration_seconds = duration_seconds
        self.results: List[PerformanceMetrics] = []
    
    async def run_load_test(self, operation_func: Callable, *args, **kwargs):
        """Run load test with specified operation function."""
        start_time = time.perf_counter()
        tasks = []
        
        # Create tasks for concurrent users
        for user_id in range(self.concurrent_users):
            task = asyncio.create_task(
                self._run_user_session(user_id, operation_func, start_time, *args, **kwargs)
            )
            tasks.append(task)
        
        # Wait for all tasks to complete or timeout
        try:
            await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True), 
                timeout=self.duration_seconds + 10
            )
        except asyncio.TimeoutError:
            # Cancel remaining tasks
            for task in tasks:
                if not task.done():
                    task.cancel()
            
            # Wait for cancellation
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _run_user_session(self, user_id: int, operation_func: Callable, start_time: float, *args, **kwargs):
        """Run a single user session for the duration of the test."""
        monitor = PerformanceMonitor()
        
        while time.perf_counter() - start_time < self.duration_seconds:
            try:
                with monitor.measure_performance(f"{self.name}_user_{user_id}"):
                    await operation_func(*args, **kwargs)
                
                # Small delay to prevent overwhelming the system
                await asyncio.sleep(0.01)
                
            except Exception as e:
                # Log error but continue test
                print(f"Error in user {user_id}: {e}")
                await asyncio.sleep(0.1)
        
        # Add metrics to results
        self.results.extend(monitor.get_metrics())
    
    def get_load_test_summary(self) -> Dict[str, Any]:
        """Get summary of load test results."""
        if not self.results:
            return {"error": "No results available"}
        
        response_times = [m.response_time for m in self.results]
        memory_usage = [m.memory_usage_mb for m in self.results]
        cpu_usage = [m.cpu_percent for m in self.results]
        
        return {
            "scenario_name": self.name,
            "concurrent_users": self.concurrent_users,
            "duration_seconds": self.duration_seconds,
            "total_requests": len(self.results),
            "successful_requests": len([r for r in self.results if r.response_time > 0]),
            "requests_per_second": len(self.results) / self.duration_seconds,
            "response_time": {
                "avg": sum(response_times) / len(response_times),
                "min": min(response_times),
                "max": max(response_times),
                "p95": sorted(response_times)[int(len(response_times) * 0.95)],
                "p99": sorted(response_times)[int(len(response_times) * 0.99)],
            },
            "memory_usage": {
                "avg": sum(memory_usage) / len(memory_usage),
                "max": max(memory_usage),
            },
            "cpu_usage": {
                "avg": sum(cpu_usage) / len(cpu_usage),
                "max": max(cpu_usage),
            }
        }


# Common load test scenarios
LOAD_TEST_SCENARIOS = {
    "light_load": LoadTestScenario("Light Load", concurrent_users=10, duration_seconds=30),
    "medium_load": LoadTestScenario("Medium Load", concurrent_users=50, duration_seconds=60),
    "heavy_load": LoadTestScenario("Heavy Load", concurrent_users=100, duration_seconds=120),
    "spike_load": LoadTestScenario("Spike Load", concurrent_users=200, duration_seconds=30),
    "sustained_load": LoadTestScenario("Sustained Load", concurrent_users=25, duration_seconds=300),
}


def get_load_test_scenario(name: str) -> LoadTestScenario:
    """Get a predefined load test scenario."""
    scenario = LOAD_TEST_SCENARIOS.get(name)
    if scenario is None:
        raise ValueError(f"Unknown load test scenario: {name}")
    return scenario