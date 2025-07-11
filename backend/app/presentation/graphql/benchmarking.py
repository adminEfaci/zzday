"""
GraphQL Performance Benchmarking and Testing

Provides comprehensive performance benchmarking tools for GraphQL operations
including load testing, performance profiling, and optimization recommendations.
"""

import asyncio
import json
import logging
import statistics
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from uuid import uuid4

import aiohttp
import psutil
from graphql import DocumentNode, parse, print_ast
from strawberry.test import BaseGraphQLTestClient

logger = logging.getLogger(__name__)


class BenchmarkStatus(Enum):
    """Benchmark execution status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class MetricType(Enum):
    """Types of performance metrics."""
    RESPONSE_TIME = "response_time"
    THROUGHPUT = "throughput"
    ERROR_RATE = "error_rate"
    MEMORY_USAGE = "memory_usage"
    CPU_USAGE = "cpu_usage"
    QUERY_COMPLEXITY = "query_complexity"


@dataclass
class BenchmarkResult:
    """Individual benchmark result."""
    query_id: str
    start_time: float
    end_time: float
    success: bool
    error: Optional[str] = None
    response_data: Optional[Dict[str, Any]] = None
    memory_usage_mb: float = 0.0
    cpu_usage_percent: float = 0.0
    
    @property
    def duration_ms(self) -> float:
        """Get duration in milliseconds."""
        return (self.end_time - self.start_time) * 1000
    
    @property
    def duration_seconds(self) -> float:
        """Get duration in seconds."""
        return self.end_time - self.start_time


@dataclass
class BenchmarkMetrics:
    """Aggregated benchmark metrics."""
    # Basic metrics
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    
    # Timing metrics
    total_duration_seconds: float = 0.0
    min_response_time_ms: float = 0.0
    max_response_time_ms: float = 0.0
    avg_response_time_ms: float = 0.0
    median_response_time_ms: float = 0.0
    p95_response_time_ms: float = 0.0
    p99_response_time_ms: float = 0.0
    
    # Performance metrics
    requests_per_second: float = 0.0
    error_rate_percent: float = 0.0
    
    # Resource metrics
    avg_memory_usage_mb: float = 0.0
    peak_memory_usage_mb: float = 0.0
    avg_cpu_usage_percent: float = 0.0
    peak_cpu_usage_percent: float = 0.0
    
    # Additional metrics
    response_times: List[float] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    
    def calculate_from_results(self, results: List[BenchmarkResult]):
        """Calculate metrics from benchmark results."""
        if not results:
            return
        
        # Basic counts
        self.total_requests = len(results)
        self.successful_requests = sum(1 for r in results if r.success)
        self.failed_requests = self.total_requests - self.successful_requests
        
        # Timing metrics
        response_times = [r.duration_ms for r in results]
        self.response_times = response_times
        
        if response_times:
            self.min_response_time_ms = min(response_times)
            self.max_response_time_ms = max(response_times)
            self.avg_response_time_ms = statistics.mean(response_times)
            self.median_response_time_ms = statistics.median(response_times)
            
            # Percentiles
            sorted_times = sorted(response_times)
            self.p95_response_time_ms = sorted_times[int(len(sorted_times) * 0.95)]
            self.p99_response_time_ms = sorted_times[int(len(sorted_times) * 0.99)]
        
        # Performance metrics
        if results:
            self.total_duration_seconds = max(r.end_time for r in results) - min(r.start_time for r in results)
            if self.total_duration_seconds > 0:
                self.requests_per_second = self.total_requests / self.total_duration_seconds
        
        self.error_rate_percent = (self.failed_requests / self.total_requests) * 100
        
        # Resource metrics
        memory_usages = [r.memory_usage_mb for r in results if r.memory_usage_mb > 0]
        cpu_usages = [r.cpu_usage_percent for r in results if r.cpu_usage_percent > 0]
        
        if memory_usages:
            self.avg_memory_usage_mb = statistics.mean(memory_usages)
            self.peak_memory_usage_mb = max(memory_usages)
        
        if cpu_usages:
            self.avg_cpu_usage_percent = statistics.mean(cpu_usages)
            self.peak_cpu_usage_percent = max(cpu_usages)
        
        # Collect errors
        self.errors = [r.error for r in results if r.error]


@dataclass
class BenchmarkConfig:
    """Benchmark configuration."""
    name: str
    queries: List[str]
    variables: List[Dict[str, Any]] = field(default_factory=list)
    
    # Load testing parameters
    concurrent_users: int = 1
    requests_per_user: int = 1
    ramp_up_time: int = 0  # seconds
    duration: Optional[int] = None  # seconds
    
    # Performance parameters
    timeout: int = 30  # seconds
    think_time: float = 0.0  # seconds between requests
    
    # Monitoring parameters
    monitor_resources: bool = True
    monitor_interval: float = 1.0  # seconds
    
    # Targeting parameters
    target_url: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate configuration."""
        if not self.queries:
            raise ValueError("At least one query must be provided")
        
        if self.concurrent_users < 1:
            raise ValueError("concurrent_users must be at least 1")
        
        if self.requests_per_user < 1:
            raise ValueError("requests_per_user must be at least 1")


class ResourceMonitor:
    """Monitors system resources during benchmarking."""
    
    def __init__(self, interval: float = 1.0):
        self.interval = interval
        self.monitoring = False
        self.measurements: List[Dict[str, Any]] = []
        self._monitor_task: Optional[asyncio.Task] = None
    
    async def start(self):
        """Start resource monitoring."""
        self.monitoring = True
        self.measurements = []
        self._monitor_task = asyncio.create_task(self._monitor_loop())
    
    async def stop(self):
        """Stop resource monitoring."""
        self.monitoring = False
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
    
    async def _monitor_loop(self):
        """Resource monitoring loop."""
        while self.monitoring:
            try:
                # Get system metrics
                cpu_percent = psutil.cpu_percent(interval=None)
                memory = psutil.virtual_memory()
                
                measurement = {
                    'timestamp': datetime.utcnow().isoformat(),
                    'cpu_percent': cpu_percent,
                    'memory_percent': memory.percent,
                    'memory_used_mb': memory.used / 1024 / 1024,
                    'memory_available_mb': memory.available / 1024 / 1024
                }
                
                self.measurements.append(measurement)
                
                await asyncio.sleep(self.interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Resource monitoring error: {e}")
    
    def get_peak_usage(self) -> Dict[str, float]:
        """Get peak resource usage."""
        if not self.measurements:
            return {}
        
        return {
            'peak_cpu_percent': max(m['cpu_percent'] for m in self.measurements),
            'peak_memory_percent': max(m['memory_percent'] for m in self.measurements),
            'peak_memory_used_mb': max(m['memory_used_mb'] for m in self.measurements)
        }


class GraphQLBenchmark:
    """GraphQL performance benchmarking tool."""
    
    def __init__(self, schema_or_client=None, target_url: Optional[str] = None):
        self.schema_or_client = schema_or_client
        self.target_url = target_url
        self.benchmark_id = str(uuid4())
        
        # Benchmark state
        self.status = BenchmarkStatus.PENDING
        self.config: Optional[BenchmarkConfig] = None
        self.results: List[BenchmarkResult] = []
        self.metrics: Optional[BenchmarkMetrics] = None
        
        # Monitoring
        self.resource_monitor = ResourceMonitor()
        
        # Timing
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None
        
        # Cancellation
        self._cancelled = False
        self._tasks: List[asyncio.Task] = []
    
    async def run_benchmark(self, config: BenchmarkConfig) -> BenchmarkMetrics:
        """Run a benchmark with the given configuration."""
        self.config = config
        self.status = BenchmarkStatus.RUNNING
        self.start_time = datetime.utcnow()
        
        try:
            # Start resource monitoring
            if config.monitor_resources:
                await self.resource_monitor.start()
            
            # Execute benchmark
            await self._execute_benchmark()
            
            # Calculate metrics
            self.metrics = BenchmarkMetrics()
            self.metrics.calculate_from_results(self.results)
            
            self.status = BenchmarkStatus.COMPLETED
            self.end_time = datetime.utcnow()
            
            logger.info(f"Benchmark {config.name} completed successfully")
            return self.metrics
            
        except Exception as e:
            self.status = BenchmarkStatus.FAILED
            self.end_time = datetime.utcnow()
            logger.error(f"Benchmark {config.name} failed: {e}")
            raise
        finally:
            # Stop resource monitoring
            if config.monitor_resources:
                await self.resource_monitor.stop()
    
    async def _execute_benchmark(self):
        """Execute the benchmark."""
        config = self.config
        
        # Create user tasks
        user_tasks = []
        for user_id in range(config.concurrent_users):
            # Stagger user start times for ramp-up
            start_delay = (config.ramp_up_time * user_id) / config.concurrent_users
            
            task = asyncio.create_task(
                self._simulate_user(user_id, start_delay)
            )
            user_tasks.append(task)
            self._tasks.append(task)
        
        # Wait for all users to complete
        await asyncio.gather(*user_tasks, return_exceptions=True)
    
    async def _simulate_user(self, user_id: int, start_delay: float):
        """Simulate a user executing queries."""
        if start_delay > 0:
            await asyncio.sleep(start_delay)
        
        config = self.config
        
        # Execute requests
        for request_id in range(config.requests_per_user):
            if self._cancelled:
                break
            
            # Select query and variables
            query_index = request_id % len(config.queries)
            query = config.queries[query_index]
            
            variables = {}
            if config.variables and query_index < len(config.variables):
                variables = config.variables[query_index]
            
            # Execute query
            await self._execute_query(
                query_id=f"user_{user_id}_request_{request_id}",
                query=query,
                variables=variables
            )
            
            # Think time between requests
            if config.think_time > 0:
                await asyncio.sleep(config.think_time)
    
    async def _execute_query(self, query_id: str, query: str, variables: Dict[str, Any]):
        """Execute a single query."""
        start_time = time.time()
        
        try:
            # Parse query
            document = parse(query)
            
            # Execute based on target
            if self.target_url:
                result = await self._execute_remote_query(query, variables)
            else:
                result = await self._execute_local_query(document, variables)
            
            end_time = time.time()
            
            # Get resource usage
            memory_usage = 0.0
            cpu_usage = 0.0
            
            if self.resource_monitor.monitoring:
                try:
                    memory_usage = psutil.virtual_memory().used / 1024 / 1024
                    cpu_usage = psutil.cpu_percent(interval=None)
                except:
                    pass
            
            # Create result
            benchmark_result = BenchmarkResult(
                query_id=query_id,
                start_time=start_time,
                end_time=end_time,
                success=True,
                response_data=result,
                memory_usage_mb=memory_usage,
                cpu_usage_percent=cpu_usage
            )
            
            self.results.append(benchmark_result)
            
        except Exception as e:
            end_time = time.time()
            
            benchmark_result = BenchmarkResult(
                query_id=query_id,
                start_time=start_time,
                end_time=end_time,
                success=False,
                error=str(e)
            )
            
            self.results.append(benchmark_result)
            logger.error(f"Query execution failed: {e}")
    
    async def _execute_local_query(self, document: DocumentNode, variables: Dict[str, Any]) -> Any:
        """Execute query against local schema."""
        if isinstance(self.schema_or_client, BaseGraphQLTestClient):
            # Use test client
            response = await self.schema_or_client.query(print_ast(document), variables)
            if response.errors:
                raise Exception(f"GraphQL errors: {response.errors}")
            return response.data
        else:
            # Use schema directly
            from graphql import execute
            result = await execute(
                self.schema_or_client,
                document,
                variable_values=variables
            )
            if result.errors:
                raise Exception(f"GraphQL errors: {result.errors}")
            return result.data
    
    async def _execute_remote_query(self, query: str, variables: Dict[str, Any]) -> Any:
        """Execute query against remote GraphQL endpoint."""
        payload = {
            'query': query,
            'variables': variables
        }
        
        headers = {
            'Content-Type': 'application/json',
            **self.config.headers
        }
        
        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(
                self.target_url,
                json=payload,
                headers=headers
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    if result.get('errors'):
                        raise Exception(f"GraphQL errors: {result['errors']}")
                    return result.get('data')
                else:
                    error_text = await response.text()
                    raise Exception(f"HTTP {response.status}: {error_text}")
    
    def cancel(self):
        """Cancel the benchmark."""
        self._cancelled = True
        self.status = BenchmarkStatus.CANCELLED
        
        # Cancel all tasks
        for task in self._tasks:
            task.cancel()
    
    def get_report(self) -> Dict[str, Any]:
        """Get comprehensive benchmark report."""
        if not self.metrics:
            return {"error": "No metrics available"}
        
        report = {
            'benchmark_id': self.benchmark_id,
            'config': {
                'name': self.config.name,
                'concurrent_users': self.config.concurrent_users,
                'requests_per_user': self.config.requests_per_user,
                'total_requests': self.config.concurrent_users * self.config.requests_per_user,
                'ramp_up_time': self.config.ramp_up_time,
                'think_time': self.config.think_time
            },
            'execution': {
                'status': self.status.value,
                'start_time': self.start_time.isoformat() if self.start_time else None,
                'end_time': self.end_time.isoformat() if self.end_time else None,
                'total_duration_seconds': self.metrics.total_duration_seconds
            },
            'metrics': {
                'total_requests': self.metrics.total_requests,
                'successful_requests': self.metrics.successful_requests,
                'failed_requests': self.metrics.failed_requests,
                'error_rate_percent': self.metrics.error_rate_percent,
                'requests_per_second': self.metrics.requests_per_second,
                'response_times': {
                    'min_ms': self.metrics.min_response_time_ms,
                    'max_ms': self.metrics.max_response_time_ms,
                    'avg_ms': self.metrics.avg_response_time_ms,
                    'median_ms': self.metrics.median_response_time_ms,
                    'p95_ms': self.metrics.p95_response_time_ms,
                    'p99_ms': self.metrics.p99_response_time_ms
                },
                'resources': {
                    'avg_memory_usage_mb': self.metrics.avg_memory_usage_mb,
                    'peak_memory_usage_mb': self.metrics.peak_memory_usage_mb,
                    'avg_cpu_usage_percent': self.metrics.avg_cpu_usage_percent,
                    'peak_cpu_usage_percent': self.metrics.peak_cpu_usage_percent
                }
            },
            'errors': self.metrics.errors[:10],  # First 10 errors
            'recommendations': self._generate_recommendations()
        }
        
        return report
    
    def _generate_recommendations(self) -> List[str]:
        """Generate performance recommendations."""
        recommendations = []
        
        if not self.metrics:
            return recommendations
        
        # Error rate recommendations
        if self.metrics.error_rate_percent > 5:
            recommendations.append(
                f"High error rate ({self.metrics.error_rate_percent:.1f}%) - investigate query errors"
            )
        
        # Response time recommendations
        if self.metrics.avg_response_time_ms > 1000:
            recommendations.append(
                f"High average response time ({self.metrics.avg_response_time_ms:.1f}ms) - consider query optimization"
            )
        
        if self.metrics.p99_response_time_ms > 5000:
            recommendations.append(
                f"Very high P99 response time ({self.metrics.p99_response_time_ms:.1f}ms) - investigate slow queries"
            )
        
        # Throughput recommendations
        if self.metrics.requests_per_second < 10:
            recommendations.append(
                f"Low throughput ({self.metrics.requests_per_second:.1f} RPS) - consider scaling or optimization"
            )
        
        # Resource recommendations
        if self.metrics.peak_memory_usage_mb > 1000:
            recommendations.append(
                f"High memory usage ({self.metrics.peak_memory_usage_mb:.1f}MB) - investigate memory leaks"
            )
        
        if self.metrics.peak_cpu_usage_percent > 80:
            recommendations.append(
                f"High CPU usage ({self.metrics.peak_cpu_usage_percent:.1f}%) - consider horizontal scaling"
            )
        
        return recommendations


class BenchmarkSuite:
    """Manages multiple benchmarks."""
    
    def __init__(self):
        self.benchmarks: Dict[str, GraphQLBenchmark] = {}
        self.results: Dict[str, Dict[str, Any]] = {}
    
    async def run_benchmark(
        self,
        name: str,
        config: BenchmarkConfig,
        schema_or_client=None,
        target_url: Optional[str] = None
    ) -> str:
        """Run a benchmark and return benchmark ID."""
        benchmark = GraphQLBenchmark(schema_or_client, target_url)
        benchmark_id = benchmark.benchmark_id
        
        self.benchmarks[benchmark_id] = benchmark
        
        try:
            metrics = await benchmark.run_benchmark(config)
            report = benchmark.get_report()
            self.results[benchmark_id] = report
            
            logger.info(f"Benchmark '{name}' completed with ID: {benchmark_id}")
            return benchmark_id
            
        except Exception as e:
            logger.error(f"Benchmark '{name}' failed: {e}")
            raise
    
    def get_benchmark_report(self, benchmark_id: str) -> Optional[Dict[str, Any]]:
        """Get benchmark report by ID."""
        return self.results.get(benchmark_id)
    
    def compare_benchmarks(self, benchmark_ids: List[str]) -> Dict[str, Any]:
        """Compare multiple benchmarks."""
        if len(benchmark_ids) < 2:
            raise ValueError("At least 2 benchmarks required for comparison")
        
        comparison = {
            'benchmarks': [],
            'comparison_metrics': {}
        }
        
        for benchmark_id in benchmark_ids:
            report = self.results.get(benchmark_id)
            if report:
                comparison['benchmarks'].append({
                    'id': benchmark_id,
                    'name': report['config']['name'],
                    'metrics': report['metrics']
                })
        
        if len(comparison['benchmarks']) < 2:
            raise ValueError("Not enough valid benchmarks for comparison")
        
        # Calculate comparison metrics
        metrics = [b['metrics'] for b in comparison['benchmarks']]
        
        comparison['comparison_metrics'] = {
            'avg_response_time_ms': {
                'min': min(m['response_times']['avg_ms'] for m in metrics),
                'max': max(m['response_times']['avg_ms'] for m in metrics),
                'improvement': self._calculate_improvement(
                    [m['response_times']['avg_ms'] for m in metrics]
                )
            },
            'requests_per_second': {
                'min': min(m['requests_per_second'] for m in metrics),
                'max': max(m['requests_per_second'] for m in metrics),
                'improvement': self._calculate_improvement(
                    [m['requests_per_second'] for m in metrics], higher_is_better=True
                )
            },
            'error_rate_percent': {
                'min': min(m['error_rate_percent'] for m in metrics),
                'max': max(m['error_rate_percent'] for m in metrics),
                'improvement': self._calculate_improvement(
                    [m['error_rate_percent'] for m in metrics]
                )
            }
        }
        
        return comparison
    
    def _calculate_improvement(self, values: List[float], higher_is_better: bool = False) -> float:
        """Calculate improvement percentage."""
        if len(values) < 2:
            return 0.0
        
        baseline = values[0]
        latest = values[-1]
        
        if baseline == 0:
            return 0.0
        
        if higher_is_better:
            return ((latest - baseline) / baseline) * 100
        else:
            return ((baseline - latest) / baseline) * 100


# Global benchmark suite instance
benchmark_suite = BenchmarkSuite()


__all__ = [
    'GraphQLBenchmark',
    'BenchmarkSuite',
    'BenchmarkConfig',
    'BenchmarkMetrics',
    'BenchmarkResult',
    'ResourceMonitor',
    'BenchmarkStatus',
    'MetricType',
    'benchmark_suite',
]