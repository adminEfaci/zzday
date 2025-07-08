"""
Chaos Monkey for failure injection testing.

Implements systematic failure injection to test system resilience.
"""

import asyncio
from contextlib import asynccontextmanager
from typing import Dict, List, Optional
from unittest.mock import patch
import pytest


class ChaosMonkey:
    """Chaos engineering tool for injecting failures into tests."""
    
    def __init__(self):
        self.active_failures = []
        self.failure_patches = {}
        
    async def __aenter__(self):
        """Async context manager entry."""
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit - cleanup all failures."""
        await self.stop_all_failures()
        
    async def break_database_connection(self, duration: int = 5):
        """Simulate database connection failure."""
        def failing_db_call(*args, **kwargs):
            raise Exception("Database connection lost")
            
        # Patch database operations
        db_patch = patch('sqlalchemy.ext.asyncio.AsyncSession.execute', side_effect=failing_db_call)
        db_patch.start()
        
        self.active_failures.append(('database', db_patch))
        
        if duration > 0:
            # Auto-restore after duration
            asyncio.create_task(self._restore_after_delay('database', duration))
            
    async def introduce_network_latency(self, ms: int = 1000):
        """Add artificial network latency."""
        original_post = None
        original_get = None
        
        async def slow_request(*args, **kwargs):
            await asyncio.sleep(ms / 1000.0)  # Convert ms to seconds
            if 'post' in str(args[0]):
                return await original_post(*args, **kwargs)
            else:
                return await original_get(*args, **kwargs)
                
        # This is a simplified example - real implementation would patch HTTP client
        self.active_failures.append(('network_latency', None))
        
    async def corrupt_cache_data(self, key_pattern: str = "*"):
        """Introduce cache inconsistencies."""
        def corrupted_cache_get(key):
            if key_pattern in key or key_pattern == "*":
                return None  # Cache miss
            return key  # Normal cache hit
            
        # Patch Redis/cache operations
        cache_patch = patch('redis.Redis.get', side_effect=corrupted_cache_get)
        cache_patch.start()
        
        self.active_failures.append(('cache_corruption', cache_patch))
        
    async def exhaust_connection_pool(self):
        """Simulate connection pool exhaustion."""
        def pool_exhausted(*args, **kwargs):
            raise Exception("Connection pool exhausted")
            
        pool_patch = patch('sqlalchemy.pool.Pool.connect', side_effect=pool_exhausted)
        pool_patch.start()
        
        self.active_failures.append(('pool_exhaustion', pool_patch))
        
    async def simulate_memory_pressure(self):
        """Simulate high memory usage."""
        # This is a placeholder - real implementation would use memory pressure tools
        self.active_failures.append(('memory_pressure', None))
        
    async def inject_random_failures(self, failure_rate: float = 0.1):
        """Inject random failures at specified rate."""
        import random
        
        def random_failure(*args, **kwargs):
            if random.random() < failure_rate:
                raise Exception(f"Random failure injected (rate: {failure_rate})")
            # Continue normally if no failure
            
        # This would patch various operations randomly
        self.active_failures.append(('random_failures', None))
        
    async def _restore_after_delay(self, failure_type: str, delay: int):
        """Restore service after specified delay."""
        await asyncio.sleep(delay)
        await self.restore_service(failure_type)
        
    async def restore_service(self, failure_type: str):
        """Restore a specific service."""
        for i, (ftype, patch_obj) in enumerate(self.active_failures):
            if ftype == failure_type:
                if patch_obj:
                    patch_obj.stop()
                self.active_failures.pop(i)
                break
                
    async def stop_all_failures(self):
        """Stop all active failure injections."""
        for failure_type, patch_obj in self.active_failures:
            if patch_obj:
                try:
                    patch_obj.stop()
                except Exception:
                    pass  # Ignore cleanup errors
        self.active_failures.clear()
        
    def get_active_failures(self) -> List[str]:
        """Get list of currently active failures."""
        return [failure_type for failure_type, _ in self.active_failures]


@pytest.fixture
async def chaos_monkey():
    """Provide ChaosMonkey for failure injection tests."""
    monkey = ChaosMonkey()
    try:
        yield monkey
    finally:
        await monkey.stop_all_failures()


@pytest.fixture
def database_failure(chaos_monkey):
    """Fixture for database failure scenarios."""
    async def inject_failure(duration=5):
        await chaos_monkey.break_database_connection(duration)
    return inject_failure


@pytest.fixture  
def network_failure(chaos_monkey):
    """Fixture for network failure scenarios."""
    async def inject_failure(latency_ms=1000):
        await chaos_monkey.introduce_network_latency(latency_ms)
    return inject_failure