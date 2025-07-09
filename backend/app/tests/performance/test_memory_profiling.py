"""
Memory Profiling Tests

Tests memory usage patterns and detects memory leaks.
"""

import asyncio
import gc
import tracemalloc
from typing import Any

import psutil
import pytest

from app.modules.identity.infrastructure.repositories.role_repository import (
    SQLRoleRepository,
)
from app.modules.identity.infrastructure.repositories.session_repository import (
    SQLSessionRepository,
)
from app.modules.identity.infrastructure.repositories.user_repository import (
    SQLUserRepository,
)
from app.tests.builders.role_builder import RoleBuilder
from app.tests.builders.session_builder import SessionBuilder
from app.tests.builders.user_builder import UserBuilder


class MemoryProfiler:
    """Memory profiler for detecting memory leaks and usage patterns."""
    
    def __init__(self):
        self.snapshots: list[tracemalloc.Snapshot] = []
        self.memory_usage: list[dict[str, Any]] = []
        self.process = psutil.Process()
    
    def start_profiling(self):
        """Start memory profiling."""
        tracemalloc.start()
        self._take_snapshot("start")
    
    def stop_profiling(self):
        """Stop memory profiling."""
        self._take_snapshot("stop")
        tracemalloc.stop()
    
    def _take_snapshot(self, label: str):
        """Take a memory snapshot."""
        snapshot = tracemalloc.take_snapshot()
        self.snapshots.append(snapshot)
        
        # Get process memory info
        memory_info = self.process.memory_info()
        memory_usage = {
            "label": label,
            "rss": memory_info.rss / 1024 / 1024,  # MB
            "vms": memory_info.vms / 1024 / 1024,  # MB
            "timestamp": asyncio.get_event_loop().time()
        }
        self.memory_usage.append(memory_usage)
    
    def check_memory_leak(self, threshold_mb: float = 5.0) -> bool:
        """Check if there's a memory leak."""
        if len(self.memory_usage) < 2:
            return False
        
        start_memory = self.memory_usage[0]["rss"]
        end_memory = self.memory_usage[-1]["rss"]
        
        memory_increase = end_memory - start_memory
        return memory_increase > threshold_mb
    
    def get_memory_stats(self) -> dict[str, Any]:
        """Get memory statistics."""
        if not self.snapshots:
            return {}
        
        current_snapshot = self.snapshots[-1]
        top_stats = current_snapshot.statistics("lineno")
        
        return {
            "total_memory_mb": sum(stat.size for stat in top_stats) / 1024 / 1024,
            "total_blocks": sum(stat.count for stat in top_stats),
            "top_memory_consumers": [
                {
                    "filename": stat.traceback.format()[0],
                    "size_mb": stat.size / 1024 / 1024,
                    "count": stat.count
                }
                for stat in top_stats[:10]
            ],
            "process_memory": self.memory_usage[-1] if self.memory_usage else None
        }
    
    def compare_snapshots(self, start_idx: int = 0, end_idx: int = -1) -> list[dict[str, Any]]:
        """Compare memory snapshots."""
        if len(self.snapshots) < 2:
            return []
        
        start_snapshot = self.snapshots[start_idx]
        end_snapshot = self.snapshots[end_idx]
        
        top_stats = end_snapshot.compare_to(start_snapshot, "lineno")
        
        return [
            {
                "filename": stat.traceback.format()[0],
                "size_diff_mb": stat.size_diff / 1024 / 1024,
                "count_diff": stat.count_diff,
                "size_mb": stat.size / 1024 / 1024,
                "count": stat.count
            }
            for stat in top_stats[:20]
        ]


@pytest.mark.performance
@pytest.mark.asyncio
class TestMemoryUsageBaseline:
    """Test memory usage meets baseline requirements."""
    
    async def test_user_repository_memory_baseline(self, db_session):
        """Test user repository memory usage baseline."""
        profiler = MemoryProfiler()
        user_repo = SQLUserRepository(db_session)
        
        profiler.start_profiling()
        
        # Perform operations
        user_builder = UserBuilder()
        user = user_builder.build()
        await user_repo.save(user)
        
        found_user = await user_repo.find_by_id(user.id)
        assert found_user is not None
        
        profiler.stop_profiling()
        
        # Check memory usage
        stats = profiler.get_memory_stats()
        assert stats["total_memory_mb"] < 50.0  # Should use less than 50MB
        
        # Check for memory leaks
        assert not profiler.check_memory_leak(threshold_mb=2.0)
    
    async def test_role_repository_memory_baseline(self, db_session):
        """Test role repository memory usage baseline."""
        profiler = MemoryProfiler()
        role_repo = SQLRoleRepository(db_session)
        
        profiler.start_profiling()
        
        # Perform operations
        role_builder = RoleBuilder()
        role = role_builder.build()
        await role_repo.save(role)
        
        found_role = await role_repo.find_by_id(role.id)
        assert found_role is not None
        
        profiler.stop_profiling()
        
        # Check memory usage
        stats = profiler.get_memory_stats()
        assert stats["total_memory_mb"] < 50.0  # Should use less than 50MB
        
        # Check for memory leaks
        assert not profiler.check_memory_leak(threshold_mb=2.0)
    
    async def test_session_repository_memory_baseline(self, db_session):
        """Test session repository memory usage baseline."""
        profiler = MemoryProfiler()
        session_repo = SQLSessionRepository(db_session)
        
        profiler.start_profiling()
        
        # Perform operations
        session_builder = SessionBuilder()
        session = session_builder.build()
        await session_repo.save(session)
        
        found_session = await session_repo.find_by_id(session.id)
        assert found_session is not None
        
        profiler.stop_profiling()
        
        # Check memory usage
        stats = profiler.get_memory_stats()
        assert stats["total_memory_mb"] < 50.0  # Should use less than 50MB
        
        # Check for memory leaks
        assert not profiler.check_memory_leak(threshold_mb=2.0)


@pytest.mark.performance
@pytest.mark.asyncio
class TestMemoryLeakDetection:
    """Test for memory leaks in critical operations."""
    
    async def test_repeated_user_operations_memory_leak(self, db_session):
        """Test repeated user operations for memory leaks."""
        profiler = MemoryProfiler()
        user_repo = SQLUserRepository(db_session)
        
        profiler.start_profiling()
        
        # Perform repeated operations
        for i in range(100):
            user_builder = UserBuilder()
            user = user_builder.build()
            await user_repo.save(user)
            
            found_user = await user_repo.find_by_id(user.id)
            assert found_user is not None
            
            await user_repo.delete(user.id)
            
            # Take snapshot every 20 operations
            if i % 20 == 0:
                profiler._take_snapshot(f"iteration_{i}")
                gc.collect()  # Force garbage collection
        
        profiler.stop_profiling()
        
        # Check for memory leaks
        assert not profiler.check_memory_leak(threshold_mb=10.0)
        
        # Analyze memory growth
        comparisons = profiler.compare_snapshots()
        
        # Check if any single source is growing significantly
        for comparison in comparisons[:5]:  # Top 5 memory consumers
            if comparison["size_diff_mb"] > 5.0:  # More than 5MB growth
                pytest.fail(f"Memory leak detected: {comparison}")
    
    async def test_concurrent_operations_memory_leak(self, db_session):
        """Test concurrent operations for memory leaks."""
        profiler = MemoryProfiler()
        user_repo = SQLUserRepository(db_session)
        
        profiler.start_profiling()
        
        async def user_operation():
            user_builder = UserBuilder()
            user = user_builder.build()
            await user_repo.save(user)
            
            found_user = await user_repo.find_by_id(user.id)
            assert found_user is not None
            
            await user_repo.delete(user.id)
        
        # Run concurrent operations
        tasks = []
        for i in range(50):
            task = asyncio.create_task(user_operation())
            tasks.append(task)
        
        await asyncio.gather(*tasks)
        
        profiler.stop_profiling()
        
        # Check for memory leaks
        assert not profiler.check_memory_leak(threshold_mb=15.0)
    
    async def test_session_cleanup_memory_leak(self, db_session):
        """Test session cleanup for memory leaks."""
        profiler = MemoryProfiler()
        session_repo = SQLSessionRepository(db_session)
        
        profiler.start_profiling()
        
        # Create many sessions
        for i in range(200):
            session_builder = SessionBuilder()
            session = session_builder.expired().build()
            await session_repo.save(session)
            
            if i % 50 == 0:
                profiler._take_snapshot(f"created_{i}")
                gc.collect()
        
        # Cleanup expired sessions
        await session_repo.cleanup_expired_sessions()
        
        profiler.stop_profiling()
        
        # Check for memory leaks
        assert not profiler.check_memory_leak(threshold_mb=20.0)


@pytest.mark.performance
@pytest.mark.asyncio
class TestMemoryOptimization:
    """Test memory optimization opportunities."""
    
    async def test_bulk_operations_memory_efficiency(self, db_session):
        """Test bulk operations memory efficiency."""
        profiler = MemoryProfiler()
        user_repo = SQLUserRepository(db_session)
        
        profiler.start_profiling()
        
        # Create users in bulk
        users = []
        for i in range(1000):
            user_builder = UserBuilder()
            user = user_builder.build()
            users.append(user)
            
            if i % 100 == 0:
                profiler._take_snapshot(f"bulk_create_{i}")
        
        # Save all users
        for user in users:
            await user_repo.save(user)
        
        profiler.stop_profiling()
        
        # Check memory efficiency
        stats = profiler.get_memory_stats()
        
        # Should use less than 100MB for 1000 users
        assert stats["total_memory_mb"] < 100.0
        
        # Check memory growth pattern
        comparisons = profiler.compare_snapshots()
        
        # Memory growth should be relatively linear
        for comparison in comparisons[:10]:
            if comparison["size_diff_mb"] > 50.0:  # Sudden spike
                pytest.fail(f"Memory spike detected: {comparison}")
    
    async def test_query_result_memory_efficiency(self, db_session):
        """Test query result memory efficiency."""
        profiler = MemoryProfiler()
        user_repo = SQLUserRepository(db_session)
        
        # Create test users
        users = []
        for i in range(100):
            user_builder = UserBuilder()
            user = user_builder.build()
            await user_repo.save(user)
            users.append(user)
        
        profiler.start_profiling()
        
        # Query all users multiple times
        for i in range(10):
            all_users = await user_repo.find_all()
            assert len(all_users) == 100
            
            profiler._take_snapshot(f"query_{i}")
            
            # Clear reference to help garbage collection
            del all_users
            gc.collect()
        
        profiler.stop_profiling()
        
        # Check memory usage stays stable
        assert not profiler.check_memory_leak(threshold_mb=5.0)
    
    async def test_large_object_memory_handling(self, db_session):
        """Test handling of large objects in memory."""
        profiler = MemoryProfiler()
        user_repo = SQLUserRepository(db_session)
        
        profiler.start_profiling()
        
        # Create user with large profile data
        user_builder = UserBuilder()
        user = user_builder.with_large_profile().build()
        await user_repo.save(user)
        
        # Query the user multiple times
        for i in range(20):
            found_user = await user_repo.find_by_id(user.id)
            assert found_user is not None
            
            if i % 5 == 0:
                profiler._take_snapshot(f"large_query_{i}")
                gc.collect()
        
        profiler.stop_profiling()
        
        # Check memory usage
        stats = profiler.get_memory_stats()
        
        # Should handle large objects efficiently
        assert stats["total_memory_mb"] < 200.0
        
        # Check for memory leaks
        assert not profiler.check_memory_leak(threshold_mb=10.0)


@pytest.mark.performance
@pytest.mark.asyncio
class TestMemoryProfiling:
    """Test memory profiling utilities."""
    
    async def test_memory_snapshot_comparison(self, db_session):
        """Test memory snapshot comparison functionality."""
        profiler = MemoryProfiler()
        user_repo = SQLUserRepository(db_session)
        
        profiler.start_profiling()
        
        # Take baseline snapshot
        profiler._take_snapshot("baseline")
        
        # Perform operations
        for i in range(50):
            user_builder = UserBuilder()
            user = user_builder.build()
            await user_repo.save(user)
        
        # Take final snapshot
        profiler._take_snapshot("final")
        
        profiler.stop_profiling()
        
        # Compare snapshots
        comparisons = profiler.compare_snapshots(start_idx=1, end_idx=2)
        
        # Should have meaningful comparison data
        assert len(comparisons) > 0
        
        # Check that we can identify memory usage patterns
        total_growth = sum(comp["size_diff_mb"] for comp in comparisons)
        assert total_growth > 0  # Should show some memory growth
    
    async def test_memory_stats_collection(self, db_session):
        """Test memory statistics collection."""
        profiler = MemoryProfiler()
        user_repo = SQLUserRepository(db_session)
        
        profiler.start_profiling()
        
        # Perform operations
        user_builder = UserBuilder()
        user = user_builder.build()
        await user_repo.save(user)
        
        profiler.stop_profiling()
        
        # Get memory statistics
        stats = profiler.get_memory_stats()
        
        # Should have complete statistics
        assert "total_memory_mb" in stats
        assert "total_blocks" in stats
        assert "top_memory_consumers" in stats
        assert "process_memory" in stats
        
        # Statistics should be reasonable
        assert stats["total_memory_mb"] > 0
        assert stats["total_blocks"] > 0
        assert len(stats["top_memory_consumers"]) > 0
        assert stats["process_memory"]["rss"] > 0