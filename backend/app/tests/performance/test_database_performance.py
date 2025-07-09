"""
Database Performance Tests

Tests database operation performance against established baselines.
"""


import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

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
from app.tests.performance.performance_baselines import (
    LoadTestScenario,
    PerformanceMonitor,
)


@pytest.mark.performance
@pytest.mark.asyncio
class TestUserRepositoryPerformance:
    """Test user repository performance."""
    
    async def test_user_query_performance_baseline(self, db_session: AsyncSession):
        """Test user query meets performance baseline."""
        monitor = PerformanceMonitor()
        user_repo = SQLUserRepository(db_session)
        
        # Create test user
        user_builder = UserBuilder()
        user = user_builder.build()
        await user_repo.save(user)
        
        # Test user query performance
        with monitor.measure_performance("db_user_query"):
            found_user = await user_repo.find_by_id(user.id)
        
        assert found_user is not None
        
        # Assert performance baseline
        metrics = monitor.get_metrics("db_user_query")[0]
        monitor.assert_performance_baseline("db_user_query", metrics)
    
    async def test_user_insert_performance_baseline(self, db_session: AsyncSession):
        """Test user insert meets performance baseline."""
        monitor = PerformanceMonitor()
        user_repo = SQLUserRepository(db_session)
        
        # Create test user
        user_builder = UserBuilder()
        user = user_builder.build()
        
        # Test user insert performance
        with monitor.measure_performance("db_user_insert"):
            await user_repo.save(user)
        
        # Assert performance baseline
        metrics = monitor.get_metrics("db_user_insert")[0]
        monitor.assert_performance_baseline("db_user_insert", metrics)
    
    async def test_user_update_performance_baseline(self, db_session: AsyncSession):
        """Test user update meets performance baseline."""
        monitor = PerformanceMonitor()
        user_repo = SQLUserRepository(db_session)
        
        # Create and save test user
        user_builder = UserBuilder()
        user = user_builder.build()
        await user_repo.save(user)
        
        # Modify user
        user.update_profile(name="Updated Name")
        
        # Test user update performance
        with monitor.measure_performance("db_user_update"):
            await user_repo.save(user)
        
        # Assert performance baseline
        metrics = monitor.get_metrics("db_user_update")[0]
        monitor.assert_performance_baseline("db_user_update", metrics)
    
    async def test_user_delete_performance_baseline(self, db_session: AsyncSession):
        """Test user delete meets performance baseline."""
        monitor = PerformanceMonitor()
        user_repo = SQLUserRepository(db_session)
        
        # Create and save test user
        user_builder = UserBuilder()
        user = user_builder.build()
        await user_repo.save(user)
        
        # Test user delete performance
        with monitor.measure_performance("db_user_delete"):
            await user_repo.delete(user.id)
        
        # Assert performance baseline
        metrics = monitor.get_metrics("db_user_delete")[0]
        monitor.assert_performance_baseline("db_user_delete", metrics)
    
    async def test_user_repository_load_test(self, db_session: AsyncSession):
        """Test user repository under load."""
        scenario = LoadTestScenario("User Repository Load", concurrent_users=20, duration_seconds=30)
        user_repo = SQLUserRepository(db_session)
        
        async def user_operations():
            # Create user
            user_builder = UserBuilder()
            user = user_builder.build()
            await user_repo.save(user)
            
            # Query user
            found_user = await user_repo.find_by_id(user.id)
            assert found_user is not None
            
            # Update user
            user.update_profile(name="Updated Name")
            await user_repo.save(user)
            
            # Delete user
            await user_repo.delete(user.id)
        
        # Run load test
        await scenario.run_load_test(user_operations)
        
        # Analyze results
        summary = scenario.get_load_test_summary()
        
        # Assert reasonable performance under load
        assert summary["requests_per_second"] >= 10  # Minimum threshold
        assert summary["response_time"]["p95"] <= 1.0  # 95% under 1 second


@pytest.mark.performance
@pytest.mark.asyncio
class TestRoleRepositoryPerformance:
    """Test role repository performance."""
    
    async def test_role_query_performance_baseline(self, db_session: AsyncSession):
        """Test role query meets performance baseline."""
        monitor = PerformanceMonitor()
        role_repo = SQLRoleRepository(db_session)
        
        # Create test role
        role_builder = RoleBuilder()
        role = role_builder.build()
        await role_repo.save(role)
        
        # Test role query performance
        with monitor.measure_performance("db_role_query"):
            found_role = await role_repo.find_by_id(role.id)
        
        assert found_role is not None
        
        # Assert performance baseline
        metrics = monitor.get_metrics("db_role_query")[0]
        # Use user query baseline as proxy for role query
        monitor.assert_performance_baseline("db_user_query", metrics)
    
    async def test_role_permission_assignment_performance(self, db_session: AsyncSession):
        """Test role permission assignment performance."""
        monitor = PerformanceMonitor()
        role_repo = SQLRoleRepository(db_session)
        
        # Create test role
        role_builder = RoleBuilder()
        role = role_builder.build()
        await role_repo.save(role)
        
        # Test permission assignment performance
        with monitor.measure_performance("role_assign"):
            await role_repo.add_permission(role.id, "user:read")
        
        # Assert performance baseline
        metrics = monitor.get_metrics("role_assign")[0]
        monitor.assert_performance_baseline("role_assign", metrics)


@pytest.mark.performance
@pytest.mark.asyncio
class TestSessionRepositoryPerformance:
    """Test session repository performance."""
    
    async def test_session_query_performance_baseline(self, db_session: AsyncSession):
        """Test session query meets performance baseline."""
        monitor = PerformanceMonitor()
        session_repo = SQLSessionRepository(db_session)
        
        # Create test session
        session_builder = SessionBuilder()
        session = session_builder.build()
        await session_repo.save(session)
        
        # Test session query performance
        with monitor.measure_performance("db_session_query"):
            found_session = await session_repo.find_by_id(session.id)
        
        assert found_session is not None
        
        # Assert performance baseline
        metrics = monitor.get_metrics("db_session_query")[0]
        # Use user query baseline as proxy for session query
        monitor.assert_performance_baseline("db_user_query", metrics)
    
    async def test_session_cleanup_performance(self, db_session: AsyncSession):
        """Test session cleanup performance."""
        monitor = PerformanceMonitor()
        session_repo = SQLSessionRepository(db_session)
        
        # Create multiple expired sessions
        for i in range(100):
            session_builder = SessionBuilder()
            session = session_builder.expired().build()
            await session_repo.save(session)
        
        # Test session cleanup performance
        with monitor.measure_performance("db_session_cleanup"):
            await session_repo.cleanup_expired_sessions()
        
        # Assert performance baseline
        metrics = monitor.get_metrics("db_session_cleanup")[0]
        # Use batch operation baseline as proxy
        monitor.assert_performance_baseline("batch_user_import", metrics)


@pytest.mark.performance
@pytest.mark.asyncio
class TestDatabaseQueryPerformance:
    """Test raw database query performance."""
    
    async def test_simple_query_performance(self, db_session: AsyncSession):
        """Test simple database query performance."""
        monitor = PerformanceMonitor()
        
        # Test simple query performance
        with monitor.measure_performance("db_simple_query"):
            result = await db_session.execute(text("SELECT 1"))
            assert result.scalar() == 1
        
        # Assert performance baseline
        metrics = monitor.get_metrics("db_simple_query")[0]
        # Should be much faster than user query
        assert metrics.response_time < 0.01  # 10ms
    
    async def test_complex_join_query_performance(self, db_session: AsyncSession):
        """Test complex join query performance."""
        monitor = PerformanceMonitor()
        
        # Create test data
        user_builder = UserBuilder()
        user = user_builder.build()
        user_repo = SQLUserRepository(db_session)
        await user_repo.save(user)
        
        role_builder = RoleBuilder()
        role = role_builder.build()
        role_repo = SQLRoleRepository(db_session)
        await role_repo.save(role)
        
        # Test complex join query performance
        with monitor.measure_performance("db_complex_query"):
            query = text("""
                SELECT u.id, u.email, r.name as role_name
                FROM users u
                LEFT JOIN user_roles ur ON u.id = ur.user_id
                LEFT JOIN roles r ON ur.role_id = r.id
                WHERE u.is_active = true
                ORDER BY u.created_at DESC
                LIMIT 10
            """)
            result = await db_session.execute(query)
            rows = result.fetchall()
        
        # Assert performance baseline
        metrics = monitor.get_metrics("db_complex_query")[0]
        # Should be similar to user query performance
        assert metrics.response_time < 0.1  # 100ms
    
    async def test_database_connection_performance(self, db_session: AsyncSession):
        """Test database connection performance."""
        monitor = PerformanceMonitor()
        
        # Test connection performance
        with monitor.measure_performance("db_connection"):
            # Test multiple queries to check connection overhead
            for i in range(10):
                result = await db_session.execute(text("SELECT :val"), {"val": i})
                assert result.scalar() == i
        
        # Assert performance baseline
        metrics = monitor.get_metrics("db_connection")[0]
        # Should be fast for connection pooling
        assert metrics.response_time < 0.05  # 50ms for 10 queries


@pytest.mark.performance
@pytest.mark.asyncio
class TestDatabaseLoadPerformance:
    """Test database performance under load."""
    
    async def test_concurrent_read_performance(self, db_session: AsyncSession):
        """Test concurrent read performance."""
        scenario = LoadTestScenario("Concurrent Reads", concurrent_users=50, duration_seconds=30)
        
        # Create test data
        user_repo = SQLUserRepository(db_session)
        user_builder = UserBuilder()
        test_user = user_builder.build()
        await user_repo.save(test_user)
        
        async def read_operation():
            found_user = await user_repo.find_by_id(test_user.id)
            return found_user is not None
        
        # Run load test
        await scenario.run_load_test(read_operation)
        
        # Analyze results
        summary = scenario.get_load_test_summary()
        
        # Assert reasonable performance under concurrent reads
        assert summary["requests_per_second"] >= 100  # Minimum threshold
        assert summary["response_time"]["p95"] <= 0.1  # 95% under 100ms
    
    async def test_concurrent_write_performance(self, db_session: AsyncSession):
        """Test concurrent write performance."""
        scenario = LoadTestScenario("Concurrent Writes", concurrent_users=20, duration_seconds=30)
        user_repo = SQLUserRepository(db_session)
        
        async def write_operation():
            user_builder = UserBuilder()
            user = user_builder.build()
            await user_repo.save(user)
            return True
        
        # Run load test
        await scenario.run_load_test(write_operation)
        
        # Analyze results
        summary = scenario.get_load_test_summary()
        
        # Assert reasonable performance under concurrent writes
        assert summary["requests_per_second"] >= 50  # Minimum threshold
        assert summary["response_time"]["p95"] <= 0.2  # 95% under 200ms
    
    async def test_mixed_read_write_performance(self, db_session: AsyncSession):
        """Test mixed read/write performance."""
        scenario = LoadTestScenario("Mixed Read/Write", concurrent_users=30, duration_seconds=60)
        user_repo = SQLUserRepository(db_session)
        
        # Create some test data
        test_users = []
        for i in range(10):
            user_builder = UserBuilder()
            user = user_builder.build()
            await user_repo.save(user)
            test_users.append(user)
        
        async def mixed_operation():
            import random
            
            if random.random() < 0.7:  # 70% reads
                user = random.choice(test_users)
                found_user = await user_repo.find_by_id(user.id)
                return found_user is not None
            # 30% writes
            user_builder = UserBuilder()
            user = user_builder.build()
            await user_repo.save(user)
            return True
        
        # Run load test
        await scenario.run_load_test(mixed_operation)
        
        # Analyze results
        summary = scenario.get_load_test_summary()
        
        # Assert reasonable performance under mixed load
        assert summary["requests_per_second"] >= 75  # Minimum threshold
        assert summary["response_time"]["p95"] <= 0.15  # 95% under 150ms