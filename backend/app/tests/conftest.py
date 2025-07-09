"""
Global pytest configuration and fixtures for all tests.

Provides:
- Database fixtures
- Mock services
- Test utilities
- Common test data
"""

import pytest
import asyncio
from typing import AsyncGenerator, Generator
from datetime import datetime, UTC
from unittest.mock import Mock, AsyncMock

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import NullPool

from app.core.database import Base, get_db
from app.core.config import get_settings
from app.main import app
from app.modules.identity.domain.entities.user import User
from app.modules.identity.domain.value_objects.email import Email
from app.modules.identity.domain.value_objects.password_hash import (
    HashAlgorithm,
    PasswordHash,
)
from app.modules.identity.domain.value_objects.security_stamp import SecurityStamp
from app.modules.identity.infrastructure.models.user_model import UserModel
from app.shared.domain.events.event_dispatcher import EventDispatcher

# Test data builders - ADDED: Eliminate hardcoded test data
from app.tests.builders import UserBuilder, SessionBuilder, EmailBuilder
from app.tests.builders.user_builder import UserMother
from app.tests.builders.session_builder import SessionMother

# Test Database Configuration
TEST_DATABASE_URL = (
    "postgresql+asyncpg://ezzday_test:test_password@localhost:5432/ezzday_test"
)


# Test database URL
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest.fixture(scope="session")
def event_loop() -> Generator:
    """Create event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
async def test_engine():
    """Create test database engine."""
    engine = create_async_engine(
        TEST_DATABASE_URL,
        echo=False,
        poolclass=NullPool,
    )
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    yield engine
    
    await engine.dispose()


@pytest.fixture(scope="function")
async def db_session(test_engine) -> AsyncGenerator[AsyncSession, None]:
    """Create database session for tests."""
    async_session = async_sessionmaker(
        test_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )
    
    async with async_session() as session:
        yield session
        await session.rollback()


@pytest.fixture(scope="function")
async def client(db_session):
    """Create test client with database override."""
    async def override_get_db():
        yield db_session
    
    app.dependency_overrides[get_db] = override_get_db
    
    from httpx import AsyncClient
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac
    
    app.dependency_overrides.clear()


# Mock service fixtures


@pytest_asyncio.fixture
async def async_client(test_app) -> AsyncGenerator[AsyncClient, None]:
    """Create async test client for asynchronous requests."""
    async with AsyncClient(app=test_app, base_url="http://testserver") as client:
        yield client


# Authentication Fixtures - FIXED: No hardcoded test data
@pytest.fixture
def test_user() -> User:
    """Create a test user entity with unique data."""
    return UserMother.active_verified_user()


@pytest_asyncio.fixture
async def test_user_model(db_session: AsyncSession, test_user: User) -> UserModel:
    """Create and persist a test user model in database."""
    user_model = UserModel(
        id=test_user.id,
        email=test_user.email.value,
        password_hash=test_user.password_hash.to_string(),
        security_stamp=test_user.security_stamp.value,
        is_active=test_user.is_active,
        is_verified=test_user.is_verified,
        created_at=test_user.created_at,
        updated_at=test_user.updated_at,
    )

    db_session.add(user_model)
    await db_session.commit()
    await db_session.refresh(user_model)

    return user_model


@pytest.fixture
def admin_user() -> User:
    """Create a test admin user with unique data."""
    return UserMother.admin_user()


@pytest.fixture
def auth_headers(test_user: User) -> dict[str, str]:
    """Create authentication headers for test requests."""
    # Mock JWT token generation
    token = f"Bearer test_token_for_{test_user.id}"
    return {"Authorization": token, "Content-Type": "application/json"}


@pytest.fixture
def admin_auth_headers(admin_user: User) -> dict[str, str]:
    """Create admin authentication headers for test requests."""
    token = f"Bearer admin_token_for_{admin_user.id}"
    return {"Authorization": token, "Content-Type": "application/json"}


# Mock Service Fixtures
@pytest.fixture
def mock_email_service():
    """Create mock email service."""
    service = AsyncMock()
    service.send_verification_email.return_value = None
    service.send_password_reset_email.return_value = None
    service.send_welcome_email.return_value = None
    service.send_security_alert.return_value = None
    return service


@pytest.fixture
def mock_sms_service():
    """Create mock SMS service."""
    service = AsyncMock()
    service.send_verification_code.return_value = None
    service.send_mfa_code.return_value = None
    service.send_security_alert.return_value = None
    return service


@pytest.fixture
def mock_cache_service():
    """Create mock cache service."""
    service = AsyncMock()
    cache_data = {}
    
    async def get(key: str):
        return cache_data.get(key)
    
    async def set(key: str, value: any, ttl: int = None):
        cache_data[key] = value
        return True
    
    async def delete(key: str):
        cache_data.pop(key, None)
        return True
    
    service.get = get
    service.set = set
    service.delete = delete
    service.exists = AsyncMock(side_effect=lambda k: k in cache_data)
    
    return service


@pytest.fixture
def mock_event_bus():
    """Create mock event bus."""
    bus = AsyncMock()
    events = []
    
    async def publish(event):
        events.append(event)
    
    async def publish_batch(batch):
        events.extend(batch)
    
    bus.publish = publish
    bus.publish_batch = publish_batch
    bus.get_events = lambda: events
    bus.clear = lambda: events.clear()
    
    return bus


@pytest.fixture
def mock_token_service():
    """Create mock token service."""
    service = Mock()
    service.generate_access_token = Mock(return_value="test_access_token")
    service.generate_refresh_token = Mock(return_value="test_refresh_token")
    service.generate_verification_token = Mock(return_value="test_verification_token")
    service.validate_token = Mock(return_value={"user_id": "test_user_id", "exp": 9999999999})
    return service


@pytest.fixture
def mock_password_service():
    """Create mock password service."""
    service = Mock()
    service.hash_password = Mock(return_value="hashed_password")
    service.verify_password = Mock(return_value=True)
    service.validate_password = Mock(return_value=True)
    service.generate_random_password = Mock(return_value="RandomPass123!")
    return service


# Test data factories


@pytest.fixture
def mock_event_dispatcher():
    """Mock event dispatcher for testing."""
    mock = AsyncMock(spec=EventDispatcher)
    mock.dispatch.return_value = None
    mock.subscribe.return_value = None
    mock.unsubscribe.return_value = None
    return mock


# Test Data Builder Fixtures - FIXED: Use proper builders
@pytest.fixture
def user_builder():
    """Provide UserBuilder for test customization."""
    return UserBuilder


@pytest.fixture
def session_builder():
    """Provide SessionBuilder for test customization."""
    return SessionBuilder


@pytest.fixture
def email_builder():
    """Provide EmailBuilder for unique emails."""
    return EmailBuilder


@pytest.fixture
def user_mother():
    """Provide UserMother for common scenarios."""
    return UserMother


@pytest.fixture
def session_mother():
    """Provide SessionMother for common scenarios."""
    return SessionMother


@pytest.fixture
def session_factory():
    """Factory for creating test sessions."""
    from app.modules.identity.domain.entities.session import Session
    from app.modules.identity.domain.value_objects.user_id import UserId
    
    def create_session(
        user_id: str = None,
        token: str = "test_token",
        **kwargs
    ) -> Session:
        return Session.create(
            user_id=UserId(user_id or "test_user_id"),
            access_token=token,
            refresh_token=f"refresh_{token}",
            expires_at=datetime.now(UTC).timestamp() + 3600,
            **kwargs
        )
    
    return create_session


# Test utilities

@pytest.fixture
def auth_headers():
    """Create authorization headers for authenticated requests."""
    def _auth_headers(token: str = "test_access_token") -> dict:
        return {"Authorization": f"Bearer {token}"}
    return _auth_headers


@pytest.fixture
def graphql_client(client):
    """Create GraphQL-specific test client."""
    class GraphQLClient:
        def __init__(self, http_client):
            self.client = http_client
        
        async def query(self, query: str, variables: dict = None, headers: dict = None):
            response = await self.client.post(
                "/graphql",
                json={"query": query, "variables": variables or {}},
                headers=headers or {}
            )
            return response.json()
        
        async def mutate(self, mutation: str, variables: dict = None, headers: dict = None):
            return await self.query(mutation, variables, headers)
    
    return GraphQLClient(client)


# Performance testing utilities

@pytest.fixture
def benchmark_async():
    """Async-compatible benchmark fixture."""
    import time
    
    class AsyncBenchmark:
        def __init__(self):
            self.results = []
        
        async def __call__(self, func, *args, **kwargs):
            start = time.perf_counter()
            result = await func(*args, **kwargs)
            end = time.perf_counter()
            
            self.results.append(end - start)
            return result
        
        @property
        def stats(self):
            if not self.results:
                return {}
            
            return {
                "min": min(self.results),
                "max": max(self.results),
                "mean": sum(self.results) / len(self.results),
                "total": sum(self.results),
                "iterations": len(self.results)
            }
    
    return AsyncBenchmark()


# Database helpers

@pytest.fixture
async def clean_db(db_session):
    """Clean database before and after test."""
    # Clean before test
    for table in reversed(Base.metadata.sorted_tables):
        await db_session.execute(table.delete())
    await db_session.commit()
    
    yield db_session
    
    # Clean after test
    for table in reversed(Base.metadata.sorted_tables):
        await db_session.execute(table.delete())
    await db_session.commit()


# Common test data

@pytest.fixture
def test_users_data():
    """Common test user data."""
    return [
        {
            "email": "alice@example.com",
            "username": "alice",
            "password": "AlicePass123!",
            "first_name": "Alice",
            "last_name": "Smith",
        },
        {
            "email": "bob@example.com",
            "username": "bob",
            "password": "BobPass123!",
            "first_name": "Bob",
            "last_name": "Johnson",
        },
        {
            "email": "charlie@example.com",
            "username": "charlie",
            "password": "CharliePass123!",
            "first_name": "Charlie",
            "last_name": "Brown",
        },
    ]


@pytest.fixture
def test_permissions_data():
    """Common test permissions data."""
    return [
        {"code": "users.read", "name": "Read Users", "resource": "users", "action": "read"},
        {"code": "users.write", "name": "Write Users", "resource": "users", "action": "write"},
        {"code": "users.delete", "name": "Delete Users", "resource": "users", "action": "delete"},
        {"code": "admin.all", "name": "Admin All", "resource": "*", "action": "*"},
    ]


# Markers for test categorization

def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line("markers", "unit: Unit tests")
    config.addinivalue_line("markers", "integration: Integration tests")
    config.addinivalue_line("markers", "e2e: End-to-end tests")
    config.addinivalue_line("markers", "slow: Slow running tests")
    config.addinivalue_line("markers", "security: Security-related tests")
    config.addinivalue_line("markers", "performance: Performance tests")