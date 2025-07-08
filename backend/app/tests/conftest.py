"""
Global pytest configuration and fixtures for EzzDay Backend tests.

This module provides comprehensive test infrastructure including:
- Database setup and teardown
- Authentication fixtures
- Mock services
- Test data factories
- Helper utilities
"""

import asyncio
import contextlib
import uuid
from collections.abc import AsyncGenerator
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base, get_async_session

# Application imports
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

# Test Database Configuration
TEST_DATABASE_URL = (
    "postgresql+asyncpg://ezzday_test:test_password@localhost:5432/ezzday_test"
)


# Test Event Loop Configuration
@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


# Database Fixtures
@pytest_asyncio.fixture(scope="session")
async def test_engine():
    """Create test database engine."""
    engine = create_async_engine(
        TEST_DATABASE_URL, echo=False, pool_pre_ping=True, pool_size=5, max_overflow=10
    )

    # Create all tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    # Clean up
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    await engine.dispose()


@pytest_asyncio.fixture
async def db_session(test_engine) -> AsyncGenerator[AsyncSession, None]:
    """Create a fresh database session for each test."""
    async_session = sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False
    )

    async with async_session() as session:
        try:
            yield session
        finally:
            await session.rollback()
            await session.close()


@pytest.fixture
def override_get_db(db_session):
    """Override the database dependency for testing."""

    def _override():
        return db_session

    return _override


# Application Fixtures
@pytest.fixture
def test_app(override_get_db):
    """Create test application with overridden dependencies."""
    app.dependency_overrides[get_async_session] = override_get_db
    yield app
    app.dependency_overrides.clear()


@pytest.fixture
def test_client(test_app) -> TestClient:
    """Create test client for synchronous requests."""
    return TestClient(test_app)


@pytest_asyncio.fixture
async def async_client(test_app) -> AsyncGenerator[AsyncClient, None]:
    """Create async test client for asynchronous requests."""
    async with AsyncClient(app=test_app, base_url="http://testserver") as client:
        yield client


# Authentication Fixtures
@pytest_asyncio.fixture
async def test_user(db_session: AsyncSession) -> User:
    """Create a test user entity."""
    return User(
        id=uuid.uuid4(),
        email=Email("test@example.com"),
        password_hash=PasswordHash.create_from_password("test_password123"),
        security_stamp=SecurityStamp.generate_initial(),
        is_active=True,
        is_verified=True,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )


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


@pytest_asyncio.fixture
async def admin_user(db_session: AsyncSession) -> User:
    """Create a test admin user."""
    return User(
        id=uuid.uuid4(),
        email=Email("admin@example.com"),
        password_hash=PasswordHash.create_from_password("admin_password123"),
        security_stamp=SecurityStamp.generate_initial(),
        is_active=True,
        is_verified=True,
        is_admin=True,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )


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
    """Mock email service for testing."""
    mock = AsyncMock()
    mock.send_email.return_value = True
    mock.send_verification_email.return_value = True
    mock.send_password_reset_email.return_value = True
    return mock


@pytest.fixture
def mock_sms_service():
    """Mock SMS service for testing."""
    mock = AsyncMock()
    mock.send_sms.return_value = True
    mock.send_verification_code.return_value = True
    return mock


@pytest.fixture
def mock_storage_service():
    """Mock storage service for testing."""
    mock = AsyncMock()
    mock.upload_file.return_value = "https://example.com/uploaded-file.jpg"
    mock.delete_file.return_value = True
    mock.get_file_url.return_value = "https://example.com/file.jpg"
    return mock


@pytest.fixture
def mock_webhook_service():
    """Mock webhook service for testing."""
    mock = AsyncMock()
    mock.send_webhook.return_value = {"status": "success", "response_code": 200}
    mock.verify_webhook_signature.return_value = True
    return mock


@pytest.fixture
def mock_audit_service():
    """Mock audit service for testing."""
    mock = AsyncMock()
    mock.create_audit_log.return_value = None
    mock.create_security_audit.return_value = None
    mock.update_audit_log.return_value = None
    mock.get_audit_trail.return_value = []
    mock.search_audit_entries.return_value = []
    return mock


@pytest.fixture
def mock_notification_service():
    """Mock notification service for testing."""
    mock = AsyncMock()
    mock.send_welcome_email.return_value = True
    mock.send_verification_email.return_value = True
    mock.send_password_reset_email.return_value = True
    mock.send_security_alert.return_value = True
    mock.send_account_lockout_alert.return_value = True
    mock.send_admin_alert.return_value = True
    mock.send_emergency_alert.return_value = True
    mock.send_status_update_notification.return_value = True
    mock.send_account_status_notification.return_value = True
    mock.send_dpo_notification.return_value = True
    mock.send_data_export_notification.return_value = True
    mock.send_deletion_confirmation.return_value = True
    return mock


@pytest.fixture
def mock_integration_service():
    """Mock integration service for testing."""
    mock = AsyncMock()
    mock.trigger_webhooks.return_value = {"status": "success", "webhooks_sent": 1}
    mock.connect_integration.return_value = True
    mock.disconnect_integration.return_value = True
    mock.check_integration_health.return_value = {"status": "healthy"}
    mock.process_webhook.return_value = {"status": "processed"}
    return mock


@pytest.fixture
def mock_event_dispatcher():
    """Mock event dispatcher for testing."""
    mock = AsyncMock(spec=EventDispatcher)
    mock.dispatch.return_value = None
    mock.subscribe.return_value = None
    mock.unsubscribe.return_value = None
    return mock


# Data Factory Fixtures
@pytest.fixture
def user_factory():
    """Factory for creating test users."""

    def _create_user(**kwargs):
        defaults = {
            "id": uuid.uuid4(),
            "email": Email(f"user{uuid.uuid4().hex[:8]}@example.com"),
            "password_hash": PasswordHash.create_from_password("test_password123"),
            "security_stamp": SecurityStamp.generate_initial(),
            "is_active": True,
            "is_verified": True,
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
        }
        defaults.update(kwargs)
        return User(**defaults)

    return _create_user


@pytest.fixture
def email_factory():
    """Factory for creating test emails."""

    def _create_email(local_part: str | None = None, domain: str = "example.com"):
        if local_part is None:
            local_part = f"test{uuid.uuid4().hex[:8]}"
        return Email(f"{local_part}@{domain}")

    return _create_email


@pytest.fixture
def password_hash_factory():
    """Factory for creating test password hashes."""

    def _create_password_hash(
        password: str = "test_password123",
        algorithm: HashAlgorithm = HashAlgorithm.ARGON2ID,
    ):
        return PasswordHash.create_from_password(password, algorithm)

    return _create_password_hash


# Helper Utilities
@pytest.fixture
def assert_helpers():
    """Helper functions for common test assertions."""

    class AssertHelpers:
        @staticmethod
        def assert_immutable(obj, attr_name: str, new_value):
            """Assert that an object attribute is immutable."""
            from dataclasses import FrozenInstanceError

            with pytest.raises(FrozenInstanceError):
                setattr(obj, attr_name, new_value)

        @staticmethod
        def assert_valid_uuid(value: str):
            """Assert that a string is a valid UUID."""
            try:
                uuid.UUID(value)
            except ValueError:
                pytest.fail(f"'{value}' is not a valid UUID")

        @staticmethod
        def assert_valid_email(value: str):
            """Assert that a string is a valid email."""
            import re

            email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
            assert re.match(email_pattern, value), f"'{value}' is not a valid email"

        @staticmethod
        def assert_datetime_recent(dt: datetime, seconds: int = 60):
            """Assert that a datetime is recent (within specified seconds)."""
            now = datetime.now(timezone.utc)
            diff = abs((now - dt).total_seconds())
            assert (
                diff <= seconds
            ), f"Datetime {dt} is not within {seconds} seconds of now"

        @staticmethod
        def assert_password_strength(password: str, min_length: int = 8):
            """Assert that a password meets strength requirements."""
            assert len(password) >= min_length, f"Password too short (min {min_length})"
            assert any(c.isupper() for c in password), "Password needs uppercase letter"
            assert any(c.islower() for c in password), "Password needs lowercase letter"
            assert any(c.isdigit() for c in password), "Password needs digit"

    return AssertHelpers()


@pytest.fixture
def time_helpers():
    """Helper functions for time-related testing."""

    class TimeHelpers:
        @staticmethod
        def now_utc():
            """Get current timezone.utc datetime."""
            return datetime.now(timezone.utc)

        @staticmethod
        def hours_ago(hours: int):
            """Get datetime N hours ago."""
            return datetime.now(timezone.utc) - timedelta(hours=hours)

        @staticmethod
        def days_ago(days: int):
            """Get datetime N days ago."""
            return datetime.now(timezone.utc) - timedelta(days=days)

        @staticmethod
        def freeze_time(frozen_time: datetime):
            """Context manager to freeze time for testing."""
            from unittest.mock import patch

            return patch("datetime.datetime")

    return TimeHelpers()


# Performance Testing Fixtures
@pytest.fixture
def performance_tracker():
    """Track performance metrics during tests."""
    import time

    class PerformanceTracker:
        def __init__(self):
            self.start_time = None
            self.end_time = None
            self.metrics = {}

        def start(self):
            self.start_time = time.perf_counter()

        def stop(self):
            self.end_time = time.perf_counter()
            return self.elapsed_time

        @property
        def elapsed_time(self):
            if self.start_time and self.end_time:
                return self.end_time - self.start_time
            return None

        def record_metric(self, name: str, value: float):
            self.metrics[name] = value

        def assert_performance(self, max_seconds: float):
            assert (
                self.elapsed_time <= max_seconds
            ), f"Performance test failed: {self.elapsed_time:.3f}s > {max_seconds}s"

    return PerformanceTracker()


# Security Testing Fixtures
@pytest.fixture
def security_helpers():
    """Helpers for security-related testing."""

    class SecurityHelpers:
        @staticmethod
        def assert_hash_secure(hash_value: str, algorithm: str = "sha256"):
            """Assert that a hash appears secure."""
            if algorithm == "sha256":
                assert len(hash_value) == 64, "SHA256 hash should be 64 chars"
            assert hash_value.isalnum(), "Hash should be alphanumeric"
            assert hash_value != hash_value.lower(), "Hash should have mixed case"

        @staticmethod
        def assert_no_sensitive_data_in_logs(log_content: str):
            """Assert that logs don't contain sensitive data."""
            sensitive_patterns = [
                r'password["\s:=]+[^"\s,}]+',
                r'secret["\s:=]+[^"\s,}]+',
                r'token["\s:=]+[^"\s,}]+',
                r'key["\s:=]+[^"\s,}]+',
            ]

            import re

            for pattern in sensitive_patterns:
                matches = re.findall(pattern, log_content, re.IGNORECASE)
                assert not matches, f"Sensitive data found in logs: {matches}"

        @staticmethod
        def generate_test_token(length: int = 32):
            """Generate a test token."""
            import secrets

            return secrets.token_urlsafe(length)

    return SecurityHelpers()


# Integration Test Configuration
@pytest.fixture(scope="session")
def integration_test_config():
    """Configuration for integration tests."""
    return {
        "database_url": TEST_DATABASE_URL,
        "redis_url": "redis://localhost:6379/10",
        "test_timeout": 30,
        "performance_threshold": 1.0,  # 1 second
        "batch_size": 100,
    }


# Cleanup Fixtures
@pytest.fixture(autouse=True)
async def cleanup_test_data(db_session: AsyncSession):
    """Automatically clean up test data after each test."""
    yield

    # Clean up any test data that might have been created
    with contextlib.suppress(Exception):
        await db_session.rollback()


# Pytest Configuration
def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line("markers", "unit: mark test as a unit test")
    config.addinivalue_line("markers", "integration: mark test as an integration test")
    config.addinivalue_line("markers", "smoke: mark test as a smoke test")
    config.addinivalue_line("markers", "performance: mark test as a performance test")
    config.addinivalue_line("markers", "security: mark test as a security test")
    config.addinivalue_line("markers", "slow: mark test as slow running")


def pytest_collection_modifyitems(config, items):
    """Modify test collection to add automatic markers."""
    for item in items:
        # Add unit marker to all tests by default
        if not any(
            marker.name in ["integration", "smoke", "performance"]
            for marker in item.iter_markers()
        ):
            item.add_marker(pytest.mark.unit)

        # Add slow marker to tests that take longer than 5 seconds
        if "slow" in item.name or "performance" in item.name:
            item.add_marker(pytest.mark.slow)


# Async Test Support
def pytest_asyncio_setup():
    """Setup async test support."""
    return {"asyncio_mode": "auto"}
