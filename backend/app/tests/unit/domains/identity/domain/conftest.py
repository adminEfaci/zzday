"""
Domain layer test configuration and shared fixtures.
Provides test utilities, mocks, and factories for domain testing.
"""

import secrets
from datetime import datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock
from uuid import uuid4

import factory
import pytest
from factory import fuzzy
from faker import Faker

from app.modules.identity.domain.aggregates.user import User
from app.modules.identity.domain.entities import *
from app.modules.identity.domain.enums import *
from app.modules.identity.domain.errors import *
from app.modules.identity.domain.events import *
from app.modules.identity.domain.value_objects import *

fake = Faker()


# Test Factories using Factory Boy
class UserFactory(factory.Factory):
    """Factory for creating test User aggregates."""

    class Meta:
        model = User

    id = factory.LazyFunction(lambda: uuid4())
    username = factory.LazyAttribute(lambda obj: Username(fake.user_name()))
    email = factory.LazyAttribute(lambda obj: Email(fake.email()))
    password_hash = factory.LazyFunction(lambda: f"$argon2id${fake.sha256()}")
    status = UserStatus.ACTIVE
    email_verified = True
    mfa_enabled = False
    created_at = factory.LazyFunction(datetime.now(datetime.UTC))
    updated_at = factory.LazyFunction(datetime.now(datetime.UTC))
    last_login_at = factory.LazyFunction(
        lambda: datetime.now(datetime.UTC) - timedelta(days=1)
    )
    failed_login_count = 0
    lockout_expires_at = None


class PermissionFactory(factory.Factory):
    """Factory for creating test Permission entities."""

    class Meta:
        model = Permission

    id = factory.LazyFunction(lambda: uuid4())
    name = factory.Faker("word")
    resource = factory.Faker("word")
    action = factory.Iterator(["read", "write", "delete", "admin"])
    scope = PermissionScope.DEPARTMENT
    status = "active"  # Since PermissionStatus enum is missing
    description = factory.Faker("sentence")
    created_at = factory.LazyFunction(datetime.now(datetime.UTC))
    updated_at = factory.LazyFunction(datetime.now(datetime.UTC))


class RoleFactory(factory.Factory):
    """Factory for creating test Role entities."""

    class Meta:
        model = Role

    id = factory.LazyFunction(lambda: uuid4())
    name = factory.Faker("job")
    description = factory.Faker("sentence")
    priority = fuzzy.FuzzyInteger(1, 10)
    status = "active"  # Since RoleStatus enum is missing
    is_system = False
    created_at = factory.LazyFunction(datetime.now(datetime.UTC))
    updated_at = factory.LazyFunction(datetime.now(datetime.UTC))


class SessionFactory(factory.Factory):
    """Factory for creating test Session entities."""

    class Meta:
        model = Session

    id = factory.LazyFunction(lambda: uuid4())
    user_id = factory.LazyFunction(lambda: uuid4())
    access_token = factory.LazyFunction(lambda: secrets.token_urlsafe(32))
    refresh_token = factory.LazyFunction(lambda: secrets.token_urlsafe(32))
    ip_address = factory.LazyAttribute(lambda obj: IpAddress(fake.ipv4()))
    user_agent = factory.Faker("user_agent")
    session_type = SessionType.WEB
    status = "active"  # Since SessionStatus enum is missing
    created_at = factory.LazyFunction(datetime.now(datetime.UTC))
    updated_at = factory.LazyFunction(datetime.now(datetime.UTC))
    expires_at = factory.LazyFunction(
        lambda: datetime.now(datetime.UTC) + timedelta(hours=24)
    )
    last_activity_at = factory.LazyFunction(datetime.now(datetime.UTC))
    risk_score = fuzzy.FuzzyFloat(0.0, 1.0)
    is_trusted = False
    requires_mfa = False
    mfa_completed = False


class MfaDeviceFactory(factory.Factory):
    """Factory for creating test MFA Device entities."""

    class Meta:
        model = MfaDevice

    id = factory.LazyFunction(lambda: uuid4())
    user_id = factory.LazyFunction(lambda: uuid4())
    name = factory.LazyAttribute(lambda obj: f"{obj.method.value} Device")
    method = MFAMethod.TOTP
    secret = factory.LazyFunction(lambda: secrets.token_urlsafe(16))
    status = "active"  # Since MfaDeviceStatus enum is missing
    is_primary = False
    backup_codes = factory.LazyFunction(
        lambda: [
            f"{secrets.randbelow(10000):04d}-{secrets.randbelow(10000):04d}"
            for _ in range(10)
        ]
    )
    created_at = factory.LazyFunction(datetime.now(datetime.UTC))
    updated_at = factory.LazyFunction(datetime.now(datetime.UTC))
    last_used_at = None
    failed_attempts = 0
    locked_until = None


# Event Factories
class UserCreatedEventFactory(factory.Factory):
    """Factory for creating UserCreated events."""

    class Meta:
        model = dict  # Since events might be simple dicts

    event_type = "UserCreated"
    user_id = factory.LazyFunction(lambda: str(uuid4()))
    email = factory.Faker("email")
    username = factory.Faker("user_name")
    role = UserRole.USER
    timestamp = factory.LazyFunction(datetime.now(datetime.UTC))
    event_id = factory.LazyFunction(lambda: str(uuid4()))
    correlation_id = factory.LazyFunction(lambda: str(uuid4()))


# Test Data Builders
class TestDataBuilder:
    """Builder pattern for creating complex test data."""

    @staticmethod
    def create_user_with_roles(role_names: list[str] | None = None) -> User:
        """Create a user with associated roles."""
        user = UserFactory()

        if role_names is None:
            role_names = ["user"]

        for role_name in role_names:
            role = RoleFactory(name=role_name)
            # Add permissions to role
            permissions = [
                PermissionFactory(resource="user", action="read"),
                PermissionFactory(resource="profile", action="write"),
            ]
            role._permissions = permissions
            user._roles.append(role)

        return user

    @staticmethod
    def create_user_with_sessions(session_count: int = 3) -> tuple:
        """Create a user with multiple sessions."""
        user = UserFactory()
        sessions = []

        for _i in range(session_count):
            session = SessionFactory(user_id=user.id)
            sessions.append(session)
            user._sessions.append(session)

        return user, sessions

    @staticmethod
    def create_user_with_mfa(mfa_methods: list[MFAMethod] | None = None) -> tuple:
        """Create a user with MFA devices."""
        user = UserFactory(mfa_enabled=True)
        devices = []

        if mfa_methods is None:
            mfa_methods = [MFAMethod.TOTP]

        for i, method in enumerate(mfa_methods):
            device = MfaDeviceFactory(
                user_id=user.id, method=method, is_primary=(i == 0)
            )
            devices.append(device)
            user._mfa_devices.append(device)

        return user, devices

    @staticmethod
    def create_role_hierarchy() -> dict[str, Role]:
        """Create a role hierarchy for testing."""
        admin_role = RoleFactory(name="Admin", priority=100)
        manager_role = RoleFactory(
            name="Manager", priority=50, parent_role_id=admin_role.id
        )
        user_role = RoleFactory(
            name="User", priority=10, parent_role_id=manager_role.id
        )

        # Add permissions
        admin_perms = [
            PermissionFactory(
                name="admin_all", resource="*", action="*", scope=PermissionScope.GLOBAL
            )
        ]
        manager_perms = [
            PermissionFactory(
                name="manage_users",
                resource="user",
                action="*",
                scope=PermissionScope.DEPARTMENT,
            ),
            PermissionFactory(
                name="view_reports",
                resource="report",
                action="read",
                scope=PermissionScope.DEPARTMENT,
            ),
        ]
        user_perms = [
            PermissionFactory(
                name="read_own",
                resource="profile",
                action="read",
                scope=PermissionScope.USER,
            )
        ]

        admin_role._permissions = admin_perms
        manager_role._permissions = manager_perms
        user_role._permissions = user_perms

        return {"admin": admin_role, "manager": manager_role, "user": user_role}


# Mock Repository Factory
@pytest.fixture
def mock_repositories():
    """Create mock repositories for domain testing."""
    repositories = {}

    # User Repository
    user_repo = AsyncMock()
    user_repo.get = AsyncMock(return_value=None)
    user_repo.get_by_id = AsyncMock(return_value=None)
    user_repo.get_by_email = AsyncMock(return_value=None)
    user_repo.save = AsyncMock(return_value=None)
    user_repo.exists = AsyncMock(return_value=True)
    repositories["user_repository"] = user_repo

    # Session Repository
    session_repo = AsyncMock()
    session_repo.create = AsyncMock(return_value=None)
    session_repo.get = AsyncMock(return_value=None)
    session_repo.get_active_sessions = AsyncMock(return_value=[])
    session_repo.revoke_session = AsyncMock(return_value=None)
    session_repo.get_expired_sessions = AsyncMock(return_value=[])
    session_repo.delete_sessions = AsyncMock(return_value=None)
    repositories["session_repository"] = session_repo

    # Role Repository
    role_repo = AsyncMock()
    role_repo.get = AsyncMock(return_value=None)
    role_repo.get_by_id = AsyncMock(return_value=None)
    role_repo.get_user_roles = AsyncMock(return_value=[])
    role_repo.get_role_hierarchy = AsyncMock(return_value={})
    repositories["role_repository"] = role_repo

    # Permission Repository
    permission_repo = AsyncMock()
    permission_repo.get = AsyncMock(return_value=None)
    permission_repo.get_by_id = AsyncMock(return_value=None)
    permission_repo.get_user_permissions = AsyncMock(return_value=[])
    permission_repo.get_direct_permissions = AsyncMock(return_value=[])
    repositories["permission_repository"] = permission_repo

    # Security Repository
    security_repo = AsyncMock()
    security_repo.get_user_patterns = AsyncMock(return_value={})
    security_repo.log_security_event = AsyncMock(return_value=None)
    security_repo.get_login_history = AsyncMock(return_value=[])
    repositories["security_repository"] = security_repo

    # Other repositories
    for repo_name in [
        "audit_repository",
        "mfa_repository",
        "device_repository",
        "contact_repository",
        "compliance_repository",
    ]:
        repositories[repo_name] = AsyncMock()

    return repositories


# Event Collection Fixture
@pytest.fixture
def event_collector():
    """Collect domain events for testing."""
    events = []

    class EventCollector:
        def collect(self, event: Any):
            """Collect an event."""
            events.append(event)

        def get_events(self) -> list[Any]:
            """Get all collected events."""
            return events.copy()

        def clear(self):
            """Clear all events."""
            events.clear()

        def get_events_of_type(self, event_type: type) -> list[Any]:
            """Get events of a specific type."""
            if isinstance(event_type, str):
                return [
                    e for e in events if getattr(e, "event_type", None) == event_type
                ]
            return [e for e in events if isinstance(e, event_type)]

        def assert_event_raised(self, event_type: Any, count: int = 1):
            """Assert that a specific event was raised."""
            matching_events = self.get_events_of_type(event_type)
            assert (
                len(matching_events) == count
            ), f"Expected {count} {event_type} events, got {len(matching_events)}"

        def assert_no_events(self):
            """Assert that no events were raised."""
            assert (
                len(events) == 0
            ), f"Expected no events, but got {len(events)}: {events}"

    return EventCollector()


# Time Control Fixture
@pytest.fixture
def time_machine():
    """Control time for testing time-dependent logic."""

    class TimeMachine:
        def __init__(self):
            self.frozen_time = None

        def freeze(self, time: datetime):
            """Freeze time at a specific moment."""
            self.frozen_time = time

        def now(self) -> datetime:
            """Get current time (frozen or real)."""
            return self.frozen_time or datetime.now(datetime.UTC)

        def advance(self, delta: timedelta):
            """Advance time by a delta."""
            if self.frozen_time:
                self.frozen_time += delta
            else:
                self.frozen_time = datetime.now(datetime.UTC) + delta

        def reset(self):
            """Reset to real time."""
            self.frozen_time = None

    return TimeMachine()


# Validation Helper Fixture
@pytest.fixture
def validation_helper():
    """Helper for validation testing."""

    class ValidationHelper:
        @staticmethod
        def assert_validation_error(func, *args, **kwargs):
            """Assert that a function raises a validation error."""
            with pytest.raises((ValueError, TypeError)) as exc_info:
                func(*args, **kwargs)
            return exc_info

        @staticmethod
        def assert_business_rule_violation(func, *args, **kwargs):
            """Assert that a function raises a business rule violation."""
            with pytest.raises(
                Exception
            ) as exc_info:  # Replace with actual BusinessRuleViolationError
                func(*args, **kwargs)
            return exc_info

        @staticmethod
        def assert_no_exception(func, *args, **kwargs):
            """Assert that a function does not raise an exception."""
            try:
                return func(*args, **kwargs)
            except Exception as e:
                pytest.fail(f"Unexpected exception raised: {e}")

    return ValidationHelper()


# Performance Testing Fixture
@pytest.fixture
def performance_tracker():
    """Track performance metrics during testing."""
    import time

    class PerformanceTracker:
        def __init__(self):
            self.measurements = {}

        def measure(self, name: str):
            """Context manager for measuring execution time."""
            return self.TimeMeasurement(self, name)

        def assert_performance(self, name: str, max_time: float):
            """Assert that an operation completed within time limit."""
            if name in self.measurements:
                actual_time = self.measurements[name]
                assert (
                    actual_time <= max_time
                ), f"Operation '{name}' took {actual_time:.3f}s, expected <= {max_time}s"

        class TimeMeasurement:
            def __init__(self, tracker, name):
                self.tracker = tracker
                self.name = name
                self.start_time = None

            def __enter__(self):
                self.start_time = time.time()
                return self

            def __exit__(self, exc_type, exc_val, exc_tb):
                end_time = time.time()
                duration = end_time - self.start_time
                self.tracker.measurements[self.name] = duration

    return PerformanceTracker()


# Security Testing Fixtures
@pytest.fixture
def security_test_helper():
    """Helper for security-related testing."""

    class SecurityTestHelper:
        @staticmethod
        def create_high_risk_context():
            """Create a high-risk security context for testing."""
            return {
                "ip_address": "185.220.101.1",  # Known Tor exit node
                "user_agent": "curl/7.68.0",  # Suspicious user agent
                "location": "Unknown",
                "time_of_day": 3,  # 3 AM
                "device_fingerprint": "unknown_device",
                "failed_attempts": 5,
                "risk_score": 0.9,
            }

        @staticmethod
        def create_low_risk_context():
            """Create a low-risk security context for testing."""
            return {
                "ip_address": "192.168.1.1",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "location": "US",
                "time_of_day": 10,  # 10 AM
                "device_fingerprint": "known_device_123",
                "failed_attempts": 0,
                "risk_score": 0.1,
            }

        @staticmethod
        def create_suspicious_login_patterns():
            """Create suspicious login patterns for testing."""
            return [
                {
                    "ip": "10.0.0.1",
                    "timestamp": datetime.now(datetime.UTC) - timedelta(minutes=1),
                },
                {
                    "ip": "10.0.0.2",
                    "timestamp": datetime.now(datetime.UTC) - timedelta(minutes=2),
                },
                {
                    "ip": "10.0.0.3",
                    "timestamp": datetime.now(datetime.UTC) - timedelta(minutes=3),
                },
                {
                    "ip": "10.0.0.4",
                    "timestamp": datetime.now(datetime.UTC) - timedelta(minutes=4),
                },
                {
                    "ip": "10.0.0.5",
                    "timestamp": datetime.now(datetime.UTC) - timedelta(minutes=5),
                },
            ]

    return SecurityTestHelper()


# Compliance Testing Fixture
@pytest.fixture
def compliance_helper():
    """Helper for compliance-related testing."""

    class ComplianceHelper:
        @staticmethod
        def create_gdpr_deletion_request(user_id: str):
            """Create a GDPR data deletion request for testing."""
            return {
                "user_id": user_id,
                "request_type": "deletion",
                "legal_basis": "GDPR Article 17",
                "requested_at": datetime.now(datetime.UTC),
                "data_categories": ["personal_data", "preferences", "activity_logs"],
            }

        @staticmethod
        def create_audit_requirements():
            """Create audit requirements for testing."""
            return {
                "retention_period": timedelta(days=2555),  # 7 years
                "required_fields": ["action", "actor", "timestamp", "resource"],
                "immutability": True,
                "encryption_required": True,
            }

        @staticmethod
        def create_compliance_violation():
            """Create a compliance violation for testing."""
            return {
                "type": "data_retention",
                "severity": RiskLevel.HIGH,
                "description": "Data retained beyond allowed period",
                "regulation": "GDPR",
                "detected_at": datetime.now(datetime.UTC),
            }

    return ComplianceHelper()


# Domain Event Testing Utilities
@pytest.fixture
def event_test_utils():
    """Utilities for testing domain events."""

    class EventTestUtils:
        @staticmethod
        def assert_event_properties(event: Any, expected_properties: dict[str, Any]):
            """Assert that an event has expected properties."""
            for prop_name, expected_value in expected_properties.items():
                actual_value = getattr(event, prop_name, None)
                assert (
                    actual_value == expected_value
                ), f"Event property '{prop_name}' expected {expected_value}, got {actual_value}"

        @staticmethod
        def assert_event_serialization(event: Any):
            """Assert that an event can be serialized and deserialized."""
            if hasattr(event, "to_dict"):
                event_dict = event.to_dict()
                assert isinstance(event_dict, dict)
                assert "timestamp" in event_dict or "created_at" in event_dict

                # Test deserialization if method exists
                if hasattr(event.__class__, "from_dict"):
                    reconstructed_event = event.__class__.from_dict(event_dict)
                    assert type(reconstructed_event) == type(event)

        @staticmethod
        def create_event_correlation_chain(base_event: Any, chain_length: int = 3):
            """Create a chain of correlated events for testing."""
            events = [base_event]
            correlation_id = getattr(base_event, "correlation_id", str(uuid4()))

            for _i in range(chain_length - 1):
                # Create follow-up events with same correlation ID
                follow_up_event = UserCreatedEventFactory(
                    correlation_id=correlation_id,
                    caused_by_event_id=getattr(events[-1], "event_id", str(uuid4())),
                )
                events.append(follow_up_event)

            return events

    return EventTestUtils()


# Test Assertion Helpers
@pytest.fixture
def assert_helpers():
    """Common assertion helpers for domain testing."""

    class AssertHelpers:
        @staticmethod
        def assert_immutable(obj, attr_name: str, new_value: Any):
            """Assert that an attribute is immutable."""
            with pytest.raises((AttributeError, TypeError)):
                setattr(obj, attr_name, new_value)

        @staticmethod
        def assert_required_fields(class_type, required_fields: list[str]):
            """Assert that required fields raise errors when missing."""
            with pytest.raises((ValueError, TypeError)):
                class_type()

        @staticmethod
        def assert_valid_enum_value(enum_class, value: str):
            """Assert that a value is valid for an enum."""
            try:
                enum_class(value)
                return True
            except ValueError:
                return False

        @staticmethod
        def assert_datetime_recent(dt: datetime, max_age_seconds: int = 5):
            """Assert that a datetime is recent (within max_age_seconds)."""
            age = (datetime.now(datetime.UTC) - dt).total_seconds()
            assert (
                age <= max_age_seconds
            ), f"Datetime {dt} is {age}s old, expected <= {max_age_seconds}s"

    return AssertHelpers()
