"""
Comprehensive tests for AuditContext value object.

This module tests the AuditContext value object with complete coverage focusing on:
- Value object immutability
- IP address validation and masking
- Environment and context validation
- Security and privacy features
- Factory methods for common contexts
"""

import pytest

from app.core.errors import ValidationError
from app.modules.audit.domain.value_objects.audit_context import AuditContext


class TestAuditContextCreation:
    """Test audit context creation and initialization."""

    def test_create_audit_context_with_all_fields(self):
        """Test creating audit context with all fields."""
        # Arrange
        additional_data = {
            "browser": "Chrome",
            "version": "96.0.4664.45",
            "platform": "Windows",
        }

        # Act
        context = AuditContext(
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            request_id="req-12345",
            session_id="sess-67890",
            environment="production",
            additional_data=additional_data,
        )

        # Assert
        assert context.ip_address == "192.168.1.100"
        assert "Mozilla/5.0" in context.user_agent
        assert context.request_id == "req-12345"
        assert context.session_id == "sess-67890"
        assert context.environment == "production"
        assert context.additional_data["browser"] == "Chrome"
        assert context.additional_data["version"] == "96.0.4664.45"
        assert context.additional_data["platform"] == "Windows"

    def test_create_audit_context_with_minimal_fields(self):
        """Test creating audit context with minimal required fields."""
        # Act
        context = AuditContext()

        # Assert
        assert context.ip_address is None
        assert context.user_agent is None
        assert context.request_id is None
        assert context.session_id is None
        assert context.environment == "production"  # Default
        assert context.additional_data == {}

    def test_create_audit_context_with_custom_environment(self):
        """Test creating audit context with custom environment."""
        # Act
        context = AuditContext(environment="staging")

        # Assert
        assert context.environment == "staging"

    def test_create_audit_context_normalizes_environment(self):
        """Test that environment is normalized to lowercase."""
        # Act
        context = AuditContext(environment="  PRODUCTION  ")

        # Assert
        assert context.environment == "production"

    def test_create_audit_context_truncates_long_user_agent(self):
        """Test that very long user agent strings are truncated."""
        # Arrange
        long_user_agent = "A" * 600  # Longer than 500 char limit

        # Act
        context = AuditContext(user_agent=long_user_agent)

        # Assert
        assert len(context.user_agent) == 500
        assert context.user_agent == "A" * 500

    def test_create_audit_context_with_none_values(self):
        """Test creating audit context with None values."""
        # Act
        context = AuditContext(
            ip_address=None,
            user_agent=None,
            request_id=None,
            session_id=None,
            additional_data=None,
        )

        # Assert
        assert context.ip_address is None
        assert context.user_agent is None
        assert context.request_id is None
        assert context.session_id is None
        assert context.additional_data == {}  # Should initialize empty dict

    @pytest.mark.parametrize("invalid_environment", ["", "   ", None])
    def test_create_audit_context_with_invalid_environment_raises_error(
        self, invalid_environment
    ):
        """Test that invalid environment raises ValidationError."""
        # Act & Assert
        with pytest.raises(ValidationError, match="environment"):
            AuditContext(environment=invalid_environment)


class TestAuditContextImmutability:
    """Test audit context value object immutability."""

    def test_audit_context_is_frozen_after_creation(self):
        """Test that audit context is immutable after creation."""
        # Arrange
        context = AuditContext(ip_address="192.168.1.1", environment="test")

        # Act & Assert - Attempting to modify should raise an error
        with pytest.raises(AttributeError):
            context.ip_address = "10.0.0.1"

        with pytest.raises(AttributeError):
            context.new_field = "value"

    def test_additional_data_is_copied_not_referenced(self):
        """Test that additional_data is copied, not referenced."""
        # Arrange
        original_data = {"key": "value"}
        context = AuditContext(additional_data=original_data)

        # Act - Modify original data
        original_data["key"] = "modified"

        # Assert - Context data should remain unchanged
        assert context.additional_data["key"] == "value"


class TestAuditContextIPAddressValidation:
    """Test IP address validation and handling."""

    @pytest.mark.parametrize(
        "valid_ip",
        [
            "192.168.1.1",
            "10.0.0.1",
            "172.16.0.1",
            "127.0.0.1",
            "8.8.8.8",
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",  # IPv6
            "::1",  # IPv6 localhost
        ],
    )
    def test_create_audit_context_with_valid_ip_addresses(self, valid_ip):
        """Test creating audit context with valid IP addresses."""
        # Act
        context = AuditContext(ip_address=valid_ip)

        # Assert
        assert context.ip_address == valid_ip.strip()

    @pytest.mark.parametrize(
        "invalid_ip",
        [
            "",
            "   ",
            "A" * 50,  # Too long
            "not.an.ip.address",
        ],
    )
    def test_create_audit_context_with_invalid_ip_raises_error(self, invalid_ip):
        """Test that invalid IP addresses raise ValidationError."""
        # Act & Assert
        with pytest.raises(ValidationError, match="Invalid IP address format"):
            AuditContext(ip_address=invalid_ip)

    def test_ip_address_whitespace_is_stripped(self):
        """Test that IP address whitespace is stripped."""
        # Act
        context = AuditContext(ip_address="  192.168.1.1  ")

        # Assert
        assert context.ip_address == "192.168.1.1"


class TestAuditContextEnvironmentClassification:
    """Test environment classification methods."""

    @pytest.mark.parametrize(
        ("environment", "expected_production"),
        [
            ("production", True),
            ("prod", True),
            ("PRODUCTION", True),
            ("staging", False),
            ("development", False),
            ("test", False),
        ],
    )
    def test_is_production(self, environment, expected_production):
        """Test production environment detection."""
        # Arrange
        context = AuditContext(environment=environment)

        # Act & Assert
        assert context.is_production() == expected_production

    @pytest.mark.parametrize(
        ("environment", "expected_development"),
        [
            ("development", True),
            ("dev", True),
            ("local", True),
            ("DEVELOPMENT", True),
            ("production", False),
            ("staging", False),
            ("test", False),
        ],
    )
    def test_is_development(self, environment, expected_development):
        """Test development environment detection."""
        # Arrange
        context = AuditContext(environment=environment)

        # Act & Assert
        assert context.is_development() == expected_development


class TestAuditContextAuthenticationDetection:
    """Test authentication context detection."""

    def test_is_authenticated_context_with_session(self):
        """Test authenticated context detection with session ID."""
        # Arrange
        context = AuditContext(session_id="sess-12345")

        # Act & Assert
        assert context.is_authenticated_context()

    def test_is_authenticated_context_without_session(self):
        """Test unauthenticated context detection without session ID."""
        # Arrange
        context = AuditContext()

        # Act & Assert
        assert not context.is_authenticated_context()


class TestAuditContextLocationHints:
    """Test location hint functionality."""

    def test_get_location_hint_no_ip(self):
        """Test location hint when no IP address is provided."""
        # Arrange
        context = AuditContext()

        # Act & Assert
        assert context.get_location_hint() is None

    @pytest.mark.parametrize(
        ("ip_address", "expected_hint"),
        [
            ("127.0.0.1", "internal"),
            ("10.0.0.1", "internal"),
            ("172.16.0.1", "internal"),
            ("192.168.1.1", "internal"),
            ("8.8.8.8", "external"),
            ("203.0.113.1", "external"),
        ],
    )
    def test_get_location_hint_with_various_ips(self, ip_address, expected_hint):
        """Test location hints for various IP addresses."""
        # Arrange
        context = AuditContext(ip_address=ip_address)

        # Act & Assert
        assert context.get_location_hint() == expected_hint


class TestAuditContextDataMasking:
    """Test sensitive data masking functionality."""

    def test_mask_sensitive_data_ip_address(self):
        """Test IP address masking."""
        # Arrange
        context = AuditContext(
            ip_address="192.168.1.100", user_agent="Mozilla/5.0 Test Browser"
        )

        # Act
        masked_context = context.mask_sensitive_data()

        # Assert
        assert masked_context.ip_address == "192.168.*.*"
        assert masked_context.user_agent == context.user_agent  # Should not be masked
        assert masked_context.session_id == context.session_id
        assert masked_context.request_id == context.request_id
        assert masked_context.environment == context.environment

    def test_mask_sensitive_data_invalid_ip_format(self):
        """Test IP masking with invalid IP format."""
        # Arrange - This would normally fail validation, but testing edge case
        context = AuditContext()
        context._ip_address = "invalid-ip"  # Bypass validation for testing

        # Act
        masked_context = context.mask_sensitive_data()

        # Assert
        assert masked_context.ip_address == "***"

    def test_mask_sensitive_data_additional_data(self):
        """Test sensitive data masking in additional data."""
        # Arrange
        context = AuditContext(
            additional_data={
                "password": "secret123",
                "api_token": "abc123",
                "user_secret": "hidden",
                "api_key": "key123",
                "normal_field": "visible",
                "credential_field": "masked",
            }
        )

        # Act
        masked_context = context.mask_sensitive_data()

        # Assert
        assert masked_context.additional_data["password"] == "***"
        assert masked_context.additional_data["api_token"] == "***"
        assert masked_context.additional_data["user_secret"] == "***"
        assert masked_context.additional_data["api_key"] == "***"
        assert masked_context.additional_data["normal_field"] == "visible"
        assert masked_context.additional_data["credential_field"] == "***"


class TestAuditContextAdditionalData:
    """Test additional data manipulation methods."""

    def test_with_additional_data(self):
        """Test adding additional data to context."""
        # Arrange
        original_context = AuditContext(
            ip_address="192.168.1.1", additional_data={"existing": "value"}
        )

        # Act
        new_context = original_context.with_additional_data(
            new_field="new_value", another_field="another_value"
        )

        # Assert
        assert new_context.ip_address == "192.168.1.1"
        assert new_context.additional_data["existing"] == "value"
        assert new_context.additional_data["new_field"] == "new_value"
        assert new_context.additional_data["another_field"] == "another_value"

        # Original context should remain unchanged
        assert "new_field" not in original_context.additional_data
        assert "another_field" not in original_context.additional_data

    def test_with_additional_data_overwrites_existing(self):
        """Test that additional data overwrites existing keys."""
        # Arrange
        original_context = AuditContext(additional_data={"key": "original_value"})

        # Act
        new_context = original_context.with_additional_data(key="new_value")

        # Assert
        assert new_context.additional_data["key"] == "new_value"
        assert original_context.additional_data["key"] == "original_value"


class TestAuditContextStringRepresentation:
    """Test string representation methods."""

    def test_str_representation_minimal(self):
        """Test string representation with minimal data."""
        # Arrange
        context = AuditContext(environment="test")

        # Act
        string_repr = str(context)

        # Assert
        assert "env=test" in string_repr
        assert "AuditContext(" in string_repr

    def test_str_representation_complete(self):
        """Test string representation with complete data."""
        # Arrange
        context = AuditContext(
            ip_address="192.168.1.1",
            session_id="sess-123",
            request_id="req-456",
            environment="production",
        )

        # Act
        string_repr = str(context)

        # Assert
        assert "env=production" in string_repr
        assert "ip=192.168.1.1" in string_repr
        assert "session=sess-123" in string_repr
        assert "request=req-456" in string_repr

    def test_str_representation_order(self):
        """Test that string representation maintains consistent order."""
        # Arrange
        context = AuditContext(
            ip_address="10.0.0.1",
            user_agent="Test Browser",
            request_id="req-789",
            session_id="sess-456",
            environment="staging",
        )

        # Act
        string_repr = str(context)

        # Assert - Should start with env and maintain logical order
        assert string_repr.startswith("AuditContext(env=staging")
        assert "ip=10.0.0.1" in string_repr
        assert "session=sess-456" in string_repr
        assert "request=req-789" in string_repr


class TestAuditContextFactoryMethods:
    """Test factory methods for common audit contexts."""

    def test_create_system_context_default(self):
        """Test system context factory method with defaults."""
        # Act
        context = AuditContext.create_system_context()

        # Assert
        assert context.ip_address == "127.0.0.1"
        assert context.user_agent == "system"
        assert context.environment == "production"
        assert context.additional_data["source"] == "system"
        assert not context.is_authenticated_context()
        assert context.get_location_hint() == "internal"

    def test_create_system_context_custom_environment(self):
        """Test system context factory method with custom environment."""
        # Act
        context = AuditContext.create_system_context(environment="development")

        # Assert
        assert context.ip_address == "127.0.0.1"
        assert context.user_agent == "system"
        assert context.environment == "development"
        assert context.additional_data["source"] == "system"
        assert context.is_development()

    def test_create_api_context(self):
        """Test API context factory method."""
        # Act
        context = AuditContext.create_api_context(
            ip_address="203.0.113.1",
            user_agent="MyApp/1.0 (API Client)",
            request_id="api-req-12345",
            environment="production",
        )

        # Assert
        assert context.ip_address == "203.0.113.1"
        assert context.user_agent == "MyApp/1.0 (API Client)"
        assert context.request_id == "api-req-12345"
        assert context.environment == "production"
        assert context.additional_data["source"] == "api"
        assert context.get_location_hint() == "external"
        assert context.is_production()

    def test_create_api_context_default_environment(self):
        """Test API context factory method with default environment."""
        # Act
        context = AuditContext.create_api_context(
            ip_address="192.168.1.1", user_agent="API Client", request_id="req-123"
        )

        # Assert
        assert context.environment == "production"  # Default
        assert context.additional_data["source"] == "api"


class TestAuditContextEquality:
    """Test equality and comparison of audit contexts."""

    def test_audit_contexts_equal_when_same_values(self):
        """Test that audit contexts with same values are equal."""
        # Arrange
        context1 = AuditContext(
            ip_address="192.168.1.1",
            user_agent="Test Browser",
            environment="test",
            additional_data={"key": "value"},
        )

        context2 = AuditContext(
            ip_address="192.168.1.1",
            user_agent="Test Browser",
            environment="test",
            additional_data={"key": "value"},
        )

        # Act & Assert
        assert context1 == context2
        assert hash(context1) == hash(context2)

    def test_audit_contexts_not_equal_when_different_values(self):
        """Test that audit contexts with different values are not equal."""
        # Arrange
        context1 = AuditContext(ip_address="192.168.1.1", environment="production")

        context2 = AuditContext(ip_address="10.0.0.1", environment="production")

        # Act & Assert
        assert context1 != context2
        assert hash(context1) != hash(context2)


class TestAuditContextEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_create_context_with_unicode_user_agent(self):
        """Test creating context with unicode characters in user agent."""
        # Act
        context = AuditContext(
            user_agent="Navigateur 🌐 Chrome/96.0", environment="test"
        )

        # Assert
        assert "🌐" in context.user_agent
        assert context.user_agent == "Navigateur 🌐 Chrome/96.0"

    def test_create_context_with_very_long_request_id(self):
        """Test creating context with very long request ID."""
        # Arrange
        long_request_id = "req-" + "A" * 1000

        # Act
        context = AuditContext(request_id=long_request_id)

        # Assert
        assert context.request_id == long_request_id
        assert len(context.request_id) == 1004  # "req-" + 1000 'A's

    def test_create_context_with_complex_additional_data(self):
        """Test creating context with complex nested additional data."""
        # Arrange
        complex_data = {
            "nested": {"level1": {"level2": "deep_value"}},
            "list": [1, 2, 3, "string"],
            "boolean": True,
            "null_value": None,
        }

        # Act
        context = AuditContext(additional_data=complex_data)

        # Assert
        assert context.additional_data["nested"]["level1"]["level2"] == "deep_value"
        assert context.additional_data["list"] == [1, 2, 3, "string"]
        assert context.additional_data["boolean"] is True
        assert context.additional_data["null_value"] is None
