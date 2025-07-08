"""
Comprehensive tests for ApiCredential entity.

Tests all behaviors, business rules, and edge cases for the ApiCredential entity,
ensuring 100% code coverage and validating all domain logic.
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import patch
from uuid import uuid4

import pytest

from app.core.errors import DomainError, ValidationError
from app.modules.integration.domain.entities.api_credential import ApiCredential
from app.modules.integration.domain.enums import AuthType
from app.modules.integration.domain.value_objects.auth_method import AuthMethod


class TestApiCredentialCreation:
    """Test ApiCredential entity creation and validation."""

    def test_create_api_credential_with_valid_data_succeeds(
        self, api_credential_factory, auth_method
    ):
        """Test creating API credential with valid data."""
        integration_id = uuid4()

        credential = api_credential_factory(
            integration_id=integration_id,
            name="Test Credential",
            auth_method=auth_method,
            is_active=True,
            rotation_period_days=90,
        )

        assert credential.integration_id == integration_id
        assert credential.name == "Test Credential"
        assert credential.auth_method == auth_method
        assert credential.is_active is True
        assert credential.rotation_period_days == 90
        assert credential.usage_count == 0
        assert credential.failure_count == 0
        assert credential.last_used_at is None
        assert credential.last_rotated_at is not None
        assert credential.metadata == {}
        assert credential._encryption_key_id is not None

    def test_create_api_credential_with_minimal_data_succeeds(self, auth_method):
        """Test creating API credential with minimal required data."""
        integration_id = uuid4()

        credential = ApiCredential(
            integration_id=integration_id,
            name="Minimal Credential",
            auth_method=auth_method,
        )

        assert credential.integration_id == integration_id
        assert credential.name == "Minimal Credential"
        assert credential.auth_method == auth_method
        assert credential.is_active is True
        assert credential.rotation_period_days is None
        assert credential.usage_count == 0
        assert credential.failure_count == 0

    def test_create_api_credential_with_usage_stats(self, auth_method):
        """Test creating API credential with usage statistics."""
        now = datetime.now(UTC)

        credential = ApiCredential(
            integration_id=uuid4(),
            name="Stats Credential",
            auth_method=auth_method,
            last_used_at=now,
            usage_count=50,
            failure_count=5,
        )

        assert credential.last_used_at == now
        assert credential.usage_count == 50
        assert credential.failure_count == 5

    def test_create_api_credential_with_custom_metadata(self, auth_method):
        """Test creating API credential with custom metadata."""
        metadata = {
            "created_by": "admin",
            "environment": "production",
            "purpose": "external_api",
        }

        credential = ApiCredential(
            integration_id=uuid4(),
            name="Metadata Credential",
            auth_method=auth_method,
            metadata=metadata,
        )

        assert credential.metadata == metadata

    @pytest.mark.parametrize("invalid_name", ["", "   ", None])
    def test_create_api_credential_with_invalid_name_fails(
        self, invalid_name, auth_method
    ):
        """Test creating API credential with invalid name fails."""
        with pytest.raises(ValidationError, match="Credential name cannot be empty"):
            ApiCredential(
                integration_id=uuid4(), name=invalid_name, auth_method=auth_method
            )

    def test_create_api_credential_with_long_name_fails(self, auth_method):
        """Test creating API credential with too long name fails."""
        long_name = "a" * 101

        with pytest.raises(
            ValidationError, match="Credential name cannot exceed 100 characters"
        ):
            ApiCredential(
                integration_id=uuid4(), name=long_name, auth_method=auth_method
            )

    def test_create_api_credential_with_invalid_auth_method_fails(self):
        """Test creating API credential with invalid auth method fails."""
        with pytest.raises(
            ValidationError, match="auth_method must be an AuthMethod instance"
        ):
            ApiCredential(
                integration_id=uuid4(),
                name="Test Credential",
                auth_method="invalid",  # String instead of AuthMethod
            )

    def test_create_api_credential_with_invalid_rotation_period_fails(
        self, auth_method
    ):
        """Test creating API credential with invalid rotation period fails."""
        with pytest.raises(
            ValidationError, match="rotation_period_days must be positive"
        ):
            ApiCredential(
                integration_id=uuid4(),
                name="Test Credential",
                auth_method=auth_method,
                rotation_period_days=0,
            )

        with pytest.raises(
            ValidationError, match="rotation_period_days cannot exceed 365"
        ):
            ApiCredential(
                integration_id=uuid4(),
                name="Test Credential",
                auth_method=auth_method,
                rotation_period_days=366,
            )

    def test_name_is_trimmed(self, auth_method):
        """Test that credential name is properly trimmed."""
        credential = ApiCredential(
            integration_id=uuid4(), name="  Trimmed Name  ", auth_method=auth_method
        )

        assert credential.name == "Trimmed Name"

    def test_negative_usage_counts_normalized(self, auth_method):
        """Test that negative usage counts are normalized to 0."""
        credential = ApiCredential(
            integration_id=uuid4(),
            name="Test Credential",
            auth_method=auth_method,
            usage_count=-5,
            failure_count=-3,
        )

        assert credential.usage_count == 0
        assert credential.failure_count == 0


class TestApiCredentialProperties:
    """Test ApiCredential entity properties."""

    def test_is_expired_property(self, api_credential):
        """Test is_expired property delegates to auth_method."""
        with patch.object(api_credential.auth_method, "is_expired", True):
            assert api_credential.is_expired is True

        with patch.object(api_credential.auth_method, "is_expired", False):
            assert api_credential.is_expired is False

    def test_needs_rotation_property_no_period(self, api_credential):
        """Test needs_rotation when no rotation period set."""
        api_credential.rotation_period_days = None
        assert api_credential.needs_rotation is False

    def test_needs_rotation_property_no_last_rotation(self, api_credential):
        """Test needs_rotation when no last rotation timestamp."""
        api_credential.rotation_period_days = 90
        api_credential.last_rotated_at = None
        assert api_credential.needs_rotation is True

    def test_needs_rotation_property_within_period(self, api_credential):
        """Test needs_rotation when within rotation period."""
        api_credential.rotation_period_days = 90
        api_credential.last_rotated_at = datetime.now(UTC) - timedelta(days=30)
        assert api_credential.needs_rotation is False

    def test_needs_rotation_property_past_period(self, api_credential):
        """Test needs_rotation when past rotation period."""
        api_credential.rotation_period_days = 90
        api_credential.last_rotated_at = datetime.now(UTC) - timedelta(days=100)
        assert api_credential.needs_rotation is True

    def test_failure_rate_property_no_attempts(self, api_credential):
        """Test failure_rate when no attempts made."""
        api_credential.usage_count = 0
        api_credential.failure_count = 0
        assert api_credential.failure_rate == 0.0

    def test_failure_rate_property_with_attempts(self, api_credential):
        """Test failure_rate calculation with attempts."""
        api_credential.usage_count = 80  # 80 successes
        api_credential.failure_count = 20  # 20 failures
        # Total = 100, failure rate = 20/100 = 0.2
        assert api_credential.failure_rate == 0.2

    def test_failure_rate_property_only_failures(self, api_credential):
        """Test failure_rate when only failures."""
        api_credential.usage_count = 0
        api_credential.failure_count = 10
        assert api_credential.failure_rate == 1.0

    def test_days_since_rotation_property_no_rotation(self, api_credential):
        """Test days_since_rotation when no rotation timestamp."""
        api_credential.last_rotated_at = None
        assert api_credential.days_since_rotation == 0

    def test_days_since_rotation_property_with_rotation(self, api_credential):
        """Test days_since_rotation calculation."""
        api_credential.last_rotated_at = datetime.now(UTC) - timedelta(days=45)

        with patch(
            "app.modules.integration.domain.entities.api_credential.datetime"
        ) as mock_datetime:
            mock_datetime.now.return_value = api_credential.last_rotated_at + timedelta(
                days=45
            )

            assert api_credential.days_since_rotation == 45

    def test_is_healthy_property_all_conditions_met(self, api_credential):
        """Test is_healthy when all conditions are met."""
        api_credential.is_active = True
        api_credential.usage_count = 90
        api_credential.failure_count = 5  # 5% failure rate
        api_credential.rotation_period_days = 90
        api_credential.last_rotated_at = datetime.now(UTC) - timedelta(days=30)

        with patch.object(api_credential.auth_method, "is_expired", False):
            assert api_credential.is_healthy is True

    def test_is_healthy_property_inactive(self, api_credential):
        """Test is_healthy when credential is inactive."""
        api_credential.is_active = False
        assert api_credential.is_healthy is False

    def test_is_healthy_property_expired(self, api_credential):
        """Test is_healthy when credential is expired."""
        with patch.object(api_credential.auth_method, "is_expired", True):
            assert api_credential.is_healthy is False

    def test_is_healthy_property_needs_rotation(self, api_credential):
        """Test is_healthy when credential needs rotation."""
        api_credential.rotation_period_days = 90
        api_credential.last_rotated_at = datetime.now(UTC) - timedelta(days=100)
        assert api_credential.is_healthy is False

    def test_is_healthy_property_high_failure_rate(self, api_credential):
        """Test is_healthy when failure rate is too high."""
        api_credential.usage_count = 80
        api_credential.failure_count = 20  # 20% failure rate (> 10%)
        assert api_credential.is_healthy is False


class TestApiCredentialUsageTracking:
    """Test ApiCredential usage tracking functionality."""

    def test_record_usage_success(self, api_credential):
        """Test recording successful usage."""
        original_usage = api_credential.usage_count
        original_failures = api_credential.failure_count

        api_credential.record_usage(success=True)

        assert api_credential.usage_count == original_usage + 1
        assert api_credential.failure_count == original_failures
        assert api_credential.last_used_at is not None

    def test_record_usage_failure(self, api_credential):
        """Test recording failed usage."""
        original_usage = api_credential.usage_count
        original_failures = api_credential.failure_count

        api_credential.record_usage(success=False)

        assert api_credential.usage_count == original_usage
        assert api_credential.failure_count == original_failures + 1
        assert api_credential.last_used_at is not None

    def test_record_usage_default_success(self, api_credential):
        """Test that record_usage defaults to success."""
        original_usage = api_credential.usage_count

        api_credential.record_usage()  # No success parameter

        assert api_credential.usage_count == original_usage + 1

    def test_record_usage_updates_timestamp(self, api_credential):
        """Test that record_usage updates last_used_at timestamp."""
        before_usage = datetime.now(UTC)
        api_credential.record_usage()
        after_usage = datetime.now(UTC)

        assert before_usage <= api_credential.last_used_at <= after_usage


class TestApiCredentialRotation:
    """Test ApiCredential rotation functionality."""

    def test_rotate_credential_succeeds(self, api_credential):
        """Test successful credential rotation."""
        # Create new auth method with same type
        new_auth_method = AuthMethod(
            auth_type=api_credential.auth_method.auth_type,
            credentials={"api_key": "new_key_123", "header_name": "X-API-Key"},
        )

        original_rotation_time = api_credential.last_rotated_at
        original_encryption_key = api_credential._encryption_key_id
        api_credential.failure_count = 5

        api_credential.rotate_credential(new_auth_method)

        assert api_credential.auth_method == new_auth_method
        assert api_credential.last_rotated_at > original_rotation_time
        assert api_credential._encryption_key_id != original_encryption_key
        assert api_credential.failure_count == 0  # Reset on rotation

    def test_rotate_credential_inactive_fails(self, api_credential):
        """Test rotating inactive credential fails."""
        api_credential.is_active = False

        new_auth_method = AuthMethod(
            auth_type=api_credential.auth_method.auth_type,
            credentials={"api_key": "new_key_123"},
        )

        with pytest.raises(DomainError, match="Cannot rotate inactive credential"):
            api_credential.rotate_credential(new_auth_method)

    def test_rotate_credential_different_type_fails(self, api_credential):
        """Test rotating credential with different auth type fails."""
        # Create auth method with different type
        new_auth_method = AuthMethod(
            auth_type=AuthType.BASIC,  # Different from original
            credentials={"username": "user", "password": "pass"},
        )

        with pytest.raises(
            DomainError, match="Cannot change authentication type during rotation"
        ):
            api_credential.rotate_credential(new_auth_method)


class TestApiCredentialActivation:
    """Test ApiCredential activation and deactivation."""

    def test_deactivate_active_credential(self, api_credential):
        """Test deactivating active credential."""
        assert api_credential.is_active is True

        reason = "Security breach"
        api_credential.deactivate(reason)

        assert api_credential.is_active is False
        assert api_credential.metadata["deactivation_reason"] == reason
        assert "deactivated_at" in api_credential.metadata

    def test_deactivate_already_inactive_credential(self, api_credential):
        """Test deactivating already inactive credential does nothing."""
        api_credential.is_active = False
        api_credential.metadata.copy()

        api_credential.deactivate("Test reason")

        # Should not change state
        assert api_credential.is_active is False

    def test_deactivate_without_reason(self, api_credential):
        """Test deactivating credential without reason."""
        api_credential.deactivate()

        assert api_credential.is_active is False
        assert "deactivation_reason" not in api_credential.metadata
        assert "deactivated_at" in api_credential.metadata

    def test_reactivate_inactive_credential(self, api_credential):
        """Test reactivating inactive credential."""
        # First deactivate
        api_credential.deactivate("Test reason")
        api_credential.failure_count = 3

        # Mock auth_method to not be expired
        with patch.object(api_credential.auth_method, "is_expired", False):
            api_credential.reactivate()

        assert api_credential.is_active is True
        assert api_credential.failure_count == 0  # Reset on reactivation
        assert "deactivation_reason" not in api_credential.metadata
        assert "deactivated_at" not in api_credential.metadata

    def test_reactivate_already_active_credential(self, api_credential):
        """Test reactivating already active credential does nothing."""
        assert api_credential.is_active is True

        api_credential.reactivate()

        assert api_credential.is_active is True

    def test_reactivate_expired_credential_fails(self, api_credential):
        """Test reactivating expired credential fails."""
        api_credential.is_active = False

        with patch.object(api_credential.auth_method, "is_expired", True):
            with pytest.raises(
                DomainError, match="Cannot reactivate expired credential"
            ):
                api_credential.reactivate()

    def test_reactivate_high_failure_rate_fails(self, api_credential):
        """Test reactivating credential with high failure rate fails."""
        api_credential.is_active = False
        api_credential.usage_count = 40
        api_credential.failure_count = 60  # 60% failure rate

        with patch.object(api_credential.auth_method, "is_expired", False):
            with pytest.raises(
                DomainError, match="Cannot reactivate credential with high failure rate"
            ):
                api_credential.reactivate()


class TestApiCredentialMetadata:
    """Test ApiCredential metadata management."""

    def test_update_metadata_succeeds(self, api_credential):
        """Test updating credential metadata."""
        api_credential.update_metadata("test_key", "test_value")

        assert api_credential.metadata["test_key"] == "test_value"

    def test_update_metadata_overwrites_existing(self, api_credential):
        """Test updating existing metadata key."""
        api_credential.update_metadata("test_key", "original_value")
        api_credential.update_metadata("test_key", "updated_value")

        assert api_credential.metadata["test_key"] == "updated_value"

    def test_update_metadata_empty_key_fails(self, api_credential):
        """Test updating metadata with empty key fails."""
        with pytest.raises(ValidationError, match="Metadata key cannot be empty"):
            api_credential.update_metadata("", "value")

        with pytest.raises(ValidationError, match="Metadata key cannot be empty"):
            api_credential.update_metadata(None, "value")

    def test_update_metadata_various_value_types(self, api_credential):
        """Test updating metadata with various value types."""
        api_credential.update_metadata("string_key", "string_value")
        api_credential.update_metadata("number_key", 42)
        api_credential.update_metadata("bool_key", True)
        api_credential.update_metadata("dict_key", {"nested": "value"})
        api_credential.update_metadata("list_key", [1, 2, 3])

        assert api_credential.metadata["string_key"] == "string_value"
        assert api_credential.metadata["number_key"] == 42
        assert api_credential.metadata["bool_key"] is True
        assert api_credential.metadata["dict_key"] == {"nested": "value"}
        assert api_credential.metadata["list_key"] == [1, 2, 3]


class TestApiCredentialFactoryMethods:
    """Test ApiCredential factory methods."""

    def test_create_api_key_credential(self):
        """Test creating API key credential via factory method."""
        integration_id = uuid4()
        credential = ApiCredential.create_api_key_credential(
            integration_id=integration_id,
            name="API Key Credential",
            api_key="secret_api_key_123",
            header_name="X-Custom-Key",
            rotation_period_days=60,
        )

        assert credential.integration_id == integration_id
        assert credential.name == "API Key Credential"
        assert credential.auth_method.auth_type == AuthType.API_KEY
        assert credential.auth_method.credentials["api_key"] == "secret_api_key_123"
        assert credential.auth_method.credentials["header_name"] == "X-Custom-Key"
        assert credential.rotation_period_days == 60

    def test_create_api_key_credential_with_defaults(self):
        """Test creating API key credential with default values."""
        integration_id = uuid4()
        credential = ApiCredential.create_api_key_credential(
            integration_id=integration_id, name="Default API Key", api_key="secret_key"
        )

        assert credential.auth_method.credentials["header_name"] == "X-API-Key"
        assert credential.rotation_period_days == 90

    def test_create_oauth2_credential(self):
        """Test creating OAuth2 credential via factory method."""
        integration_id = uuid4()
        credential = ApiCredential.create_oauth2_credential(
            integration_id=integration_id,
            name="OAuth2 Credential",
            client_id="client_123",
            client_secret="secret_456",
            token_endpoint="https://auth.example.com/token",
            scopes=["read", "write"],
            rotation_period_days=120,
        )

        assert credential.integration_id == integration_id
        assert credential.name == "OAuth2 Credential"
        assert credential.auth_method.auth_type == AuthType.OAUTH2
        assert credential.auth_method.credentials["client_id"] == "client_123"
        assert credential.auth_method.credentials["client_secret"] == "secret_456"
        assert credential.auth_method.token_endpoint == "https://auth.example.com/token"
        assert credential.auth_method.scopes == ["read", "write"]
        assert credential.rotation_period_days == 120

    def test_create_oauth2_credential_with_defaults(self):
        """Test creating OAuth2 credential with default values."""
        integration_id = uuid4()
        credential = ApiCredential.create_oauth2_credential(
            integration_id=integration_id,
            name="Default OAuth2",
            client_id="client_123",
            client_secret="secret_456",
            token_endpoint="https://auth.example.com/token",
        )

        assert credential.auth_method.credentials["grant_type"] == "client_credentials"
        assert credential.rotation_period_days == 180


class TestApiCredentialValidation:
    """Test ApiCredential entity validation."""

    def test_validate_entity_with_missing_integration_id_fails(self, auth_method):
        """Test validation fails with missing integration_id."""
        credential = ApiCredential(
            integration_id=uuid4(), name="Test Credential", auth_method=auth_method
        )

        # Manually set invalid integration_id to test validation
        credential.integration_id = None

        with pytest.raises(ValidationError, match="integration_id is required"):
            credential._validate_entity()

    def test_validate_entity_with_invalid_auth_method_fails(self, auth_method):
        """Test validation fails with invalid auth_method."""
        credential = ApiCredential(
            integration_id=uuid4(), name="Test Credential", auth_method=auth_method
        )

        # Manually set invalid auth_method to test validation
        credential.auth_method = "invalid"

        with pytest.raises(
            ValidationError, match="auth_method must be an AuthMethod instance"
        ):
            credential._validate_entity()

    def test_validate_entity_with_negative_rotation_period_fails(self, auth_method):
        """Test validation fails with negative rotation period."""
        credential = ApiCredential(
            integration_id=uuid4(), name="Test Credential", auth_method=auth_method
        )

        # Manually set invalid rotation period to test validation
        credential.rotation_period_days = -1

        with pytest.raises(
            ValidationError, match="rotation_period_days must be positive"
        ):
            credential._validate_entity()

    def test_validate_entity_with_excessive_rotation_period_fails(self, auth_method):
        """Test validation fails with excessive rotation period."""
        credential = ApiCredential(
            integration_id=uuid4(), name="Test Credential", auth_method=auth_method
        )

        # Manually set invalid rotation period to test validation
        credential.rotation_period_days = 400

        with pytest.raises(
            ValidationError, match="rotation_period_days cannot exceed 365"
        ):
            credential._validate_entity()


class TestApiCredentialSerialization:
    """Test ApiCredential serialization and string representation."""

    def test_to_dict_includes_all_fields(self, api_credential):
        """Test to_dict includes all expected fields."""
        data = api_credential.to_dict()

        # Check basic fields
        assert data["integration_id"] == str(api_credential.integration_id)
        assert data["name"] == api_credential.name
        assert data["auth_type"] == api_credential.auth_method.auth_type.value
        assert data["is_active"] == api_credential.is_active
        assert data["usage_count"] == api_credential.usage_count
        assert data["failure_count"] == api_credential.failure_count
        assert data["rotation_period_days"] == api_credential.rotation_period_days
        assert data["metadata"] == api_credential.metadata

        # Check computed properties
        assert data["is_expired"] == api_credential.is_expired
        assert data["needs_rotation"] == api_credential.needs_rotation
        assert data["is_healthy"] == api_credential.is_healthy
        assert data["failure_rate"] == round(api_credential.failure_rate, 3)
        assert data["days_since_rotation"] == api_credential.days_since_rotation

        # Check security fields
        assert data["has_credentials"] is True
        assert "encryption_key_id" in data

    def test_to_dict_with_timestamps(self, api_credential):
        """Test to_dict with timestamp fields."""
        now = datetime.now(UTC)
        api_credential.last_used_at = now
        api_credential.last_rotated_at = now

        data = api_credential.to_dict()

        assert data["last_used_at"] == now.isoformat()
        assert data["last_rotated_at"] == now.isoformat()

    def test_to_dict_without_timestamps(self, api_credential):
        """Test to_dict without optional timestamps."""
        api_credential.last_used_at = None

        data = api_credential.to_dict()

        assert data["last_used_at"] is None
        assert data["last_rotated_at"] is not None  # Set in constructor

    def test_str_representation(self, api_credential):
        """Test string representation of API credential."""
        str_repr = str(api_credential)

        assert api_credential.name in str_repr
        assert api_credential.auth_method.auth_type.value in str_repr
        assert "active" in str_repr

        # Test inactive credential
        api_credential.is_active = False
        str_repr = str(api_credential)
        assert "inactive" in str_repr


class TestApiCredentialSecurityFeatures:
    """Test ApiCredential security-related features."""

    def test_clear_sensitive_data_method_exists(self, api_credential):
        """Test that clear_sensitive_data method can be called."""
        # This method is a placeholder for security cleanup
        # In production, it would clear sensitive data from memory
        api_credential.clear_sensitive_data()

        # Should not raise any errors
        assert True

    def test_encryption_key_id_generated(self, api_credential):
        """Test that encryption key ID is generated."""
        assert api_credential._encryption_key_id is not None
        assert isinstance(api_credential._encryption_key_id, str)
        assert len(api_credential._encryption_key_id) > 0

    def test_encryption_key_id_changes_on_rotation(self, api_credential):
        """Test that encryption key ID changes on rotation."""
        original_key_id = api_credential._encryption_key_id

        # Create new auth method for rotation
        new_auth_method = AuthMethod(
            auth_type=api_credential.auth_method.auth_type,
            credentials={"api_key": "new_key_123"},
        )

        api_credential.rotate_credential(new_auth_method)

        assert api_credential._encryption_key_id != original_key_id


class TestApiCredentialEdgeCases:
    """Test ApiCredential edge cases and boundary conditions."""

    def test_failure_rate_calculation_edge_cases(self, api_credential):
        """Test failure rate calculation edge cases."""
        # Only successes
        api_credential.usage_count = 100
        api_credential.failure_count = 0
        assert api_credential.failure_rate == 0.0

        # Only failures
        api_credential.usage_count = 0
        api_credential.failure_count = 50
        assert api_credential.failure_rate == 1.0

        # Mixed but boundary failure rate
        api_credential.usage_count = 9
        api_credential.failure_count = 1
        assert api_credential.failure_rate == 0.1  # Exactly 10%

    def test_health_check_with_exact_boundary_failure_rate(self, api_credential):
        """Test health check with exactly 10% failure rate."""
        api_credential.is_active = True
        api_credential.usage_count = 90
        api_credential.failure_count = 10  # Exactly 10% failure rate

        with patch.object(api_credential.auth_method, "is_expired", False):
            # Should be considered unhealthy at 10% (not less than 10%)
            assert api_credential.is_healthy is False

    def test_rotation_with_minimal_delay(self, api_credential):
        """Test rotation timing with minimal delay."""
        # Set rotation just barely past due
        api_credential.rotation_period_days = 1
        api_credential.last_rotated_at = datetime.now(UTC) - timedelta(
            days=1, seconds=1
        )

        assert api_credential.needs_rotation is True

    def test_rotation_exactly_on_time(self, api_credential):
        """Test rotation timing exactly on due date."""
        with patch(
            "app.modules.integration.domain.entities.api_credential.datetime"
        ) as mock_datetime:
            fixed_now = datetime.now(UTC)
            mock_datetime.now.return_value = fixed_now

            api_credential.rotation_period_days = 90
            api_credential.last_rotated_at = fixed_now - timedelta(days=90)

            assert api_credential.needs_rotation is True

    def test_reactivate_with_exactly_50_percent_failure_rate(self, api_credential):
        """Test reactivation with exactly 50% failure rate."""
        api_credential.is_active = False
        api_credential.usage_count = 50
        api_credential.failure_count = 50  # Exactly 50% failure rate

        with patch.object(api_credential.auth_method, "is_expired", False):
            # Should fail at exactly 50% (not > 50%)
            api_credential.reactivate()  # Should succeed
            assert api_credential.is_active is True

    def test_reactivate_with_just_over_50_percent_failure_rate(self, api_credential):
        """Test reactivation with just over 50% failure rate."""
        api_credential.is_active = False
        api_credential.usage_count = 99
        api_credential.failure_count = 101  # 50.5% failure rate

        with patch.object(api_credential.auth_method, "is_expired", False):
            with pytest.raises(
                DomainError, match="Cannot reactivate credential with high failure rate"
            ):
                api_credential.reactivate()
