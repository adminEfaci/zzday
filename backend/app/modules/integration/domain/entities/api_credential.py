"""API credential entity for secure credential management.

This module provides a comprehensive API credential entity with
encryption support, expiration tracking, and secure handling.
"""

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from app.core.domain.base import Entity
from app.core.errors import DomainError, ValidationError
from app.modules.integration.domain.enums import AuthType
from app.modules.integration.domain.value_objects.auth_method import AuthMethod


class ApiCredential(Entity):
    """Entity representing API credentials for external systems.

    This class manages secure storage and lifecycle of API credentials,
    including encryption, rotation, and expiration handling.
    """

    def __init__(
        self,
        integration_id: UUID,
        name: str,
        auth_method: AuthMethod,
        is_active: bool = True,
        last_used_at: datetime | None = None,
        last_rotated_at: datetime | None = None,
        rotation_period_days: int | None = None,
        usage_count: int = 0,
        failure_count: int = 0,
        metadata: dict[str, Any] | None = None,
        entity_id: UUID | None = None,
    ):
        """Initialize API credential entity.

        Args:
            integration_id: ID of the integration
            name: Name of the credential
            auth_method: Authentication method configuration
            is_active: Whether credential is active
            last_used_at: Last usage timestamp
            last_rotated_at: Last rotation timestamp
            rotation_period_days: Auto-rotation period in days
            usage_count: Number of times used
            failure_count: Number of authentication failures
            metadata: Additional metadata
            entity_id: Optional entity ID
        """
        super().__init__(entity_id)

        # Core attributes
        self.integration_id = integration_id
        self.name = self._validate_name(name)
        self.auth_method = auth_method
        self.is_active = is_active

        # Usage tracking
        self.last_used_at = last_used_at
        self.usage_count = max(0, usage_count)
        self.failure_count = max(0, failure_count)

        # Rotation management
        self.last_rotated_at = last_rotated_at or datetime.now(UTC)
        self.rotation_period_days = rotation_period_days

        # Additional metadata
        self.metadata = metadata or {}

        # Encryption key reference (actual encryption handled by infrastructure)
        self._encryption_key_id = str(uuid4())

        # Validate state
        self._validate_entity()

    def _validate_name(self, name: str) -> str:
        """Validate credential name.

        Args:
            name: Name to validate

        Returns:
            str: Validated name

        Raises:
            ValidationError: If name is invalid
        """
        if not name or not name.strip():
            raise ValidationError("Credential name cannot be empty")

        name = name.strip()
        if len(name) > 100:
            raise ValidationError("Credential name cannot exceed 100 characters")

        return name

    def _validate_entity(self) -> None:
        """Validate entity state."""
        super()._validate_entity()

        if not self.integration_id:
            raise ValidationError("integration_id is required")

        if not isinstance(self.auth_method, AuthMethod):
            raise ValidationError("auth_method must be an AuthMethod instance")

        if self.rotation_period_days is not None:
            if self.rotation_period_days <= 0:
                raise ValidationError("rotation_period_days must be positive")
            if self.rotation_period_days > 365:
                raise ValidationError("rotation_period_days cannot exceed 365")

    @property
    def is_expired(self) -> bool:
        """Check if credential is expired."""
        return self.auth_method.is_expired

    @property
    def needs_rotation(self) -> bool:
        """Check if credential needs rotation."""
        if not self.rotation_period_days:
            return False

        if not self.last_rotated_at:
            return True

        rotation_due = self.last_rotated_at + timedelta(days=self.rotation_period_days)
        return datetime.now(UTC) >= rotation_due

    @property
    def failure_rate(self) -> float:
        """Calculate authentication failure rate."""
        total_attempts = self.usage_count + self.failure_count
        if total_attempts == 0:
            return 0.0
        return self.failure_count / total_attempts

    @property
    def days_since_rotation(self) -> int:
        """Get days since last rotation."""
        if not self.last_rotated_at:
            return 0
        delta = datetime.now(UTC) - self.last_rotated_at
        return delta.days

    @property
    def is_healthy(self) -> bool:
        """Check if credential is healthy."""
        return (
            self.is_active
            and not self.is_expired
            and not self.needs_rotation
            and self.failure_rate < 0.1  # Less than 10% failure rate
        )

    def record_usage(self, success: bool = True) -> None:
        """Record credential usage.

        Args:
            success: Whether authentication was successful
        """
        self.last_used_at = datetime.now(UTC)

        if success:
            self.usage_count += 1
        else:
            self.failure_count += 1

        self.mark_modified()

    def rotate_credential(self, new_auth_method: AuthMethod) -> None:
        """Rotate credential with new authentication method.

        Args:
            new_auth_method: New authentication method

        Raises:
            DomainError: If rotation is not allowed
        """
        if not self.is_active:
            raise DomainError("Cannot rotate inactive credential")

        if new_auth_method.auth_type != self.auth_method.auth_type:
            raise DomainError("Cannot change authentication type during rotation")

        self.auth_method = new_auth_method
        self.last_rotated_at = datetime.now(UTC)
        self.failure_count = 0  # Reset failure count after rotation
        self._encryption_key_id = str(uuid4())  # New encryption key

        self.mark_modified()

    def deactivate(self, reason: str | None = None) -> None:
        """Deactivate credential.

        Args:
            reason: Optional deactivation reason
        """
        if not self.is_active:
            return

        self.is_active = False

        if reason:
            self.metadata["deactivation_reason"] = reason
        self.metadata["deactivated_at"] = datetime.now(UTC).isoformat()

        self.mark_modified()

    def reactivate(self) -> None:
        """Reactivate credential.

        Raises:
            DomainError: If credential cannot be reactivated
        """
        if self.is_active:
            return

        if self.is_expired:
            raise DomainError("Cannot reactivate expired credential")

        if self.failure_rate > 0.5:
            raise DomainError("Cannot reactivate credential with high failure rate")

        self.is_active = True
        self.failure_count = 0  # Reset failures on reactivation

        # Remove deactivation metadata
        self.metadata.pop("deactivation_reason", None)
        self.metadata.pop("deactivated_at", None)

        self.mark_modified()

    def update_metadata(self, key: str, value: Any) -> None:
        """Update credential metadata.

        Args:
            key: Metadata key
            value: Metadata value
        """
        if not key:
            raise ValidationError("Metadata key cannot be empty")

        self.metadata[key] = value
        self.mark_modified()

    def clear_sensitive_data(self) -> None:
        """Clear sensitive data from memory (for security)."""
        # This would be called when credential is no longer needed in memory
        # Actual implementation would depend on infrastructure layer

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        data = super().to_dict()

        # Add credential-specific fields
        data.update(
            {
                "integration_id": str(self.integration_id),
                "name": self.name,
                "auth_type": self.auth_method.auth_type.value,
                "is_active": self.is_active,
                "is_expired": self.is_expired,
                "needs_rotation": self.needs_rotation,
                "is_healthy": self.is_healthy,
                "last_used_at": self.last_used_at.isoformat()
                if self.last_used_at
                else None,
                "last_rotated_at": self.last_rotated_at.isoformat()
                if self.last_rotated_at
                else None,
                "rotation_period_days": self.rotation_period_days,
                "usage_count": self.usage_count,
                "failure_count": self.failure_count,
                "failure_rate": round(self.failure_rate, 3),
                "days_since_rotation": self.days_since_rotation,
                "metadata": self.metadata,
                "encryption_key_id": self._encryption_key_id,
            }
        )

        # Don't include actual credentials in serialization
        data["has_credentials"] = True

        return data

    @classmethod
    def create_api_key_credential(
        cls,
        integration_id: UUID,
        name: str,
        api_key: str,
        header_name: str = "X-API-Key",
        rotation_period_days: int | None = 90,
        **kwargs,
    ) -> "ApiCredential":
        """Create API key credential.

        Args:
            integration_id: Integration ID
            name: Credential name
            api_key: API key value
            header_name: Header name for API key
            rotation_period_days: Rotation period
            **kwargs: Additional parameters

        Returns:
            ApiCredential: Created credential
        """
        auth_method = AuthMethod(
            auth_type=AuthType.API_KEY,
            credentials={"api_key": api_key, "header_name": header_name},
        )

        return cls(
            integration_id=integration_id,
            name=name,
            auth_method=auth_method,
            rotation_period_days=rotation_period_days,
            **kwargs,
        )

    @classmethod
    def create_oauth2_credential(
        cls,
        integration_id: UUID,
        name: str,
        client_id: str,
        client_secret: str,
        token_endpoint: str,
        scopes: list[str] | None = None,
        rotation_period_days: int | None = 180,
        **kwargs,
    ) -> "ApiCredential":
        """Create OAuth2 credential.

        Args:
            integration_id: Integration ID
            name: Credential name
            client_id: OAuth2 client ID
            client_secret: OAuth2 client secret
            token_endpoint: Token endpoint URL
            scopes: OAuth2 scopes
            rotation_period_days: Rotation period
            **kwargs: Additional parameters

        Returns:
            ApiCredential: Created credential
        """
        auth_method = AuthMethod(
            auth_type=AuthType.OAUTH2,
            credentials={
                "client_id": client_id,
                "client_secret": client_secret,
                "grant_type": "client_credentials",
            },
            token_endpoint=token_endpoint,
            scopes=scopes,
        )

        return cls(
            integration_id=integration_id,
            name=name,
            auth_method=auth_method,
            rotation_period_days=rotation_period_days,
            **kwargs,
        )

    def __str__(self) -> str:
        """String representation."""
        status = "active" if self.is_active else "inactive"
        return (
            f"ApiCredential({self.name}, {self.auth_method.auth_type.value}, {status})"
        )
