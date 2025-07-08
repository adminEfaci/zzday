"""Credential DTOs for application layer.

This module provides data transfer objects for credential data,
ensuring secure handling of authentication information.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from app.modules.integration.domain.enums import AuthType


@dataclass(frozen=True)
class CredentialDTO:
    """DTO for credential information (without sensitive data)."""

    credential_id: UUID
    integration_id: UUID
    name: str
    auth_type: AuthType
    is_active: bool
    is_valid: bool
    expires_at: datetime | None
    last_used_at: datetime | None
    last_validated_at: datetime | None
    created_by: UUID
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_domain(cls, credential: Any) -> "CredentialDTO":
        """Create DTO from domain model."""
        return cls(
            credential_id=credential.id,
            integration_id=credential.integration_id,
            name=credential.name,
            auth_type=credential.auth_type,
            is_active=credential.is_active,
            is_valid=credential.is_valid,
            expires_at=credential.expires_at,
            last_used_at=credential.last_used_at,
            last_validated_at=credential.last_validated_at,
            created_by=credential.created_by,
            created_at=credential.created_at,
            updated_at=credential.updated_at,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "credential_id": str(self.credential_id),
            "integration_id": str(self.integration_id),
            "name": self.name,
            "auth_type": self.auth_type.value,
            "is_active": self.is_active,
            "is_valid": self.is_valid,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "last_used_at": self.last_used_at.isoformat()
            if self.last_used_at
            else None,
            "last_validated_at": self.last_validated_at.isoformat()
            if self.last_validated_at
            else None,
            "created_by": str(self.created_by),
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


@dataclass(frozen=True)
class CredentialCreateDTO:
    """DTO for creating credentials."""

    integration_id: UUID
    name: str
    auth_type: AuthType
    credentials: dict[str, Any]  # Encrypted in transit
    expires_at: datetime | None

    def validate(self) -> None:
        """Validate credential creation data."""
        if not self.name or not self.name.strip():
            raise ValueError("Credential name is required")

        if not self.credentials:
            raise ValueError("Credentials data is required")

        # Validate based on auth type
        if self.auth_type == AuthType.API_KEY:
            if "api_key" not in self.credentials:
                raise ValueError("API key is required for API_KEY auth type")

        elif self.auth_type == AuthType.OAUTH2:
            required = ["client_id", "client_secret"]
            missing = [field for field in required if field not in self.credentials]
            if missing:
                raise ValueError(
                    f"Missing required OAuth2 fields: {', '.join(missing)}"
                )

        elif self.auth_type == AuthType.BASIC:
            required = ["username", "password"]
            missing = [field for field in required if field not in self.credentials]
            if missing:
                raise ValueError(
                    f"Missing required Basic auth fields: {', '.join(missing)}"
                )

        elif self.auth_type == AuthType.JWT and (
            "token" not in self.credentials and "private_key" not in self.credentials
        ):
            raise ValueError("JWT token or private key is required")


@dataclass(frozen=True)
class CredentialUpdateDTO:
    """DTO for updating credentials."""

    credential_id: UUID
    name: str | None
    credentials: dict[str, Any] | None  # Encrypted in transit
    expires_at: datetime | None
    is_active: bool | None

    def validate(self) -> None:
        """Validate credential update data."""
        if self.name is not None and not self.name.strip():
            raise ValueError("Credential name cannot be empty")

        # At least one field must be provided for update
        if all(
            field is None
            for field in [self.name, self.credentials, self.expires_at, self.is_active]
        ):
            raise ValueError("At least one field must be provided for update")
