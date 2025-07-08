"""Credential repository interface."""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any
from uuid import UUID

from app.modules.integration.domain.entities import ApiCredential
from app.modules.integration.domain.enums import AuthType, CredentialStatus


class ICredentialRepository(ABC):
    """Repository interface for ApiCredential entity operations."""

    @abstractmethod
    async def get_by_id(self, credential_id: UUID) -> ApiCredential | None:
        """Get a credential by its ID.

        Args:
            credential_id: The unique identifier of the credential

        Returns:
            ApiCredential | None: The credential if found, None otherwise
        """

    @abstractmethod
    async def get_by_integration_id(self, integration_id: UUID) -> list[ApiCredential]:
        """Get all credentials for an integration.

        Args:
            integration_id: The integration identifier

        Returns:
            list[ApiCredential]: List of credentials for the integration
        """

    @abstractmethod
    async def get_active_credential(self, integration_id: UUID) -> ApiCredential | None:
        """Get the active credential for an integration.

        Args:
            integration_id: The integration identifier

        Returns:
            ApiCredential | None: The active credential if found, None otherwise
        """

    @abstractmethod
    async def get_by_auth_type(
        self, tenant_id: UUID, auth_type: AuthType
    ) -> list[ApiCredential]:
        """Get credentials by authentication type.

        Args:
            tenant_id: The tenant identifier
            auth_type: The authentication type

        Returns:
            list[ApiCredential]: List of credentials with the specified auth type
        """

    @abstractmethod
    async def save(self, credential: ApiCredential) -> ApiCredential:
        """Save a credential (create or update).

        Args:
            credential: The credential to save

        Returns:
            ApiCredential: The saved credential
        """

    @abstractmethod
    async def delete(self, credential_id: UUID) -> bool:
        """Delete a credential.

        Args:
            credential_id: The unique identifier of the credential

        Returns:
            bool: True if deleted successfully, False otherwise
        """

    @abstractmethod
    async def exists(self, credential_id: UUID) -> bool:
        """Check if a credential exists.

        Args:
            credential_id: The unique identifier of the credential

        Returns:
            bool: True if exists, False otherwise
        """

    @abstractmethod
    async def update_status(
        self,
        credential_id: UUID,
        status: CredentialStatus,
        error_message: str | None = None,
    ) -> bool:
        """Update the status of a credential.

        Args:
            credential_id: The unique identifier of the credential
            status: The new status
            error_message: Optional error message if status is error

        Returns:
            bool: True if updated successfully, False otherwise
        """

    @abstractmethod
    async def rotate_credential(
        self, credential_id: UUID, new_credential_data: dict[str, Any]
    ) -> ApiCredential:
        """Rotate a credential with new authentication data.

        Args:
            credential_id: The unique identifier of the credential
            new_credential_data: The new credential data

        Returns:
            ApiCredential: The updated credential
        """

    @abstractmethod
    async def mark_for_renewal(
        self, credential_id: UUID, renewal_date: datetime
    ) -> bool:
        """Mark a credential for renewal.

        Args:
            credential_id: The unique identifier of the credential
            renewal_date: The date when renewal is needed

        Returns:
            bool: True if marked successfully, False otherwise
        """

    @abstractmethod
    async def get_expiring_credentials(
        self, tenant_id: UUID, days_before_expiry: int = 7
    ) -> list[ApiCredential]:
        """Get credentials that are expiring soon.

        Args:
            tenant_id: The tenant identifier
            days_before_expiry: Number of days before expiry to check

        Returns:
            list[ApiCredential]: List of expiring credentials
        """

    @abstractmethod
    async def store_encrypted(
        self, credential_id: UUID, encrypted_data: bytes, encryption_key_id: str
    ) -> bool:
        """Store encrypted credential data.

        Args:
            credential_id: The unique identifier of the credential
            encrypted_data: The encrypted credential data
            encryption_key_id: The ID of the encryption key used

        Returns:
            bool: True if stored successfully, False otherwise
        """

    @abstractmethod
    async def retrieve_encrypted(self, credential_id: UUID) -> dict[str, Any] | None:
        """Retrieve encrypted credential data.

        Args:
            credential_id: The unique identifier of the credential

        Returns:
            dict[str, Any] | None: Dictionary with encrypted_data and encryption_key_id
        """
