"""Credential repository implementation with encryption support.

This module provides the repository for API credentials with
secure encryption and decryption of sensitive data.
"""

from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import and_, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.errors import ConflictError, NotFoundError
from app.core.infrastructure.repositories import BaseRepository
from app.modules.integration.domain.entities import ApiCredential
from app.modules.integration.domain.enums import AuthType
from app.modules.integration.domain.value_objects import AuthMethod
from app.modules.integration.infrastructure.models import CredentialModel
from app.modules.integration.infrastructure.security import CredentialEncryptionService
from app.core.infrastructure.repository import BaseRepository


class CredentialRepository(BaseRepository[ApiCredential, CredentialModel]):
    """Repository for managing API credentials with encryption."""

    def __init__(
        self, session: Session, encryption_service: CredentialEncryptionService
    ):
        """Initialize repository with session and encryption service."""
        super().__init__(session, CredentialModel)
        self._encryption = encryption_service

    def _to_domain(self, model: CredentialModel) -> ApiCredential:
        """Convert database model to domain entity with decryption."""
        data = model.to_entity_dict()

        # Decrypt credentials
        decrypted_credentials = self._encryption.decrypt_data(
            model.encrypted_credentials, model.encryption_key_id
        )

        # Decrypt optional fields
        token_endpoint = None
        if model.encrypted_token_endpoint:
            token_endpoint = self._encryption.decrypt_data(
                model.encrypted_token_endpoint, model.encryption_key_id
            )

        refresh_token = None
        if model.encrypted_refresh_token:
            refresh_token = self._encryption.decrypt_data(
                model.encrypted_refresh_token, model.encryption_key_id
            )

        # Reconstruct AuthMethod
        auth_method = AuthMethod(
            auth_type=AuthType(data.pop("auth_type")),
            credentials=decrypted_credentials,
            token_endpoint=token_endpoint,
            scopes=data.pop("scopes"),
            expires_at=data.pop("expires_at"),
            refresh_token=refresh_token,
            custom_headers=data.pop("custom_headers"),
        )

        # Create entity
        credential = ApiCredential(
            integration_id=data.pop("integration_id"),
            name=data.pop("name"),
            auth_method=auth_method,
            is_active=data.pop("is_active"),
            last_used_at=data.pop("last_used_at"),
            last_rotated_at=data.pop("last_rotated_at"),
            rotation_period_days=data.pop("rotation_period_days"),
            usage_count=data.pop("usage_count"),
            failure_count=data.pop("failure_count"),
            metadata=data.pop("metadata"),
            entity_id=data.pop("entity_id"),
        )

        # Set timestamps
        credential.created_at = data.pop("created_at")
        credential.updated_at = data.pop("updated_at")
        credential._version = data.pop("version")
        credential._encryption_key_id = data.pop("_encryption_key_id")

        # Clear modification tracking
        credential._modified = False

        return credential

    def _to_model(self, entity: ApiCredential) -> CredentialModel:
        """Convert domain entity to database model with encryption."""
        data = entity.to_dict()

        # Extract auth method data
        auth_method = entity.auth_method
        data["auth_type"] = auth_method.auth_type.value
        data["scopes"] = auth_method.scopes
        data["expires_at"] = auth_method.expires_at
        data["custom_headers"] = auth_method.custom_headers

        # Encrypt sensitive data
        encrypted_data = {
            "encrypted_credentials": self._encryption.encrypt_data(
                auth_method.credentials, entity._encryption_key_id
            )
        }

        if auth_method.token_endpoint:
            encrypted_data["encrypted_token_endpoint"] = self._encryption.encrypt_data(
                auth_method.token_endpoint, entity._encryption_key_id
            )

        if auth_method.refresh_token:
            encrypted_data["encrypted_refresh_token"] = self._encryption.encrypt_data(
                auth_method.refresh_token, entity._encryption_key_id
            )

        # Map id to entity_id
        data["entity_id"] = data.pop("id")

        return CredentialModel.from_entity_dict(data, encrypted_data)

    async def find_by_id(self, credential_id: UUID) -> ApiCredential | None:
        """Find credential by ID."""
        stmt = select(CredentialModel).where(CredentialModel.id == credential_id)

        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()

        return self._to_domain(model) if model else None

    async def find_by_integration(
        self, integration_id: UUID, active_only: bool = True
    ) -> list[ApiCredential]:
        """Find all credentials for an integration."""
        stmt = select(CredentialModel).where(
            CredentialModel.integration_id == integration_id
        )

        if active_only:
            stmt = stmt.where(CredentialModel.is_active is True)

        stmt = stmt.order_by(CredentialModel.created_at.desc())

        result = await self._session.execute(stmt)
        models = result.scalars().all()

        return [self._to_domain(model) for model in models]

    async def find_by_auth_type(
        self, integration_id: UUID, auth_type: AuthType
    ) -> list[ApiCredential]:
        """Find credentials by authentication type."""
        stmt = select(CredentialModel).where(
            and_(
                CredentialModel.integration_id == integration_id,
                CredentialModel.auth_type == auth_type.value,
            )
        )

        result = await self._session.execute(stmt)
        models = result.scalars().all()

        return [self._to_domain(model) for model in models]

    async def find_expiring_soon(self, days_ahead: int = 7) -> list[ApiCredential]:
        """Find credentials expiring within specified days."""
        expiry_cutoff = datetime.now(UTC) + timedelta(days=days_ahead)

        stmt = select(CredentialModel).where(
            and_(
                CredentialModel.is_active is True,
                CredentialModel.expires_at is not None,
                CredentialModel.expires_at <= expiry_cutoff,
                CredentialModel.expires_at > datetime.now(UTC),
            )
        )

        result = await self._session.execute(stmt)
        models = result.scalars().all()

        return [self._to_domain(model) for model in models]

    async def find_needing_rotation(self) -> list[ApiCredential]:
        """Find credentials that need rotation."""
        stmt = select(CredentialModel).where(
            and_(
                CredentialModel.is_active is True,
                CredentialModel.rotation_period_days is not None,
            )
        )

        result = await self._session.execute(stmt)
        models = result.scalars().all()

        # Filter by rotation logic
        credentials = []
        for model in models:
            credential = self._to_domain(model)
            if credential.needs_rotation:
                credentials.append(credential)

        return credentials

    async def find_with_high_failure_rate(
        self, threshold: float = 0.1
    ) -> list[ApiCredential]:
        """Find credentials with high failure rate."""
        # Use database calculation for efficiency
        stmt = select(CredentialModel).where(
            and_(
                CredentialModel.is_active is True,
                (CredentialModel.usage_count + CredentialModel.failure_count) > 0,
                (
                    CredentialModel.failure_count.cast(Float)
                    / (CredentialModel.usage_count + CredentialModel.failure_count)
                )
                > threshold,
            )
        )

        result = await self._session.execute(stmt)
        models = result.scalars().all()

        return [self._to_domain(model) for model in models]

    async def count_by_integration(
        self, integration_id: UUID, active_only: bool = True
    ) -> int:
        """Count credentials for an integration."""
        stmt = select(func.count(CredentialModel.id)).where(
            CredentialModel.integration_id == integration_id
        )

        if active_only:
            stmt = stmt.where(CredentialModel.is_active is True)

        result = await self._session.execute(stmt)
        return result.scalar() or 0

    async def exists_by_name(
        self, integration_id: UUID, name: str, exclude_id: UUID | None = None
    ) -> bool:
        """Check if credential with name exists for integration."""
        stmt = select(CredentialModel.id).where(
            and_(
                CredentialModel.integration_id == integration_id,
                CredentialModel.name == name,
            )
        )

        if exclude_id:
            stmt = stmt.where(CredentialModel.id != exclude_id)

        result = await self._session.execute(stmt)
        return result.scalar() is not None

    async def update_usage_stats(self, credential_id: UUID, success: bool) -> None:
        """Update credential usage statistics."""
        stmt = select(CredentialModel).where(CredentialModel.id == credential_id)

        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()

        if not model:
            raise NotFoundError(f"Credential {credential_id} not found")

        model.last_used_at = datetime.now(UTC)
        if success:
            model.usage_count += 1
        else:
            model.failure_count += 1

        await self._session.flush()

    async def rotate_encryption_key(self, credential_id: UUID, new_key_id: str) -> None:
        """Rotate encryption key for a credential."""
        # Fetch and decrypt with old key
        credential = await self.find_by_id(credential_id)
        if not credential:
            raise NotFoundError(f"Credential {credential_id} not found")

        # Update encryption key
        credential._encryption_key_id = new_key_id

        # Re-encrypt and save
        await self.save(credential)

    async def save_with_lock(self, credential: ApiCredential) -> ApiCredential:
        """Save credential with optimistic locking."""
        model = self._to_model(credential)

        if credential._version > 1:
            # Update with version check
            stmt = select(CredentialModel).where(
                and_(
                    CredentialModel.id == model.id,
                    CredentialModel.version == credential._version - 1,
                )
            )

            result = await self._session.execute(stmt)
            existing = result.scalar_one_or_none()

            if not existing:
                raise ConflictError("Credential has been modified by another process")

            # Update fields
            for key, value in model.__dict__.items():
                if not key.startswith("_"):
                    setattr(existing, key, value)

            existing.version = credential._version
            model = existing
        else:
            # New credential
            self._session.add(model)

        try:
            await self._session.flush()
            credential._version = model.version
            return credential
        except IntegrityError as e:
            raise ConflictError(f"Failed to save credential: {e!s}")

    async def delete(self, credential_id: UUID) -> None:
        """Delete credential."""
        stmt = select(CredentialModel).where(CredentialModel.id == credential_id)

        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()

        if not model:
            raise NotFoundError(f"Credential {credential_id} not found")

        await self._session.delete(model)
        await self._session.flush()

    async def cleanup_expired(self, days_old: int = 30) -> int:
        """Clean up expired credentials older than specified days."""
        cutoff_date = datetime.now(UTC) - timedelta(days=days_old)

        stmt = select(CredentialModel).where(
            and_(
                CredentialModel.expires_at is not None,
                CredentialModel.expires_at < cutoff_date,
                CredentialModel.is_active is False,
            )
        )

        result = await self._session.execute(stmt)
        models = result.scalars().all()

        count = len(models)
        for model in models:
            await self._session.delete(model)

        await self._session.flush()
        return count
