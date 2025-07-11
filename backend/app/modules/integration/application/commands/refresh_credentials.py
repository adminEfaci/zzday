"""Refresh credentials command and handler.

This module provides the command and handler for refreshing authentication
credentials with automatic token renewal and validation.
"""

from datetime import datetime, timedelta
from uuid import UUID

from app.core.cqrs.base import Command, CommandHandler
from app.core.errors import NotFoundError, ValidationError
from app.core.logging import get_logger
from app.modules.integration.application.dto import CredentialDTO
from app.modules.integration.domain.entities import ApiCredential
from app.modules.integration.domain.enums import AuthType
from app.modules.integration.domain.errors import AuthenticationError
from typing import Any

logger = get_logger(__name__)


class RefreshCredentialsCommand(Command):
    """Command to refresh authentication credentials."""

    def __init__(
        self,
        credential_id: UUID,
        force_refresh: bool = False,
        validate_after_refresh: bool = True,
    ):
        """Initialize refresh credentials command.

        Args:
            credential_id: ID of credential to refresh
            force_refresh: Force refresh even if not expired
            validate_after_refresh: Validate credentials after refresh
        """
        super().__init__()

        self.credential_id = credential_id
        self.force_refresh = force_refresh
        self.validate_after_refresh = validate_after_refresh

        self._freeze()

    def _validate_command(self) -> None:
        """Validate command state."""
        if not self.credential_id:
            raise ValidationError("credential_id is required")


class RefreshCredentialsCommandHandler(
    CommandHandler[RefreshCredentialsCommand, CredentialDTO]
):
    """Handler for refreshing credentials."""

    def __init__(
        self,
        credential_repository: Any,
        integration_repository: Any,
        auth_service: Any,
        encryption_service: Any,
        event_publisher: Any,
    ):
        """Initialize handler with dependencies.

        Args:
            credential_repository: Repository for credential persistence
            integration_repository: Repository for integrations
            auth_service: Service for authentication operations
            encryption_service: Service for credential encryption
            event_publisher: Event publisher for domain events
        """
        super().__init__()
        self._credential_repository = credential_repository
        self._integration_repository = integration_repository
        self._auth_service = auth_service
        self._encryption_service = encryption_service
        self._event_publisher = event_publisher

    async def handle(self, command: RefreshCredentialsCommand) -> CredentialDTO:
        """Handle refresh credentials command.

        Args:
            command: Refresh credentials command

        Returns:
            CredentialDTO: Refreshed credential

        Raises:
            NotFoundError: If credential not found
            AuthenticationError: If refresh fails
            ValidationError: If credential cannot be refreshed
        """
        logger.info(
            "Refreshing credentials",
            credential_id=command.credential_id,
            force_refresh=command.force_refresh,
        )

        # Get credential
        credential = await self._credential_repository.get_by_id(command.credential_id)
        if not credential:
            raise NotFoundError(f"Credential not found: {command.credential_id}")

        # Get integration
        integration = await self._integration_repository.get_by_id(
            credential.integration_id
        )
        if not integration:
            raise NotFoundError(f"Integration not found: {credential.integration_id}")

        # Check if credential needs refresh
        if not command.force_refresh and not credential.needs_refresh:
            logger.info(
                "Credential does not need refresh",
                credential_id=credential.id,
                expires_at=credential.expires_at,
            )
            return CredentialDTO.from_domain(credential)

        # Check if auth type supports refresh
        if not credential.auth_type.requires_refresh:
            if command.force_refresh:
                logger.warning(
                    "Auth type does not support refresh",
                    credential_id=credential.id,
                    auth_type=credential.auth_type.value,
                )
                return CredentialDTO.from_domain(credential)
            raise ValidationError(
                f"Auth type {credential.auth_type.value} does not support refresh"
            )

        try:
            # Refresh based on auth type
            if credential.auth_type == AuthType.OAUTH2:
                await self._refresh_oauth2_token(credential, integration)
            elif credential.auth_type == AuthType.JWT:
                await self._refresh_jwt_token(credential, integration)
            else:
                raise ValidationError(
                    f"Unsupported auth type for refresh: {credential.auth_type.value}"
                )

            # Validate refreshed credentials if requested
            if command.validate_after_refresh:
                validation_result = await self._auth_service.validate_credential(
                    credential=credential, integration=integration
                )

                if not validation_result.is_valid:
                    raise AuthenticationError(
                        f"Refreshed credential validation failed: {validation_result.error}"
                    )

                credential.mark_validated()

            # Update last refresh time
            credential.record_refresh()

            # Save changes
            await self._credential_repository.save(credential)

            # Publish events
            for event in credential.collect_events():
                await self._event_publisher.publish(event)

            logger.info(
                "Credentials refreshed successfully",
                credential_id=credential.id,
                expires_at=credential.expires_at,
            )

            return CredentialDTO.from_domain(credential)

        except Exception as e:
            logger.exception(
                "Failed to refresh credentials",
                credential_id=credential.id,
                error=str(e),
            )

            # Mark credential as invalid
            credential.mark_invalid(str(e))
            await self._credential_repository.save(credential)

            if isinstance(e, AuthenticationError | ValidationError):
                raise
            raise AuthenticationError(f"Failed to refresh credentials: {e!s}")

    async def _refresh_oauth2_token(
        self, credential: ApiCredential, integration: Any
    ) -> None:
        """Refresh OAuth2 access token.

        Args:
            credential: Credential to refresh
            integration: Associated integration
        """
        # Get current credential data
        credential_data = await self._encryption_service.decrypt(
            credential.encrypted_data
        )

        if "refresh_token" not in credential_data:
            raise AuthenticationError(
                "No refresh token available for OAuth2 credential"
            )

        # Use auth service to refresh token
        refreshed_data = await self._auth_service.refresh_oauth2_token(
            integration=integration,
            refresh_token=credential_data["refresh_token"],
            client_id=credential_data.get("client_id"),
            client_secret=credential_data.get("client_secret"),
        )

        # Update credential with new token data
        new_credential_data = {
            **credential_data,
            "access_token": refreshed_data["access_token"],
            "expires_in": refreshed_data.get("expires_in", 3600),
            "token_type": refreshed_data.get("token_type", "Bearer"),
        }

        # Update refresh token if provided
        if "refresh_token" in refreshed_data:
            new_credential_data["refresh_token"] = refreshed_data["refresh_token"]

        # Encrypt and store new data
        encrypted_data = await self._encryption_service.encrypt(new_credential_data)
        credential.update_credentials(encrypted_data)

        # Set new expiration time
        if "expires_in" in refreshed_data:
            expires_at = datetime.utcnow() + timedelta(
                seconds=refreshed_data["expires_in"]
            )
            credential.set_expiration(expires_at)

    async def _refresh_jwt_token(
        self, credential: ApiCredential, integration: Any
    ) -> None:
        """Refresh JWT token.

        Args:
            credential: Credential to refresh
            integration: Associated integration
        """
        # Get current credential data
        credential_data = await self._encryption_service.decrypt(
            credential.encrypted_data
        )

        # Generate new JWT token
        new_token_data = await self._auth_service.generate_jwt_token(
            integration=integration,
            private_key=credential_data.get("private_key"),
            payload=credential_data.get("payload", {}),
            algorithm=credential_data.get("algorithm", "RS256"),
        )

        # Update credential with new token
        new_credential_data = {
            **credential_data,
            "token": new_token_data["token"],
            "expires_in": new_token_data.get("expires_in", 3600),
        }

        # Encrypt and store new data
        encrypted_data = await self._encryption_service.encrypt(new_credential_data)
        credential.update_credentials(encrypted_data)

        # Set new expiration time
        if "expires_in" in new_token_data:
            expires_at = datetime.utcnow() + timedelta(
                seconds=new_token_data["expires_in"]
            )
            credential.set_expiration(expires_at)

    @property
    def command_type(self) -> type[RefreshCredentialsCommand]:
        """Get command type this handler processes."""
        return RefreshCredentialsCommand
