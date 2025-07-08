"""
Integration Mutations for GraphQL API

This module provides comprehensive integration management mutations including
configuration management, testing, synchronization, and lifecycle operations.
"""

from typing import Any
from uuid import UUID

import strawberry

from app.core.errors import DomainError, ValidationError
from app.core.logging import get_logger
from app.core.middleware.auth import require_auth, require_permission
from app.modules.identity.presentation.graphql.decorators import (
    audit_operation,
    rate_limit,
    track_metrics,
)

from ...schemas.inputs.integration_inputs import (
    ActivateIntegrationInput,
    CreateIntegrationInput,
    DeactivateIntegrationInput,
    IntegrationConfigurationInput,
    RefreshCredentialsInput,
    TestIntegrationInput,
    UpdateIntegrationInput,
)
from ...schemas.types.integration_type import IntegrationType

logger = get_logger(__name__)


@strawberry.type
class IntegrationMutations:
    """Integration management GraphQL mutations."""

    @strawberry.field(description="Create a new integration")
    @require_auth()
    @require_permission("integration.create")
    @audit_operation("integration.create")
    @rate_limit(requests=10, window=60)
    @track_metrics("create_integration")
    async def create_integration(
        self, info: strawberry.Info, input: CreateIntegrationInput
    ) -> IntegrationType:
        """
        Create a new integration configuration.

        Args:
            input: Integration creation parameters

        Returns:
            Created integration details

        Raises:
            ValidationError: If input validation fails
            DomainError: If business rules are violated
        """
        try:
            # Validate required fields
            if not input.name or len(input.name.strip()) < 3:
                raise ValidationError("Integration name must be at least 3 characters")

            if not input.system_name or len(input.system_name.strip()) < 2:
                raise ValidationError("System name is required")

            info.context["container"].resolve("IntegrationService")
            command = info.context["container"].resolve("CreateIntegrationCommand")

            # Execute creation command
            result = await command.execute(
                name=input.name.strip(),
                description=input.description,
                integration_type=input.integration_type,
                system_name=input.system_name.strip(),
                configuration=input.configuration or {},
                owner_id=info.context["user_id"],
            )

            logger.info(
                "Integration created successfully",
                integration_id=str(result.integration_id),
                name=input.name,
                system_name=input.system_name,
                user_id=str(info.context["user_id"]),
            )

            mapper = info.context["container"].resolve("IntegrationMapper")
            return mapper.dto_to_graphql_type(result)

        except ValidationError:
            raise
        except DomainError:
            raise
        except Exception as e:
            logger.exception(
                "Error creating integration", name=input.name, error=str(e)
            )
            raise DomainError("Failed to create integration")

    @strawberry.field(description="Update an existing integration")
    @require_auth()
    @require_permission("integration.update")
    @audit_operation("integration.update")
    @rate_limit(requests=20, window=60)
    @track_metrics("update_integration")
    async def update_integration(
        self, info: strawberry.Info, integration_id: UUID, input: UpdateIntegrationInput
    ) -> IntegrationType:
        """
        Update an existing integration configuration.

        Args:
            integration_id: UUID of the integration to update
            input: Integration update parameters

        Returns:
            Updated integration details
        """
        try:
            service = info.context["container"].resolve("IntegrationService")
            command = info.context["container"].resolve("UpdateIntegrationCommand")

            # Check if integration exists and user has access
            existing = await service.get_integration(integration_id)
            if not existing:
                raise ValidationError("Integration not found")

            # Execute update command
            result = await command.execute(
                integration_id=integration_id,
                name=input.name,
                description=input.description,
                configuration=input.configuration,
                is_active=input.is_active,
                updated_by=info.context["user_id"],
            )

            logger.info(
                "Integration updated successfully",
                integration_id=str(integration_id),
                user_id=str(info.context["user_id"]),
            )

            mapper = info.context["container"].resolve("IntegrationMapper")
            return mapper.dto_to_graphql_type(result)

        except ValidationError:
            raise
        except DomainError:
            raise
        except Exception as e:
            logger.exception(
                "Error updating integration",
                integration_id=str(integration_id),
                error=str(e),
            )
            raise DomainError("Failed to update integration")

    @strawberry.field(description="Delete an integration")
    @require_auth()
    @require_permission("integration.delete")
    @audit_operation("integration.delete")
    @rate_limit(requests=5, window=60)
    @track_metrics("delete_integration")
    async def delete_integration(
        self, info: strawberry.Info, integration_id: UUID, force: bool = False
    ) -> bool:
        """
        Delete an integration and all related data.

        Args:
            integration_id: UUID of the integration to delete
            force: Whether to force deletion even with active connections

        Returns:
            True if deletion was successful
        """
        try:
            service = info.context["container"].resolve("IntegrationService")
            command = info.context["container"].resolve("DeleteIntegrationCommand")

            # Check if integration exists
            existing = await service.get_integration(integration_id)
            if not existing:
                raise ValidationError("Integration not found")

            # Execute deletion command
            await command.execute(
                integration_id=integration_id,
                force=force,
                deleted_by=info.context["user_id"],
            )

            logger.info(
                "Integration deleted successfully",
                integration_id=str(integration_id),
                force=force,
                user_id=str(info.context["user_id"]),
            )

            return True

        except ValidationError:
            raise
        except DomainError:
            raise
        except Exception as e:
            logger.exception(
                "Error deleting integration",
                integration_id=str(integration_id),
                error=str(e),
            )
            raise DomainError("Failed to delete integration")

    @strawberry.field(description="Test integration connectivity")
    @require_auth()
    @require_permission("integration.test")
    @audit_operation("integration.test")
    @rate_limit(requests=10, window=60)
    @track_metrics("test_integration")
    async def test_integration(
        self,
        info: strawberry.Info,
        integration_id: UUID,
        input: TestIntegrationInput | None = None,
    ) -> dict[str, Any]:
        """
        Test integration connectivity and configuration.

        Args:
            integration_id: UUID of the integration to test
            input: Optional test configuration parameters

        Returns:
            Test results and diagnostics
        """
        try:
            service = info.context["container"].resolve("IntegrationTestService")

            # Execute test
            result = await service.test_integration(
                integration_id=integration_id,
                test_config=input,
                tested_by=info.context["user_id"],
            )

            logger.info(
                "Integration test completed",
                integration_id=str(integration_id),
                success=result.success,
                user_id=str(info.context["user_id"]),
            )

            return {
                "success": result.success,
                "connection_status": result.connection_status,
                "response_time_ms": result.response_time_ms,
                "test_results": result.test_results,
                "errors": result.errors,
                "warnings": result.warnings,
                "tested_at": result.tested_at,
                "test_id": str(result.test_id),
            }

        except Exception as e:
            logger.exception(
                "Error testing integration",
                integration_id=str(integration_id),
                error=str(e),
            )
            raise DomainError("Failed to test integration")

    @strawberry.field(description="Refresh integration credentials")
    @require_auth()
    @require_permission("integration.credentials.refresh")
    @audit_operation("integration.refresh_credentials")
    @rate_limit(requests=10, window=60)
    @track_metrics("refresh_integration_credentials")
    async def refresh_integration_credentials(
        self,
        info: strawberry.Info,
        integration_id: UUID,
        input: RefreshCredentialsInput | None = None,
    ) -> dict[str, Any]:
        """
        Refresh integration authentication credentials.

        Args:
            integration_id: UUID of the integration
            input: Optional refresh parameters

        Returns:
            Credential refresh results
        """
        try:
            info.context["container"].resolve("IntegrationCredentialService")
            command = info.context["container"].resolve("RefreshCredentialsCommand")

            # Execute credential refresh
            result = await command.execute(
                integration_id=integration_id,
                refresh_config=input,
                refreshed_by=info.context["user_id"],
            )

            logger.info(
                "Integration credentials refreshed",
                integration_id=str(integration_id),
                success=result.success,
                user_id=str(info.context["user_id"]),
            )

            return {
                "success": result.success,
                "credential_status": result.credential_status,
                "expires_at": result.expires_at,
                "refresh_token_updated": result.refresh_token_updated,
                "errors": result.errors,
                "refreshed_at": result.refreshed_at,
            }

        except Exception as e:
            logger.exception(
                "Error refreshing credentials",
                integration_id=str(integration_id),
                error=str(e),
            )
            raise DomainError("Failed to refresh credentials")

    @strawberry.field(description="Activate an integration")
    @require_auth()
    @require_permission("integration.activate")
    @audit_operation("integration.activate")
    @rate_limit(requests=20, window=60)
    @track_metrics("activate_integration")
    async def activate_integration(
        self,
        info: strawberry.Info,
        integration_id: UUID,
        input: ActivateIntegrationInput | None = None,
    ) -> IntegrationType:
        """
        Activate an integration for use.

        Args:
            integration_id: UUID of the integration to activate
            input: Optional activation parameters

        Returns:
            Updated integration details
        """
        try:
            info.context["container"].resolve("IntegrationService")
            command = info.context["container"].resolve("ActivateIntegrationCommand")

            # Execute activation
            result = await command.execute(
                integration_id=integration_id,
                activation_config=input,
                activated_by=info.context["user_id"],
            )

            logger.info(
                "Integration activated successfully",
                integration_id=str(integration_id),
                user_id=str(info.context["user_id"]),
            )

            mapper = info.context["container"].resolve("IntegrationMapper")
            return mapper.dto_to_graphql_type(result)

        except Exception as e:
            logger.exception(
                "Error activating integration",
                integration_id=str(integration_id),
                error=str(e),
            )
            raise DomainError("Failed to activate integration")

    @strawberry.field(description="Deactivate an integration")
    @require_auth()
    @require_permission("integration.deactivate")
    @audit_operation("integration.deactivate")
    @rate_limit(requests=20, window=60)
    @track_metrics("deactivate_integration")
    async def deactivate_integration(
        self,
        info: strawberry.Info,
        integration_id: UUID,
        input: DeactivateIntegrationInput | None = None,
    ) -> IntegrationType:
        """
        Deactivate an integration.

        Args:
            integration_id: UUID of the integration to deactivate
            input: Optional deactivation parameters

        Returns:
            Updated integration details
        """
        try:
            info.context["container"].resolve("IntegrationService")
            command = info.context["container"].resolve("DeactivateIntegrationCommand")

            # Execute deactivation
            result = await command.execute(
                integration_id=integration_id,
                deactivation_config=input,
                deactivated_by=info.context["user_id"],
            )

            logger.info(
                "Integration deactivated successfully",
                integration_id=str(integration_id),
                user_id=str(info.context["user_id"]),
            )

            mapper = info.context["container"].resolve("IntegrationMapper")
            return mapper.dto_to_graphql_type(result)

        except Exception as e:
            logger.exception(
                "Error deactivating integration",
                integration_id=str(integration_id),
                error=str(e),
            )
            raise DomainError("Failed to deactivate integration")

    @strawberry.field(description="Update integration configuration")
    @require_auth()
    @require_permission("integration.configuration.update")
    @audit_operation("integration.update_configuration")
    @rate_limit(requests=15, window=60)
    @track_metrics("update_integration_configuration")
    async def update_integration_configuration(
        self,
        info: strawberry.Info,
        integration_id: UUID,
        configuration: IntegrationConfigurationInput,
    ) -> IntegrationType:
        """
        Update integration configuration settings.

        Args:
            integration_id: UUID of the integration
            configuration: New configuration parameters

        Returns:
            Updated integration details
        """
        try:
            info.context["container"].resolve("IntegrationConfigurationService")
            command = info.context["container"].resolve("UpdateConfigurationCommand")

            # Validate configuration
            validation_service = info.context["container"].resolve(
                "IntegrationValidationService"
            )
            validation_result = await validation_service.validate_configuration(
                integration_id=integration_id, configuration=configuration.to_dict()
            )

            if not validation_result.is_valid:
                raise ValidationError(
                    f"Configuration validation failed: {validation_result.errors}"
                )

            # Execute configuration update
            result = await command.execute(
                integration_id=integration_id,
                configuration=configuration,
                updated_by=info.context["user_id"],
            )

            logger.info(
                "Integration configuration updated",
                integration_id=str(integration_id),
                user_id=str(info.context["user_id"]),
            )

            mapper = info.context["container"].resolve("IntegrationMapper")
            return mapper.dto_to_graphql_type(result)

        except ValidationError:
            raise
        except Exception as e:
            logger.exception(
                "Error updating configuration",
                integration_id=str(integration_id),
                error=str(e),
            )
            raise DomainError("Failed to update configuration")

    @strawberry.field(description="Reset integration to default state")
    @require_auth()
    @require_permission("integration.reset")
    @audit_operation("integration.reset")
    @rate_limit(requests=5, window=60)
    @track_metrics("reset_integration")
    async def reset_integration(
        self,
        info: strawberry.Info,
        integration_id: UUID,
        reset_credentials: bool = False,
        reset_configuration: bool = False,
    ) -> IntegrationType:
        """
        Reset integration to its default state.

        Args:
            integration_id: UUID of the integration to reset
            reset_credentials: Whether to reset credentials
            reset_configuration: Whether to reset configuration

        Returns:
            Reset integration details
        """
        try:
            info.context["container"].resolve("IntegrationService")
            command = info.context["container"].resolve("ResetIntegrationCommand")

            # Execute reset
            result = await command.execute(
                integration_id=integration_id,
                reset_credentials=reset_credentials,
                reset_configuration=reset_configuration,
                reset_by=info.context["user_id"],
            )

            logger.info(
                "Integration reset successfully",
                integration_id=str(integration_id),
                reset_credentials=reset_credentials,
                reset_configuration=reset_configuration,
                user_id=str(info.context["user_id"]),
            )

            mapper = info.context["container"].resolve("IntegrationMapper")
            return mapper.dto_to_graphql_type(result)

        except Exception as e:
            logger.exception(
                "Error resetting integration",
                integration_id=str(integration_id),
                error=str(e),
            )
            raise DomainError("Failed to reset integration")

    @strawberry.field(description="Clone an existing integration")
    @require_auth()
    @require_permission("integration.clone")
    @audit_operation("integration.clone")
    @rate_limit(requests=5, window=60)
    @track_metrics("clone_integration")
    async def clone_integration(
        self,
        info: strawberry.Info,
        source_integration_id: UUID,
        name: str,
        system_name: str | None = None,
        copy_credentials: bool = False,
    ) -> IntegrationType:
        """
        Clone an existing integration with new name.

        Args:
            source_integration_id: UUID of integration to clone
            name: Name for the new integration
            system_name: Optional system name for new integration
            copy_credentials: Whether to copy credentials (if permitted)

        Returns:
            Cloned integration details
        """
        try:
            # Validate inputs
            if not name or len(name.strip()) < 3:
                raise ValidationError("Integration name must be at least 3 characters")

            service = info.context["container"].resolve("IntegrationService")
            command = info.context["container"].resolve("CloneIntegrationCommand")

            # Check source integration exists
            source = await service.get_integration(source_integration_id)
            if not source:
                raise ValidationError("Source integration not found")

            # Execute clone
            result = await command.execute(
                source_integration_id=source_integration_id,
                name=name.strip(),
                system_name=system_name,
                copy_credentials=copy_credentials,
                cloned_by=info.context["user_id"],
            )

            logger.info(
                "Integration cloned successfully",
                source_integration_id=str(source_integration_id),
                new_integration_id=str(result.integration_id),
                name=name,
                user_id=str(info.context["user_id"]),
            )

            mapper = info.context["container"].resolve("IntegrationMapper")
            return mapper.dto_to_graphql_type(result)

        except ValidationError:
            raise
        except Exception as e:
            logger.exception(
                "Error cloning integration",
                source_integration_id=str(source_integration_id),
                name=name,
                error=str(e),
            )
            raise DomainError("Failed to clone integration")


__all__ = ["IntegrationMutations"]
