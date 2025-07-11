"""
Third-party connection command implementation.

Handles connections to third-party services and platforms for identity data exchange.
"""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    require_permission,
    validate_request,
)
from app.modules.identity.application.dtos.internal import (
    AuditContext,
    NotificationContext,
)
from app.modules.identity.application.dtos.request import ThirdPartyConnectRequest
from app.modules.identity.application.dtos.response import ThirdPartyConnectResponse
from app.modules.identity.domain.enums import (
    AuditAction,
    ConnectionStatus,
    DataSyncDirection,
    NotificationType,
)
from app.modules.identity.domain.events import ThirdPartyConnected
from app.modules.identity.domain.exceptions import (
    ConnectionConfigurationError,
    CredentialError,
    ThirdPartyAuthenticationError,
    ThirdPartyConnectionError,
    ThirdPartyValidationError,
)
from app.modules.identity.domain.interfaces.repositories.user_repository import (
    IUserRepository,
)
from app.modules.identity.domain.interfaces.services.communication.notification_service import (
    IEmailService,
    INotificationService,
)
from app.modules.identity.domain.services import (
from app.modules.identity.domain.interfaces.services import (
    IAuditService,
)
    EncryptionService,
    RetryService,
    SecurityService,
    ValidationService,
)


class ConnectionMethod(Enum):
    """Method used to connect to third-party service."""
    API_KEY = "api_key"
    OAUTH = "oauth"
    BASIC_AUTH = "basic_auth"
    JWT = "jwt"
    CERTIFICATE = "certificate"
    WEBHOOK = "webhook"
    CUSTOM = "custom"


@dataclass
class ThirdPartyConfig:
    """Configuration for third-party service connection."""
    service_name: str
    service_type: str
    endpoint_url: str
    auth_method: ConnectionMethod
    api_version: str = "v1"
    timeout_seconds: int = 30
    retry_attempts: int = 3
    rate_limit_per_minute: int = 60
    supports_webhooks: bool = False
    data_retention_days: int = 90
    encryption_required: bool = True


class ThirdPartyConnectCommand(Command[ThirdPartyConnectResponse]):
    """Command to connect to third-party services."""
    
    def __init__(
        self,
        operation_type: str,  # "connect", "disconnect", "test", "sync", "refresh_credentials"
        service_provider: str,
        connection_id: UUID | None = None,
        user_id: UUID | None = None,
        connection_name: str | None = None,
        service_config: dict[str, Any] | None = None,
        authentication_data: dict[str, Any] | None = None,
        connection_method: ConnectionMethod = ConnectionMethod.API_KEY,
        auto_sync_enabled: bool = True,
        sync_direction: DataSyncDirection = DataSyncDirection.BIDIRECTIONAL,
        sync_frequency_hours: int = 24,
        webhook_url: str | None = None,
        webhook_secret: str | None = None,
        data_mapping: dict[str, str] | None = None,
        field_filters: list[str] | None = None,
        encryption_enabled: bool = True,
        store_credentials: bool = True,
        test_connection: bool = True,
        validate_permissions: bool = True,
        notification_settings: dict[str, Any] | None = None,
        custom_headers: dict[str, str] | None = None,
        proxy_settings: dict[str, str] | None = None,
        ssl_verify: bool = True,
        connection_timeout: int = 30,
        read_timeout: int = 60,
        max_retries: int = 3,
        retry_backoff_factor: float = 2.0,
        initiated_by: UUID | None = None,
        metadata: dict[str, Any] | None = None
    ):
        self.operation_type = operation_type
        self.service_provider = service_provider
        self.connection_id = connection_id
        self.user_id = user_id
        self.connection_name = connection_name
        self.service_config = service_config or {}
        self.authentication_data = authentication_data or {}
        self.connection_method = connection_method
        self.auto_sync_enabled = auto_sync_enabled
        self.sync_direction = sync_direction
        self.sync_frequency_hours = sync_frequency_hours
        self.webhook_url = webhook_url
        self.webhook_secret = webhook_secret
        self.data_mapping = data_mapping or {}
        self.field_filters = field_filters or []
        self.encryption_enabled = encryption_enabled
        self.store_credentials = store_credentials
        self.test_connection = test_connection
        self.validate_permissions = validate_permissions
        self.notification_settings = notification_settings or {}
        self.custom_headers = custom_headers or {}
        self.proxy_settings = proxy_settings or {}
        self.ssl_verify = ssl_verify
        self.connection_timeout = connection_timeout
        self.read_timeout = read_timeout
        self.max_retries = max_retries
        self.retry_backoff_factor = retry_backoff_factor
        self.initiated_by = initiated_by
        self.metadata = metadata or {}


class ThirdPartyConnectCommandHandler(CommandHandler[ThirdPartyConnectCommand, ThirdPartyConnectResponse]):
    """Handler for third-party connection operations."""
    
    def __init__(
        self,
        user_repository: IUserRepository,
        third_party_repository: IThirdPartyRepository,
        connection_repository: IConnectionRepository,
        credential_repository: ICredentialRepository,
        http_service: IHttpService,
        validation_service: ValidationService,
        security_service: SecurityService,
        encryption_service: EncryptionService,
        retry_service: RetryService,
        notification_service: INotificationService,
        audit_service: IAuditService,
        email_service: IEmailService,
        event_bus: EventBus,
        unit_of_work: UnitOfWork
    ):
        self._user_repository = user_repository
        self._third_party_repository = third_party_repository
        self._connection_repository = connection_repository
        self._credential_repository = credential_repository
        self._http_service = http_service
        self._validation_service = validation_service
        self._security_service = security_service
        self._encryption_service = encryption_service
        self._retry_service = retry_service
        self._notification_service = notification_service
        self._audit_service = audit_service
        self._email_service = email_service
        self._event_bus = event_bus
        self._unit_of_work = unit_of_work
    
    @audit_action(
        action=AuditAction.THIRD_PARTY_CONNECTION,
        resource_type="third_party_connection",
        include_request=True,
        include_response=True
    )
    @validate_request(ThirdPartyConnectRequest)
    @rate_limit(
        max_requests=50,
        window_seconds=3600,
        strategy='user'
    )
    @require_permission("integrations.third_party.manage")
    async def handle(self, command: ThirdPartyConnectCommand) -> ThirdPartyConnectResponse:
        """
        Handle third-party connection operations.
        
        Supports multiple operations:
        - connect: Establish connection to third-party service
        - disconnect: Remove connection to third-party service
        - test: Test existing connection
        - sync: Trigger data synchronization
        - refresh_credentials: Refresh authentication credentials
        
        Returns:
            ThirdPartyConnectResponse with operation results
        """
        async with self._unit_of_work:
            # Route to appropriate handler based on operation type
            if command.operation_type == "connect":
                return await self._handle_connection_establishment(command)
            if command.operation_type == "disconnect":
                return await self._handle_connection_removal(command)
            if command.operation_type == "test":
                return await self._handle_connection_test(command)
            if command.operation_type == "sync":
                return await self._handle_data_synchronization(command)
            if command.operation_type == "refresh_credentials":
                return await self._handle_credential_refresh(command)
            raise ThirdPartyValidationError(f"Unsupported operation type: {command.operation_type}")
    
    async def _handle_connection_establishment(self, command: ThirdPartyConnectCommand) -> ThirdPartyConnectResponse:
        """Handle establishing connection to third-party service."""
        # 1. Validate connection configuration
        await self._validate_connection_configuration(command)
        
        # 2. Load third-party service configuration
        service_config = await self._load_service_configuration(command.service_provider)
        
        # 3. Prepare authentication credentials
        auth_credentials = await self._prepare_authentication_credentials(
            command.authentication_data,
            command.connection_method,
            service_config
        )
        
        # 4. Test connection if requested
        connection_test_result = None
        if command.test_connection:
            connection_test_result = await self._test_service_connection(
                service_config,
                auth_credentials,
                command
            )
            
            if not connection_test_result["success"]:
                raise ThirdPartyConnectionError(
                    f"Connection test failed: {connection_test_result.get('error')}"
                )
        
        # 5. Store encrypted credentials if enabled
        credential_id = None
        if command.store_credentials:
            credential_id = await self._store_encrypted_credentials(
                auth_credentials,
                command.connection_method,
                command
            )
        
        # 6. Create connection record
        connection_data = {
            "id": UUID(),
            "user_id": command.user_id,
            "service_provider": command.service_provider,
            "connection_name": command.connection_name or f"{command.service_provider} Connection",
            "connection_method": command.connection_method.value,
            "status": ConnectionStatus.ACTIVE,
            "service_config": service_config,
            "credential_id": credential_id,
            "auto_sync_enabled": command.auto_sync_enabled,
            "sync_direction": command.sync_direction.value,
            "sync_frequency_hours": command.sync_frequency_hours,
            "webhook_url": command.webhook_url,
            "webhook_secret": command.webhook_secret,
            "data_mapping": command.data_mapping,
            "field_filters": command.field_filters,
            "encryption_enabled": command.encryption_enabled,
            "notification_settings": command.notification_settings,
            "custom_headers": command.custom_headers,
            "proxy_settings": command.proxy_settings,
            "ssl_verify": command.ssl_verify,
            "connection_timeout": command.connection_timeout,
            "read_timeout": command.read_timeout,
            "max_retries": command.max_retries,
            "retry_backoff_factor": command.retry_backoff_factor,
            "last_test_at": datetime.now(UTC) if command.test_connection else None,
            "last_test_result": connection_test_result,
            "created_at": datetime.now(UTC),
            "created_by": command.initiated_by,
            "metadata": command.metadata
        }
        
        connection = await self._connection_repository.create(connection_data)
        
        # 7. Set up webhook if configured
        webhook_setup_result = None
        if command.webhook_url:
            webhook_setup_result = await self._setup_webhook_integration(
                connection,
                service_config,
                auth_credentials,
                command
            )
        
        # 8. Perform initial data sync if enabled
        initial_sync_result = None
        if command.auto_sync_enabled:
            try:
                initial_sync_result = await self._perform_initial_data_sync(
                    connection,
                    service_config,
                    auth_credentials,
                    command
                )
            except Exception as e:
                await self._audit_service.log_warning(
                    f"Initial sync failed for connection {connection.id}: {e!s}"
                )
        
        # 9. Set up notification settings
        if command.notification_settings:
            await self._configure_connection_notifications(
                connection,
                command.notification_settings,
                command
            )
        
        # 10. Log connection establishment
        await self._log_connection_establishment(connection, command)
        
        # 11. Publish domain event
        await self._event_bus.publish(
            ThirdPartyConnected(
                aggregate_id=connection.id,
                connection_id=connection.id,
                user_id=command.user_id,
                service_provider=command.service_provider,
                connection_method=command.connection_method.value,
                auto_sync_enabled=command.auto_sync_enabled,
                webhook_configured=bool(command.webhook_url),
                connected_by=command.initiated_by
            )
        )
        
        # 12. Commit transaction
        await self._unit_of_work.commit()
        
        # 13. Generate response
        return ThirdPartyConnectResponse(
            success=True,
            operation_type="connect",
            connection_id=connection.id,
            service_provider=command.service_provider,
            connection_name=connection.connection_name,
            status=ConnectionStatus.ACTIVE.value,
            connection_method=command.connection_method.value,
            test_result=connection_test_result,
            webhook_setup_result=webhook_setup_result,
            initial_sync_result=initial_sync_result,
            credentials_stored=command.store_credentials,
            auto_sync_enabled=command.auto_sync_enabled,
            created_at=connection.created_at,
            message="Third-party connection established successfully"
        )
    
    async def _validate_connection_configuration(self, command: ThirdPartyConnectCommand) -> None:
        """Validate connection configuration parameters."""
        # Validate service provider
        if not command.service_provider:
            raise ConnectionConfigurationError("Service provider is required")
        
        # Validate authentication data
        if not command.authentication_data:
            raise ConnectionConfigurationError("Authentication data is required")
        
        # Validate authentication method requirements
        required_auth_fields = {
            ConnectionMethod.API_KEY: ["api_key"],
            ConnectionMethod.OAUTH: ["access_token"],
            ConnectionMethod.BASIC_AUTH: ["username", "password"],
            ConnectionMethod.JWT: ["token"],
            ConnectionMethod.CERTIFICATE: ["certificate", "private_key"]
        }
        
        required_fields = required_auth_fields.get(command.connection_method, [])
        for field in required_fields:
            if field not in command.authentication_data:
                raise ConnectionConfigurationError(f"Missing required field for {command.connection_method.value}: {field}")
        
        # Validate webhook configuration
        if command.webhook_url:
            if not self._validation_service.validate_url(command.webhook_url):
                raise ConnectionConfigurationError("Invalid webhook URL")
            
            if not command.webhook_url.startswith("https://"):
                raise ConnectionConfigurationError("Webhook URL must use HTTPS")
        
        # Validate sync configuration
        if command.sync_frequency_hours < 1 or command.sync_frequency_hours > 168:
            raise ConnectionConfigurationError("Sync frequency must be between 1 and 168 hours")
        
        # Validate timeout settings
        if command.connection_timeout < 5 or command.connection_timeout > 300:
            raise ConnectionConfigurationError("Connection timeout must be between 5 and 300 seconds")
    
    async def _load_service_configuration(self, service_provider: str) -> dict[str, Any]:
        """Load configuration for the specified service provider."""
        service = await self._third_party_repository.get_service_by_name(service_provider)
        if not service:
            raise ConnectionConfigurationError(f"Unknown service provider: {service_provider}")
        
        if not service.enabled:
            raise ConnectionConfigurationError(f"Service provider {service_provider} is disabled")
        
        return service.configuration
    
    async def _prepare_authentication_credentials(
        self,
        auth_data: dict[str, Any],
        auth_method: ConnectionMethod,
        service_config: dict[str, Any]
    ) -> dict[str, Any]:
        """Prepare authentication credentials for the service."""
        credentials = auth_data.copy()
        
        # Add service-specific authentication parameters
        if auth_method == ConnectionMethod.OAUTH:
            # Ensure OAuth token is valid and not expired
            if "expires_at" in credentials:
                expires_at = datetime.fromisoformat(credentials["expires_at"])
                if expires_at <= datetime.now(UTC):
                    raise ThirdPartyAuthenticationError("OAuth token has expired")
        
        elif auth_method == ConnectionMethod.JWT:
            # Validate JWT token structure
            token = credentials.get("token")
            if not self._security_service.validate_jwt_structure(token):
                raise ThirdPartyAuthenticationError("Invalid JWT token format")
        
        elif auth_method == ConnectionMethod.CERTIFICATE:
            # Validate certificate and private key
            cert = credentials.get("certificate")
            private_key = credentials.get("private_key")
            if not self._security_service.validate_certificate(cert, private_key):
                raise ThirdPartyAuthenticationError("Invalid certificate or private key")
        
        return credentials
    
    async def _test_service_connection(
        self,
        service_config: dict[str, Any],
        auth_credentials: dict[str, Any],
        command: ThirdPartyConnectCommand
    ) -> dict[str, Any]:
        """Test connection to the third-party service."""
        test_endpoint = service_config.get("test_endpoint") or service_config.get("base_url")
        if not test_endpoint:
            return {"success": False, "error": "No test endpoint configured"}
        
        try:
            # Prepare authentication headers
            headers = await self._prepare_auth_headers(
                auth_credentials,
                command.connection_method,
                service_config
            )
            headers.update(command.custom_headers)
            
            # Make test request with retry logic
            response = await self._retry_service.retry_async(
                self._make_test_request,
                max_attempts=command.max_retries,
                delay_seconds=1,
                exponential_backoff=True,
                backoff_factor=command.retry_backoff_factor,
                args=(test_endpoint, headers, command)
            )
            
            # Evaluate test result
            success = 200 <= response.get("status_code", 0) < 300
            
            return {
                "success": success,
                "status_code": response.get("status_code"),
                "response_time_ms": response.get("response_time_ms"),
                "error": response.get("error") if not success else None,
                "test_endpoint": test_endpoint,
                "timestamp": datetime.now(UTC).isoformat()
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "test_endpoint": test_endpoint,
                "timestamp": datetime.now(UTC).isoformat()
            }
    
    async def _prepare_auth_headers(
        self,
        auth_credentials: dict[str, Any],
        auth_method: ConnectionMethod,
        service_config: dict[str, Any]
    ) -> dict[str, str]:
        """Prepare authentication headers for API requests."""
        headers = {
            "User-Agent": "EzzDay-Integration/1.0",
            "Accept": "application/json"
        }
        
        if auth_method == ConnectionMethod.API_KEY:
            api_key = auth_credentials["api_key"]
            key_header = service_config.get("api_key_header", "Authorization")
            key_prefix = service_config.get("api_key_prefix", "Bearer")
            headers[key_header] = f"{key_prefix} {api_key}"
        
        elif auth_method == ConnectionMethod.OAUTH:
            access_token = auth_credentials["access_token"]
            headers["Authorization"] = f"Bearer {access_token}"
        
        elif auth_method == ConnectionMethod.BASIC_AUTH:
            username = auth_credentials["username"]
            password = auth_credentials["password"]
            import base64
            credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
            headers["Authorization"] = f"Basic {credentials}"
        
        elif auth_method == ConnectionMethod.JWT:
            token = auth_credentials["token"]
            headers["Authorization"] = f"Bearer {token}"
        
        return headers
    
    async def _make_test_request(
        self,
        test_endpoint: str,
        headers: dict[str, str],
        command: ThirdPartyConnectCommand
    ) -> dict[str, Any]:
        """Make test request to service endpoint."""
        start_time = datetime.now(UTC)
        
        try:
            response = await self._http_service.get(
                test_endpoint,
                headers=headers,
                timeout=command.connection_timeout,
                verify_ssl=command.ssl_verify,
                proxy=command.proxy_settings
            )
            
            end_time = datetime.now(UTC)
            response_time_ms = int((end_time - start_time).total_seconds() * 1000)
            
            return {
                "status_code": response.get("status_code"),
                "response_time_ms": response_time_ms,
                "content": response.get("content")
            }
            
        except Exception as e:
            end_time = datetime.now(UTC)
            response_time_ms = int((end_time - start_time).total_seconds() * 1000)
            
            return {
                "error": str(e),
                "response_time_ms": response_time_ms
            }
    
    async def _store_encrypted_credentials(
        self,
        auth_credentials: dict[str, Any],
        auth_method: ConnectionMethod,
        command: ThirdPartyConnectCommand
    ) -> UUID:
        """Store encrypted authentication credentials."""
        if not command.encryption_enabled:
            raise CredentialError("Encryption must be enabled to store credentials")
        
        # Encrypt sensitive credential data
        encrypted_credentials = {}
        for key, value in auth_credentials.items():
            if isinstance(value, str) and key in ["api_key", "password", "token", "private_key", "secret"]:
                encrypted_credentials[key] = await self._encryption_service.encrypt(value)
            else:
                encrypted_credentials[key] = value
        
        credential_data = {
            "id": UUID(),
            "user_id": command.user_id,
            "service_provider": command.service_provider,
            "auth_method": auth_method.value,
            "encrypted_credentials": encrypted_credentials,
            "encryption_key_id": await self._encryption_service.get_current_key_id(),
            "created_at": datetime.now(UTC),
            "created_by": command.initiated_by,
            "expires_at": None  # Set based on credential type
        }
        
        # Set expiration based on credential type
        if auth_method == ConnectionMethod.OAUTH and "expires_in" in auth_credentials:
            credential_data["expires_at"] = datetime.now(UTC) + timedelta(
                seconds=int(auth_credentials["expires_in"])
            )
        
        return await self._credential_repository.create(credential_data)
    
    async def _setup_webhook_integration(
        self,
        connection: Any,
        service_config: dict[str, Any],
        auth_credentials: dict[str, Any],
        command: ThirdPartyConnectCommand
    ) -> dict[str, Any]:
        """Set up webhook integration with the third-party service."""
        webhook_endpoint = service_config.get("webhook_endpoint")
        if not webhook_endpoint:
            return {"success": False, "error": "Service does not support webhooks"}
        
        try:
            # Prepare webhook registration payload
            webhook_payload = {
                "url": command.webhook_url,
                "secret": command.webhook_secret,
                "events": service_config.get("supported_webhook_events", ["*"]),
                "active": True
            }
            
            # Register webhook with service
            headers = await self._prepare_auth_headers(
                auth_credentials,
                command.connection_method,
                service_config
            )
            
            response = await self._http_service.post(
                webhook_endpoint,
                json=webhook_payload,
                headers=headers,
                timeout=command.connection_timeout
            )
            
            success = 200 <= response.get("status_code", 0) < 300
            
            return {
                "success": success,
                "webhook_id": response.get("content", {}).get("id") if success else None,
                "status_code": response.get("status_code"),
                "error": response.get("content", {}).get("error") if not success else None
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _perform_initial_data_sync(
        self,
        connection: Any,
        service_config: dict[str, Any],
        auth_credentials: dict[str, Any],
        command: ThirdPartyConnectCommand
    ) -> dict[str, Any]:
        """Perform initial data synchronization."""
        sync_endpoint = service_config.get("sync_endpoint")
        if not sync_endpoint:
            return {"success": False, "error": "Service does not support data sync"}
        
        try:
            # Prepare headers
            headers = await self._prepare_auth_headers(
                auth_credentials,
                command.connection_method,
                service_config
            )
            
            # Make sync request
            response = await self._http_service.get(
                sync_endpoint,
                headers=headers,
                timeout=command.read_timeout
            )
            
            success = 200 <= response.get("status_code", 0) < 300
            
            if success:
                sync_data = response.get("content", {})
                
                # Process and store synced data
                await self._process_synced_data(
                    connection,
                    sync_data,
                    command
                )
                
                return {
                    "success": True,
                    "records_synced": len(sync_data.get("data", [])),
                    "sync_timestamp": datetime.now(UTC).isoformat()
                }
            return {
                "success": False,
                "error": f"Sync failed with status {response.get('status_code')}"
            }
                
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    async def _process_synced_data(
        self,
        connection: Any,
        sync_data: dict[str, Any],
        command: ThirdPartyConnectCommand
    ) -> None:
        """Process and store synced data from third-party service."""
        # Apply data mapping if configured
        if command.data_mapping:
            sync_data = await self._apply_data_mapping(sync_data, command.data_mapping)
        
        # Apply field filters if configured
        if command.field_filters:
            sync_data = await self._apply_field_filters(sync_data, command.field_filters)
        
        # Store processed data (implementation would depend on specific service)
        await self._third_party_repository.store_sync_data(
            connection.id,
            sync_data,
            datetime.now(UTC)
        )
    
    async def _apply_data_mapping(
        self,
        data: dict[str, Any],
        mapping: dict[str, str]
    ) -> dict[str, Any]:
        """Apply field mapping to synced data."""
        mapped_data = {}
        
        for source_field, target_field in mapping.items():
            if source_field in data:
                mapped_data[target_field] = data[source_field]
        
        # Include unmapped fields
        for key, value in data.items():
            if key not in mapping and key not in mapped_data:
                mapped_data[key] = value
        
        return mapped_data
    
    async def _apply_field_filters(
        self,
        data: dict[str, Any],
        filters: list[str]
    ) -> dict[str, Any]:
        """Apply field filters to synced data."""
        if not filters:
            return data
        
        filtered_data = {}
        for field in filters:
            if field in data:
                filtered_data[field] = data[field]
        
        return filtered_data
    
    async def _configure_connection_notifications(
        self,
        connection: Any,
        notification_settings: dict[str, Any],
        command: ThirdPartyConnectCommand
    ) -> None:
        """Configure notifications for the connection."""
        if notification_settings.get("sync_notifications"):
            await self._notification_service.create_notification(
                NotificationContext(
                    notification_id=UUID(),
                    recipient_id=command.user_id,
                    notification_type=NotificationType.THIRD_PARTY_CONNECTED,
                    channel="in_app",
                    template_id="third_party_connected",
                    template_data={
                        "service_provider": command.service_provider,
                        "connection_name": connection.connection_name,
                        "connected_at": datetime.now(UTC).isoformat()
                    },
                    priority="low"
                )
            )
    
    async def _log_connection_establishment(
        self,
        connection: Any,
        command: ThirdPartyConnectCommand
    ) -> None:
        """Log third-party connection establishment."""
        await self._audit_service.log_action(
            AuditContext(
                action=AuditAction.THIRD_PARTY_CONNECTED,
                actor_id=command.initiated_by,
                resource_type="third_party_connection",
                resource_id=connection.id,
                details={
                    "service_provider": command.service_provider,
                    "connection_name": connection.connection_name,
                    "connection_method": command.connection_method.value,
                    "auto_sync_enabled": command.auto_sync_enabled,
                    "webhook_configured": bool(command.webhook_url),
                    "encryption_enabled": command.encryption_enabled
                },
                risk_level="low"
            )
        )
    
    async def _handle_connection_removal(self, command: ThirdPartyConnectCommand) -> ThirdPartyConnectResponse:
        """Handle disconnection from third-party service."""
        # Implementation for disconnecting from service
        raise NotImplementedError("Connection removal not yet implemented")
    
    async def _handle_connection_test(self, command: ThirdPartyConnectCommand) -> ThirdPartyConnectResponse:
        """Handle testing existing connection."""
        # Implementation for testing connection
        raise NotImplementedError("Connection testing not yet implemented")
    
    async def _handle_data_synchronization(self, command: ThirdPartyConnectCommand) -> ThirdPartyConnectResponse:
        """Handle manual data synchronization."""
        # Implementation for manual sync trigger
        raise NotImplementedError("Data synchronization not yet implemented")
    
    async def _handle_credential_refresh(self, command: ThirdPartyConnectCommand) -> ThirdPartyConnectResponse:
        """Handle refreshing authentication credentials."""
        # Implementation for credential refresh
        raise NotImplementedError("Credential refresh not yet implemented")