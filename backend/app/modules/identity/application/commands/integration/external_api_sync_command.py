"""
External API sync command implementation.

Handles synchronization with external APIs and systems for user data and metadata.
"""

import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import aiohttp

from app.core.cqrs import Command, CommandHandler
from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    require_permission,
    validate_request,
)
from app.modules.identity.application.dtos.internal import AuditContext, EmailContext
from app.modules.identity.application.dtos.request import ExternalApiSyncRequest
from app.modules.identity.application.dtos.response import ExternalApiSyncResponse
from app.modules.identity.domain.enums import (
    ApiSyncType,
    AuditAction,
    ConflictResolution,
    SyncMode,
    SyncStatus,
)
from app.modules.identity.domain.events import ExternalApiSyncCompleted
from app.modules.identity.domain.exceptions import (
    ApiAuthenticationError,
    ApiRateLimitError,
    ApiTimeoutError,
    ExternalApiError,
    SyncConfigurationError,
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
    MappingService,
    RetryService,
    SecurityService,
    ValidationService,
)


@dataclass
class ApiEndpointConfig:
    """Configuration for an API endpoint."""
    url: str
    method: str = "GET"
    headers: dict[str, str] = None
    auth_type: str = "bearer"  # bearer, basic, api_key, oauth
    timeout_seconds: int = 30
    retry_attempts: int = 3
    retry_delay_seconds: int = 5
    rate_limit_per_minute: int = 60


class ExternalApiSyncCommand(Command[ExternalApiSyncResponse]):
    """Command to synchronize data with external APIs."""
    
    def __init__(
        self,
        api_config_id: UUID,
        sync_type: ApiSyncType = ApiSyncType.USER_DATA,
        sync_mode: SyncMode = SyncMode.BIDIRECTIONAL,
        target_user_ids: list[UUID] | None = None,
        data_filters: dict[str, Any] | None = None,
        field_mapping: dict[str, str] | None = None,
        conflict_resolution: ConflictResolution = ConflictResolution.EXTERNAL_WINS,
        dry_run: bool = False,
        batch_size: int = 50,
        max_concurrent_requests: int = 10,
        timeout_minutes: int = 30,
        include_metadata: bool = True,
        validate_data: bool = True,
        transform_data: bool = True,
        notification_on_completion: bool = True,
        save_raw_responses: bool = False,
        initiated_by: UUID | None = None,
        scheduled: bool = False,
        metadata: dict[str, Any] | None = None
    ):
        self.api_config_id = api_config_id
        self.sync_type = sync_type
        self.sync_mode = sync_mode
        self.target_user_ids = target_user_ids or []
        self.data_filters = data_filters or {}
        self.field_mapping = field_mapping or {}
        self.conflict_resolution = conflict_resolution
        self.dry_run = dry_run
        self.batch_size = batch_size
        self.max_concurrent_requests = max_concurrent_requests
        self.timeout_minutes = timeout_minutes
        self.include_metadata = include_metadata
        self.validate_data = validate_data
        self.transform_data = transform_data
        self.notification_on_completion = notification_on_completion
        self.save_raw_responses = save_raw_responses
        self.initiated_by = initiated_by
        self.scheduled = scheduled
        self.metadata = metadata or {}


class ExternalApiSyncCommandHandler(CommandHandler[ExternalApiSyncCommand, ExternalApiSyncResponse]):
    """Handler for external API synchronization operations."""
    
    def __init__(
        self,
        user_repository: IUserRepository,
        external_api_repository: IExternalApiRepository,
        sync_history_repository: ISyncHistoryRepository,
        http_service: IHttpService,
        validation_service: ValidationService,
        mapping_service: MappingService,
        security_service: SecurityService,
        retry_service: RetryService,
        notification_service: INotificationService,
        audit_service: IAuditService,
        email_service: IEmailService,
        event_bus: EventBus,
        unit_of_work: UnitOfWork
    ):
        self._user_repository = user_repository
        self._external_api_repository = external_api_repository
        self._sync_history_repository = sync_history_repository
        self._http_service = http_service
        self._validation_service = validation_service
        self._mapping_service = mapping_service
        self._security_service = security_service
        self._retry_service = retry_service
        self._notification_service = notification_service
        self._audit_service = audit_service
        self._email_service = email_service
        self._event_bus = event_bus
        self._unit_of_work = unit_of_work
    
    @audit_action(
        action=AuditAction.EXTERNAL_API_SYNC_INITIATED,
        resource_type="api_sync",
        include_request=True,
        include_response=True,
        include_sync_details=True
    )
    @validate_request(ExternalApiSyncRequest)
    @rate_limit(
        max_requests=20,
        window_seconds=3600,
        strategy='global'
    )
    @require_permission("integrations.api.sync")
    async def handle(self, command: ExternalApiSyncCommand) -> ExternalApiSyncResponse:
        """
        Synchronize data with external APIs.
        
        Process:
        1. Load API configuration and validate
        2. Determine target data for synchronization
        3. Prepare API requests with proper authentication
        4. Execute API calls with concurrency control
        5. Process and validate responses
        6. Transform and map data to internal schema
        7. Apply conflict resolution and update data
        8. Handle errors and retries
        9. Generate sync report and notifications
        10. Log operations and publish events
        
        Returns:
            ExternalApiSyncResponse with sync operation details
            
        Raises:
            ExternalApiError: If external API operations fail
            ApiAuthenticationError: If API authentication fails
            SyncConfigurationError: If sync configuration invalid
            DataMappingError: If data mapping fails
        """
        async with self._unit_of_work:
            # 1. Load and validate API configuration
            api_config = await self._external_api_repository.find_by_id(command.api_config_id)
            if not api_config:
                raise SyncConfigurationError(f"API configuration {command.api_config_id} not found")
            
            if not api_config.enabled:
                raise SyncConfigurationError("API configuration is disabled")
            
            # 2. Validate sync configuration
            await self._validate_sync_configuration(api_config, command)
            
            # 3. Create sync session
            sync_session = await self._create_sync_session(api_config, command)
            
            try:
                # 4. Determine target data for sync
                target_data = await self._determine_sync_targets(api_config, command)
                
                # 5. Prepare API authentication
                auth_headers = await self._prepare_api_authentication(api_config)
                
                # 6. Execute API synchronization
                sync_results = await self._execute_api_synchronization(
                    target_data,
                    api_config,
                    auth_headers,
                    sync_session,
                    command
                )
                
                # 7. Process and apply results (unless dry run)
                if not command.dry_run:
                    await self._apply_sync_results(sync_results, api_config, command)
                
                # 8. Update sync session with results
                await self._update_sync_session_results(
                    sync_session,
                    sync_results,
                    command
                )
                
                # 9. Send notifications if enabled
                if command.notification_on_completion:
                    await self._send_sync_completion_notifications(
                        sync_session,
                        sync_results,
                        command
                    )
                
                # 10. Log sync completion
                await self._log_sync_completion(sync_session, sync_results, command)
                
                # 11. Publish domain event
                await self._event_bus.publish(
                    ExternalApiSyncCompleted(
                        aggregate_id=sync_session.id,
                        api_config_id=command.api_config_id,
                        sync_type=command.sync_type,
                        records_processed=len(sync_results.get("records", [])),
                        records_updated=sync_results.get("stats", {}).get("updated", 0),
                        records_created=sync_results.get("stats", {}).get("created", 0),
                        errors_count=len(sync_results.get("errors", [])),
                        sync_status=sync_session.status,
                        initiated_by=command.initiated_by,
                        dry_run=command.dry_run
                    )
                )
                
                # 12. Commit transaction
                if not command.dry_run:
                    await self._unit_of_work.commit()
                
                # 13. Generate response
                return self._generate_sync_response(
                    sync_session,
                    sync_results,
                    api_config,
                    command
                )
                
            except Exception as e:
                # Update sync session with error
                sync_session.status = SyncStatus.FAILED
                sync_session.error_message = str(e)
                sync_session.completed_at = datetime.now(UTC)
                
                if not command.dry_run:
                    await self._sync_history_repository.update(sync_session)
                
                # Log error
                await self._audit_service.log_error(
                    f"External API sync failed for config {command.api_config_id}: {e!s}"
                )
                
                raise
    
    async def _validate_sync_configuration(
        self,
        api_config: Any,
        command: ExternalApiSyncCommand
    ) -> None:
        """Validate external API sync configuration."""
        # Validate API endpoint configuration
        if not api_config.endpoint_url:
            raise SyncConfigurationError("API endpoint URL is required")
        
        # Validate authentication configuration
        if not api_config.authentication:
            raise SyncConfigurationError("API authentication configuration is required")
        
        # Validate batch size
        if command.batch_size < 1 or command.batch_size > 1000:
            raise SyncConfigurationError("Batch size must be between 1 and 1000")
        
        # Validate concurrency limits
        if command.max_concurrent_requests < 1 or command.max_concurrent_requests > 50:
            raise SyncConfigurationError("Max concurrent requests must be between 1 and 50")
        
        # Validate timeout
        if command.timeout_minutes < 1 or command.timeout_minutes > 240:
            raise SyncConfigurationError("Timeout must be between 1 and 240 minutes")
        
        # Validate field mapping if provided
        if command.field_mapping:
            for _external_field, internal_field in command.field_mapping.items():
                if not self._validation_service.validate_field_name(internal_field):
                    raise SyncConfigurationError(f"Invalid internal field name: {internal_field}")
    
    async def _create_sync_session(
        self,
        api_config: Any,
        command: ExternalApiSyncCommand
    ) -> Any:
        """Create new sync session record."""
        sync_session = {
            "id": UUID(),
            "api_config_id": command.api_config_id,
            "api_name": api_config.name,
            "sync_type": command.sync_type.value,
            "sync_mode": command.sync_mode.value,
            "status": SyncStatus.INITIATED,
            "initiated_by": command.initiated_by,
            "initiated_at": datetime.now(UTC),
            "scheduled": command.scheduled,
            "dry_run": command.dry_run,
            "configuration": {
                "target_user_ids": [str(uid) for uid in command.target_user_ids],
                "data_filters": command.data_filters,
                "field_mapping": command.field_mapping,
                "conflict_resolution": command.conflict_resolution.value,
                "batch_size": command.batch_size,
                "max_concurrent_requests": command.max_concurrent_requests,
                "timeout_minutes": command.timeout_minutes,
                "include_metadata": command.include_metadata,
                "validate_data": command.validate_data,
                "transform_data": command.transform_data
            },
            "metadata": command.metadata
        }
        
        if not command.dry_run:
            return await self._sync_history_repository.create(sync_session)
        return type('SyncSession', (), sync_session)()
    
    async def _determine_sync_targets(
        self,
        api_config: Any,
        command: ExternalApiSyncCommand
    ) -> list[dict[str, Any]]:
        """Determine what data needs to be synchronized."""
        if command.target_user_ids:
            # Sync specific users
            users = await self._user_repository.find_by_ids(command.target_user_ids)
            return [{"type": "user", "data": user} for user in users]
        
        if command.sync_type == ApiSyncType.USER_DATA:
            # Sync all users (filtered if needed)
            users = await self._user_repository.find_all_active()
            
            # Apply data filters if specified
            if command.data_filters:
                users = self._apply_data_filters(users, command.data_filters)
            
            return [{"type": "user", "data": user} for user in users]
        
        if command.sync_type == ApiSyncType.ORGANIZATION_DATA:
            # Sync organization data
            # This would fetch organization records
            return [{"type": "organization", "data": {}}]
        
        if command.sync_type == ApiSyncType.CUSTOM:
            # Custom sync logic based on API configuration
            return await self._get_custom_sync_targets(api_config, command)
        
        raise SyncConfigurationError(f"Unsupported sync type: {command.sync_type}")
    
    def _apply_data_filters(
        self,
        data: list[Any],
        filters: dict[str, Any]
    ) -> list[Any]:
        """Apply data filters to limit what gets synchronized."""
        filtered_data = []
        
        for item in data:
            include_item = True
            
            for filter_field, filter_value in filters.items():
                item_value = getattr(item, filter_field, None)
                
                if isinstance(filter_value, dict):
                    # Complex filter (e.g., {"gt": 100, "lt": 1000})
                    if "eq" in filter_value and item_value != filter_value["eq"]:
                        include_item = False
                        break
                    if "gt" in filter_value and (item_value is None or item_value <= filter_value["gt"]):
                        include_item = False
                        break
                    if "lt" in filter_value and (item_value is None or item_value >= filter_value["lt"]):
                        include_item = False
                        break
                    if "in" in filter_value and item_value not in filter_value["in"]:
                        include_item = False
                        break
                # Simple equality filter
                elif item_value != filter_value:
                    include_item = False
                    break
            
            if include_item:
                filtered_data.append(item)
        
        return filtered_data
    
    async def _get_custom_sync_targets(
        self,
        api_config: Any,
        command: ExternalApiSyncCommand
    ) -> list[dict[str, Any]]:
        """Get custom sync targets based on API configuration."""
        # This would implement custom logic based on the API configuration
        # For example, fetching specific data sets, applying custom queries, etc.
        return []
    
    async def _prepare_api_authentication(self, api_config: Any) -> dict[str, str]:
        """Prepare authentication headers for API requests."""
        auth_config = api_config.authentication
        headers = {}
        
        if auth_config["type"] == "bearer":
            # Bearer token authentication
            token = auth_config.get("token") or await self._get_bearer_token(auth_config)
            headers["Authorization"] = f"Bearer {token}"
        
        elif auth_config["type"] == "basic":
            # Basic authentication
            import base64
            credentials = f"{auth_config['username']}:{auth_config['password']}"
            encoded_credentials = base64.b64encode(credentials.encode()).decode()
            headers["Authorization"] = f"Basic {encoded_credentials}"
        
        elif auth_config["type"] == "api_key":
            # API key authentication
            key_header = auth_config.get("header", "X-API-Key")
            headers[key_header] = auth_config["api_key"]
        
        elif auth_config["type"] == "oauth":
            # OAuth 2.0 authentication
            access_token = await self._get_oauth_access_token(auth_config)
            headers["Authorization"] = f"Bearer {access_token}"
        
        else:
            raise ApiAuthenticationError(f"Unsupported authentication type: {auth_config['type']}")
        
        # Add custom headers if specified
        if api_config.custom_headers:
            headers.update(api_config.custom_headers)
        
        return headers
    
    async def _get_bearer_token(self, auth_config: dict[str, Any]) -> str:
        """Get bearer token for API authentication."""
        if "token_endpoint" in auth_config:
            # Get token from endpoint
            token_response = await self._http_service.post(
                auth_config["token_endpoint"],
                data=auth_config.get("token_request_data", {}),
                headers=auth_config.get("token_request_headers", {})
            )
            return token_response.get("access_token")
        return auth_config["token"]
    
    async def _get_oauth_access_token(self, auth_config: dict[str, Any]) -> str:
        """Get OAuth access token for API authentication."""
        # Implement OAuth client credentials flow
        token_data = {
            "grant_type": "client_credentials",
            "client_id": auth_config["client_id"],
            "client_secret": auth_config["client_secret"],
            "scope": auth_config.get("scope", "")
        }
        
        token_response = await self._http_service.post(
            auth_config["token_endpoint"],
            data=token_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        
        if "access_token" not in token_response:
            raise ApiAuthenticationError("Failed to obtain OAuth access token")
        
        return token_response["access_token"]
    
    async def _execute_api_synchronization(
        self,
        target_data: list[dict[str, Any]],
        api_config: Any,
        auth_headers: dict[str, str],
        sync_session: Any,
        command: ExternalApiSyncCommand
    ) -> dict[str, Any]:
        """Execute API synchronization with concurrency control."""
        sync_results = {
            "records": [],
            "stats": {
                "total": len(target_data),
                "processed": 0,
                "updated": 0,
                "created": 0,
                "skipped": 0,
                "failed": 0
            },
            "errors": [],
            "raw_responses": [] if command.save_raw_responses else None
        }
        
        # Create semaphore for concurrency control
        semaphore = asyncio.Semaphore(command.max_concurrent_requests)
        
        # Process data in batches
        for i in range(0, len(target_data), command.batch_size):
            batch = target_data[i:i + command.batch_size]
            
            # Create tasks for concurrent processing
            tasks = [
                self._process_sync_item(
                    item,
                    api_config,
                    auth_headers,
                    semaphore,
                    command
                )
                for item in batch
            ]
            
            # Execute batch with timeout
            try:
                batch_results = await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True),
                    timeout=command.timeout_minutes * 60
                )
                
                # Process batch results
                for result in batch_results:
                    if isinstance(result, Exception):
                        sync_results["errors"].append({
                            "error": str(result),
                            "batch_index": i // command.batch_size
                        })
                        sync_results["stats"]["failed"] += 1
                    else:
                        sync_results["records"].append(result)
                        sync_results["stats"]["processed"] += 1
                        
                        if result.get("operation") == "updated":
                            sync_results["stats"]["updated"] += 1
                        elif result.get("operation") == "created":
                            sync_results["stats"]["created"] += 1
                        else:
                            sync_results["stats"]["skipped"] += 1
                        
                        if command.save_raw_responses and result.get("raw_response"):
                            sync_results["raw_responses"].append(result["raw_response"])
                
            except TimeoutError:
                error_msg = f"Batch timeout after {command.timeout_minutes} minutes"
                sync_results["errors"].append({
                    "error": error_msg,
                    "batch_index": i // command.batch_size
                })
                await self._audit_service.log_warning(error_msg)
        
        return sync_results
    
    async def _process_sync_item(
        self,
        item: dict[str, Any],
        api_config: Any,
        auth_headers: dict[str, str],
        semaphore: asyncio.Semaphore,
        command: ExternalApiSyncCommand
    ) -> dict[str, Any]:
        """Process a single sync item with retry logic."""
        async with semaphore:
            try:
                # Determine API endpoint for this item
                endpoint_url = self._build_api_endpoint_url(item, api_config, command)
                
                # Prepare request data
                request_data = await self._prepare_request_data(item, api_config, command)
                
                # Execute API request with retries
                response = await self._retry_service.retry_async(
                    self._make_api_request,
                    max_attempts=3,
                    delay_seconds=5,
                    exponential_backoff=True,
                    args=(endpoint_url, auth_headers, request_data, api_config)
                )
                
                # Process and validate response
                processed_data = await self._process_api_response(
                    response,
                    item,
                    api_config,
                    command
                )
                
                return {
                    "item_id": item.get("data", {}).get("id"),
                    "item_type": item["type"],
                    "operation": processed_data.get("operation", "processed"),
                    "data": processed_data.get("data"),
                    "changes": processed_data.get("changes", {}),
                    "raw_response": response if command.save_raw_responses else None,
                    "processed_at": datetime.now(UTC).isoformat(),
                    "success": True
                }
                
            except Exception as e:
                return {
                    "item_id": item.get("data", {}).get("id"),
                    "item_type": item["type"],
                    "operation": "failed",
                    "error": str(e),
                    "processed_at": datetime.now(UTC).isoformat(),
                    "success": False
                }
    
    def _build_api_endpoint_url(
        self,
        item: dict[str, Any],
        api_config: Any,
        command: ExternalApiSyncCommand
    ) -> str:
        """Build API endpoint URL for specific item."""
        base_url = api_config.endpoint_url
        
        # Handle URL templates (e.g., /users/{user_id})
        if "{" in base_url and "}" in base_url:
            # Replace placeholders with actual values
            item_data = item.get("data", {})
            for field_name, field_value in item_data.__dict__.items():
                placeholder = f"{{{field_name}}}"
                if placeholder in base_url:
                    base_url = base_url.replace(placeholder, str(field_value))
        
        return base_url
    
    async def _prepare_request_data(
        self,
        item: dict[str, Any],
        api_config: Any,
        command: ExternalApiSyncCommand
    ) -> dict[str, Any] | None:
        """Prepare request data for API call."""
        if command.sync_mode == SyncMode.READ_ONLY:
            # No request data needed for read-only operations
            return None
        
        item_data = item.get("data")
        if not item_data:
            return None
        
        # Map internal fields to external API fields
        mapped_data = {}
        
        if command.field_mapping:
            # Use custom field mapping
            for internal_field, external_field in command.field_mapping.items():
                if hasattr(item_data, internal_field):
                    mapped_data[external_field] = getattr(item_data, internal_field)
        else:
            # Use default mapping from API configuration
            default_mapping = api_config.field_mapping or {}
            for internal_field, external_field in default_mapping.items():
                if hasattr(item_data, internal_field):
                    mapped_data[external_field] = getattr(item_data, internal_field)
        
        # Include metadata if requested
        if command.include_metadata:
            mapped_data["_metadata"] = {
                "sync_timestamp": datetime.now(UTC).isoformat(),
                "sync_type": command.sync_type.value,
                "initiated_by": str(command.initiated_by) if command.initiated_by else None
            }
        
        return mapped_data
    
    async def _make_api_request(
        self,
        url: str,
        headers: dict[str, str],
        data: dict[str, Any] | None,
        api_config: Any
    ) -> dict[str, Any]:
        """Make API request with proper error handling."""
        method = api_config.request_method or "GET"
        timeout = api_config.timeout_seconds or 30
        
        try:
            if method.upper() == "GET":
                response = await self._http_service.get(
                    url,
                    headers=headers,
                    timeout=timeout
                )
            elif method.upper() == "POST":
                response = await self._http_service.post(
                    url,
                    json=data,
                    headers=headers,
                    timeout=timeout
                )
            elif method.upper() == "PUT":
                response = await self._http_service.put(
                    url,
                    json=data,
                    headers=headers,
                    timeout=timeout
                )
            elif method.upper() == "PATCH":
                response = await self._http_service.patch(
                    url,
                    json=data,
                    headers=headers,
                    timeout=timeout
                )
            else:
                raise ExternalApiError(f"Unsupported HTTP method: {method}")
            
            return response
            
        except aiohttp.ClientTimeout as e:
            raise ApiTimeoutError(f"API request timed out after {timeout} seconds") from e
        except aiohttp.ClientResponseError as e:
            if e.status == 401:
                raise ApiAuthenticationError("API authentication failed") from e
            if e.status == 429:
                raise ApiRateLimitError("API rate limit exceeded") from e
            raise ExternalApiError(f"API request failed with status {e.status}: {e.message}") from e
        except Exception as e:
            raise ExternalApiError(f"API request failed: {e!s}") from e
    
    async def _process_api_response(
        self,
        response: dict[str, Any],
        item: dict[str, Any],
        api_config: Any,
        command: ExternalApiSyncCommand
    ) -> dict[str, Any]:
        """Process and validate API response."""
        # Validate response structure if configured
        if command.validate_data and api_config.response_schema:
            await self._validation_service.validate_data(response, api_config.response_schema)
        
        # Transform data if requested
        if command.transform_data:
            response = await self._transform_response_data(response, api_config, command)
        
        # Map external fields back to internal fields
        mapped_data = await self._map_response_to_internal_fields(
            response,
            api_config,
            command
        )
        
        # Determine what operation was performed
        operation = self._determine_response_operation(response, item, api_config)
        
        # Calculate changes if applicable
        changes = {}
        if operation in ["updated", "synchronized"]:
            changes = await self._calculate_data_changes(
                item.get("data"),
                mapped_data,
                command
            )
        
        return {
            "operation": operation,
            "data": mapped_data,
            "changes": changes,
            "response_metadata": response.get("_metadata", {})
        }
    
    async def _transform_response_data(
        self,
        response: dict[str, Any],
        api_config: Any,
        command: ExternalApiSyncCommand
    ) -> dict[str, Any]:
        """Transform API response data using configured transformations."""
        # Apply data transformations from API configuration
        transformations = api_config.data_transformations or []
        
        for transformation in transformations:
            if transformation["type"] == "rename_field":
                old_name = transformation["from"]
                new_name = transformation["to"]
                if old_name in response:
                    response[new_name] = response.pop(old_name)
            
            elif transformation["type"] == "format_date":
                field_name = transformation["field"]
                date_format = transformation["format"]
                if response.get(field_name):
                    # Convert date format
                    try:
                        date_obj = datetime.fromisoformat(response[field_name])
                        response[field_name] = date_obj.strftime(date_format)
                    except ValueError:
                        pass  # Keep original value if conversion fails
            
            elif transformation["type"] == "extract_nested":
                field_path = transformation["path"].split(".")
                extracted_value = response
                for path_part in field_path:
                    if isinstance(extracted_value, dict) and path_part in extracted_value:
                        extracted_value = extracted_value[path_part]
                    else:
                        extracted_value = None
                        break
                
                if extracted_value is not None:
                    response[transformation["target_field"]] = extracted_value
        
        return response
    
    async def _map_response_to_internal_fields(
        self,
        response: dict[str, Any],
        api_config: Any,
        command: ExternalApiSyncCommand
    ) -> dict[str, Any]:
        """Map external API fields to internal application fields."""
        mapped_data = {}
        
        # Use reverse mapping (external -> internal)
        field_mapping = command.field_mapping or api_config.field_mapping or {}
        reverse_mapping = {v: k for k, v in field_mapping.items()}
        
        for external_field, internal_field in reverse_mapping.items():
            if external_field in response:
                mapped_data[internal_field] = response[external_field]
        
        # Copy unmapped fields if they match internal field names
        for field_name, field_value in response.items():
            if field_name not in reverse_mapping and not field_name.startswith("_"):
                mapped_data[field_name] = field_value
        
        return mapped_data
    
    def _determine_response_operation(
        self,
        response: dict[str, Any],
        item: dict[str, Any],
        api_config: Any
    ) -> str:
        """Determine what operation the API response represents."""
        # Check for operation indicators in response
        if "operation" in response:
            return response["operation"]
        
        # Check HTTP status code if available
        if "_status_code" in response:
            status_code = response["_status_code"]
            if status_code == 201:
                return "created"
            if status_code == 200:
                return "updated"
            if status_code == 204:
                return "deleted"
        
        # Default to synchronized
        return "synchronized"
    
    async def _calculate_data_changes(
        self,
        original_data: Any,
        new_data: dict[str, Any],
        command: ExternalApiSyncCommand
    ) -> dict[str, Any]:
        """Calculate changes between original and new data."""
        changes = {}
        
        if not original_data:
            return {"_all": "created"}
        
        # Compare fields
        for field_name, new_value in new_data.items():
            if hasattr(original_data, field_name):
                original_value = getattr(original_data, field_name)
                if original_value != new_value:
                    changes[field_name] = {
                        "from": original_value,
                        "to": new_value
                    }
        
        return changes
    
    async def _apply_sync_results(
        self,
        sync_results: dict[str, Any],
        api_config: Any,
        command: ExternalApiSyncCommand
    ) -> None:
        """Apply synchronization results to update internal data."""
        for record in sync_results["records"]:
            if not record["success"]:
                continue
            
            try:
                if record["item_type"] == "user" and record.get("data"):
                    await self._apply_user_data_changes(
                        record,
                        api_config,
                        command
                    )
                # Add handling for other data types as needed
                
            except Exception as e:
                sync_results["errors"].append({
                    "error": f"Failed to apply changes for {record['item_id']}: {e!s}",
                    "item_id": record["item_id"],
                    "item_type": record["item_type"]
                })
    
    async def _apply_user_data_changes(
        self,
        record: dict[str, Any],
        api_config: Any,
        command: ExternalApiSyncCommand
    ) -> None:
        """Apply user data changes from API sync."""
        user_id = record["item_id"]
        changes = record.get("changes", {})
        new_data = record.get("data", {})
        
        if not changes and not new_data:
            return
        
        # Apply conflict resolution strategy
        update_data = {}
        
        if command.conflict_resolution == ConflictResolution.EXTERNAL_WINS:
            # External API data overwrites internal data
            update_data.update(new_data)
        elif command.conflict_resolution == ConflictResolution.INTERNAL_WINS:
            # Skip updates - internal data takes precedence
            return
        elif command.conflict_resolution == ConflictResolution.MERGE:
            # Merge data intelligently
            for field, change in changes.items():
                # Only update if external data is newer or more complete
                if change["to"] and (not change["from"] or len(str(change["to"])) > len(str(change["from"]))):
                    update_data[field] = change["to"]
        
        if update_data:
            update_data["external_api_last_sync"] = datetime.now(UTC)
            update_data["external_api_sync_source"] = api_config.name
            
            await self._user_repository.update(user_id, update_data)
    
    async def _update_sync_session_results(
        self,
        sync_session: Any,
        sync_results: dict[str, Any],
        command: ExternalApiSyncCommand
    ) -> None:
        """Update sync session with results."""
        sync_session.status = SyncStatus.COMPLETED if not sync_results.get("errors") else SyncStatus.COMPLETED_WITH_ERRORS
        sync_session.completed_at = datetime.now(UTC)
        sync_session.results = sync_results
        sync_session.summary = {
            "total_records": sync_results["stats"]["total"],
            "processed_records": sync_results["stats"]["processed"],
            "total_errors": len(sync_results["errors"]),
            "statistics": sync_results["stats"]
        }
        
        if not command.dry_run:
            await self._sync_history_repository.update(sync_session)
    
    async def _send_sync_completion_notifications(
        self,
        sync_session: Any,
        sync_results: dict[str, Any],
        command: ExternalApiSyncCommand
    ) -> None:
        """Send notifications about sync completion."""
        if command.initiated_by:
            # Email notification to sync initiator
            stats = sync_results["stats"]
            await self._email_service.send_email(
                EmailContext(
                    recipient=f"user_{command.initiated_by}@internal",
                    template="external_api_sync_completed",
                    subject=f"External API Sync {'Simulation' if command.dry_run else 'Completed'}",
                    variables={
                        "sync_id": str(sync_session.id),
                        "api_name": sync_session.api_name,
                        "sync_type": command.sync_type.value,
                        "dry_run": command.dry_run,
                        "total_records": stats["total"],
                        "processed_records": stats["processed"],
                        "updated_records": stats["updated"],
                        "created_records": stats["created"],
                        "failed_records": stats["failed"],
                        "errors_count": len(sync_results.get("errors", [])),
                        "duration": (sync_session.completed_at - sync_session.initiated_at).total_seconds(),
                        "view_details_link": f"https://app.example.com/admin/api-sync/{sync_session.id}"
                    }
                )
            )
    
    async def _log_sync_completion(
        self,
        sync_session: Any,
        sync_results: dict[str, Any],
        command: ExternalApiSyncCommand
    ) -> None:
        """Log sync completion for audit purposes."""
        await self._audit_service.log_action(
            AuditContext(
                action=AuditAction.EXTERNAL_API_SYNC_COMPLETED,
                actor_id=command.initiated_by,
                resource_type="api_sync",
                resource_id=sync_session.id,
                details={
                    "api_config_id": str(command.api_config_id),
                    "sync_type": command.sync_type.value,
                    "sync_mode": command.sync_mode.value,
                    "status": sync_session.status.value,
                    "dry_run": command.dry_run,
                    "duration_seconds": (sync_session.completed_at - sync_session.initiated_at).total_seconds(),
                    "statistics": sync_results["stats"],
                    "errors_count": len(sync_results.get("errors", [])),
                    "batch_size": command.batch_size,
                    "max_concurrent_requests": command.max_concurrent_requests,
                    "conflict_resolution": command.conflict_resolution.value
                },
                risk_level="medium"
            )
        )
    
    def _generate_sync_response(
        self,
        sync_session: Any,
        sync_results: dict[str, Any],
        api_config: Any,
        command: ExternalApiSyncCommand
    ) -> ExternalApiSyncResponse:
        """Generate the final sync response."""
        stats = sync_results["stats"]
        
        return ExternalApiSyncResponse(
            sync_id=sync_session.id,
            api_config_id=command.api_config_id,
            api_name=api_config.name,
            sync_type=command.sync_type,
            sync_mode=command.sync_mode,
            status=sync_session.status,
            dry_run=command.dry_run,
            initiated_by=command.initiated_by,
            initiated_at=sync_session.initiated_at,
            completed_at=sync_session.completed_at,
            duration_seconds=(sync_session.completed_at - sync_session.initiated_at).total_seconds(),
            total_records=stats["total"],
            processed_records=stats["processed"],
            updated_records=stats["updated"],
            created_records=stats["created"],
            skipped_records=stats["skipped"],
            failed_records=stats["failed"],
            total_errors=len(sync_results.get("errors", [])),
            errors=sync_results.get("errors", []),
            conflict_resolution=command.conflict_resolution,
            configuration_summary={
                "batch_size": command.batch_size,
                "max_concurrent_requests": command.max_concurrent_requests,
                "target_users": len(command.target_user_ids),
                "data_filters_applied": bool(command.data_filters),
                "field_mapping_applied": bool(command.field_mapping),
                "data_transformation": command.transform_data,
                "data_validation": command.validate_data
            },
            message=f"External API sync {'simulation' if command.dry_run else 'operation'} completed successfully"
        )