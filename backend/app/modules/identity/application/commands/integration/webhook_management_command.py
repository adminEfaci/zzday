"""
Webhook management command implementation.

Handles webhook configuration, delivery, retry logic, and monitoring.
"""

import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.contracts.ports import (
    IAuditService,
    IEmailService,
    IHttpService,
    INotificationService,
    IUserRepository,
    IWebhookDeliveryRepository,
    IWebhookRepository,
)
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    require_permission,
    validate_request,
)
from app.modules.identity.application.dtos.internal import (
    AuditContext,
)
from app.modules.identity.application.dtos.request import WebhookManagementRequest
from app.modules.identity.application.dtos.response import WebhookManagementResponse
from app.modules.identity.domain.enums import (
    AuditAction,
    DeliveryStatus,
    WebhookEvent,
    WebhookStatus,
)
from app.modules.identity.domain.events import (
    WebhookConfigured,
    WebhookDelivered,
    WebhookFailed,
)
from app.modules.identity.domain.exceptions import (
    WebhookConfigurationError,
    WebhookDeliveryError,
    WebhookSecurityError,
    WebhookTimeoutError,
    WebhookValidationError,
)
from app.modules.identity.domain.services import (
    RetryService,
    SecurityService,
    ValidationService,
)


class WebhookManagementCommand(Command[WebhookManagementResponse]):
    """Command to manage webhook configurations and deliveries."""
    
    def __init__(
        self,
        operation_type: str,  # "configure", "deliver", "test", "disable", "delete", "retry_failed"
        webhook_id: UUID | None = None,
        webhook_url: str | None = None,
        events: list[WebhookEvent] | None = None,
        secret: str | None = None,
        headers: dict[str, str] | None = None,
        timeout_seconds: int = 30,
        retry_attempts: int = 3,
        retry_delay_seconds: int = 5,
        retry_exponential_backoff: bool = True,
        active: bool = True,
        verify_ssl: bool = True,
        custom_payload_template: str | None = None,
        payload_data: dict[str, Any] | None = None,
        event_type: WebhookEvent | None = None,
        user_id: UUID | None = None,
        delivery_id: UUID | None = None,
        batch_delivery: bool = False,
        batch_size: int = 100,
        batch_timeout_minutes: int = 5,
        include_metadata: bool = True,
        filter_criteria: dict[str, Any] | None = None,
        signing_algorithm: str = "sha256",
        delivery_mode: str = "immediate",  # immediate, delayed, scheduled
        scheduled_at: datetime | None = None,
        priority: str = "normal",  # low, normal, high, critical
        initiated_by: UUID | None = None,
        metadata: dict[str, Any] | None = None
    ):
        self.operation_type = operation_type
        self.webhook_id = webhook_id
        self.webhook_url = webhook_url
        self.events = events or []
        self.secret = secret
        self.headers = headers or {}
        self.timeout_seconds = timeout_seconds
        self.retry_attempts = retry_attempts
        self.retry_delay_seconds = retry_delay_seconds
        self.retry_exponential_backoff = retry_exponential_backoff
        self.active = active
        self.verify_ssl = verify_ssl
        self.custom_payload_template = custom_payload_template
        self.payload_data = payload_data or {}
        self.event_type = event_type
        self.user_id = user_id
        self.delivery_id = delivery_id
        self.batch_delivery = batch_delivery
        self.batch_size = batch_size
        self.batch_timeout_minutes = batch_timeout_minutes
        self.include_metadata = include_metadata
        self.filter_criteria = filter_criteria or {}
        self.signing_algorithm = signing_algorithm
        self.delivery_mode = delivery_mode
        self.scheduled_at = scheduled_at
        self.priority = priority
        self.initiated_by = initiated_by
        self.metadata = metadata or {}


class WebhookManagementCommandHandler(CommandHandler[WebhookManagementCommand, WebhookManagementResponse]):
    """Handler for webhook management operations."""
    
    def __init__(
        self,
        webhook_repository: IWebhookRepository,
        webhook_delivery_repository: IWebhookDeliveryRepository,
        user_repository: IUserRepository,
        http_service: IHttpService,
        validation_service: ValidationService,
        security_service: SecurityService,
        retry_service: RetryService,
        notification_service: INotificationService,
        audit_service: IAuditService,
        email_service: IEmailService,
        event_bus: EventBus,
        unit_of_work: UnitOfWork
    ):
        self._webhook_repository = webhook_repository
        self._webhook_delivery_repository = webhook_delivery_repository
        self._user_repository = user_repository
        self._http_service = http_service
        self._validation_service = validation_service
        self._security_service = security_service
        self._retry_service = retry_service
        self._notification_service = notification_service
        self._audit_service = audit_service
        self._email_service = email_service
        self._event_bus = event_bus
        self._unit_of_work = unit_of_work
    
    @audit_action(
        action=AuditAction.WEBHOOK_OPERATION,
        resource_type="webhook",
        include_request=True,
        include_response=True
    )
    @validate_request(WebhookManagementRequest)
    @rate_limit(
        max_requests=100,
        window_seconds=3600,
        strategy='user'
    )
    @require_permission("integrations.webhooks.manage")
    async def handle(self, command: WebhookManagementCommand) -> WebhookManagementResponse:
        """
        Handle webhook management operations.
        
        Supports multiple operations:
        - configure: Create or update webhook configuration
        - deliver: Deliver webhook payload to endpoint
        - test: Test webhook delivery
        - disable: Disable webhook
        - delete: Delete webhook configuration
        - retry_failed: Retry failed webhook deliveries
        
        Returns:
            WebhookManagementResponse with operation results
        """
        async with self._unit_of_work:
            # Route to appropriate handler based on operation type
            if command.operation_type == "configure":
                return await self._handle_webhook_configuration(command)
            if command.operation_type == "deliver":
                return await self._handle_webhook_delivery(command)
            if command.operation_type == "test":
                return await self._handle_webhook_test(command)
            if command.operation_type == "disable":
                return await self._handle_webhook_disable(command)
            if command.operation_type == "delete":
                return await self._handle_webhook_deletion(command)
            if command.operation_type == "retry_failed":
                return await self._handle_failed_delivery_retry(command)
            raise WebhookValidationError(f"Unsupported operation type: {command.operation_type}")
    
    async def _handle_webhook_configuration(self, command: WebhookManagementCommand) -> WebhookManagementResponse:
        """Handle webhook configuration (create/update)."""
        # 1. Validate webhook configuration
        await self._validate_webhook_configuration(command)
        
        # 2. Check if webhook exists (update) or create new
        webhook = None
        is_new = True
        
        if command.webhook_id:
            webhook = await self._webhook_repository.get_by_id(command.webhook_id)
            if webhook:
                is_new = False
            else:
                raise WebhookConfigurationError(f"Webhook {command.webhook_id} not found")
        
        # 3. Prepare webhook data
        webhook_data = {
            "webhook_url": command.webhook_url,
            "events": [event.value for event in command.events],
            "secret": command.secret,
            "headers": command.headers,
            "timeout_seconds": command.timeout_seconds,
            "retry_attempts": command.retry_attempts,
            "retry_delay_seconds": command.retry_delay_seconds,
            "retry_exponential_backoff": command.retry_exponential_backoff,
            "active": command.active,
            "verify_ssl": command.verify_ssl,
            "custom_payload_template": command.custom_payload_template,
            "filter_criteria": command.filter_criteria,
            "signing_algorithm": command.signing_algorithm,
            "priority": command.priority,
            "created_by": command.initiated_by,
            "metadata": command.metadata
        }
        
        # 4. Create or update webhook
        if is_new:
            webhook_data["id"] = UUID()
            webhook_data["created_at"] = datetime.now(UTC)
            webhook_data["status"] = WebhookStatus.ACTIVE if command.active else WebhookStatus.INACTIVE
            webhook = await self._webhook_repository.create(webhook_data)
        else:
            webhook_data["updated_at"] = datetime.now(UTC)
            webhook_data["updated_by"] = command.initiated_by
            webhook = await self._webhook_repository.update(command.webhook_id, webhook_data)
        
        # 5. Test webhook if it's active and newly created
        test_result = None
        if is_new and command.active:
            try:
                test_result = await self._perform_webhook_test(webhook, command)
            except Exception as e:
                # Log test failure but don't fail configuration
                await self._audit_service.log_warning(
                    f"Webhook test failed for {webhook.id}: {e!s}"
                )
        
        # 6. Log configuration
        await self._log_webhook_configuration(webhook, is_new, command)
        
        # 7. Publish domain event
        await self._event_bus.publish(
            WebhookConfigured(
                aggregate_id=webhook.id,
                webhook_url=webhook.webhook_url,
                events=webhook.events,
                is_new=is_new,
                active=webhook.active,
                configured_by=command.initiated_by
            )
        )
        
        # 8. Commit transaction
        await self._unit_of_work.commit()
        
        # 9. Generate response
        return WebhookManagementResponse(
            success=True,
            operation_type="configure",
            webhook_id=webhook.id,
            webhook_url=webhook.webhook_url,
            events=webhook.events,
            status=webhook.status.value,
            is_new=is_new,
            test_result=test_result,
            message=f"Webhook {'created' if is_new else 'updated'} successfully"
        )
    
    async def _validate_webhook_configuration(self, command: WebhookManagementCommand) -> None:
        """Validate webhook configuration parameters."""
        # Validate webhook URL
        if not command.webhook_url:
            raise WebhookConfigurationError("Webhook URL is required")
        
        if not self._validation_service.validate_url(command.webhook_url):
            raise WebhookConfigurationError("Invalid webhook URL")
        
        # Ensure HTTPS for production
        if not command.webhook_url.startswith("https://") and not command.webhook_url.startswith("http://localhost"):
            raise WebhookConfigurationError("Webhook URL must use HTTPS")
        
        # Validate events
        if not command.events:
            raise WebhookConfigurationError("At least one event must be specified")
        
        # Validate timeout
        if command.timeout_seconds < 1 or command.timeout_seconds > 300:
            raise WebhookConfigurationError("Timeout must be between 1 and 300 seconds")
        
        # Validate retry configuration
        if command.retry_attempts < 0 or command.retry_attempts > 10:
            raise WebhookConfigurationError("Retry attempts must be between 0 and 10")
        
        if command.retry_delay_seconds < 1 or command.retry_delay_seconds > 3600:
            raise WebhookConfigurationError("Retry delay must be between 1 and 3600 seconds")
        
        # Validate batch configuration
        if command.batch_delivery:
            if command.batch_size < 1 or command.batch_size > 1000:
                raise WebhookConfigurationError("Batch size must be between 1 and 1000")
        
        # Validate signing algorithm
        supported_algorithms = ["sha256", "sha1", "sha512"]
        if command.signing_algorithm not in supported_algorithms:
            raise WebhookConfigurationError(f"Unsupported signing algorithm: {command.signing_algorithm}")
    
    async def _handle_webhook_delivery(self, command: WebhookManagementCommand) -> WebhookManagementResponse:
        """Handle webhook payload delivery."""
        # 1. Load webhook configuration
        webhook = await self._webhook_repository.get_by_id(command.webhook_id)
        if not webhook:
            raise WebhookConfigurationError(f"Webhook {command.webhook_id} not found")
        
        if not webhook.active:
            raise WebhookDeliveryError("Webhook is not active")
        
        # 2. Prepare payload
        payload = await self._prepare_webhook_payload(webhook, command)
        
        # 3. Create delivery record
        delivery_record = await self._create_delivery_record(webhook, payload, command)
        
        # 4. Deliver webhook
        try:
            if command.delivery_mode == "immediate":
                delivery_result = await self._deliver_webhook_immediately(
                    webhook,
                    payload,
                    delivery_record,
                    command
                )
            elif command.delivery_mode == "scheduled":
                delivery_result = await self._schedule_webhook_delivery(
                    webhook,
                    payload,
                    delivery_record,
                    command
                )
            else:
                raise WebhookDeliveryError(f"Unsupported delivery mode: {command.delivery_mode}")
            
            # 5. Update delivery record with result
            await self._update_delivery_record(delivery_record, delivery_result)
            
            # 6. Log delivery
            await self._log_webhook_delivery(webhook, delivery_record, delivery_result, command)
            
            # 7. Publish domain event
            if delivery_result["success"]:
                await self._event_bus.publish(
                    WebhookDelivered(
                        aggregate_id=webhook.id,
                        delivery_id=delivery_record.id,
                        webhook_url=webhook.webhook_url,
                        event_type=command.event_type.value if command.event_type else None,
                        status_code=delivery_result.get("status_code"),
                        response_time_ms=delivery_result.get("response_time_ms"),
                        delivered_at=delivery_result.get("delivered_at")
                    )
                )
            else:
                await self._event_bus.publish(
                    WebhookFailed(
                        aggregate_id=webhook.id,
                        delivery_id=delivery_record.id,
                        webhook_url=webhook.webhook_url,
                        event_type=command.event_type.value if command.event_type else None,
                        error_message=delivery_result.get("error"),
                        retry_count=delivery_result.get("retry_count", 0),
                        failed_at=delivery_result.get("failed_at")
                    )
                )
            
            # 8. Commit transaction
            await self._unit_of_work.commit()
            
            # 9. Generate response
            return WebhookManagementResponse(
                success=delivery_result["success"],
                operation_type="deliver",
                webhook_id=webhook.id,
                delivery_id=delivery_record.id,
                status_code=delivery_result.get("status_code"),
                response_time_ms=delivery_result.get("response_time_ms"),
                error_message=delivery_result.get("error"),
                retry_count=delivery_result.get("retry_count", 0),
                message=f"Webhook delivery {'succeeded' if delivery_result['success'] else 'failed'}"
            )
            
        except Exception as e:
            # Update delivery record with error
            await self._update_delivery_record(delivery_record, {
                "success": False,
                "error": str(e),
                "failed_at": datetime.now(UTC)
            })
            
            await self._audit_service.log_error(
                f"Webhook delivery failed for {webhook.id}: {e!s}"
            )
            
            raise
    
    async def _prepare_webhook_payload(
        self,
        webhook: Any,
        command: WebhookManagementCommand
    ) -> dict[str, Any]:
        """Prepare webhook payload."""
        # Base payload structure
        payload = {
            "event": command.event_type.value if command.event_type else "test",
            "timestamp": datetime.now(UTC).isoformat(),
            "webhook_id": str(webhook.id),
            "data": command.payload_data
        }
        
        # Add metadata if requested
        if command.include_metadata:
            payload["metadata"] = {
                "delivery_id": str(UUID()),
                "delivery_mode": command.delivery_mode,
                "priority": command.priority,
                "initiated_by": str(command.initiated_by) if command.initiated_by else None,
                "custom_metadata": command.metadata
            }
        
        # Apply custom payload template if configured
        if webhook.custom_payload_template:
            payload = await self._apply_payload_template(
                webhook.custom_payload_template,
                payload,
                command
            )
        
        return payload
    
    async def _apply_payload_template(
        self,
        template: str,
        payload: dict[str, Any],
        command: WebhookManagementCommand
    ) -> dict[str, Any]:
        """Apply custom payload template."""
        try:
            # Simple template substitution (in production, use a proper template engine)
            import json
            from string import Template
            
            # Convert payload to JSON string for template substitution
            json.dumps(payload)
            template_obj = Template(template)
            
            # Apply template with payload data
            customized_payload_str = template_obj.safe_substitute(**payload)
            
            # Parse back to dict
            return json.loads(customized_payload_str)
            
        except Exception as e:
            await self._audit_service.log_warning(
                f"Failed to apply payload template: {e!s}, using default payload"
            )
            return payload
    
    async def _create_delivery_record(
        self,
        webhook: Any,
        payload: dict[str, Any],
        command: WebhookManagementCommand
    ) -> Any:
        """Create webhook delivery record."""
        delivery_data = {
            "id": UUID(),
            "webhook_id": webhook.id,
            "event_type": command.event_type.value if command.event_type else "test",
            "payload": payload,
            "target_url": webhook.webhook_url,
            "status": DeliveryStatus.PENDING,
            "priority": command.priority,
            "delivery_mode": command.delivery_mode,
            "scheduled_at": command.scheduled_at,
            "max_retry_attempts": webhook.retry_attempts,
            "retry_delay_seconds": webhook.retry_delay_seconds,
            "created_at": datetime.now(UTC),
            "metadata": {
                "initiated_by": str(command.initiated_by) if command.initiated_by else None,
                "user_id": str(command.user_id) if command.user_id else None,
                "batch_delivery": command.batch_delivery
            }
        }
        
        return await self._webhook_delivery_repository.create(delivery_data)
    
    async def _deliver_webhook_immediately(
        self,
        webhook: Any,
        payload: dict[str, Any],
        delivery_record: Any,
        command: WebhookManagementCommand
    ) -> dict[str, Any]:
        """Deliver webhook immediately with retry logic."""
        return await self._retry_service.retry_async(
            self._make_webhook_request,
            max_attempts=webhook.retry_attempts + 1,
            delay_seconds=webhook.retry_delay_seconds,
            exponential_backoff=webhook.retry_exponential_backoff,
            args=(webhook, payload, delivery_record)
        )
    
    async def _make_webhook_request(
        self,
        webhook: Any,
        payload: dict[str, Any],
        delivery_record: Any
    ) -> dict[str, Any]:
        """Make the actual webhook HTTP request."""
        start_time = datetime.now(UTC)
        
        try:
            # Prepare headers
            headers = {
                "Content-Type": "application/json",
                "User-Agent": "EzzDay-Webhook/1.0",
                **webhook.headers
            }
            
            # Add signature if secret is configured
            if webhook.secret:
                signature = self._generate_webhook_signature(
                    payload,
                    webhook.secret,
                    webhook.signing_algorithm
                )
                headers[f"X-{webhook.signing_algorithm.upper()}-Signature"] = signature
            
            # Make HTTP request
            response = await self._http_service.post(
                webhook.webhook_url,
                json=payload,
                headers=headers,
                timeout=webhook.timeout_seconds,
                verify_ssl=webhook.verify_ssl
            )
            
            end_time = datetime.now(UTC)
            response_time_ms = int((end_time - start_time).total_seconds() * 1000)
            
            # Check if response indicates success
            success = 200 <= response.get("status_code", 0) < 300
            
            return {
                "success": success,
                "status_code": response.get("status_code"),
                "response_headers": response.get("headers", {}),
                "response_body": response.get("content"),
                "response_time_ms": response_time_ms,
                "delivered_at": end_time
            }
            
        except TimeoutError as e:
            raise WebhookTimeoutError(f"Webhook request timed out after {webhook.timeout_seconds} seconds") from e
        except Exception as e:
            end_time = datetime.now(UTC)
            response_time_ms = int((end_time - start_time).total_seconds() * 1000)
            
            return {
                "success": False,
                "error": str(e),
                "response_time_ms": response_time_ms,
                "failed_at": end_time
            }
    
    def _generate_webhook_signature(
        self,
        payload: dict[str, Any],
        secret: str,
        algorithm: str
    ) -> str:
        """Generate webhook signature for payload verification."""
        
        # Convert payload to canonical JSON string
        payload_str = json.dumps(payload, sort_keys=True, separators=(',', ':'))
        payload_bytes = payload_str.encode('utf-8')
        secret_bytes = secret.encode('utf-8')
        
        # Generate HMAC signature
        if algorithm == "sha256":
            signature = hmac.new(secret_bytes, payload_bytes, hashlib.sha256).hexdigest()
        elif algorithm == "sha1":
            signature = hmac.new(secret_bytes, payload_bytes, hashlib.sha1).hexdigest()
        elif algorithm == "sha512":
            signature = hmac.new(secret_bytes, payload_bytes, hashlib.sha512).hexdigest()
        else:
            raise WebhookSecurityError(f"Unsupported signing algorithm: {algorithm}")
        
        return f"{algorithm}={signature}"
    
    async def _schedule_webhook_delivery(
        self,
        webhook: Any,
        payload: dict[str, Any],
        delivery_record: Any,
        command: WebhookManagementCommand
    ) -> dict[str, Any]:
        """Schedule webhook delivery for later execution."""
        # Update delivery record status
        delivery_record.status = DeliveryStatus.SCHEDULED
        delivery_record.scheduled_at = command.scheduled_at or datetime.now(UTC) + timedelta(minutes=5)
        
        await self._webhook_delivery_repository.update(delivery_record)
        
        return {
            "success": True,
            "scheduled": True,
            "scheduled_at": delivery_record.scheduled_at,
            "message": "Webhook delivery scheduled successfully"
        }
    
    async def _update_delivery_record(
        self,
        delivery_record: Any,
        result: dict[str, Any]
    ) -> None:
        """Update delivery record with result."""
        update_data = {
            "status": DeliveryStatus.DELIVERED if result["success"] else DeliveryStatus.FAILED,
            "response_status_code": result.get("status_code"),
            "response_headers": result.get("response_headers"),
            "response_body": result.get("response_body"),
            "response_time_ms": result.get("response_time_ms"),
            "error_message": result.get("error"),
            "delivered_at": result.get("delivered_at"),
            "failed_at": result.get("failed_at"),
            "updated_at": datetime.now(UTC)
        }
        
        await self._webhook_delivery_repository.update(delivery_record.id, update_data)
    
    async def _perform_webhook_test(self, webhook: Any, command: WebhookManagementCommand) -> dict[str, Any]:
        """Perform webhook test delivery."""
        test_payload = {
            "event": "webhook.test",
            "timestamp": datetime.now(UTC).isoformat(),
            "webhook_id": str(webhook.id),
            "data": {
                "test": True,
                "message": "This is a test webhook delivery"
            }
        }
        
        try:
            result = await self._make_webhook_request(webhook, test_payload, None)
            return {
                "test_successful": result["success"],
                "status_code": result.get("status_code"),
                "response_time_ms": result.get("response_time_ms"),
                "error": result.get("error")
            }
        except Exception as e:
            return {
                "test_successful": False,
                "error": str(e)
            }
    
    async def _handle_webhook_test(self, command: WebhookManagementCommand) -> WebhookManagementResponse:
        """Handle webhook test operation."""
        webhook = await self._webhook_repository.get_by_id(command.webhook_id)
        if not webhook:
            raise WebhookConfigurationError(f"Webhook {command.webhook_id} not found")
        
        test_result = await self._perform_webhook_test(webhook, command)
        
        # Log test operation
        await self._audit_service.log_action(
            AuditContext(
                action=AuditAction.WEBHOOK_TESTED,
                actor_id=command.initiated_by,
                resource_type="webhook",
                resource_id=webhook.id,
                details={
                    "webhook_url": webhook.webhook_url,
                    "test_result": test_result
                }
            )
        )
        
        return WebhookManagementResponse(
            success=test_result["test_successful"],
            operation_type="test",
            webhook_id=webhook.id,
            test_result=test_result,
            message=f"Webhook test {'succeeded' if test_result['test_successful'] else 'failed'}"
        )
    
    async def _handle_webhook_disable(self, command: WebhookManagementCommand) -> WebhookManagementResponse:
        """Handle webhook disable operation."""
        webhook = await self._webhook_repository.get_by_id(command.webhook_id)
        if not webhook:
            raise WebhookConfigurationError(f"Webhook {command.webhook_id} not found")
        
        # Update webhook status
        await self._webhook_repository.update(webhook.id, {
            "active": False,
            "status": WebhookStatus.INACTIVE,
            "updated_at": datetime.now(UTC),
            "updated_by": command.initiated_by
        })
        
        # Log disable operation
        await self._audit_service.log_action(
            AuditContext(
                action=AuditAction.WEBHOOK_DISABLED,
                actor_id=command.initiated_by,
                resource_type="webhook",
                resource_id=webhook.id,
                details={
                    "webhook_url": webhook.webhook_url,
                    "events": webhook.events
                }
            )
        )
        
        await self._unit_of_work.commit()
        
        return WebhookManagementResponse(
            success=True,
            operation_type="disable",
            webhook_id=webhook.id,
            message="Webhook disabled successfully"
        )
    
    async def _handle_webhook_deletion(self, command: WebhookManagementCommand) -> WebhookManagementResponse:
        """Handle webhook deletion operation."""
        webhook = await self._webhook_repository.get_by_id(command.webhook_id)
        if not webhook:
            raise WebhookConfigurationError(f"Webhook {command.webhook_id} not found")
        
        # Soft delete webhook
        await self._webhook_repository.soft_delete(webhook.id, command.initiated_by)
        
        # Log deletion operation
        await self._audit_service.log_action(
            AuditContext(
                action=AuditAction.WEBHOOK_DELETED,
                actor_id=command.initiated_by,
                resource_type="webhook",
                resource_id=webhook.id,
                details={
                    "webhook_url": webhook.webhook_url,
                    "events": webhook.events
                },
                risk_level="medium"
            )
        )
        
        await self._unit_of_work.commit()
        
        return WebhookManagementResponse(
            success=True,
            operation_type="delete",
            webhook_id=webhook.id,
            message="Webhook deleted successfully"
        )
    
    async def _handle_failed_delivery_retry(self, command: WebhookManagementCommand) -> WebhookManagementResponse:
        """Handle retry of failed webhook deliveries."""
        # Get failed deliveries for the webhook
        failed_deliveries = await self._webhook_delivery_repository.find_failed_deliveries(
            webhook_id=command.webhook_id,
            max_retry_attempts_reached=False
        )
        
        retry_results = []
        for delivery in failed_deliveries:
            try:
                webhook = await self._webhook_repository.get_by_id(delivery.webhook_id)
                if webhook and webhook.active:
                    # Retry delivery
                    result = await self._make_webhook_request(
                        webhook,
                        delivery.payload,
                        delivery
                    )
                    
                    # Update delivery record
                    await self._update_delivery_record(delivery, result)
                    
                    retry_results.append({
                        "delivery_id": delivery.id,
                        "success": result["success"],
                        "error": result.get("error")
                    })
                    
            except Exception as e:
                retry_results.append({
                    "delivery_id": delivery.id,
                    "success": False,
                    "error": str(e)
                })
        
        # Log retry operation
        await self._audit_service.log_action(
            AuditContext(
                action=AuditAction.WEBHOOK_RETRY_FAILED,
                actor_id=command.initiated_by,
                resource_type="webhook",
                resource_id=command.webhook_id,
                details={
                    "failed_deliveries_count": len(failed_deliveries),
                    "retry_results": retry_results
                }
            )
        )
        
        await self._unit_of_work.commit()
        
        successful_retries = sum(1 for result in retry_results if result["success"])
        
        return WebhookManagementResponse(
            success=True,
            operation_type="retry_failed",
            webhook_id=command.webhook_id,
            retry_results=retry_results,
            message=f"Retried {len(retry_results)} failed deliveries, {successful_retries} successful"
        )
    
    async def _log_webhook_configuration(
        self,
        webhook: Any,
        is_new: bool,
        command: WebhookManagementCommand
    ) -> None:
        """Log webhook configuration operation."""
        await self._audit_service.log_action(
            AuditContext(
                action=AuditAction.WEBHOOK_CONFIGURED if is_new else AuditAction.WEBHOOK_UPDATED,
                actor_id=command.initiated_by,
                resource_type="webhook",
                resource_id=webhook.id,
                details={
                    "webhook_url": webhook.webhook_url,
                    "events": webhook.events,
                    "active": webhook.active,
                    "verify_ssl": webhook.verify_ssl,
                    "timeout_seconds": webhook.timeout_seconds,
                    "retry_attempts": webhook.retry_attempts,
                    "is_new": is_new
                },
                risk_level="low"
            )
        )
    
    async def _log_webhook_delivery(
        self,
        webhook: Any,
        delivery_record: Any,
        delivery_result: dict[str, Any],
        command: WebhookManagementCommand
    ) -> None:
        """Log webhook delivery operation."""
        await self._audit_service.log_action(
            AuditContext(
                action=AuditAction.WEBHOOK_DELIVERED if delivery_result["success"] else AuditAction.WEBHOOK_DELIVERY_FAILED,
                actor_id=command.initiated_by,
                resource_type="webhook",
                resource_id=webhook.id,
                details={
                    "delivery_id": str(delivery_record.id),
                    "webhook_url": webhook.webhook_url,
                    "event_type": command.event_type.value if command.event_type else None,
                    "status_code": delivery_result.get("status_code"),
                    "response_time_ms": delivery_result.get("response_time_ms"),
                    "error": delivery_result.get("error"),
                    "delivery_mode": command.delivery_mode,
                    "priority": command.priority
                },
                risk_level="low" if delivery_result["success"] else "medium"
            )
        )