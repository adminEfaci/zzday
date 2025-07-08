"""
Audit integration command implementation.

Handles integration with external audit systems and log management platforms.
"""

import base64
import gzip
import hashlib
import json
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.contracts.ports import (
    IAuditIntegrationRepository,
    IAuditRepository,
    IAuditService,
    IEmailService,
    IFileStorageService,
    IHttpService,
    INotificationService,
    IUserRepository,
)
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    require_permission,
    validate_request,
)
from app.modules.identity.application.dtos.internal import AuditContext, EmailContext
from app.modules.identity.application.dtos.request import AuditIntegrationRequest
from app.modules.identity.application.dtos.response import AuditIntegrationResponse
from app.modules.identity.domain.enums import (
    AlertSeverity,
    AuditAction,
    AuditIntegrationType,
    CompressionType,
    DeliveryMethod,
    ExportFormat,
)
from app.modules.identity.domain.events import (
    AuditDataExported,
    AuditIntegrationConfigured,
)
from app.modules.identity.domain.exceptions import (
    AuditConfigurationError,
    AuditExportError,
    AuditValidationError,
)
from app.modules.identity.domain.services import (
    CompressionService,
    FilterService,
    SecurityService,
    ValidationService,
)


class AuditDataType(Enum):
    """Type of audit data to integrate."""
    AUTHENTICATION_LOGS = "authentication_logs"
    AUTHORIZATION_LOGS = "authorization_logs"
    USER_ACTIVITY = "user_activity"
    SECURITY_EVENTS = "security_events"
    CONFIGURATION_CHANGES = "configuration_changes"
    DATA_ACCESS = "data_access"
    API_CALLS = "api_calls"
    SYSTEM_EVENTS = "system_events"
    COMPLIANCE_EVENTS = "compliance_events"
    ALL = "all"


class AuditFrequency(Enum):
    """Frequency of audit data export."""
    REAL_TIME = "real_time"
    MINUTE = "minute"
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    ON_DEMAND = "on_demand"


@dataclass
class AuditFilter:
    """Filter configuration for audit data."""
    start_time: datetime | None = None
    end_time: datetime | None = None
    user_ids: list[UUID] | None = None
    event_types: list[str] | None = None
    severity_levels: list[str] | None = None
    ip_addresses: list[str] | None = None
    resource_types: list[str] | None = None
    include_sensitive: bool = False
    include_metadata: bool = True


@dataclass
class AuditDestination:
    """Destination configuration for audit data."""
    type: DeliveryMethod
    endpoint_url: str | None = None
    auth_headers: dict[str, str] | None = None
    file_path: str | None = None
    email_addresses: list[str] | None = None
    compression: CompressionType = CompressionType.GZIP
    encryption_enabled: bool = True
    max_file_size_mb: int = 100


class AuditIntegrationCommand(Command[AuditIntegrationResponse]):
    """Command to handle audit system integrations."""
    
    def __init__(
        self,
        operation_type: str,  # "configure", "export", "stream", "alert", "test"
        integration_id: UUID | None = None,
        integration_name: str | None = None,
        integration_type: AuditIntegrationType = AuditIntegrationType.SIEM,
        audit_data_types: list[AuditDataType] | None = None,
        export_frequency: AuditFrequency = AuditFrequency.DAILY,
        export_format: ExportFormat = ExportFormat.JSON,
        destination_config: AuditDestination | None = None,
        filter_config: AuditFilter | None = None,
        real_time_streaming: bool = False,
        batch_size: int = 1000,
        max_retention_days: int = 365,
        include_pii: bool = False,
        anonymize_data: bool = True,
        enable_compression: bool = True,
        enable_encryption: bool = True,
        alert_rules: list[dict[str, Any]] | None = None,
        webhook_config: dict[str, Any] | None = None,
        api_config: dict[str, Any] | None = None,
        field_mapping: dict[str, str] | None = None,
        custom_headers: dict[str, str] | None = None,
        timeout_seconds: int = 300,
        retry_attempts: int = 3,
        validate_schema: bool = True,
        dry_run: bool = False,
        initiated_by: UUID | None = None,
        metadata: dict[str, Any] | None = None
    ):
        self.operation_type = operation_type
        self.integration_id = integration_id
        self.integration_name = integration_name
        self.integration_type = integration_type
        self.audit_data_types = audit_data_types or [AuditDataType.ALL]
        self.export_frequency = export_frequency
        self.export_format = export_format
        self.destination_config = destination_config
        self.filter_config = filter_config or AuditFilter()
        self.real_time_streaming = real_time_streaming
        self.batch_size = batch_size
        self.max_retention_days = max_retention_days
        self.include_pii = include_pii
        self.anonymize_data = anonymize_data
        self.enable_compression = enable_compression
        self.enable_encryption = enable_encryption
        self.alert_rules = alert_rules or []
        self.webhook_config = webhook_config or {}
        self.api_config = api_config or {}
        self.field_mapping = field_mapping or {}
        self.custom_headers = custom_headers or {}
        self.timeout_seconds = timeout_seconds
        self.retry_attempts = retry_attempts
        self.validate_schema = validate_schema
        self.dry_run = dry_run
        self.initiated_by = initiated_by
        self.metadata = metadata or {}


class AuditIntegrationCommandHandler(CommandHandler[AuditIntegrationCommand, AuditIntegrationResponse]):
    """Handler for audit integration operations."""
    
    def __init__(
        self,
        audit_repository: IAuditRepository,
        audit_integration_repository: IAuditIntegrationRepository,
        user_repository: IUserRepository,
        http_service: IHttpService,
        file_storage_service: IFileStorageService,
        validation_service: ValidationService,
        security_service: SecurityService,
        filter_service: FilterService,
        compression_service: CompressionService,
        notification_service: INotificationService,
        audit_service: IAuditService,
        email_service: IEmailService,
        event_bus: EventBus,
        unit_of_work: UnitOfWork
    ):
        self._audit_repository = audit_repository
        self._audit_integration_repository = audit_integration_repository
        self._user_repository = user_repository
        self._http_service = http_service
        self._file_storage_service = file_storage_service
        self._validation_service = validation_service
        self._security_service = security_service
        self._filter_service = filter_service
        self._compression_service = compression_service
        self._notification_service = notification_service
        self._audit_service = audit_service
        self._email_service = email_service
        self._event_bus = event_bus
        self._unit_of_work = unit_of_work
    
    @audit_action(
        action=AuditAction.AUDIT_INTEGRATION_OPERATION,
        resource_type="audit_integration",
        include_request=True,
        include_response=True
    )
    @validate_request(AuditIntegrationRequest)
    @rate_limit(
        max_requests=100,
        window_seconds=3600,
        strategy='user'
    )
    @require_permission("integrations.audit.manage")
    async def handle(self, command: AuditIntegrationCommand) -> AuditIntegrationResponse:
        """
        Handle audit integration operations.
        
        Supports multiple operations:
        - configure: Configure audit system integration
        - export: Export audit data to external system
        - stream: Set up real-time audit streaming
        - alert: Configure audit alerting rules
        - test: Test integration configuration
        
        Returns:
            AuditIntegrationResponse with operation results
        """
        async with self._unit_of_work:
            # Route to appropriate handler based on operation type
            if command.operation_type == "configure":
                return await self._handle_integration_configuration(command)
            if command.operation_type == "export":
                return await self._handle_audit_export(command)
            if command.operation_type == "stream":
                return await self._handle_real_time_streaming(command)
            if command.operation_type == "alert":
                return await self._handle_alert_configuration(command)
            if command.operation_type == "test":
                return await self._handle_integration_test(command)
            raise AuditValidationError(f"Unsupported operation type: {command.operation_type}")
    
    async def _handle_integration_configuration(self, command: AuditIntegrationCommand) -> AuditIntegrationResponse:
        """Handle audit integration configuration."""
        # 1. Validate configuration parameters
        await self._validate_integration_config(command)
        
        # 2. Check if integration exists (update) or create new
        integration = None
        is_new = True
        
        if command.integration_id:
            integration = await self._audit_integration_repository.get_by_id(command.integration_id)
            if integration:
                is_new = False
            else:
                raise AuditConfigurationError(f"Integration {command.integration_id} not found")
        
        # 3. Prepare integration configuration
        integration_config = {
            "integration_name": command.integration_name or f"{command.integration_type.value} Integration",
            "integration_type": command.integration_type.value,
            "audit_data_types": [dt.value for dt in command.audit_data_types],
            "export_frequency": command.export_frequency.value,
            "export_format": command.export_format.value,
            "destination_config": self._serialize_destination_config(command.destination_config),
            "filter_config": self._serialize_filter_config(command.filter_config),
            "real_time_streaming": command.real_time_streaming,
            "batch_size": command.batch_size,
            "max_retention_days": command.max_retention_days,
            "include_pii": command.include_pii,
            "anonymize_data": command.anonymize_data,
            "enable_compression": command.enable_compression,
            "enable_encryption": command.enable_encryption,
            "alert_rules": command.alert_rules,
            "webhook_config": command.webhook_config,
            "api_config": command.api_config,
            "field_mapping": command.field_mapping,
            "custom_headers": command.custom_headers,
            "timeout_seconds": command.timeout_seconds,
            "retry_attempts": command.retry_attempts,
            "validate_schema": command.validate_schema,
            "status": "active",
            "created_by": command.initiated_by,
            "metadata": command.metadata
        }
        
        # 4. Create or update integration
        if is_new:
            integration_config["id"] = UUID()
            integration_config["created_at"] = datetime.now(UTC)
            integration = await self._audit_integration_repository.create(integration_config)
        else:
            integration_config["updated_at"] = datetime.now(UTC)
            integration_config["updated_by"] = command.initiated_by
            integration = await self._audit_integration_repository.update(
                command.integration_id, 
                integration_config
            )
        
        # 5. Test integration if requested
        test_result = None
        if not command.dry_run:
            try:
                test_result = await self._test_integration_connectivity(integration, command)
            except Exception as e:
                await self._audit_service.log_warning(
                    f"Integration test failed for {integration.id}: {e!s}"
                )
        
        # 6. Set up real-time streaming if enabled
        streaming_result = None
        if command.real_time_streaming and not command.dry_run:
            streaming_result = await self._setup_real_time_streaming(integration, command)
        
        # 7. Configure alert rules if provided
        alert_result = None
        if command.alert_rules and not command.dry_run:
            alert_result = await self._configure_alert_rules(integration, command.alert_rules, command)
        
        # 8. Log configuration
        await self._log_integration_configuration(integration, is_new, command)
        
        # 9. Publish domain event
        await self._event_bus.publish(
            AuditIntegrationConfigured(
                aggregate_id=integration.id,
                integration_id=integration.id,
                integration_name=integration.integration_name,
                integration_type=integration.integration_type,
                is_new=is_new,
                real_time_enabled=command.real_time_streaming,
                configured_by=command.initiated_by
            )
        )
        
        # 10. Commit transaction
        await self._unit_of_work.commit()
        
        # 11. Generate response
        return AuditIntegrationResponse(
            success=True,
            operation_type="configure",
            integration_id=integration.id,
            integration_name=integration.integration_name,
            integration_type=integration.integration_type,
            is_new=is_new,
            test_result=test_result,
            streaming_result=streaming_result,
            alert_result=alert_result,
            dry_run=command.dry_run,
            message=f"Audit integration {'created' if is_new else 'updated'} successfully"
        )
    
    async def _validate_integration_config(self, command: AuditIntegrationCommand) -> None:
        """Validate audit integration configuration."""
        # Validate integration name
        if not command.integration_name and not command.integration_id:
            raise AuditConfigurationError("Integration name is required for new integrations")
        
        # Validate destination configuration
        if not command.destination_config:
            raise AuditConfigurationError("Destination configuration is required")
        
        dest = command.destination_config
        if dest.type == DeliveryMethod.HTTP and not dest.endpoint_url:
            raise AuditConfigurationError("Endpoint URL is required for HTTP delivery")
        
        if dest.type == DeliveryMethod.EMAIL and not dest.email_addresses:
            raise AuditConfigurationError("Email addresses are required for email delivery")
        
        if dest.type == DeliveryMethod.FILE and not dest.file_path:
            raise AuditConfigurationError("File path is required for file delivery")
        
        # Validate export frequency
        if command.export_frequency == AuditFrequency.REAL_TIME and not command.real_time_streaming:
            raise AuditConfigurationError("Real-time streaming must be enabled for real-time frequency")
        
        # Validate batch size
        if command.batch_size < 1 or command.batch_size > 10000:
            raise AuditConfigurationError("Batch size must be between 1 and 10000")
        
        # Validate retention period
        if command.max_retention_days < 1 or command.max_retention_days > 2555:  # ~7 years
            raise AuditConfigurationError("Retention period must be between 1 and 2555 days")
        
        # Validate timeout
        if command.timeout_seconds < 10 or command.timeout_seconds > 3600:
            raise AuditConfigurationError("Timeout must be between 10 and 3600 seconds")
    
    def _serialize_destination_config(self, dest_config: AuditDestination | None) -> dict[str, Any]:
        """Serialize destination configuration to dictionary."""
        if not dest_config:
            return {}
        
        return {
            "type": dest_config.type.value,
            "endpoint_url": dest_config.endpoint_url,
            "auth_headers": dest_config.auth_headers,
            "file_path": dest_config.file_path,
            "email_addresses": dest_config.email_addresses,
            "compression": dest_config.compression.value,
            "encryption_enabled": dest_config.encryption_enabled,
            "max_file_size_mb": dest_config.max_file_size_mb
        }
    
    def _serialize_filter_config(self, filter_config: AuditFilter | None) -> dict[str, Any]:
        """Serialize filter configuration to dictionary."""
        if not filter_config:
            return {}
        
        return {
            "start_time": filter_config.start_time.isoformat() if filter_config.start_time else None,
            "end_time": filter_config.end_time.isoformat() if filter_config.end_time else None,
            "user_ids": [str(uid) for uid in (filter_config.user_ids or [])],
            "event_types": filter_config.event_types,
            "severity_levels": filter_config.severity_levels,
            "ip_addresses": filter_config.ip_addresses,
            "resource_types": filter_config.resource_types,
            "include_sensitive": filter_config.include_sensitive,
            "include_metadata": filter_config.include_metadata
        }
    
    async def _test_integration_connectivity(self, integration: Any, command: AuditIntegrationCommand) -> dict[str, Any]:
        """Test connectivity to the audit integration destination."""
        dest_config = integration.destination_config
        
        try:
            if dest_config["type"] == DeliveryMethod.HTTP.value:
                # Test HTTP endpoint
                test_payload = {
                    "test": True,
                    "timestamp": datetime.now(UTC).isoformat(),
                    "integration_id": str(integration.id),
                    "message": "Audit integration connectivity test"
                }
                
                headers = {
                    "Content-Type": "application/json",
                    "User-Agent": "EzzDay-Audit-Integration/1.0",
                    **command.custom_headers,
                    **(dest_config.get("auth_headers", {}))
                }
                
                response = await self._http_service.post(
                    dest_config["endpoint_url"],
                    json=test_payload,
                    headers=headers,
                    timeout=command.timeout_seconds
                )
                
                success = 200 <= response.get("status_code", 0) < 300
                
                return {
                    "success": success,
                    "method": "http",
                    "status_code": response.get("status_code"),
                    "response_time_ms": response.get("response_time_ms"),
                    "error": response.get("error") if not success else None
                }
            
            if dest_config["type"] == DeliveryMethod.EMAIL.value:
                # Test email delivery
                test_email = EmailContext(
                    recipient=dest_config["email_addresses"][0],
                    subject="Audit Integration Test",
                    template="audit_integration_test",
                    variables={
                        "integration_name": integration.integration_name,
                        "test_time": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
                    }
                )
                
                await self._email_service.send_email(test_email)
                
                return {
                    "success": True,
                    "method": "email",
                    "recipients": dest_config["email_addresses"]
                }
            
            if dest_config["type"] == DeliveryMethod.FILE.value:
                # Test file system access
                test_file_path = f"{dest_config['file_path']}/audit_integration_test_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}.json"
                test_data = {
                    "test": True,
                    "timestamp": datetime.now(UTC).isoformat(),
                    "integration_id": str(integration.id)
                }
                
                await self._file_storage_service.write_file(
                    test_file_path,
                    json.dumps(test_data, indent=2)
                )
                
                # Clean up test file
                await self._file_storage_service.delete_file(test_file_path)
                
                return {
                    "success": True,
                    "method": "file",
                    "test_file_path": test_file_path
                }
            
            return {
                "success": False,
                "error": f"Unsupported delivery method: {dest_config['type']}"
            }
                
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "method": dest_config.get("type", "unknown")
            }
    
    async def _setup_real_time_streaming(self, integration: Any, command: AuditIntegrationCommand) -> dict[str, Any]:
        """Set up real-time audit data streaming."""
        try:
            # Configure streaming pipeline (implementation would depend on specific infrastructure)
            streaming_config = {
                "integration_id": integration.id,
                "destination": integration.destination_config,
                "data_types": integration.audit_data_types,
                "batch_size": command.batch_size,
                "compression": command.enable_compression,
                "encryption": command.enable_encryption,
                "field_mapping": command.field_mapping
            }
            
            # Register streaming pipeline
            pipeline_id = await self._audit_integration_repository.create_streaming_pipeline(streaming_config)
            
            return {
                "success": True,
                "pipeline_id": pipeline_id,
                "streaming_enabled": True,
                "batch_size": command.batch_size
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "streaming_enabled": False
            }
    
    async def _configure_alert_rules(
        self,
        integration: Any,
        alert_rules: list[dict[str, Any]],
        command: AuditIntegrationCommand
    ) -> dict[str, Any]:
        """Configure audit alert rules."""
        try:
            configured_rules = []
            
            for rule in alert_rules:
                rule_config = {
                    "id": UUID(),
                    "integration_id": integration.id,
                    "rule_name": rule.get("name", "Unnamed Rule"),
                    "conditions": rule.get("conditions", {}),
                    "severity": rule.get("severity", AlertSeverity.MEDIUM.value),
                    "notification_channels": rule.get("notification_channels", ["email"]),
                    "cooldown_minutes": rule.get("cooldown_minutes", 60),
                    "enabled": rule.get("enabled", True),
                    "created_at": datetime.now(UTC),
                    "created_by": command.initiated_by
                }
                
                rule_id = await self._audit_integration_repository.create_alert_rule(rule_config)
                configured_rules.append(rule_id)
            
            return {
                "success": True,
                "rules_configured": len(configured_rules),
                "rule_ids": configured_rules
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "rules_configured": 0
            }
    
    async def _handle_audit_export(self, command: AuditIntegrationCommand) -> AuditIntegrationResponse:
        """Handle audit data export operation."""
        # 1. Load integration configuration
        integration = await self._audit_integration_repository.get_by_id(command.integration_id)
        if not integration:
            raise AuditConfigurationError(f"Integration {command.integration_id} not found")
        
        # 2. Apply audit data filters
        audit_records = await self._fetch_filtered_audit_data(
            command.filter_config,
            command.audit_data_types,
            command.batch_size
        )
        
        if not audit_records:
            return AuditIntegrationResponse(
                success=True,
                operation_type="export",
                integration_id=integration.id,
                records_exported=0,
                message="No audit records found matching filter criteria"
            )
        
        # 3. Process and transform audit data
        processed_data = await self._process_audit_data(
            audit_records,
            command.export_format,
            command.field_mapping,
            command.anonymize_data,
            command.include_pii
        )
        
        # 4. Compress data if enabled
        if command.enable_compression:
            processed_data = await self._compress_audit_data(
                processed_data,
                integration.destination_config.get("compression", "gzip")
            )
        
        # 5. Encrypt data if enabled
        if command.enable_encryption:
            processed_data = await self._encrypt_audit_data(processed_data, integration)
        
        # 6. Deliver audit data
        delivery_result = await self._deliver_audit_data(
            processed_data,
            integration.destination_config,
            command
        )
        
        # 7. Log export operation
        await self._log_audit_export(integration, len(audit_records), delivery_result, command)
        
        # 8. Publish domain event
        await self._event_bus.publish(
            AuditDataExported(
                aggregate_id=integration.id,
                integration_id=integration.id,
                export_id=UUID(),
                records_exported=len(audit_records),
                export_format=command.export_format.value,
                delivered_successfully=delivery_result["success"],
                exported_by=command.initiated_by
            )
        )
        
        # 9. Commit transaction
        await self._unit_of_work.commit()
        
        # 10. Generate response
        return AuditIntegrationResponse(
            success=delivery_result["success"],
            operation_type="export",
            integration_id=integration.id,
            records_exported=len(audit_records),
            export_format=command.export_format.value,
            delivery_result=delivery_result,
            compressed=command.enable_compression,
            encrypted=command.enable_encryption,
            message=f"Audit export {'completed' if delivery_result['success'] else 'failed'}: {len(audit_records)} records"
        )
    
    async def _fetch_filtered_audit_data(
        self,
        filter_config: AuditFilter,
        data_types: list[AuditDataType],
        batch_size: int
    ) -> list[dict[str, Any]]:
        """Fetch audit data based on filter criteria."""
        query_params = {}
        
        # Apply time filters
        if filter_config.start_time:
            query_params["start_time"] = filter_config.start_time
        if filter_config.end_time:
            query_params["end_time"] = filter_config.end_time
        
        # Apply user filters
        if filter_config.user_ids:
            query_params["user_ids"] = filter_config.user_ids
        
        # Apply event type filters
        if filter_config.event_types:
            query_params["event_types"] = filter_config.event_types
        elif AuditDataType.ALL not in data_types:
            # Convert data types to event types
            event_types = []
            for data_type in data_types:
                event_types.extend(self._get_event_types_for_data_type(data_type))
            query_params["event_types"] = event_types
        
        # Apply severity filters
        if filter_config.severity_levels:
            query_params["severity_levels"] = filter_config.severity_levels
        
        # Apply IP address filters
        if filter_config.ip_addresses:
            query_params["ip_addresses"] = filter_config.ip_addresses
        
        # Apply resource type filters
        if filter_config.resource_types:
            query_params["resource_types"] = filter_config.resource_types
        
        # Set query limits
        query_params["limit"] = batch_size
        query_params["include_metadata"] = filter_config.include_metadata
        
        return await self._audit_repository.find_by_criteria(query_params)
    
    def _get_event_types_for_data_type(self, data_type: AuditDataType) -> list[str]:
        """Get event types corresponding to audit data type."""
        type_mapping = {
            AuditDataType.AUTHENTICATION_LOGS: ["login", "logout", "authentication_failed"],
            AuditDataType.AUTHORIZATION_LOGS: ["permission_granted", "permission_denied", "role_changed"],
            AuditDataType.USER_ACTIVITY: ["user_created", "user_updated", "user_deleted"],
            AuditDataType.SECURITY_EVENTS: ["security_incident", "suspicious_activity", "breach_detected"],
            AuditDataType.CONFIGURATION_CHANGES: ["config_updated", "setting_changed", "policy_modified"],
            AuditDataType.DATA_ACCESS: ["data_read", "data_written", "data_deleted"],
            AuditDataType.API_CALLS: ["api_request", "api_response", "api_error"],
            AuditDataType.SYSTEM_EVENTS: ["system_startup", "system_shutdown", "service_restarted"],
            AuditDataType.COMPLIANCE_EVENTS: ["compliance_check", "violation_detected", "report_generated"]
        }
        
        return type_mapping.get(data_type, [])
    
    async def _process_audit_data(
        self,
        audit_records: list[dict[str, Any]],
        export_format: ExportFormat,
        field_mapping: dict[str, str],
        anonymize_data: bool,
        include_pii: bool
    ) -> bytes:
        """Process and format audit data for export."""
        processed_records = []
        
        for record in audit_records:
            # Apply field mapping
            if field_mapping:
                record = self._apply_field_mapping(record, field_mapping)
            
            # Handle PII data
            if not include_pii:
                record = self._remove_pii_fields(record)
            elif anonymize_data:
                record = await self._anonymize_sensitive_data(record)
            
            processed_records.append(record)
        
        # Format data according to export format
        if export_format == ExportFormat.JSON:
            return json.dumps(processed_records, indent=2, default=str).encode('utf-8')
        if export_format == ExportFormat.CSV:
            return await self._convert_to_csv(processed_records)
        if export_format == ExportFormat.XML:
            return await self._convert_to_xml(processed_records)
        raise AuditExportError(f"Unsupported export format: {export_format.value}")
    
    def _apply_field_mapping(self, record: dict[str, Any], field_mapping: dict[str, str]) -> dict[str, Any]:
        """Apply field mapping to audit record."""
        mapped_record = {}
        
        for original_field, mapped_field in field_mapping.items():
            if original_field in record:
                mapped_record[mapped_field] = record[original_field]
        
        # Include unmapped fields
        for field, value in record.items():
            if field not in field_mapping:
                mapped_record[field] = value
        
        return mapped_record
    
    def _remove_pii_fields(self, record: dict[str, Any]) -> dict[str, Any]:
        """Remove PII fields from audit record."""
        pii_fields = [
            "email", "phone_number", "ssn", "credit_card", "ip_address",
            "personal_id", "address", "full_name", "date_of_birth"
        ]
        
        cleaned_record = record.copy()
        for field in pii_fields:
            if field in cleaned_record:
                del cleaned_record[field]
        
        return cleaned_record
    
    async def _anonymize_sensitive_data(self, record: dict[str, Any]) -> dict[str, Any]:
        """Anonymize sensitive data in audit record."""
        anonymized_record = record.copy()
        
        # Anonymize email addresses
        if "email" in anonymized_record:
            email = anonymized_record["email"]
            if "@" in email:
                local, domain = email.split("@", 1)
                anonymized_record["email"] = f"****@{domain}"
        
        # Anonymize IP addresses
        if "ip_address" in anonymized_record:
            ip = anonymized_record["ip_address"]
            if "." in ip:
                parts = ip.split(".")
                anonymized_record["ip_address"] = f"{parts[0]}.{parts[1]}.***.**"
        
        # Hash user IDs for consistency while maintaining anonymity
        if "user_id" in anonymized_record:
            user_id = str(anonymized_record["user_id"])
            hashed_id = hashlib.sha256(user_id.encode()).hexdigest()[:12]
            anonymized_record["user_id"] = f"user_{hashed_id}"
        
        return anonymized_record
    
    async def _convert_to_csv(self, records: list[dict[str, Any]]) -> bytes:
        """Convert audit records to CSV format."""
        if not records:
            return b""
        
        import csv
        from io import StringIO
        
        output = StringIO()
        
        # Get all possible field names
        all_fields = set()
        for record in records:
            all_fields.update(record.keys())
        
        writer = csv.DictWriter(output, fieldnames=sorted(all_fields))
        writer.writeheader()
        
        for record in records:
            # Flatten nested objects
            flattened_record = self._flatten_dict(record)
            writer.writerow(flattened_record)
        
        return output.getvalue().encode('utf-8')
    
    async def _convert_to_xml(self, records: list[dict[str, Any]]) -> bytes:
        """Convert audit records to XML format."""
        import xml.etree.ElementTree as ET
        
        root = ET.Element("audit_records")
        root.set("export_time", datetime.now(UTC).isoformat())
        root.set("record_count", str(len(records)))
        
        for record in records:
            record_element = ET.SubElement(root, "audit_record")
            self._dict_to_xml_element(record, record_element)
        
        return ET.tostring(root, encoding='utf-8', xml_declaration=True)
    
    def _flatten_dict(self, d: dict[str, Any], parent_key: str = '', sep: str = '_') -> dict[str, Any]:
        """Flatten nested dictionary for CSV export."""
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep=sep).items())
            elif isinstance(v, list):
                items.append((new_key, json.dumps(v)))
            else:
                items.append((new_key, str(v) if v is not None else ''))
        return dict(items)
    
    def _dict_to_xml_element(self, d: dict[str, Any], parent: ET.Element) -> None:
        """Convert dictionary to XML element."""
        for key, value in d.items():
            child = ET.SubElement(parent, key)
            if isinstance(value, dict):
                self._dict_to_xml_element(value, child)
            elif isinstance(value, list):
                child.text = json.dumps(value)
            else:
                child.text = str(value) if value is not None else ''
    
    async def _compress_audit_data(self, data: bytes, compression_type: str) -> bytes:
        """Compress audit data."""
        if compression_type == "gzip":
            return gzip.compress(data)
        if compression_type == "none":
            return data
        raise AuditExportError(f"Unsupported compression type: {compression_type}")
    
    async def _encrypt_audit_data(self, data: bytes, integration: Any) -> bytes:
        """Encrypt audit data."""
        # Use security service to encrypt data
        return await self._security_service.encrypt_data(data, integration.id)
    
    async def _deliver_audit_data(
        self,
        data: bytes,
        destination_config: dict[str, Any],
        command: AuditIntegrationCommand
    ) -> dict[str, Any]:
        """Deliver audit data to configured destination."""
        try:
            delivery_method = destination_config["type"]
            
            if delivery_method == DeliveryMethod.HTTP.value:
                return await self._deliver_via_http(data, destination_config, command)
            if delivery_method == DeliveryMethod.EMAIL.value:
                return await self._deliver_via_email(data, destination_config, command)
            if delivery_method == DeliveryMethod.FILE.value:
                return await self._deliver_via_file(data, destination_config, command)
            return {
                "success": False,
                "error": f"Unsupported delivery method: {delivery_method}"
            }
                
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    async def _deliver_via_http(
        self,
        data: bytes,
        destination_config: dict[str, Any],
        command: AuditIntegrationCommand
    ) -> dict[str, Any]:
        """Deliver audit data via HTTP."""
        headers = {
            "Content-Type": "application/octet-stream" if command.enable_compression else "application/json",
            "User-Agent": "EzzDay-Audit-Export/1.0",
            **command.custom_headers,
            **destination_config.get("auth_headers", {})
        }
        
        if command.enable_compression:
            headers["Content-Encoding"] = "gzip"
        
        response = await self._http_service.post(
            destination_config["endpoint_url"],
            data=data,
            headers=headers,
            timeout=command.timeout_seconds
        )
        
        success = 200 <= response.get("status_code", 0) < 300
        
        return {
            "success": success,
            "method": "http",
            "status_code": response.get("status_code"),
            "response_time_ms": response.get("response_time_ms"),
            "bytes_sent": len(data),
            "error": response.get("error") if not success else None
        }
    
    async def _deliver_via_email(
        self,
        data: bytes,
        destination_config: dict[str, Any],
        command: AuditIntegrationCommand
    ) -> dict[str, Any]:
        """Deliver audit data via email."""
        # Create attachment
        attachment_name = f"audit_export_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}.{command.export_format.value}"
        if command.enable_compression:
            attachment_name += ".gz"
        
        # Send email with audit data as attachment
        for email_address in destination_config["email_addresses"]:
            email_context = EmailContext(
                recipient=email_address,
                subject=f"Audit Data Export - {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S')}",
                template="audit_data_export",
                variables={
                    "export_time": datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC'),
                    "records_count": "N/A",
                    "format": command.export_format.value,
                    "compressed": command.enable_compression,
                    "encrypted": command.enable_encryption
                },
                attachments=[{
                    "filename": attachment_name,
                    "content": base64.b64encode(data).decode(),
                    "content_type": "application/octet-stream"
                }]
            )
            
            await self._email_service.send_email(email_context)
        
        return {
            "success": True,
            "method": "email",
            "recipients": destination_config["email_addresses"],
            "attachment_size_bytes": len(data)
        }
    
    async def _deliver_via_file(
        self,
        data: bytes,
        destination_config: dict[str, Any],
        command: AuditIntegrationCommand
    ) -> dict[str, Any]:
        """Deliver audit data via file system."""
        # Generate filename
        timestamp = datetime.now(UTC).strftime('%Y%m%d_%H%M%S')
        filename = f"audit_export_{timestamp}.{command.export_format.value}"
        if command.enable_compression:
            filename += ".gz"
        
        file_path = f"{destination_config['file_path']}/{filename}"
        
        # Write file
        await self._file_storage_service.write_file(file_path, data)
        
        return {
            "success": True,
            "method": "file",
            "file_path": file_path,
            "file_size_bytes": len(data)
        }
    
    async def _log_audit_export(
        self,
        integration: Any,
        records_count: int,
        delivery_result: dict[str, Any],
        command: AuditIntegrationCommand
    ) -> None:
        """Log audit export operation."""
        await self._audit_service.log_action(
            AuditContext(
                action=AuditAction.AUDIT_DATA_EXPORTED,
                actor_id=command.initiated_by,
                resource_type="audit_integration",
                resource_id=integration.id,
                details={
                    "integration_name": integration.integration_name,
                    "records_exported": records_count,
                    "export_format": command.export_format.value,
                    "delivery_method": delivery_result.get("method"),
                    "delivery_success": delivery_result["success"],
                    "compressed": command.enable_compression,
                    "encrypted": command.enable_encryption,
                    "anonymized": command.anonymize_data,
                    "dry_run": command.dry_run
                },
                risk_level="low"
            )
        )
    
    async def _log_integration_configuration(
        self,
        integration: Any,
        is_new: bool,
        command: AuditIntegrationCommand
    ) -> None:
        """Log audit integration configuration."""
        await self._audit_service.log_action(
            AuditContext(
                action=AuditAction.AUDIT_INTEGRATION_CONFIGURED if is_new else AuditAction.AUDIT_INTEGRATION_UPDATED,
                actor_id=command.initiated_by,
                resource_type="audit_integration",
                resource_id=integration.id,
                details={
                    "integration_name": integration.integration_name,
                    "integration_type": integration.integration_type,
                    "audit_data_types": integration.audit_data_types,
                    "export_frequency": integration.export_frequency,
                    "real_time_streaming": command.real_time_streaming,
                    "alert_rules_count": len(command.alert_rules),
                    "is_new": is_new
                },
                risk_level="low"
            )
        )
    
    async def _handle_real_time_streaming(self, command: AuditIntegrationCommand) -> AuditIntegrationResponse:
        """Handle real-time audit streaming setup."""
        # Implementation for real-time streaming
        raise NotImplementedError("Real-time streaming not yet implemented")
    
    async def _handle_alert_configuration(self, command: AuditIntegrationCommand) -> AuditIntegrationResponse:
        """Handle audit alert configuration."""
        # Implementation for alert configuration
        raise NotImplementedError("Alert configuration not yet implemented")
    
    async def _handle_integration_test(self, command: AuditIntegrationCommand) -> AuditIntegrationResponse:
        """Handle integration test."""
        # Implementation for integration testing
        raise NotImplementedError("Integration testing not yet implemented")