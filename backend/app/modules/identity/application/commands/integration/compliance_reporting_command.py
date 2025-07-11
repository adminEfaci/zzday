"""
Compliance reporting command implementation.

Handles generation and delivery of compliance reports for various regulations.
"""

import csv
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from io import StringIO
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
from app.modules.identity.application.dtos.internal import AuditContext, EmailContext
from app.modules.identity.application.dtos.request import ComplianceReportingRequest
from app.modules.identity.application.dtos.response import ComplianceReportingResponse
from app.modules.identity.domain.entities import User
from app.modules.identity.domain.enums import (
    AuditAction,
    ComplianceStandard,
    ReportDeliveryMethod,
    ReportFormat,
    UserStatus,
)
from app.modules.identity.domain.events import ComplianceReportGenerated
from app.modules.identity.domain.exceptions import (
    ComplianceValidationError,
    InvalidReportConfigurationError,
    ReportGenerationError,
)
from app.modules.identity.domain.interfaces.repositories.audit_repository import (
    IAuditRepository,
)
from app.modules.identity.domain.interfaces.repositories.device_registration_repository import (
    IDeviceRepository,
)
from app.modules.identity.domain.interfaces.repositories.session_repository import (
    ISessionRepository,
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
    IComplianceRepository,
    IFileStorageService,
)
    EncryptionService,
    SecurityService,
    ValidationService,
)


class ReportScope(Enum):
    """Scope of compliance report."""
    ALL_USERS = "all_users"
    ACTIVE_USERS = "active_users"
    SPECIFIC_USERS = "specific_users"
    DEPARTMENT = "department"
    ROLE_BASED = "role_based"
    RISK_BASED = "risk_based"


@dataclass
class ComplianceReportConfig:
    """Configuration for compliance report generation."""
    standard: ComplianceStandard
    scope: ReportScope
    format: ReportFormat
    include_personal_data: bool = False
    include_audit_trail: bool = True
    include_device_info: bool = True
    include_session_data: bool = True
    anonymize_data: bool = True
    encrypt_report: bool = True
    retention_days: int = 90


class ComplianceReportingCommand(Command[ComplianceReportingResponse]):
    """Command to generate and deliver compliance reports."""
    
    def __init__(
        self,
        operation_type: str,  # "generate", "schedule", "deliver", "archive"
        compliance_standard: ComplianceStandard,
        report_scope: ReportScope = ReportScope.ALL_USERS,
        report_format: ReportFormat = ReportFormat.JSON,
        date_range_start: datetime | None = None,
        date_range_end: datetime | None = None,
        target_user_ids: list[UUID] | None = None,
        department_filter: str | None = None,
        role_filter: str | None = None,
        risk_level_filter: str | None = None,
        include_personal_data: bool = False,
        include_audit_trail: bool = True,
        include_device_info: bool = True,
        include_session_data: bool = True,
        include_security_events: bool = True,
        anonymize_data: bool = True,
        encrypt_report: bool = True,
        delivery_methods: list[ReportDeliveryMethod] | None = None,
        delivery_email: str | None = None,
        delivery_webhook: str | None = None,
        schedule_frequency: str | None = None,  # daily, weekly, monthly, quarterly
        schedule_day_of_week: int | None = None,
        schedule_day_of_month: int | None = None,
        retention_days: int = 90,
        custom_fields: list[str] | None = None,
        filters: dict[str, Any] | None = None,
        template_id: UUID | None = None,
        initiated_by: UUID | None = None,
        metadata: dict[str, Any] | None = None
    ):
        self.operation_type = operation_type
        self.compliance_standard = compliance_standard
        self.report_scope = report_scope
        self.report_format = report_format
        self.date_range_start = date_range_start or datetime.now(UTC) - timedelta(days=30)
        self.date_range_end = date_range_end or datetime.now(UTC)
        self.target_user_ids = target_user_ids or []
        self.department_filter = department_filter
        self.role_filter = role_filter
        self.risk_level_filter = risk_level_filter
        self.include_personal_data = include_personal_data
        self.include_audit_trail = include_audit_trail
        self.include_device_info = include_device_info
        self.include_session_data = include_session_data
        self.include_security_events = include_security_events
        self.anonymize_data = anonymize_data
        self.encrypt_report = encrypt_report
        self.delivery_methods = delivery_methods or []
        self.delivery_email = delivery_email
        self.delivery_webhook = delivery_webhook
        self.schedule_frequency = schedule_frequency
        self.schedule_day_of_week = schedule_day_of_week
        self.schedule_day_of_month = schedule_day_of_month
        self.retention_days = retention_days
        self.custom_fields = custom_fields or []
        self.filters = filters or {}
        self.template_id = template_id
        self.initiated_by = initiated_by
        self.metadata = metadata or {}


class ComplianceReportingCommandHandler(CommandHandler[ComplianceReportingCommand, ComplianceReportingResponse]):
    """Handler for compliance reporting operations."""
    
    def __init__(
        self,
        user_repository: IUserRepository,
        audit_repository: IAuditRepository,
        compliance_repository: IComplianceRepository,
        session_repository: ISessionRepository,
        device_repository: IDeviceRepository,
        file_storage_service: IFileStorageService,
        validation_service: ValidationService,
        security_service: SecurityService,
        encryption_service: EncryptionService,
        notification_service: INotificationService,
        audit_service: IAuditService,
        email_service: IEmailService,
        event_bus: EventBus,
        unit_of_work: UnitOfWork
    ):
        self._user_repository = user_repository
        self._audit_repository = audit_repository
        self._compliance_repository = compliance_repository
        self._session_repository = session_repository
        self._device_repository = device_repository
        self._file_storage_service = file_storage_service
        self._validation_service = validation_service
        self._security_service = security_service
        self._encryption_service = encryption_service
        self._notification_service = notification_service
        self._audit_service = audit_service
        self._email_service = email_service
        self._event_bus = event_bus
        self._unit_of_work = unit_of_work
    
    @audit_action(
        action=AuditAction.COMPLIANCE_REPORT_GENERATED,
        resource_type="compliance_report",
        include_request=True,
        include_response=True
    )
    @validate_request(ComplianceReportingRequest)
    @rate_limit(
        max_requests=10,
        window_seconds=3600,
        strategy='user'
    )
    @require_permission("compliance.reports.generate")
    async def handle(self, command: ComplianceReportingCommand) -> ComplianceReportingResponse:
        """
        Handle compliance reporting operations.
        
        Supports multiple operations:
        - generate: Generate compliance report immediately
        - schedule: Schedule recurring compliance reports
        - deliver: Deliver existing report
        - archive: Archive old reports
        
        Returns:
            ComplianceReportingResponse with operation results
        """
        async with self._unit_of_work:
            # Route to appropriate handler based on operation type
            if command.operation_type == "generate":
                return await self._handle_report_generation(command)
            if command.operation_type == "schedule":
                return await self._handle_report_scheduling(command)
            if command.operation_type == "deliver":
                return await self._handle_report_delivery(command)
            if command.operation_type == "archive":
                return await self._handle_report_archiving(command)
            raise ComplianceValidationError(f"Unsupported operation type: {command.operation_type}")
    
    async def _handle_report_generation(self, command: ComplianceReportingCommand) -> ComplianceReportingResponse:
        """Handle compliance report generation."""
        # 1. Validate report configuration
        await self._validate_report_configuration(command)
        
        # 2. Create report metadata record
        report_metadata = await self._create_report_metadata(command)
        
        try:
            # 3. Collect data for report
            report_data = await self._collect_report_data(command)
            
            # 4. Apply compliance-specific processing
            processed_data = await self._apply_compliance_processing(
                report_data,
                command.compliance_standard,
                command
            )
            
            # 5. Generate report in requested format
            report_content = await self._generate_report_content(
                processed_data,
                command.report_format,
                command
            )
            
            # 6. Apply security measures (encryption, etc.)
            secured_content = await self._apply_security_measures(
                report_content,
                command
            )
            
            # 7. Store report
            report_file_id = await self._store_report(
                secured_content,
                report_metadata,
                command
            )
            
            # 8. Update report metadata with results
            await self._update_report_metadata(
                report_metadata,
                {
                    "status": "completed",
                    "file_id": report_file_id,
                    "record_count": len(processed_data.get("users", [])),
                    "file_size_bytes": len(secured_content),
                    "completed_at": datetime.now(UTC)
                }
            )
            
            # 9. Deliver report if delivery methods specified
            delivery_results = []
            if command.delivery_methods:
                delivery_results = await self._deliver_report(
                    report_metadata,
                    secured_content,
                    command
                )
            
            # 10. Log report generation
            await self._log_report_generation(report_metadata, command)
            
            # 11. Publish domain event
            await self._event_bus.publish(
                ComplianceReportGenerated(
                    aggregate_id=report_metadata.id,
                    compliance_standard=command.compliance_standard,
                    report_format=command.report_format,
                    record_count=len(processed_data.get("users", [])),
                    file_size_bytes=len(secured_content),
                    generated_by=command.initiated_by,
                    delivery_methods=command.delivery_methods
                )
            )
            
            # 12. Commit transaction
            await self._unit_of_work.commit()
            
            # 13. Generate response
            return ComplianceReportingResponse(
                success=True,
                operation_type="generate",
                report_id=report_metadata.id,
                compliance_standard=command.compliance_standard.value,
                report_format=command.report_format.value,
                record_count=len(processed_data.get("users", [])),
                file_size_bytes=len(secured_content),
                file_id=report_file_id,
                encrypted=command.encrypt_report,
                delivery_results=delivery_results,
                generated_at=report_metadata.created_at,
                expires_at=report_metadata.expires_at,
                message="Compliance report generated successfully"
            )
            
        except Exception as e:
            # Update report metadata with error
            await self._update_report_metadata(
                report_metadata,
                {
                    "status": "failed",
                    "error_message": str(e),
                    "failed_at": datetime.now(UTC)
                }
            )
            
            await self._audit_service.log_error(
                f"Compliance report generation failed: {e!s}"
            )
            
            raise
    
    async def _validate_report_configuration(self, command: ComplianceReportingCommand) -> None:
        """Validate compliance report configuration."""
        # Validate date range
        if command.date_range_start >= command.date_range_end:
            raise InvalidReportConfigurationError("Start date must be before end date")
        
        # Validate date range is not too large
        date_range_days = (command.date_range_end - command.date_range_start).days
        if date_range_days > 365:
            raise InvalidReportConfigurationError("Date range cannot exceed 365 days")
        
        # Validate scope-specific parameters
        if command.report_scope == ReportScope.SPECIFIC_USERS and not command.target_user_ids:
            raise InvalidReportConfigurationError("User IDs required for specific users scope")
        
        if command.report_scope == ReportScope.DEPARTMENT and not command.department_filter:
            raise InvalidReportConfigurationError("Department filter required for department scope")
        
        if command.report_scope == ReportScope.ROLE_BASED and not command.role_filter:
            raise InvalidReportConfigurationError("Role filter required for role-based scope")
        
        # Validate delivery configuration
        if command.delivery_methods:
            if ReportDeliveryMethod.EMAIL in command.delivery_methods and not command.delivery_email:
                raise InvalidReportConfigurationError("Email address required for email delivery")
            
            if ReportDeliveryMethod.WEBHOOK in command.delivery_methods and not command.delivery_webhook:
                raise InvalidReportConfigurationError("Webhook URL required for webhook delivery")
        
        # Validate retention period
        if command.retention_days < 1 or command.retention_days > 2555:  # 7 years max
            raise InvalidReportConfigurationError("Retention period must be between 1 and 2555 days")
        
        # Validate compliance standard specific requirements
        await self._validate_compliance_standard_requirements(command)
    
    async def _validate_compliance_standard_requirements(self, command: ComplianceReportingCommand) -> None:
        """Validate requirements specific to compliance standards."""
        if command.compliance_standard == ComplianceStandard.GDPR:
            # GDPR specific validations
            if command.include_personal_data and not command.anonymize_data:
                raise ComplianceValidationError("GDPR reports with personal data must be anonymized")
        
        elif command.compliance_standard == ComplianceStandard.HIPAA:
            # HIPAA specific validations
            if not command.encrypt_report:
                raise ComplianceValidationError("HIPAA reports must be encrypted")
        
        elif command.compliance_standard == ComplianceStandard.SOX:
            # SOX specific validations
            if not command.include_audit_trail:
                raise ComplianceValidationError("SOX reports must include audit trail")
        
        elif command.compliance_standard == ComplianceStandard.PCI_DSS:
            # PCI DSS specific validations
            if command.include_personal_data:
                raise ComplianceValidationError("PCI DSS reports should not include personal data")
    
    async def _create_report_metadata(self, command: ComplianceReportingCommand) -> Any:
        """Create report metadata record."""
        metadata = {
            "id": UUID(),
            "compliance_standard": command.compliance_standard.value,
            "report_scope": command.report_scope.value,
            "report_format": command.report_format.value,
            "date_range_start": command.date_range_start,
            "date_range_end": command.date_range_end,
            "status": "generating",
            "created_by": command.initiated_by,
            "created_at": datetime.now(UTC),
            "expires_at": datetime.now(UTC) + timedelta(days=command.retention_days),
            "configuration": {
                "target_user_ids": [str(uid) for uid in command.target_user_ids],
                "department_filter": command.department_filter,
                "role_filter": command.role_filter,
                "risk_level_filter": command.risk_level_filter,
                "include_personal_data": command.include_personal_data,
                "include_audit_trail": command.include_audit_trail,
                "include_device_info": command.include_device_info,
                "include_session_data": command.include_session_data,
                "include_security_events": command.include_security_events,
                "anonymize_data": command.anonymize_data,
                "encrypt_report": command.encrypt_report,
                "custom_fields": command.custom_fields,
                "filters": command.filters
            },
            "metadata": command.metadata
        }
        
        return await self._compliance_repository.create_report_metadata(metadata)
    
    async def _collect_report_data(self, command: ComplianceReportingCommand) -> dict[str, Any]:
        """Collect data for compliance report."""
        report_data = {
            "users": [],
            "audit_records": [],
            "sessions": [],
            "devices": [],
            "security_events": []
        }
        
        # 1. Collect user data
        if command.report_scope == ReportScope.ALL_USERS:
            users = await self._user_repository.find_all()
        elif command.report_scope == ReportScope.ACTIVE_USERS:
            users = await self._user_repository.find_by_status(UserStatus.ACTIVE)
        elif command.report_scope == ReportScope.SPECIFIC_USERS:
            users = await self._user_repository.find_by_ids(command.target_user_ids)
        elif command.report_scope == ReportScope.DEPARTMENT:
            users = await self._user_repository.find_by_department(command.department_filter)
        elif command.report_scope == ReportScope.ROLE_BASED:
            users = await self._user_repository.find_by_role(command.role_filter)
        elif command.report_scope == ReportScope.RISK_BASED:
            users = await self._user_repository.find_by_risk_level(command.risk_level_filter)
        else:
            users = []
        
        # Apply additional filters
        users = await self._apply_user_filters(users, command.filters)
        report_data["users"] = users
        
        # 2. Collect audit data if requested
        if command.include_audit_trail:
            user_ids = [user.id for user in users]
            audit_records = await self._audit_repository.find_by_users_and_date_range(
                user_ids,
                command.date_range_start,
                command.date_range_end
            )
            report_data["audit_records"] = audit_records
        
        # 3. Collect session data if requested
        if command.include_session_data:
            user_ids = [user.id for user in users]
            sessions = await self._session_repository.find_by_users_and_date_range(
                user_ids,
                command.date_range_start,
                command.date_range_end
            )
            report_data["sessions"] = sessions
        
        # 4. Collect device data if requested
        if command.include_device_info:
            user_ids = [user.id for user in users]
            devices = await self._device_repository.find_by_users(user_ids)
            report_data["devices"] = devices
        
        # 5. Collect security events if requested
        if command.include_security_events:
            user_ids = [user.id for user in users]
            security_events = await self._audit_repository.find_security_events_by_users_and_date_range(
                user_ids,
                command.date_range_start,
                command.date_range_end
            )
            report_data["security_events"] = security_events
        
        return report_data
    
    async def _apply_user_filters(self, users: list[User], filters: dict[str, Any]) -> list[User]:
        """Apply additional filters to user data."""
        if not filters:
            return users
        
        filtered_users = []
        for user in users:
            include_user = True
            
            for filter_key, filter_value in filters.items():
                user_value = getattr(user, filter_key, None)
                
                if isinstance(filter_value, dict):
                    # Complex filter operations
                    if "eq" in filter_value and user_value != filter_value["eq"]:
                        include_user = False
                        break
                    if "ne" in filter_value and user_value == filter_value["ne"]:
                        include_user = False
                        break
                    if "in" in filter_value and user_value not in filter_value["in"]:
                        include_user = False
                        break
                    if "contains" in filter_value and filter_value["contains"] not in str(user_value):
                        include_user = False
                        break
                # Simple equality filter
                elif user_value != filter_value:
                    include_user = False
                    break
            
            if include_user:
                filtered_users.append(user)
        
        return filtered_users
    
    async def _apply_compliance_processing(
        self,
        report_data: dict[str, Any],
        compliance_standard: ComplianceStandard,
        command: ComplianceReportingCommand
    ) -> dict[str, Any]:
        """Apply compliance-specific data processing."""
        processed_data = report_data.copy()
        
        if compliance_standard == ComplianceStandard.GDPR:
            processed_data = await self._apply_gdpr_processing(processed_data, command)
        elif compliance_standard == ComplianceStandard.HIPAA:
            processed_data = await self._apply_hipaa_processing(processed_data, command)
        elif compliance_standard == ComplianceStandard.SOX:
            processed_data = await self._apply_sox_processing(processed_data, command)
        elif compliance_standard == ComplianceStandard.PCI_DSS:
            processed_data = await self._apply_pci_dss_processing(processed_data, command)
        elif compliance_standard == ComplianceStandard.ISO_27001:
            processed_data = await self._apply_iso27001_processing(processed_data, command)
        
        # Apply anonymization if requested
        if command.anonymize_data:
            processed_data = await self._anonymize_report_data(processed_data, command)
        
        return processed_data
    
    async def _apply_gdpr_processing(self, data: dict[str, Any], command: ComplianceReportingCommand) -> dict[str, Any]:
        """Apply GDPR-specific data processing."""
        # Remove or mask personal identifiers
        for user in data.get("users", []):
            if command.anonymize_data:
                user.email = self._mask_email(user.email)
                user.phone_number = self._mask_phone(user.phone_number) if user.phone_number else None
                user.first_name = self._mask_name(user.first_name)
                user.last_name = self._mask_name(user.last_name)
        
        # Add GDPR-specific fields
        gdpr_data = {
            "data_processing_lawful_basis": "legitimate_interest",
            "data_categories": ["identity", "contact", "usage"],
            "retention_period": f"{command.retention_days} days",
            "data_subject_rights": {
                "access": True,
                "rectification": True,
                "erasure": True,
                "portability": True,
                "objection": True
            }
        }
        
        data["gdpr_compliance"] = gdpr_data
        return data
    
    async def _apply_hipaa_processing(self, data: dict[str, Any], command: ComplianceReportingCommand) -> dict[str, Any]:
        """Apply HIPAA-specific data processing."""
        # Remove all personal health information
        for user in data.get("users", []):
            # Remove potentially sensitive fields
            user.phone_number = None
            user.profile_image_url = None
            
        # Add HIPAA-specific compliance metadata
        hipaa_data = {
            "covered_entity": True,
            "business_associate": False,
            "phi_categories": ["none"],  # No PHI in identity data
            "safeguards": {
                "administrative": True,
                "physical": True,
                "technical": True
            }
        }
        
        data["hipaa_compliance"] = hipaa_data
        return data
    
    async def _apply_sox_processing(self, data: dict[str, Any], command: ComplianceReportingCommand) -> dict[str, Any]:
        """Apply SOX-specific data processing."""
        # SOX focuses on financial controls and audit trails
        sox_data = {
            "internal_controls": {
                "user_access_controls": True,
                "segregation_of_duties": True,
                "audit_trail_integrity": True
            },
            "financial_reporting_relevance": "user_access_to_financial_systems",
            "control_testing_period": {
                "start": command.date_range_start.isoformat(),
                "end": command.date_range_end.isoformat()
            }
        }
        
        data["sox_compliance"] = sox_data
        return data
    
    async def _apply_pci_dss_processing(self, data: dict[str, Any], command: ComplianceReportingCommand) -> dict[str, Any]:
        """Apply PCI DSS-specific data processing."""
        # PCI DSS focuses on payment card data protection
        pci_data = {
            "cardholder_data_environment": False,  # Identity system shouldn't have CHD
            "security_requirements": {
                "install_maintain_firewall": True,
                "default_passwords_security_parameters": True,
                "protect_stored_cardholder_data": "not_applicable",
                "encrypt_transmission_cardholder_data": True,
                "use_maintain_antivirus_software": True,
                "develop_maintain_secure_systems": True,
                "restrict_access_cardholder_data": "not_applicable",
                "identify_authenticate_access": True,
                "restrict_physical_access": True,
                "track_monitor_access": True,
                "regularly_test_security_systems": True,
                "maintain_information_security_policy": True
            }
        }
        
        data["pci_dss_compliance"] = pci_data
        return data
    
    async def _apply_iso27001_processing(self, data: dict[str, Any], command: ComplianceReportingCommand) -> dict[str, Any]:
        """Apply ISO 27001-specific data processing."""
        # ISO 27001 focuses on information security management
        iso_data = {
            "information_security_controls": {
                "access_control": True,
                "cryptography": True,
                "physical_environmental_security": True,
                "operations_security": True,
                "communications_security": True,
                "system_acquisition_development_maintenance": True,
                "supplier_relationships": True,
                "information_security_incident_management": True,
                "business_continuity": True,
                "compliance": True
            },
            "risk_assessment_period": {
                "start": command.date_range_start.isoformat(),
                "end": command.date_range_end.isoformat()
            }
        }
        
        data["iso27001_compliance"] = iso_data
        return data
    
    def _mask_email(self, email: str) -> str:
        """Mask email address for anonymization."""
        if not email or "@" not in email:
            return email
        
        local, domain = email.split("@", 1)
        masked_local = local[:2] + "*" * (len(local) - 2) if len(local) > 2 else "*" * len(local)
        return f"{masked_local}@{domain}"
    
    def _mask_phone(self, phone: str) -> str:
        """Mask phone number for anonymization."""
        if not phone:
            return phone
        
        # Keep first 3 and last 2 digits
        if len(phone) > 5:
            return phone[:3] + "*" * (len(phone) - 5) + phone[-2:]
        return "*" * len(phone)
    
    def _mask_name(self, name: str) -> str:
        """Mask name for anonymization."""
        if not name:
            return name
        
        return name[0] + "*" * (len(name) - 1) if len(name) > 1 else "*"
    
    async def _anonymize_report_data(self, data: dict[str, Any], command: ComplianceReportingCommand) -> dict[str, Any]:
        """Apply general anonymization to report data."""
        # Generate consistent anonymization mapping
        anonymization_map = {}
        
        for user in data.get("users", []):
            if user.id not in anonymization_map:
                anonymization_map[user.id] = f"user_{len(anonymization_map) + 1:04d}"
            
            # Replace user ID with anonymous identifier
            user.anonymous_id = anonymization_map[user.id]
            user.id = None  # Remove actual ID
        
        # Apply same anonymization to related records
        for record in data.get("audit_records", []):
            if record.user_id in anonymization_map:
                record.anonymous_user_id = anonymization_map[record.user_id]
                record.user_id = None
        
        for session in data.get("sessions", []):
            if session.user_id in anonymization_map:
                session.anonymous_user_id = anonymization_map[session.user_id]
                session.user_id = None
        
        for device in data.get("devices", []):
            if device.user_id in anonymization_map:
                device.anonymous_user_id = anonymization_map[device.user_id]
                device.user_id = None
        
        return data
    
    async def _generate_report_content(
        self,
        data: dict[str, Any],
        report_format: ReportFormat,
        command: ComplianceReportingCommand
    ) -> bytes:
        """Generate report content in specified format."""
        if report_format == ReportFormat.JSON:
            return await self._generate_json_report(data, command)
        if report_format == ReportFormat.CSV:
            return await self._generate_csv_report(data, command)
        if report_format == ReportFormat.XML:
            return await self._generate_xml_report(data, command)
        if report_format == ReportFormat.PDF:
            return await self._generate_pdf_report(data, command)
        raise ReportGenerationError(f"Unsupported report format: {report_format}")
    
    async def _generate_json_report(self, data: dict[str, Any], command: ComplianceReportingCommand) -> bytes:
        """Generate JSON format report."""
        report = {
            "report_metadata": {
                "compliance_standard": command.compliance_standard.value,
                "generated_at": datetime.now(UTC).isoformat(),
                "date_range": {
                    "start": command.date_range_start.isoformat(),
                    "end": command.date_range_end.isoformat()
                },
                "scope": command.report_scope.value,
                "anonymized": command.anonymize_data,
                "encrypted": command.encrypt_report
            },
            "data": data,
            "summary": {
                "total_users": len(data.get("users", [])),
                "total_audit_records": len(data.get("audit_records", [])),
                "total_sessions": len(data.get("sessions", [])),
                "total_devices": len(data.get("devices", [])),
                "total_security_events": len(data.get("security_events", []))
            }
        }
        
        return json.dumps(report, indent=2, default=str).encode('utf-8')
    
    async def _generate_csv_report(self, data: dict[str, Any], command: ComplianceReportingCommand) -> bytes:
        """Generate CSV format report."""
        output = StringIO()
        
        # Write users data
        if data.get("users"):
            writer = csv.writer(output)
            
            # Header
            headers = ["user_id", "username", "email", "status", "created_at", "last_login_at"]
            if command.anonymize_data:
                headers = ["anonymous_id"] + headers[1:]
            writer.writerow(headers)
            
            # Data rows
            for user in data["users"]:
                row = []
                if command.anonymize_data:
                    row.append(getattr(user, "anonymous_id", ""))
                else:
                    row.append(str(user.id))
                
                row.extend([
                    user.username,
                    user.email,
                    user.status.value if hasattr(user.status, 'value') else str(user.status),
                    user.created_at.isoformat() if user.created_at else "",
                    user.last_login_at.isoformat() if user.last_login_at else ""
                ])
                writer.writerow(row)
        
        return output.getvalue().encode('utf-8')
    
    async def _generate_xml_report(self, data: dict[str, Any], command: ComplianceReportingCommand) -> bytes:
        """Generate XML format report."""
        import xml.etree.ElementTree as ET
        
        root = ET.Element("compliance_report")
        
        # Metadata
        metadata = ET.SubElement(root, "metadata")
        ET.SubElement(metadata, "compliance_standard").text = command.compliance_standard.value
        ET.SubElement(metadata, "generated_at").text = datetime.now(UTC).isoformat()
        ET.SubElement(metadata, "scope").text = command.report_scope.value
        
        # Users
        users_elem = ET.SubElement(root, "users")
        for user in data.get("users", []):
            user_elem = ET.SubElement(users_elem, "user")
            if command.anonymize_data:
                ET.SubElement(user_elem, "anonymous_id").text = getattr(user, "anonymous_id", "")
            else:
                ET.SubElement(user_elem, "id").text = str(user.id)
            ET.SubElement(user_elem, "username").text = user.username
            ET.SubElement(user_elem, "email").text = user.email
        
        return ET.tostring(root, encoding='utf-8')
    
    async def _generate_pdf_report(self, data: dict[str, Any], command: ComplianceReportingCommand) -> bytes:
        """Generate PDF format report."""
        # This would require a PDF library like reportlab
        # For now, return a placeholder
        raise ReportGenerationError("PDF report generation not yet implemented")
    
    async def _apply_security_measures(self, content: bytes, command: ComplianceReportingCommand) -> bytes:
        """Apply security measures to report content."""
        if command.encrypt_report:
            # Encrypt the report content
            return await self._encryption_service.encrypt_data(
                content,
                purpose="compliance_report"
            )
        
        return content
    
    async def _store_report(
        self,
        content: bytes,
        metadata: Any,
        command: ComplianceReportingCommand
    ) -> UUID:
        """Store report in secure file storage."""
        file_name = f"compliance_report_{metadata.id}_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}.{command.report_format.value.lower()}"
        
        return await self._file_storage_service.store_file(
            content,
            file_name,
            content_type=self._get_content_type(command.report_format),
            encrypted=command.encrypt_report,
            retention_days=command.retention_days,
            access_level="confidential"
        )
        
    
    def _get_content_type(self, report_format: ReportFormat) -> str:
        """Get content type for report format."""
        content_types = {
            ReportFormat.JSON: "application/json",
            ReportFormat.CSV: "text/csv",
            ReportFormat.XML: "application/xml",
            ReportFormat.PDF: "application/pdf"
        }
        return content_types.get(report_format, "application/octet-stream")
    
    async def _deliver_report(
        self,
        metadata: Any,
        content: bytes,
        command: ComplianceReportingCommand
    ) -> list[dict[str, Any]]:
        """Deliver report using specified delivery methods."""
        delivery_results = []
        
        for delivery_method in command.delivery_methods:
            try:
                if delivery_method == ReportDeliveryMethod.EMAIL:
                    result = await self._deliver_via_email(metadata, content, command)
                elif delivery_method == ReportDeliveryMethod.WEBHOOK:
                    result = await self._deliver_via_webhook(metadata, content, command)
                elif delivery_method == ReportDeliveryMethod.DOWNLOAD:
                    result = await self._prepare_download_link(metadata, command)
                else:
                    result = {"method": delivery_method.value, "success": False, "error": "Unsupported delivery method"}
                
                delivery_results.append(result)
                
            except Exception as e:
                delivery_results.append({
                    "method": delivery_method.value,
                    "success": False,
                    "error": str(e)
                })
        
        return delivery_results
    
    async def _deliver_via_email(
        self,
        metadata: Any,
        content: bytes,
        command: ComplianceReportingCommand
    ) -> dict[str, Any]:
        """Deliver report via email."""
        await self._email_service.send_email(
            EmailContext(
                recipient=command.delivery_email,
                template="compliance_report_delivery",
                subject=f"Compliance Report - {command.compliance_standard.value}",
                variables={
                    "compliance_standard": command.compliance_standard.value,
                    "report_scope": command.report_scope.value,
                    "generated_at": metadata.created_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "record_count": metadata.record_count if hasattr(metadata, 'record_count') else 0,
                    "encrypted": command.encrypt_report
                },
                attachments=[{
                    "filename": f"compliance_report_{metadata.id}.{command.report_format.value.lower()}",
                    "content": content,
                    "content_type": self._get_content_type(command.report_format)
                }]
            )
        )
        
        return {
            "method": "email",
            "success": True,
            "recipient": command.delivery_email,
            "delivered_at": datetime.now(UTC).isoformat()
        }
    
    async def _deliver_via_webhook(
        self,
        metadata: Any,
        content: bytes,
        command: ComplianceReportingCommand
    ) -> dict[str, Any]:
        """Deliver report via webhook."""
        # This would implement webhook delivery
        # For now, return a placeholder
        return {
            "method": "webhook",
            "success": True,
            "webhook_url": command.delivery_webhook,
            "delivered_at": datetime.now(UTC).isoformat()
        }
    
    async def _prepare_download_link(self, metadata: Any, command: ComplianceReportingCommand) -> dict[str, Any]:
        """Prepare secure download link for report."""
        download_token = await self._security_service.generate_secure_token(
            purpose="report_download",
            resource_id=metadata.id,
            expires_in_hours=24
        )
        
        download_url = f"https://app.example.com/api/compliance/reports/{metadata.id}/download?token={download_token}"
        
        return {
            "method": "download",
            "success": True,
            "download_url": download_url,
            "expires_at": (datetime.now(UTC) + timedelta(hours=24)).isoformat()
        }
    
    async def _update_report_metadata(self, metadata: Any, update_data: dict[str, Any]) -> None:
        """Update report metadata with results."""
        await self._compliance_repository.update_report_metadata(metadata.id, update_data)
    
    async def _log_report_generation(self, metadata: Any, command: ComplianceReportingCommand) -> None:
        """Log compliance report generation."""
        await self._audit_service.log_action(
            AuditContext(
                action=AuditAction.COMPLIANCE_REPORT_GENERATED,
                actor_id=command.initiated_by,
                resource_type="compliance_report",
                resource_id=metadata.id,
                details={
                    "compliance_standard": command.compliance_standard.value,
                    "report_scope": command.report_scope.value,
                    "report_format": command.report_format.value,
                    "date_range": {
                        "start": command.date_range_start.isoformat(),
                        "end": command.date_range_end.isoformat()
                    },
                    "include_personal_data": command.include_personal_data,
                    "anonymized": command.anonymize_data,
                    "encrypted": command.encrypt_report,
                    "delivery_methods": [method.value for method in command.delivery_methods],
                    "retention_days": command.retention_days
                },
                risk_level="medium"
            )
        )
    
    async def _handle_report_scheduling(self, command: ComplianceReportingCommand) -> ComplianceReportingResponse:
        """Handle compliance report scheduling."""
        # This would implement report scheduling logic
        raise NotImplementedError("Report scheduling not yet implemented")
    
    async def _handle_report_delivery(self, command: ComplianceReportingCommand) -> ComplianceReportingResponse:
        """Handle delivery of existing report."""
        # This would implement delivery of existing reports
        raise NotImplementedError("Report delivery not yet implemented")
    
    async def _handle_report_archiving(self, command: ComplianceReportingCommand) -> ComplianceReportingResponse:
        """Handle archiving of old reports."""
        # This would implement report archiving logic
        raise NotImplementedError("Report archiving not yet implemented")