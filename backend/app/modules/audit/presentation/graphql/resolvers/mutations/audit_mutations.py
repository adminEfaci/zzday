"""
Comprehensive Audit Mutations GraphQL Resolver

This module provides comprehensive audit trail mutations with enterprise-grade features:
- Manual audit entry creation and management
- Compliance report generation and scheduling
- Audit log archival and retention management
- Policy configuration and violation handling
- Integration with external audit systems

Features:
- Comprehensive audit entry creation
- Bulk operations for efficiency
- Report generation and scheduling
- Compliance violation management
- Audit retention and archival
- Integration with notification systems

Security:
- All mutations require authentication
- Role-based access control for sensitive operations
- Comprehensive audit logging of all mutations
- Input validation and sanitization
- Rate limiting to prevent abuse
"""

from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

import strawberry

# Core imports
from app.core.errors import AuthorizationError, ValidationError
from app.core.logging import get_logger
from app.modules.audit.application.commands.archive_audit_log_command import (
    ArchiveAuditLogCommand,
)
from app.modules.audit.application.commands.generate_audit_report_command import (
    GenerateAuditReportCommand,
)
from app.modules.audit.application.commands.record_audit_entry_command import (
    RecordAuditEntryCommand,
)
from app.modules.audit.application.commands.update_retention_policy_command import (
    UpdateRetentionPolicyCommand,
)
from app.modules.audit.application.services.archival_service import ArchivalService

# Audit domain imports
from app.modules.audit.application.services.audit_service import AuditService
from app.modules.audit.application.services.compliance_service import ComplianceService
from app.modules.audit.application.services.reporting_service import ReportingService
from app.modules.audit.presentation.graphql.schemas.inputs.audit_inputs import (
    BulkAuditEntryInput,
    CreateAuditEntryInput,
)
from app.modules.audit.presentation.graphql.schemas.inputs.audit_search_input import (
    SavedSearchInput,
)
from app.modules.audit.presentation.graphql.schemas.inputs.report_inputs import (
    ComplianceCheckInput,
    ReportGenerationInput,
    ScheduleReportInput,
)

# GraphQL types and inputs
from app.modules.audit.presentation.graphql.schemas.types.audit_entry_type import (
    AuditEntryType,
)
from app.modules.audit.presentation.graphql.schemas.types.audit_report_type import (
    AuditReportType,
)
from app.modules.audit.presentation.graphql.schemas.types.compliance_type import (
    ComplianceReportType,
)

# Mappers
from app.modules.audit.presentation.mappers.audit_mapper import AuditMapper
from app.modules.audit.presentation.mappers.report_mapper import ReportMapper

# Identity imports for authentication
from app.modules.identity.presentation.graphql.decorators import (
    admin_only,
    audit_log,
    batch_size_limit,
    operation_timeout,
    rate_limit,
    require_auth,
    require_permission,
    track_metrics,
)

logger = get_logger(__name__)


@strawberry.type
class AuditMutations:
    """
    Comprehensive audit mutations with enterprise features.

    Provides audit trail management, compliance reporting, and system
    administration capabilities for enterprise audit requirements.
    """

    @strawberry.mutation(description="Create a new audit entry manually")
    @require_auth()
    @require_permission("audit.entries.create")
    @rate_limit(requests=100, window=60)
    @audit_log("audit.entry.create")
    @track_metrics("audit_entry_create")
    async def create_audit_entry(
        self, info: strawberry.Info, input: CreateAuditEntryInput
    ) -> AuditEntryType:
        """
        Create a new audit entry manually.

        Features:
        - Manual audit entry creation for external events
        - Comprehensive validation and metadata
        - Integration with compliance frameworks
        - Automatic risk scoring and categorization

        Args:
            input: Audit entry creation data

        Returns:
            Created audit entry with full metadata

        Raises:
            ValidationError: If input data is invalid
            AuthorizationError: If user lacks required permissions
        """
        try:
            # Validate input
            validation_errors = input.validate()
            if validation_errors:
                raise ValidationError(
                    f"Invalid audit entry data: {'; '.join(validation_errors)}"
                )

            # Get audit service
            audit_service: AuditService = info.context["container"].resolve(
                AuditService
            )
            current_user = info.context.get("current_user")

            # Build command
            command = RecordAuditEntryCommand(
                user_id=UUID(str(input.user_id)) if input.user_id else current_user.id,
                action_type=input.action.action_type,
                operation=input.action.operation,
                description=input.action.description,
                resource_type=input.resource.resource_type,
                resource_id=input.resource.resource_id,
                resource_name=input.resource.resource_name,
                outcome=input.result.outcome,
                severity=input.result.severity,
                category=input.result.category,
                duration_ms=input.result.duration_ms,
                error_details=input.result.error_details,
                ip_address=input.context.ip_address,
                user_agent=input.context.user_agent,
                session_id=UUID(str(input.context.session_id))
                if input.context.session_id
                else None,
                correlation_id=input.context.correlation_id,
                changes=input.changes or [],
                tags=input.metadata.tags or [],
                compliance_tags=input.metadata.compliance_tags or [],
                custom_fields=input.metadata.custom_fields,
                created_by=current_user.id,
                manual_entry=True,
            )

            logger.info(
                "Creating manual audit entry",
                user_id=str(current_user.id),
                target_user_id=str(command.user_id),
                resource_type=command.resource_type,
                action_type=command.action_type,
            )

            # Execute command
            audit_entry = await audit_service.record_entry(command)

            # Convert to GraphQL type
            return AuditMapper.domain_to_graphql(audit_entry)

        except (ValidationError, AuthorizationError):
            raise
        except Exception as e:
            logger.error(f"Audit entry creation failed: {e}", exc_info=True)
            raise ValidationError("Failed to create audit entry")

    @strawberry.mutation(description="Create multiple audit entries in bulk")
    @require_auth()
    @require_permission("audit.entries.bulk_create")
    @rate_limit(requests=10, window=60)
    @audit_log("audit.entry.bulk_create")
    @batch_size_limit(max_size=100)
    @operation_timeout(60)
    async def bulk_create_audit_entries(
        self, info: strawberry.Info, input: BulkAuditEntryInput
    ) -> list[AuditEntryType]:
        """
        Create multiple audit entries efficiently in bulk.

        Features:
        - Batch processing for performance
        - Transactional consistency
        - Error handling per entry
        - Progress tracking for large batches

        Args:
            input: Bulk audit entry creation data

        Returns:
            List of created audit entries

        Raises:
            ValidationError: If bulk input is invalid
        """
        try:
            # Validate input
            validation_errors = input.validate()
            if validation_errors:
                raise ValidationError(
                    f"Invalid bulk input: {'; '.join(validation_errors)}"
                )

            # Get audit service
            audit_service: AuditService = info.context["container"].resolve(
                AuditService
            )
            current_user = info.context.get("current_user")

            logger.info(
                "Creating bulk audit entries",
                user_id=str(current_user.id),
                entry_count=len(input.entries),
            )

            # Convert entries to commands
            commands = []
            for entry_input in input.entries:
                command = RecordAuditEntryCommand(
                    user_id=UUID(str(entry_input.user_id))
                    if entry_input.user_id
                    else current_user.id,
                    action_type=entry_input.action.action_type,
                    operation=entry_input.action.operation,
                    description=entry_input.action.description,
                    resource_type=entry_input.resource.resource_type,
                    resource_id=entry_input.resource.resource_id,
                    resource_name=entry_input.resource.resource_name,
                    outcome=entry_input.result.outcome,
                    severity=entry_input.result.severity,
                    category=entry_input.result.category,
                    duration_ms=entry_input.result.duration_ms,
                    ip_address=entry_input.context.ip_address,
                    user_agent=entry_input.context.user_agent,
                    session_id=UUID(str(entry_input.context.session_id))
                    if entry_input.context.session_id
                    else None,
                    correlation_id=entry_input.context.correlation_id,
                    changes=entry_input.changes or [],
                    tags=entry_input.metadata.tags or [],
                    compliance_tags=entry_input.metadata.compliance_tags or [],
                    custom_fields=entry_input.metadata.custom_fields,
                    created_by=current_user.id,
                    manual_entry=True,
                )
                commands.append(command)

            # Execute bulk command
            audit_entries = await audit_service.bulk_record_entries(commands)

            # Convert to GraphQL types
            return [AuditMapper.domain_to_graphql(entry) for entry in audit_entries]

        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Bulk audit entry creation failed: {e}", exc_info=True)
            raise ValidationError("Failed to create bulk audit entries")

    @strawberry.mutation(description="Generate comprehensive audit report")
    @require_auth()
    @require_permission("audit.reports.generate")
    @rate_limit(requests=10, window=300)  # 10 reports per 5 minutes
    @audit_log("audit.report.generate")
    @operation_timeout(180)  # 3 minute timeout for reports
    async def generate_audit_report(
        self, info: strawberry.Info, input: ReportGenerationInput
    ) -> AuditReportType:
        """
        Generate comprehensive audit reports for compliance and analysis.

        Features:
        - Multiple report types (summary, detailed, compliance, security)
        - Customizable date ranges and filters
        - Automated compliance framework mapping
        - Export to multiple formats
        - Scheduled report generation

        Args:
            input: Report generation parameters

        Returns:
            Generated audit report with metadata

        Raises:
            ValidationError: If report parameters are invalid
        """
        try:
            # Validate input
            validation_errors = input.validate()
            if validation_errors:
                raise ValidationError(
                    f"Invalid report parameters: {'; '.join(validation_errors)}"
                )

            # Get reporting service
            reporting_service: ReportingService = info.context["container"].resolve(
                ReportingService
            )
            current_user = info.context.get("current_user")

            # Build command
            command = GenerateAuditReportCommand(
                report_type=input.report_type,
                start_date=input.date_range.start_date,
                end_date=input.date_range.end_date,
                filters=input.filters.to_criteria_dto() if input.filters else {},
                include_statistics=input.include_statistics,
                include_timeline=input.include_timeline,
                include_recommendations=input.include_recommendations,
                compliance_frameworks=input.compliance_frameworks or [],
                export_format=input.export_format,
                generated_by=current_user.id,
                title=input.title,
                description=input.description,
            )

            # Apply permission restrictions
            if not current_user.has_permission("audit.reports.generate_all"):
                command.scope_to_user = current_user.id

            logger.info(
                "Generating audit report",
                user_id=str(current_user.id),
                report_type=input.report_type,
                date_range=f"{input.date_range.start_date} to {input.date_range.end_date}",
            )

            # Execute command
            report = await reporting_service.generate_report(command)

            # Convert to GraphQL type
            return ReportMapper.domain_to_graphql(report)

        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Report generation failed: {e}", exc_info=True)
            raise ValidationError("Failed to generate report")

    @strawberry.mutation(description="Schedule recurring audit report generation")
    @require_auth()
    @require_permission("audit.reports.schedule")
    @rate_limit(requests=5, window=300)
    @audit_log("audit.report.schedule")
    async def schedule_audit_report(
        self, info: strawberry.Info, input: ScheduleReportInput
    ) -> dict[str, Any]:
        """
        Schedule recurring audit report generation.

        Features:
        - Flexible scheduling options (daily, weekly, monthly)
        - Email delivery to stakeholders
        - Conditional generation based on criteria
        - Management of scheduled reports

        Args:
            input: Report scheduling parameters

        Returns:
            Scheduled report configuration
        """
        try:
            # Validate input
            validation_errors = input.validate()
            if validation_errors:
                raise ValidationError(
                    f"Invalid schedule parameters: {'; '.join(validation_errors)}"
                )

            # Get reporting service
            reporting_service: ReportingService = info.context["container"].resolve(
                ReportingService
            )
            current_user = info.context.get("current_user")

            logger.info(
                "Scheduling audit report",
                user_id=str(current_user.id),
                schedule_name=input.name,
                frequency=input.frequency,
            )

            # Create schedule
            schedule = await reporting_service.schedule_report(
                name=input.name,
                description=input.description,
                report_config=input.report_config,
                frequency=input.frequency,
                recipients=input.recipients,
                created_by=current_user.id,
                enabled=input.enabled,
            )

            return {
                "id": str(schedule.id),
                "name": schedule.name,
                "frequency": schedule.frequency,
                "next_run": schedule.next_run.isoformat()
                if schedule.next_run
                else None,
                "enabled": schedule.enabled,
            }

        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Report scheduling failed: {e}", exc_info=True)
            raise ValidationError("Failed to schedule report")

    @strawberry.mutation(description="Run compliance check against audit data")
    @require_auth()
    @require_permission("audit.compliance.check")
    @rate_limit(requests=20, window=300)
    @audit_log("audit.compliance.check")
    async def run_compliance_check(
        self, info: strawberry.Info, input: ComplianceCheckInput
    ) -> ComplianceReportType:
        """
        Run compliance checks against audit data.

        Features:
        - Multiple compliance framework support
        - Automated violation detection
        - Risk assessment and scoring
        - Remediation recommendations

        Args:
            input: Compliance check parameters

        Returns:
            Compliance report with violations and recommendations
        """
        try:
            # Validate input
            validation_errors = input.validate()
            if validation_errors:
                raise ValidationError(
                    f"Invalid compliance check: {'; '.join(validation_errors)}"
                )

            # Get compliance service
            compliance_service: ComplianceService = info.context["container"].resolve(
                ComplianceService
            )
            current_user = info.context.get("current_user")

            logger.info(
                "Running compliance check",
                user_id=str(current_user.id),
                frameworks=input.frameworks,
                date_range=f"{input.date_range.start_date} to {input.date_range.end_date}",
            )

            # Execute compliance check
            compliance_report = await compliance_service.run_compliance_check(
                frameworks=input.frameworks,
                start_date=input.date_range.start_date,
                end_date=input.date_range.end_date,
                scope=input.scope,
                include_recommendations=input.include_recommendations,
                checked_by=current_user.id,
            )

            # Convert to GraphQL type
            return ReportMapper.compliance_report_to_graphql(compliance_report)

        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Compliance check failed: {e}", exc_info=True)
            raise ValidationError("Failed to run compliance check")

    @strawberry.mutation(description="Archive old audit logs based on retention policy")
    @require_auth()
    @require_permission("audit.administration.archive")
    @admin_only
    @rate_limit(requests=5, window=3600)  # 5 archives per hour
    @audit_log("audit.archive")
    @operation_timeout(300)  # 5 minute timeout
    async def archive_audit_logs(
        self,
        info: strawberry.Info,
        older_than_days: int,
        archive_location: str,
        compression: bool = True,
        verify_integrity: bool = True,
    ) -> dict[str, Any]:
        """
        Archive old audit logs based on retention policies.

        Features:
        - Configurable retention periods
        - Multiple storage backends (S3, local, etc.)
        - Data compression and encryption
        - Integrity verification
        - Progress tracking for large archives

        Args:
            older_than_days: Archive logs older than this many days
            archive_location: Storage location for archived data
            compression: Enable data compression
            verify_integrity: Verify archive integrity

        Returns:
            Archive operation status and statistics
        """
        try:
            # Validate parameters
            if older_than_days < 30:
                raise ValidationError("Cannot archive logs less than 30 days old")
            if older_than_days > 2555:  # ~7 years
                raise ValidationError("Retention period too long (max 7 years)")

            # Get archival service
            archival_service: ArchivalService = info.context["container"].resolve(
                ArchivalService
            )
            current_user = info.context.get("current_user")

            # Calculate cutoff date
            cutoff_date = datetime.utcnow() - timedelta(days=older_than_days)

            # Build command
            command = ArchiveAuditLogCommand(
                cutoff_date=cutoff_date,
                archive_location=archive_location,
                compression_enabled=compression,
                verify_integrity=verify_integrity,
                initiated_by=current_user.id,
            )

            logger.info(
                "Starting audit log archival",
                user_id=str(current_user.id),
                cutoff_date=cutoff_date.isoformat(),
                archive_location=archive_location,
            )

            # Execute archival (async operation)
            archive_task = await archival_service.archive_logs(command)

            return {
                "task_id": archive_task.task_id,
                "status": "initiated",
                "cutoff_date": cutoff_date.isoformat(),
                "estimated_records": archive_task.estimated_records,
                "archive_location": archive_location,
            }

        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Archive initiation failed: {e}", exc_info=True)
            raise ValidationError("Failed to initiate archive")

    @strawberry.mutation(description="Update audit retention policy")
    @require_auth()
    @require_permission("audit.administration.retention")
    @admin_only
    @rate_limit(requests=10, window=3600)
    @audit_log("audit.retention.update")
    async def update_retention_policy(
        self,
        info: strawberry.Info,
        policy_name: str,
        retention_days: int,
        archive_enabled: bool = True,
        compliance_frameworks: list[str] | None = None,
    ) -> dict[str, Any]:
        """
        Update audit data retention policies.

        Features:
        - Configurable retention periods per policy
        - Compliance framework requirements
        - Automated archival configuration
        - Policy validation and enforcement

        Args:
            policy_name: Name of the retention policy
            retention_days: Number of days to retain data
            archive_enabled: Enable automatic archival
            compliance_frameworks: Applicable compliance frameworks

        Returns:
            Updated retention policy configuration
        """
        try:
            # Validate parameters
            if retention_days < 1:
                raise ValidationError("Retention period must be positive")
            if retention_days < 90:
                logger.warning(f"Short retention period: {retention_days} days")

            # Get audit service
            audit_service: AuditService = info.context["container"].resolve(
                AuditService
            )
            current_user = info.context.get("current_user")

            # Build command
            command = UpdateRetentionPolicyCommand(
                policy_name=policy_name,
                retention_days=retention_days,
                archive_enabled=archive_enabled,
                compliance_frameworks=compliance_frameworks or [],
                updated_by=current_user.id,
            )

            logger.info(
                "Updating retention policy",
                user_id=str(current_user.id),
                policy_name=policy_name,
                retention_days=retention_days,
            )

            # Execute command
            policy = await audit_service.update_retention_policy(command)

            return {
                "policy_name": policy.name,
                "retention_days": policy.retention_days,
                "archive_enabled": policy.archive_enabled,
                "compliance_frameworks": policy.compliance_frameworks,
                "updated_at": policy.updated_at.isoformat(),
            }

        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Retention policy update failed: {e}", exc_info=True)
            raise ValidationError("Failed to update retention policy")

    @strawberry.mutation(description="Save audit search for reuse")
    @require_auth()
    @rate_limit(requests=20, window=300)
    @audit_log("audit.search.save")
    async def save_audit_search(
        self, info: strawberry.Info, input: SavedSearchInput
    ) -> dict[str, Any]:
        """
        Save audit search criteria for reuse and alerting.

        Features:
        - Named search configurations
        - Alert threshold monitoring
        - Shared searches across teams
        - Search result notifications

        Args:
            input: Saved search configuration

        Returns:
            Saved search configuration with ID
        """
        try:
            # Validate input
            validation_errors = input.validate()
            if validation_errors:
                raise ValidationError(
                    f"Invalid saved search: {'; '.join(validation_errors)}"
                )

            # Get audit service
            audit_service: AuditService = info.context["container"].resolve(
                AuditService
            )
            current_user = info.context.get("current_user")

            logger.info(
                "Saving audit search",
                user_id=str(current_user.id),
                search_name=input.name,
                alert_enabled=input.is_alert_enabled,
            )

            # Save search
            saved_search = await audit_service.save_search(
                name=input.name,
                description=input.description,
                criteria=input.search_criteria.to_criteria_dto(),
                is_alert_enabled=input.is_alert_enabled,
                alert_threshold=input.alert_threshold,
                created_by=current_user.id,
            )

            return {
                "id": str(saved_search.id),
                "name": saved_search.name,
                "description": saved_search.description,
                "is_alert_enabled": saved_search.is_alert_enabled,
                "alert_threshold": saved_search.alert_threshold,
                "created_at": saved_search.created_at.isoformat(),
            }

        except ValidationError:
            raise
        except Exception as e:
            logger.error(f"Search save failed: {e}", exc_info=True)
            raise ValidationError("Failed to save search")

    @strawberry.mutation(description="Delete saved audit search")
    @require_auth()
    @rate_limit(requests=30, window=300)
    @audit_log("audit.search.delete")
    async def delete_saved_search(
        self, info: strawberry.Info, search_id: strawberry.ID
    ) -> bool:
        """
        Delete a saved audit search.

        Args:
            search_id: ID of search to delete

        Returns:
            True if deletion successful
        """
        try:
            audit_service: AuditService = info.context["container"].resolve(
                AuditService
            )
            current_user = info.context.get("current_user")

            logger.info(
                "Deleting saved search",
                user_id=str(current_user.id),
                search_id=str(search_id),
            )

            return await audit_service.delete_saved_search(
                search_id=UUID(str(search_id)), user_id=current_user.id
            )

        except Exception as e:
            logger.error(f"Search deletion failed: {e}", exc_info=True)
            raise ValidationError("Failed to delete search")
