"""
Audit & Compliance Subscription Resolvers

Real-time subscriptions for audit logs, compliance violations,
GDPR requests, data exports, and data retention events.
"""

from collections.abc import AsyncGenerator
from uuid import UUID

import strawberry
from strawberry.types import Info

from ..middleware import require_authentication, require_mfa, require_permission
from .base_subscription import (
    BaseSubscriptionResolver,
    RateLimitConfig,
    SubscriptionFilter,
)


@strawberry.type
class AuditLogCreated:
    """Audit log creation event."""
    log_id: strawberry.ID
    user_id: strawberry.ID | None = None
    action: str
    resource_type: str
    resource_id: strawberry.ID | None = None
    details: str
    ip_address: str
    user_agent: str | None = None
    outcome: str  # success, failure, partial
    risk_level: str
    compliance_category: str | None = None
    retention_period: int  # days
    timestamp: str


@strawberry.type
class ComplianceViolation:
    """Compliance violation event."""
    violation_id: strawberry.ID
    user_id: strawberry.ID | None = None
    violation_type: str
    regulation: str  # GDPR, CCPA, HIPAA, SOX, etc.
    severity: str
    description: str
    affected_data_types: list[str]
    data_subjects_count: int
    auto_remediation_attempted: bool
    remediation_actions: list[str]
    requires_notification: bool
    notification_deadline: str | None = None
    timestamp: str


@strawberry.type
class GDPRRequestCreated:
    """GDPR request creation event."""
    request_id: strawberry.ID
    user_id: strawberry.ID
    request_type: str  # access, rectification, erasure, portability, restriction
    request_status: str
    requested_by: strawberry.ID  # may be different from user_id (legal guardian, etc.)
    legal_basis: str
    urgency_level: str
    estimated_completion: str
    data_categories: list[str]
    processing_activities: list[str]
    third_parties_involved: list[str]
    timestamp: str


@strawberry.type
class DataExportReady:
    """Data export completion event."""
    export_id: strawberry.ID
    user_id: strawberry.ID
    export_type: str  # gdpr_export, backup, migration, audit
    initiated_by: strawberry.ID
    file_format: str
    file_size_bytes: int
    includes_personal_data: bool
    encryption_used: bool
    download_expires_at: str
    access_restrictions: list[str]
    data_categories: list[str]
    timestamp: str


@strawberry.type
class DataRetentionEvent:
    """Data retention policy event."""
    event_id: strawberry.ID
    user_id: strawberry.ID | None = None
    event_type: str  # retention_policy_applied, data_archived, data_purged
    data_category: str
    retention_period: int  # days
    records_affected: int
    policy_name: str
    triggered_by: str  # automatic, manual, compliance_requirement
    compliance_regulation: str | None = None
    backup_created: bool
    irreversible: bool
    timestamp: str


class AuditComplianceSubscriptions(BaseSubscriptionResolver):
    """Subscription resolvers for audit and compliance events."""
    
    @strawberry.subscription
    @require_authentication
    @require_permission("audit:view")
    async def audit_log_created(
        self,
        info: Info,
        user_id: strawberry.ID | None = None,
        action: str | None = None
    ) -> AsyncGenerator[AuditLogCreated, None]:
        """Subscribe to audit log creation events."""
        security_context = await self._authenticate_connection(info)
        
        filters = SubscriptionFilter()
        if user_id:
            target_user_id = UUID(user_id)
            # Users can view their own audit logs with basic permission
            if (target_user_id != security_context.user_id and 
                not security_context.has_permission("audit:view_all")):
                self._authorize_subscription(
                    security_context,
                    "audit_logs_user",
                    ["audit:admin"]
                )
            filters.user_ids.add(target_user_id)
        else:
            # Viewing all audit logs requires admin permission
            self._authorize_subscription(
                security_context,
                "audit_logs",
                ["audit:admin"]
            )
        
        if action:
            filters.custom_filters["action"] = action
        
        filters.event_types.add("audit_log_created")
        
        context = self._create_connection_context(
            security_context,
            "audit_logs",
            filters,
            RateLimitConfig(max_events=150, window_seconds=60, burst_limit=40)
        )
        
        event_stream = self._listen_to_channel("audit")
        
        async for event in self._subscription_generator(context, event_stream):
            if event.get("event_type") == "audit_log_created":
                yield AuditLogCreated(
                    log_id=event["log_id"],
                    user_id=event.get("user_id"),
                    action=event["action"],
                    resource_type=event["resource_type"],
                    resource_id=event.get("resource_id"),
                    details=event["details"],
                    ip_address=event["ip_address"],
                    user_agent=event.get("user_agent"),
                    outcome=event["outcome"],
                    risk_level=event.get("risk_level", "low"),
                    compliance_category=event.get("compliance_category"),
                    retention_period=event.get("retention_period", 365),
                    timestamp=event["timestamp"]
                )
    
    @strawberry.subscription
    @require_authentication
    @require_permission("compliance:view")
    @require_mfa
    async def compliance_violation(
        self,
        info: Info,
        user_id: strawberry.ID | None = None,
        violation_type: str | None = None
    ) -> AsyncGenerator[ComplianceViolation, None]:
        """Subscribe to compliance violation events."""
        security_context = await self._authenticate_connection(info)
        
        # Compliance violations are highly sensitive
        self._authorize_subscription(
            security_context,
            "compliance_violations",
            ["compliance:admin", "security:admin"]
        )
        
        filters = SubscriptionFilter()
        if user_id:
            filters.user_ids.add(UUID(user_id))
        
        if violation_type:
            filters.custom_filters["violation_type"] = violation_type
        
        filters.event_types.add("compliance_violation")
        
        context = self._create_connection_context(
            security_context,
            "compliance_violations",
            filters,
            RateLimitConfig(max_events=25, window_seconds=60)
        )
        
        event_stream = self._listen_to_channel("compliance")
        
        async for event in self._subscription_generator(context, event_stream):
            if event.get("event_type") == "compliance_violation":
                yield ComplianceViolation(
                    violation_id=event["violation_id"],
                    user_id=event.get("user_id"),
                    violation_type=event["violation_type"],
                    regulation=event["regulation"],
                    severity=event["severity"],
                    description=event["description"],
                    affected_data_types=event.get("affected_data_types", []),
                    data_subjects_count=event.get("data_subjects_count", 0),
                    auto_remediation_attempted=event.get("auto_remediation_attempted", False),
                    remediation_actions=event.get("remediation_actions", []),
                    requires_notification=event.get("requires_notification", False),
                    notification_deadline=event.get("notification_deadline"),
                    timestamp=event["timestamp"]
                )
    
    @strawberry.subscription
    @require_authentication
    @require_permission("gdpr:view")
    async def gdpr_request_created(
        self,
        info: Info,
        user_id: strawberry.ID | None = None
    ) -> AsyncGenerator[GDPRRequestCreated, None]:
        """Subscribe to GDPR request creation events."""
        security_context = await self._authenticate_connection(info)
        
        filters = SubscriptionFilter()
        if user_id:
            target_user_id = UUID(user_id)
            # Users can view their own GDPR requests
            if (target_user_id != security_context.user_id and 
                not security_context.has_permission("gdpr:admin")):
                self._authorize_subscription(
                    security_context,
                    "gdpr_requests_user",
                    ["gdpr:admin", "privacy:admin"]
                )
            filters.user_ids.add(target_user_id)
        else:
            self._authorize_subscription(
                security_context,
                "gdpr_requests",
                ["gdpr:admin", "privacy:admin"]
            )
        
        filters.event_types.add("gdpr_request_created")
        
        context = self._create_connection_context(
            security_context,
            "gdpr_requests",
            filters,
            RateLimitConfig(max_events=20, window_seconds=60)
        )
        
        event_stream = self._listen_to_channel("privacy")
        
        async for event in self._subscription_generator(context, event_stream):
            if event.get("event_type") == "gdpr_request_created":
                yield GDPRRequestCreated(
                    request_id=event["request_id"],
                    user_id=event["user_id"],
                    request_type=event["request_type"],
                    request_status=event["request_status"],
                    requested_by=event["requested_by"],
                    legal_basis=event["legal_basis"],
                    urgency_level=event.get("urgency_level", "normal"),
                    estimated_completion=event["estimated_completion"],
                    data_categories=event.get("data_categories", []),
                    processing_activities=event.get("processing_activities", []),
                    third_parties_involved=event.get("third_parties_involved", []),
                    timestamp=event["timestamp"]
                )
    
    @strawberry.subscription
    @require_authentication
    async def data_export_ready(
        self,
        info: Info,
        user_id: strawberry.ID | None = None
    ) -> AsyncGenerator[DataExportReady, None]:
        """Subscribe to data export completion events."""
        security_context = await self._authenticate_connection(info)
        
        filters = SubscriptionFilter()
        if user_id:
            target_user_id = UUID(user_id)
            # Users can be notified of their own data exports
            if (target_user_id != security_context.user_id and 
                not security_context.has_permission("data:admin")):
                self._authorize_subscription(
                    security_context,
                    "data_exports_user",
                    ["data:admin", "privacy:admin"]
                )
            filters.user_ids.add(target_user_id)
        else:
            self._authorize_subscription(
                security_context,
                "data_exports",
                ["data:admin", "privacy:admin"]
            )
        
        filters.event_types.add("data_export_ready")
        
        context = self._create_connection_context(
            security_context,
            "data_exports",
            filters,
            RateLimitConfig(max_events=15, window_seconds=60)
        )
        
        event_stream = self._listen_to_channel("data")
        
        async for event in self._subscription_generator(context, event_stream):
            if event.get("event_type") == "data_export_ready":
                yield DataExportReady(
                    export_id=event["export_id"],
                    user_id=event["user_id"],
                    export_type=event["export_type"],
                    initiated_by=event["initiated_by"],
                    file_format=event["file_format"],
                    file_size_bytes=event["file_size_bytes"],
                    includes_personal_data=event.get("includes_personal_data", True),
                    encryption_used=event.get("encryption_used", True),
                    download_expires_at=event["download_expires_at"],
                    access_restrictions=event.get("access_restrictions", []),
                    data_categories=event.get("data_categories", []),
                    timestamp=event["timestamp"]
                )
    
    @strawberry.subscription
    @require_authentication
    @require_permission("data:view")
    async def data_retention_event(
        self,
        info: Info,
        user_id: strawberry.ID | None = None
    ) -> AsyncGenerator[DataRetentionEvent, None]:
        """Subscribe to data retention policy events."""
        security_context = await self._authenticate_connection(info)
        
        filters = SubscriptionFilter()
        if user_id:
            target_user_id = UUID(user_id)
            # Users can be notified of their own data retention events
            if (target_user_id != security_context.user_id and 
                not security_context.has_permission("data:admin")):
                self._authorize_subscription(
                    security_context,
                    "data_retention_user",
                    ["data:admin", "privacy:admin"]
                )
            filters.user_ids.add(target_user_id)
        else:
            self._authorize_subscription(
                security_context,
                "data_retention",
                ["data:admin", "privacy:admin"]
            )
        
        filters.event_types.add("data_retention_event")
        
        context = self._create_connection_context(
            security_context,
            "data_retention",
            filters,
            RateLimitConfig(max_events=30, window_seconds=60)
        )
        
        event_stream = self._listen_to_channel("data")
        
        async for event in self._subscription_generator(context, event_stream):
            if event.get("event_type") == "data_retention_event":
                yield DataRetentionEvent(
                    event_id=event["event_id"],
                    user_id=event.get("user_id"),
                    event_type=event["retention_event_type"],
                    data_category=event["data_category"],
                    retention_period=event["retention_period"],
                    records_affected=event["records_affected"],
                    policy_name=event["policy_name"],
                    triggered_by=event["triggered_by"],
                    compliance_regulation=event.get("compliance_regulation"),
                    backup_created=event.get("backup_created", False),
                    irreversible=event.get("irreversible", False),
                    timestamp=event["timestamp"]
                )