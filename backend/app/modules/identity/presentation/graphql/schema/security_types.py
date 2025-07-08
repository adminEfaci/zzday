"""
Security GraphQL Type Definitions for Identity Module

This module contains all GraphQL types related to security, including
security events, audit logs, notifications, blacklists, and related input types.
"""


import graphene

from .common_types import (
    AuditMetadataType,
    DateRangeInput,
    FilterInput,
    GeolocationResponse,
    MetadataType,
)
from .enums import (
    AuditActionEnum,
    ComplianceStatusEnum,
    DeviceTypeEnum,
    NotificationChannelEnum,
    NotificationTypeEnum,
    RiskLevelEnum,
    SecurityEventTypeEnum,
)


class SecurityEventType(graphene.ObjectType):
    """Security event information."""
    
    class Meta:
        description = "Security event detected by the system"
    
    id = graphene.ID(
        required=True,
        description="Unique identifier for the security event"
    )
    
    event_type = graphene.Field(
        SecurityEventTypeEnum,
        required=True,
        description="Type of security event"
    )
    
    severity = graphene.Field(
        RiskLevelEnum,
        required=True,
        description="Severity level of the security event"
    )
    
    title = graphene.String(
        required=True,
        description="Brief title describing the event"
    )
    
    description = graphene.String(
        description="Detailed description of the security event"
    )
    
    user_id = graphene.ID(
        description="ID of the user involved in the event (if applicable)"
    )
    
    session_id = graphene.ID(
        description="ID of the session involved in the event (if applicable)"
    )
    
    ip_address = graphene.String(
        description="IP address where the event originated"
    )
    
    user_agent = graphene.String(
        description="User agent string of the client"
    )
    
    location = graphene.Field(
        GeolocationResponse,
        description="Geographic location of the event"
    )
    
    device_fingerprint = graphene.String(
        description="Device fingerprint involved in the event"
    )
    
    device_type = graphene.Field(
        DeviceTypeEnum,
        description="Type of device involved"
    )
    
    source_system = graphene.String(
        description="System component that detected the event"
    )
    
    event_data = graphene.JSONString(
        description="Additional event-specific data as JSON"
    )
    
    indicators = graphene.List(
        graphene.String,
        description="List of security indicators related to this event"
    )
    
    threat_score = graphene.Float(
        description="Calculated threat score for this event (0.0 - 1.0)"
    )
    
    is_false_positive = graphene.Boolean(
        default_value=False,
        description="Whether this event has been marked as a false positive"
    )
    
    is_resolved = graphene.Boolean(
        default_value=False,
        description="Whether this security event has been resolved"
    )
    
    resolved_by = graphene.ID(
        description="ID of user who resolved the event"
    )
    
    resolved_at = graphene.DateTime(
        description="When the event was resolved"
    )
    
    resolution_notes = graphene.String(
        description="Notes about the resolution of this event"
    )
    
    related_events = graphene.List(
        "SecurityEventType",
        description="Related security events"
    )
    
    occurred_at = graphene.DateTime(
        required=True,
        description="When the security event occurred"
    )
    
    detected_at = graphene.DateTime(
        required=True,
        description="When the security event was detected"
    )
    
    metadata = graphene.Field(
        AuditMetadataType,
        required=True,
        description="Creation, modification, and audit metadata"
    )


class AuditLogType(graphene.ObjectType):
    """Audit log entry information."""
    
    class Meta:
        description = "Audit log entry for tracking system activities"
    
    id = graphene.ID(
        required=True,
        description="Unique identifier for the audit log entry"
    )
    
    action = graphene.Field(
        AuditActionEnum,
        required=True,
        description="Action that was performed"
    )
    
    resource_type = graphene.String(
        description="Type of resource that was acted upon"
    )
    
    resource_id = graphene.String(
        description="ID of the resource that was acted upon"
    )
    
    resource_name = graphene.String(
        description="Name or identifier of the resource"
    )
    
    actor_id = graphene.ID(
        description="ID of the user who performed the action"
    )
    
    actor_type = graphene.String(
        description="Type of actor (user, system, service, etc.)"
    )
    
    actor_name = graphene.String(
        description="Name or identifier of the actor"
    )
    
    target_id = graphene.ID(
        description="ID of the target user/resource (if different from resource)"
    )
    
    target_name = graphene.String(
        description="Name of the target user/resource"
    )
    
    session_id = graphene.ID(
        description="ID of the session during which the action occurred"
    )
    
    ip_address = graphene.String(
        description="IP address from which the action was performed"
    )
    
    user_agent = graphene.String(
        description="User agent string of the client"
    )
    
    location = graphene.Field(
        GeolocationResponse,
        description="Geographic location of the action"
    )
    
    success = graphene.Boolean(
        required=True,
        description="Whether the action was successful"
    )
    
    error_message = graphene.String(
        description="Error message if the action failed"
    )
    
    changes = graphene.JSONString(
        description="JSON representation of changes made (before/after)"
    )
    
    additional_data = graphene.JSONString(
        description="Additional context data as JSON"
    )
    
    risk_level = graphene.Field(
        RiskLevelEnum,
        description="Risk level assessed for this action"
    )
    
    compliance_flags = graphene.List(
        graphene.String,
        description="Compliance-related flags for this action"
    )
    
    retention_until = graphene.DateTime(
        description="When this audit log entry should be purged"
    )
    
    occurred_at = graphene.DateTime(
        required=True,
        description="When the audited action occurred"
    )


class NotificationType(graphene.ObjectType):
    """Notification information."""
    
    class Meta:
        description = "Notification sent to users"
    
    id = graphene.ID(
        required=True,
        description="Unique identifier for the notification"
    )
    
    recipient_id = graphene.ID(
        required=True,
        description="ID of the user who should receive the notification"
    )
    
    notification_type = graphene.Field(
        NotificationTypeEnum,
        required=True,
        description="Type of notification"
    )
    
    channel = graphene.Field(
        NotificationChannelEnum,
        required=True,
        description="Channel through which the notification was sent"
    )
    
    title = graphene.String(
        required=True,
        description="Title/subject of the notification"
    )
    
    message = graphene.String(
        required=True,
        description="Content of the notification"
    )
    
    priority = graphene.Field(
        RiskLevelEnum,
        default_value=RiskLevelEnum.LOW,
        description="Priority level of the notification"
    )
    
    is_read = graphene.Boolean(
        default_value=False,
        description="Whether the notification has been read"
    )
    
    read_at = graphene.DateTime(
        description="When the notification was read"
    )
    
    is_sent = graphene.Boolean(
        default_value=False,
        description="Whether the notification has been sent"
    )
    
    sent_at = graphene.DateTime(
        description="When the notification was sent"
    )
    
    delivery_attempts = graphene.Int(
        default_value=0,
        description="Number of delivery attempts"
    )
    
    last_delivery_attempt = graphene.DateTime(
        description="When the last delivery attempt was made"
    )
    
    delivery_error = graphene.String(
        description="Error message from last failed delivery attempt"
    )
    
    action_url = graphene.String(
        description="URL for action related to this notification"
    )
    
    action_label = graphene.String(
        description="Label for the action button/link"
    )
    
    expires_at = graphene.DateTime(
        description="When this notification expires"
    )
    
    related_entity_type = graphene.String(
        description="Type of entity this notification relates to"
    )
    
    related_entity_id = graphene.ID(
        description="ID of the entity this notification relates to"
    )
    
    template_data = graphene.JSONString(
        description="Template data for generating the notification content"
    )
    
    metadata = graphene.Field(
        MetadataType,
        required=True,
        description="Creation and modification metadata"
    )


class BlacklistType(graphene.ObjectType):
    """Blacklist entry information."""
    
    class Meta:
        description = "Blacklisted item (IP, email, device, etc.)"
    
    id = graphene.ID(
        required=True,
        description="Unique identifier for the blacklist entry"
    )
    
    entry_type = graphene.String(
        required=True,
        description="Type of blacklisted item (ip, email, device_fingerprint, etc.)"
    )
    
    value = graphene.String(
        required=True,
        description="The blacklisted value"
    )
    
    pattern = graphene.String(
        description="Pattern for matching (if using wildcards or regex)"
    )
    
    reason = graphene.String(
        required=True,
        description="Reason for blacklisting"
    )
    
    severity = graphene.Field(
        RiskLevelEnum,
        required=True,
        description="Severity level of the blacklisted item"
    )
    
    added_by = graphene.ID(
        description="ID of user who added this entry to the blacklist"
    )
    
    added_at = graphene.DateTime(
        required=True,
        description="When the entry was added to the blacklist"
    )
    
    expires_at = graphene.DateTime(
        description="When this blacklist entry expires"
    )
    
    is_active = graphene.Boolean(
        default_value=True,
        description="Whether this blacklist entry is currently active"
    )
    
    is_permanent = graphene.Boolean(
        default_value=False,
        description="Whether this is a permanent blacklist entry"
    )
    
    hit_count = graphene.Int(
        default_value=0,
        description="Number of times this blacklist entry has been matched"
    )
    
    last_hit = graphene.DateTime(
        description="When this blacklist entry was last matched"
    )
    
    source = graphene.String(
        description=(
            "Source of the blacklist entry (manual, automated, threat_intel, etc.)"
        )
    )
    
    threat_intelligence_id = graphene.String(
        description="ID from threat intelligence source (if applicable)"
    )
    
    additional_data = graphene.JSONString(
        description="Additional data about the blacklisted item"
    )
    
    whitelist_exceptions = graphene.List(
        graphene.String,
        description="Exceptions to this blacklist entry"
    )
    
    metadata = graphene.Field(
        AuditMetadataType,
        required=True,
        description="Creation, modification, and audit metadata"
    )


class ComplianceReportType(graphene.ObjectType):
    """Compliance report information."""
    
    class Meta:
        description = "Compliance assessment report"
    
    id = graphene.ID(
        required=True,
        description="Unique identifier for the compliance report"
    )
    
    report_type = graphene.String(
        required=True,
        description="Type of compliance report"
    )
    
    status = graphene.Field(
        ComplianceStatusEnum,
        required=True,
        description="Overall compliance status"
    )
    
    scope = graphene.String(
        description="Scope of the compliance assessment"
    )
    
    assessment_date = graphene.DateTime(
        required=True,
        description="When the compliance assessment was performed"
    )
    
    assessor_id = graphene.ID(
        description="ID of user who performed the assessment"
    )
    
    findings = graphene.List(
        graphene.String,
        description="List of compliance findings"
    )
    
    violations = graphene.List(
        graphene.String,
        description="List of compliance violations"
    )
    
    recommendations = graphene.List(
        graphene.String,
        description="List of recommendations for compliance"
    )
    
    compliance_score = graphene.Float(
        description="Numerical compliance score (0.0 - 1.0)"
    )
    
    risk_level = graphene.Field(
        RiskLevelEnum,
        description="Overall risk level based on compliance status"
    )
    
    next_assessment_due = graphene.DateTime(
        description="When the next assessment is due"
    )
    
    remediation_deadline = graphene.DateTime(
        description="Deadline for remediation of violations"
    )
    
    report_data = graphene.JSONString(
        description="Detailed report data as JSON"
    )
    
    metadata = graphene.Field(
        MetadataType,
        required=True,
        description="Creation and modification metadata"
    )


# Input Types for Security Operations

class SecurityEventCreateInput(graphene.InputObjectType):
    """Input type for creating a security event."""
    
    class Meta:
        description = "Input for creating a new security event"
    
    event_type = graphene.Field(
        SecurityEventTypeEnum,
        required=True,
        description="Type of security event"
    )
    
    severity = graphene.Field(
        RiskLevelEnum,
        required=True,
        description="Severity level of the event"
    )
    
    title = graphene.String(
        required=True,
        description="Brief title describing the event"
    )
    
    description = graphene.String(
        description="Detailed description of the event"
    )
    
    user_id = graphene.ID(
        description="ID of the user involved"
    )
    
    session_id = graphene.ID(
        description="ID of the session involved"
    )
    
    ip_address = graphene.String(
        description="IP address where the event originated"
    )
    
    user_agent = graphene.String(
        description="User agent string"
    )
    
    device_fingerprint = graphene.String(
        description="Device fingerprint"
    )
    
    event_data = graphene.JSONString(
        description="Additional event data as JSON"
    )
    
    indicators = graphene.List(
        graphene.String,
        description="List of security indicators"
    )
    
    threat_score = graphene.Float(
        description="Calculated threat score (0.0 - 1.0)"
    )


class SecurityEventUpdateInput(graphene.InputObjectType):
    """Input type for updating a security event."""
    
    class Meta:
        description = "Input for updating a security event"
    
    is_false_positive = graphene.Boolean(
        description="Mark as false positive"
    )
    
    is_resolved = graphene.Boolean(
        description="Mark as resolved"
    )
    
    resolution_notes = graphene.String(
        description="Notes about the resolution"
    )


class NotificationCreateInput(graphene.InputObjectType):
    """Input type for creating a notification."""
    
    class Meta:
        description = "Input for creating a new notification"
    
    recipient_id = graphene.ID(
        required=True,
        description="ID of the recipient user"
    )
    
    notification_type = graphene.Field(
        NotificationTypeEnum,
        required=True,
        description="Type of notification"
    )
    
    channel = graphene.Field(
        NotificationChannelEnum,
        required=True,
        description="Delivery channel"
    )
    
    title = graphene.String(
        required=True,
        description="Notification title"
    )
    
    message = graphene.String(
        required=True,
        description="Notification message"
    )
    
    priority = graphene.Field(
        RiskLevelEnum,
        default_value=RiskLevelEnum.LOW,
        description="Priority level"
    )
    
    action_url = graphene.String(
        description="URL for related action"
    )
    
    action_label = graphene.String(
        description="Label for action button"
    )
    
    expires_at = graphene.DateTime(
        description="When the notification expires"
    )
    
    template_data = graphene.JSONString(
        description="Template data for content generation"
    )


class BlacklistCreateInput(graphene.InputObjectType):
    """Input type for creating a blacklist entry."""
    
    class Meta:
        description = "Input for creating a new blacklist entry"
    
    entry_type = graphene.String(
        required=True,
        description="Type of item to blacklist"
    )
    
    value = graphene.String(
        required=True,
        description="Value to blacklist"
    )
    
    pattern = graphene.String(
        description="Pattern for matching"
    )
    
    reason = graphene.String(
        required=True,
        description="Reason for blacklisting"
    )
    
    severity = graphene.Field(
        RiskLevelEnum,
        required=True,
        description="Severity level"
    )
    
    expires_at = graphene.DateTime(
        description="When the entry expires"
    )
    
    is_permanent = graphene.Boolean(
        default_value=False,
        description="Whether this is permanent"
    )
    
    additional_data = graphene.JSONString(
        description="Additional data"
    )


# Filter Input Types

class SecurityEventFilterInput(FilterInput):
    """Input type for filtering security events."""
    
    class Meta:
        description = "Filters for querying security events"
    
    event_type = graphene.List(
        SecurityEventTypeEnum,
        description="Filter by event type"
    )
    
    severity = graphene.List(
        RiskLevelEnum,
        description="Filter by severity level"
    )
    
    user_id = graphene.ID(
        description="Filter by user ID"
    )
    
    ip_address = graphene.String(
        description="Filter by IP address"
    )
    
    is_resolved = graphene.Boolean(
        description="Filter by resolution status"
    )
    
    is_false_positive = graphene.Boolean(
        description="Filter by false positive status"
    )
    
    occurred_at = graphene.Field(
        DateRangeInput,
        description="Filter by occurrence date range"
    )
    
    threat_score_min = graphene.Float(
        description="Minimum threat score"
    )
    
    threat_score_max = graphene.Float(
        description="Maximum threat score"
    )


class AuditLogFilterInput(FilterInput):
    """Input type for filtering audit logs."""
    
    class Meta:
        description = "Filters for querying audit logs"
    
    action = graphene.List(
        AuditActionEnum,
        description="Filter by action type"
    )
    
    actor_id = graphene.ID(
        description="Filter by actor ID"
    )
    
    resource_type = graphene.String(
        description="Filter by resource type"
    )
    
    resource_id = graphene.String(
        description="Filter by resource ID"
    )
    
    success = graphene.Boolean(
        description="Filter by success status"
    )
    
    ip_address = graphene.String(
        description="Filter by IP address"
    )
    
    occurred_at = graphene.Field(
        DateRangeInput,
        description="Filter by occurrence date range"
    )


class NotificationFilterInput(FilterInput):
    """Input type for filtering notifications."""
    
    class Meta:
        description = "Filters for querying notifications"
    
    recipient_id = graphene.ID(
        description="Filter by recipient ID"
    )
    
    notification_type = graphene.List(
        NotificationTypeEnum,
        description="Filter by notification type"
    )
    
    channel = graphene.List(
        NotificationChannelEnum,
        description="Filter by delivery channel"
    )
    
    is_read = graphene.Boolean(
        description="Filter by read status"
    )
    
    is_sent = graphene.Boolean(
        description="Filter by sent status"
    )
    
    priority = graphene.List(
        RiskLevelEnum,
        description="Filter by priority level"
    )


# Export all types
__all__ = [
    "AuditLogFilterInput",
    "AuditLogType",
    "BlacklistCreateInput",
    "BlacklistType",
    "ComplianceReportType",
    "NotificationCreateInput",
    "NotificationFilterInput",
    "NotificationType",
    "SecurityEventCreateInput",
    "SecurityEventFilterInput",
    "SecurityEventType",
    "SecurityEventUpdateInput",
]