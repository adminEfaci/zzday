"""
Administrative Subscription Resolvers

Real-time subscriptions for administrative events like user creation/deletion,
bulk operations, system maintenance, and configuration changes.
"""

from collections.abc import AsyncGenerator

import strawberry
from strawberry.types import Info

from ..middleware import (
    require_authentication,
    require_mfa,
    require_permission,
    require_role,
)
from .base_subscription import (
    BaseSubscriptionResolver,
    RateLimitConfig,
    SubscriptionFilter,
)


@strawberry.type
class UserCreated:
    """User creation event."""
    user_id: strawberry.ID
    username: str
    email: str
    created_by: strawberry.ID
    creation_method: str  # manual, bulk_import, self_registration, api
    initial_roles: list[str]
    verification_required: bool
    welcome_email_sent: bool
    ip_address: str
    user_agent: str
    timestamp: str


@strawberry.type
class UserDeleted:
    """User deletion event."""
    user_id: strawberry.ID
    username: str
    email: str
    deleted_by: strawberry.ID
    deletion_reason: str
    deletion_type: str  # soft_delete, hard_delete, anonymize
    data_retention_days: int | None = None
    backup_created: bool
    related_data_handling: str
    ip_address: str
    user_agent: str
    timestamp: str


@strawberry.type
class UserSuspended:
    """User suspension event."""
    user_id: strawberry.ID
    suspended_by: strawberry.ID
    suspension_reason: str
    suspension_duration: int | None = None  # days
    automatic_reactivation: bool
    access_level_during_suspension: str
    notification_sent: bool
    appeal_process_available: bool
    timestamp: str


@strawberry.type
class UserReactivated:
    """User reactivation event."""
    user_id: strawberry.ID
    reactivated_by: strawberry.ID
    reactivation_reason: str
    previous_suspension_duration: int  # days
    password_reset_required: bool
    mfa_verification_required: bool
    notification_sent: bool
    timestamp: str


@strawberry.type
class BulkOperationProgress:
    """Bulk operation progress update."""
    operation_id: strawberry.ID
    operation_type: str  # bulk_import, bulk_update, bulk_delete, bulk_export
    initiated_by: strawberry.ID
    total_records: int
    processed_records: int
    successful_records: int
    failed_records: int
    progress_percentage: float
    estimated_completion: str | None = None
    current_phase: str
    errors: list[str]
    warnings: list[str]
    timestamp: str


@strawberry.type
class SystemMaintenanceStatus:
    """System maintenance status update."""
    maintenance_id: strawberry.ID
    maintenance_type: str  # scheduled, emergency, security_patch
    status: str  # planned, starting, in_progress, completed, failed
    affected_services: list[str]
    start_time: str
    estimated_end_time: str | None = None
    actual_end_time: str | None = None
    impact_level: str  # low, medium, high, critical
    user_message: str
    downtime_duration: int | None = None  # seconds
    rollback_available: bool
    timestamp: str


@strawberry.type
class ConfigurationChanged:
    """Configuration change event."""
    change_id: strawberry.ID
    config_section: str
    config_key: str
    old_value: str | None = None
    new_value: str
    changed_by: strawberry.ID
    change_reason: str
    validation_status: str  # valid, invalid, warning
    requires_restart: bool
    security_impact: str  # none, low, medium, high
    rollback_available: bool
    applied_to_environments: list[str]
    timestamp: str


class AdministrativeSubscriptions(BaseSubscriptionResolver):
    """Subscription resolvers for administrative events."""
    
    @strawberry.subscription
    @require_authentication
    @require_permission("user:admin")
    async def user_created(
        self,
        info: Info
    ) -> AsyncGenerator[UserCreated, None]:
        """Subscribe to user creation events."""
        security_context = await self._authenticate_connection(info)
        
        filters = SubscriptionFilter()
        filters.event_types.add("user_created")
        
        context = self._create_connection_context(
            security_context,
            "user_created",
            filters,
            RateLimitConfig(max_events=30, window_seconds=60)
        )
        
        event_stream = self._listen_to_channel("admin")
        
        async for event in self._subscription_generator(context, event_stream):
            if event.get("event_type") == "user_created":
                yield UserCreated(
                    user_id=event["user_id"],
                    username=event["username"],
                    email=event["email"],
                    created_by=event["created_by"],
                    creation_method=event["creation_method"],
                    initial_roles=event.get("initial_roles", []),
                    verification_required=event.get("verification_required", True),
                    welcome_email_sent=event.get("welcome_email_sent", False),
                    ip_address=event["ip_address"],
                    user_agent=event["user_agent"],
                    timestamp=event["timestamp"]
                )
    
    @strawberry.subscription
    @require_authentication
    @require_permission("user:admin")
    @require_mfa
    async def user_deleted(
        self,
        info: Info
    ) -> AsyncGenerator[UserDeleted, None]:
        """Subscribe to user deletion events."""
        security_context = await self._authenticate_connection(info)
        
        filters = SubscriptionFilter()
        filters.event_types.add("user_deleted")
        
        context = self._create_connection_context(
            security_context,
            "user_deleted",
            filters,
            RateLimitConfig(max_events=15, window_seconds=60)
        )
        
        event_stream = self._listen_to_channel("admin")
        
        async for event in self._subscription_generator(context, event_stream):
            if event.get("event_type") == "user_deleted":
                yield UserDeleted(
                    user_id=event["user_id"],
                    username=event["username"],
                    email=event["email"],
                    deleted_by=event["deleted_by"],
                    deletion_reason=event["deletion_reason"],
                    deletion_type=event["deletion_type"],
                    data_retention_days=event.get("data_retention_days"),
                    backup_created=event.get("backup_created", False),
                    related_data_handling=event.get("related_data_handling", "preserve"),
                    ip_address=event["ip_address"],
                    user_agent=event["user_agent"],
                    timestamp=event["timestamp"]
                )
    
    @strawberry.subscription
    @require_authentication
    @require_permission("user:admin")
    async def user_suspended(
        self,
        info: Info
    ) -> AsyncGenerator[UserSuspended, None]:
        """Subscribe to user suspension events."""
        security_context = await self._authenticate_connection(info)
        
        filters = SubscriptionFilter()
        filters.event_types.add("user_suspended")
        
        context = self._create_connection_context(
            security_context,
            "user_suspended",
            filters,
            RateLimitConfig(max_events=20, window_seconds=60)
        )
        
        event_stream = self._listen_to_channel("admin")
        
        async for event in self._subscription_generator(context, event_stream):
            if event.get("event_type") == "user_suspended":
                yield UserSuspended(
                    user_id=event["user_id"],
                    suspended_by=event["suspended_by"],
                    suspension_reason=event["suspension_reason"],
                    suspension_duration=event.get("suspension_duration"),
                    automatic_reactivation=event.get("automatic_reactivation", False),
                    access_level_during_suspension=event.get("access_level_during_suspension", "none"),
                    notification_sent=event.get("notification_sent", True),
                    appeal_process_available=event.get("appeal_process_available", True),
                    timestamp=event["timestamp"]
                )
    
    @strawberry.subscription
    @require_authentication
    @require_permission("user:admin")
    async def user_reactivated(
        self,
        info: Info
    ) -> AsyncGenerator[UserReactivated, None]:
        """Subscribe to user reactivation events."""
        security_context = await self._authenticate_connection(info)
        
        filters = SubscriptionFilter()
        filters.event_types.add("user_reactivated")
        
        context = self._create_connection_context(
            security_context,
            "user_reactivated",
            filters,
            RateLimitConfig(max_events=20, window_seconds=60)
        )
        
        event_stream = self._listen_to_channel("admin")
        
        async for event in self._subscription_generator(context, event_stream):
            if event.get("event_type") == "user_reactivated":
                yield UserReactivated(
                    user_id=event["user_id"],
                    reactivated_by=event["reactivated_by"],
                    reactivation_reason=event["reactivation_reason"],
                    previous_suspension_duration=event["previous_suspension_duration"],
                    password_reset_required=event.get("password_reset_required", False),
                    mfa_verification_required=event.get("mfa_verification_required", False),
                    notification_sent=event.get("notification_sent", True),
                    timestamp=event["timestamp"]
                )
    
    @strawberry.subscription
    @require_authentication
    @require_permission("admin:operations")
    async def bulk_operation_progress(
        self,
        info: Info,
        operation_id: strawberry.ID
    ) -> AsyncGenerator[BulkOperationProgress, None]:
        """Subscribe to bulk operation progress updates."""
        security_context = await self._authenticate_connection(info)
        
        filters = SubscriptionFilter()
        filters.event_types.add("bulk_operation_progress")
        filters.custom_filters["operation_id"] = operation_id
        
        context = self._create_connection_context(
            security_context,
            "bulk_operations",
            filters,
            RateLimitConfig(max_events=100, window_seconds=60, burst_limit=30)
        )
        
        event_stream = self._listen_to_channel("admin")
        
        async for event in self._subscription_generator(context, event_stream):
            if (event.get("event_type") == "bulk_operation_progress" and 
                event.get("operation_id") == operation_id):
                yield BulkOperationProgress(
                    operation_id=event["operation_id"],
                    operation_type=event["operation_type"],
                    initiated_by=event["initiated_by"],
                    total_records=event["total_records"],
                    processed_records=event["processed_records"],
                    successful_records=event["successful_records"],
                    failed_records=event["failed_records"],
                    progress_percentage=event["progress_percentage"],
                    estimated_completion=event.get("estimated_completion"),
                    current_phase=event["current_phase"],
                    errors=event.get("errors", []),
                    warnings=event.get("warnings", []),
                    timestamp=event["timestamp"]
                )
    
    @strawberry.subscription
    @require_authentication
    async def system_maintenance_status(
        self,
        info: Info
    ) -> AsyncGenerator[SystemMaintenanceStatus, None]:
        """Subscribe to system maintenance status updates."""
        security_context = await self._authenticate_connection(info)
        
        # All authenticated users can subscribe to maintenance updates
        filters = SubscriptionFilter()
        filters.event_types.add("system_maintenance_status")
        
        context = self._create_connection_context(
            security_context,
            "system_maintenance",
            filters,
            RateLimitConfig(max_events=50, window_seconds=60)
        )
        
        event_stream = self._listen_to_channel("system")
        
        async for event in self._subscription_generator(context, event_stream):
            if event.get("event_type") == "system_maintenance_status":
                yield SystemMaintenanceStatus(
                    maintenance_id=event["maintenance_id"],
                    maintenance_type=event["maintenance_type"],
                    status=event["status"],
                    affected_services=event["affected_services"],
                    start_time=event["start_time"],
                    estimated_end_time=event.get("estimated_end_time"),
                    actual_end_time=event.get("actual_end_time"),
                    impact_level=event["impact_level"],
                    user_message=event["user_message"],
                    downtime_duration=event.get("downtime_duration"),
                    rollback_available=event.get("rollback_available", False),
                    timestamp=event["timestamp"]
                )
    
    @strawberry.subscription
    @require_authentication
    @require_role("admin")
    @require_mfa
    async def configuration_changed(
        self,
        info: Info
    ) -> AsyncGenerator[ConfigurationChanged, None]:
        """Subscribe to configuration change events."""
        security_context = await self._authenticate_connection(info)
        
        filters = SubscriptionFilter()
        filters.event_types.add("configuration_changed")
        
        context = self._create_connection_context(
            security_context,
            "configuration_changes",
            filters,
            RateLimitConfig(max_events=25, window_seconds=60)
        )
        
        event_stream = self._listen_to_channel("admin")
        
        async for event in self._subscription_generator(context, event_stream):
            if event.get("event_type") == "configuration_changed":
                yield ConfigurationChanged(
                    change_id=event["change_id"],
                    config_section=event["config_section"],
                    config_key=event["config_key"],
                    old_value=event.get("old_value"),
                    new_value=event["new_value"],
                    changed_by=event["changed_by"],
                    change_reason=event["change_reason"],
                    validation_status=event.get("validation_status", "valid"),
                    requires_restart=event.get("requires_restart", False),
                    security_impact=event.get("security_impact", "none"),
                    rollback_available=event.get("rollback_available", True),
                    applied_to_environments=event.get("applied_to_environments", []),
                    timestamp=event["timestamp"]
                )