"""User role changed event handler.

This module handles UserRoleChangedEvent to create audit trails
for role modifications and access control compliance.
"""

from typing import Any

from ddd_implementation.shared_contracts import UserRoleChangedEvent

from app.core.logging import get_logger
from app.modules.audit.application.services.audit_service import AuditService

logger = get_logger(__name__)


class UserRoleChangedEventHandler:
    """
    Event handler for user role change events.

    Creates audit trails when user roles are modified,
    supporting access control compliance and security monitoring.
    """

    def __init__(self, audit_service: AuditService):
        """
        Initialize handler.

        Args:
            audit_service: Audit service for creating audit trails
        """
        self.audit_service = audit_service

    async def handle(self, event: UserRoleChangedEvent) -> None:
        """
        Handle user role changed event.

        Args:
            event: UserRoleChangedEvent instance
        """
        logger.info(
            "Handling user role changed event",
            user_id=event.user_id,
            old_roles=event.old_roles,
            new_roles=event.new_roles,
            changed_by=event.changed_by,
            event_id=event.metadata.event_id,
        )

        try:
            # Determine the type of role change
            role_change_type = self._determine_role_change_type(
                event.old_roles, event.new_roles
            )

            # Create audit trail for role change
            await self.audit_service.create_audit_trail(
                user_id=event.changed_by,  # User who made the change
                action_type="user_role_change",
                operation="update",
                description=f"User roles changed from {event.old_roles} to {event.new_roles}. Reason: {event.reason or 'Not specified'}",
                resource_type="user_roles",
                resource_id=str(event.user_id),
                resource_name=f"Roles for user {event.user_id}",
                context={
                    "event_id": str(event.metadata.event_id),
                    "correlation_id": str(event.metadata.correlation_id)
                    if event.metadata.correlation_id
                    else None,
                    "target_user_id": str(event.user_id),
                    "changed_by": str(event.changed_by),
                    "reason": event.reason,
                },
                outcome="success",
                severity=self._calculate_severity(
                    role_change_type, event.old_roles, event.new_roles
                ),
                category="access_control",
                correlation_id=str(event.metadata.correlation_id)
                if event.metadata.correlation_id
                else None,
                tags=["role_management", "access_control", "privilege_change"],
                custom_fields={
                    "old_roles": event.old_roles,
                    "new_roles": event.new_roles,
                    "changed_by": str(event.changed_by),
                    "target_user": str(event.user_id),
                    "change_type": role_change_type,
                    "reason": event.reason,
                    "roles_added": list(set(event.new_roles) - set(event.old_roles)),
                    "roles_removed": list(set(event.old_roles) - set(event.new_roles)),
                },
                compliance_tags=[
                    "access_control",
                    "privilege_management",
                    "role_based_access",
                ],
            )

            # Create privilege escalation audit trail if applicable
            if role_change_type in ["privilege_escalation", "admin_granted"]:
                await self._create_privilege_escalation_audit_trail(
                    event, role_change_type
                )

            # Create privilege reduction audit trail if applicable
            if role_change_type in ["privilege_reduction", "admin_revoked"]:
                await self._create_privilege_reduction_audit_trail(
                    event, role_change_type
                )

            # Create compliance audit trail for sensitive role changes
            await self._create_compliance_audit_trail(event, role_change_type)

            logger.info(
                "User role change audit trail created successfully",
                user_id=event.user_id,
                change_type=role_change_type,
            )

        except Exception as e:
            logger.exception(
                "Failed to create audit trail for user role change",
                user_id=event.user_id,
                changed_by=event.changed_by,
                error=str(e),
            )
            # Don't re-raise to avoid disrupting the role change process

    def _determine_role_change_type(
        self, old_roles: list[str], new_roles: list[str]
    ) -> str:
        """
        Determine the type of role change.

        Args:
            old_roles: Previous roles
            new_roles: New roles

        Returns:
            Type of role change
        """
        old_set = set(old_roles)
        new_set = set(new_roles)

        # Check for administrative role changes
        admin_roles = {"admin", "administrator", "super_admin", "system_admin"}
        old_admin = old_set.intersection(admin_roles)
        new_admin = new_set.intersection(admin_roles)

        if new_admin and not old_admin:
            return "admin_granted"
        if old_admin and not new_admin:
            return "admin_revoked"

        # Check for privilege level changes
        privilege_levels = {
            "super_admin": 5,
            "admin": 4,
            "manager": 3,
            "user": 2,
            "guest": 1,
        }

        old_max_privilege = max(
            (privilege_levels.get(role, 0) for role in old_roles), default=0
        )
        new_max_privilege = max(
            (privilege_levels.get(role, 0) for role in new_roles), default=0
        )

        if new_max_privilege > old_max_privilege:
            return "privilege_escalation"
        if new_max_privilege < old_max_privilege:
            return "privilege_reduction"
        if len(new_set) > len(old_set):
            return "roles_added"
        if len(new_set) < len(old_set):
            return "roles_removed"
        return "roles_modified"

    def _calculate_severity(
        self, change_type: str, old_roles: list[str], new_roles: list[str]
    ) -> str:
        """
        Calculate the severity of the role change.

        Args:
            change_type: Type of role change
            old_roles: Previous roles
            new_roles: New roles

        Returns:
            Severity level
        """
        if change_type in ["admin_granted", "privilege_escalation"]:
            return "high"
        if change_type in ["admin_revoked", "privilege_reduction"]:
            return "medium"
        return "low"

    async def _create_privilege_escalation_audit_trail(
        self, event: UserRoleChangedEvent, change_type: str
    ) -> None:
        """
        Create audit trail for privilege escalation.

        Args:
            event: UserRoleChangedEvent instance
            change_type: Type of role change
        """
        try:
            await self.audit_service.create_audit_trail(
                user_id=event.changed_by,
                action_type="privilege_escalation",
                operation="grant",
                description=f"Privilege escalation detected: User {event.user_id} granted elevated privileges",
                resource_type="user_privileges",
                resource_id=str(event.user_id),
                resource_name=f"Privileges for user {event.user_id}",
                outcome="success",
                severity="high",
                category="security",
                correlation_id=str(event.metadata.correlation_id)
                if event.metadata.correlation_id
                else None,
                tags=["privilege_escalation", "security_critical", "access_elevation"],
                custom_fields={
                    "escalation_type": change_type,
                    "target_user": str(event.user_id),
                    "authorized_by": str(event.changed_by),
                    "new_privileges": event.new_roles,
                    "previous_privileges": event.old_roles,
                    "risk_level": "high",
                },
                compliance_tags=[
                    "privilege_management",
                    "security_controls",
                    "access_escalation",
                ],
            )

            logger.debug(
                "Privilege escalation audit trail created",
                user_id=event.user_id,
                change_type=change_type,
            )

        except Exception as e:
            logger.warning(
                "Failed to create privilege escalation audit trail",
                user_id=event.user_id,
                error=str(e),
            )

    async def _create_privilege_reduction_audit_trail(
        self, event: Any, change_type: str
    ) -> None:
        """
        Create audit trail for privilege reduction.

        Args:
            event: UserRoleChangedEvent instance
            change_type: Type of role change
        """
        try:
            await self.audit_service.create_audit_trail(
                user_id=event.changed_by,
                action_type="privilege_reduction",
                operation="revoke",
                description=f"Privilege reduction: User {event.user_id} had privileges reduced",
                resource_type="user_privileges",
                resource_id=str(event.user_id),
                resource_name=f"Privileges for user {event.user_id}",
                outcome="success",
                severity="medium",
                category="security",
                correlation_id=str(event.metadata.correlation_id)
                if event.metadata.correlation_id
                else None,
                tags=["privilege_reduction", "access_control", "security_adjustment"],
                custom_fields={
                    "reduction_type": change_type,
                    "target_user": str(event.user_id),
                    "authorized_by": str(event.changed_by),
                    "new_privileges": event.new_roles,
                    "previous_privileges": event.old_roles,
                    "revoked_privileges": list(
                        set(event.old_roles) - set(event.new_roles)
                    ),
                },
                compliance_tags=[
                    "privilege_management",
                    "access_control",
                    "security_reduction",
                ],
            )

            logger.debug(
                "Privilege reduction audit trail created",
                user_id=event.user_id,
                change_type=change_type,
            )

        except Exception as e:
            logger.warning(
                "Failed to create privilege reduction audit trail",
                user_id=event.user_id,
                error=str(e),
            )

    async def _create_compliance_audit_trail(
        self, event: Any, change_type: str
    ) -> None:
        """
        Create compliance audit trail for role changes.

        Args:
            event: UserRoleChangedEvent instance
            change_type: Type of role change
        """
        try:
            await self.audit_service.create_audit_trail(
                user_id=event.changed_by,
                action_type="compliance_role_change",
                operation="modify",
                description=f"Role change compliance record: {change_type} for user {event.user_id}",
                resource_type="compliance_record",
                resource_id=str(event.user_id),
                resource_name=f"Compliance record for user {event.user_id}",
                outcome="success",
                severity="low",
                category="compliance",
                correlation_id=str(event.metadata.correlation_id)
                if event.metadata.correlation_id
                else None,
                tags=["compliance", "role_management", "access_audit"],
                custom_fields={
                    "compliance_event_type": "role_modification",
                    "change_justification": event.reason,
                    "role_change_type": change_type,
                    "data_subject": str(event.user_id),
                    "processing_activity": "role_management",
                },
                compliance_tags=[
                    "SOX_compliance",
                    "data_protection",
                    "access_governance",
                ],
            )

            logger.debug(
                "Compliance audit trail created for role change", user_id=event.user_id
            )

        except Exception as e:
            logger.warning(
                "Failed to create compliance audit trail",
                user_id=event.user_id,
                error=str(e),
            )


__all__ = ["UserRoleChangedEventHandler"]
