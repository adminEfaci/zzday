"""
Create permission command implementation.

Handles creating new permissions with validation and categorization.
"""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    require_mfa,
    require_permission,
    validate_request,
)
from app.modules.identity.application.dtos.command_params import (
    CommandHandlerDependencies,
    PermissionCreationParams,
)
from app.modules.identity.application.dtos.internal import (
    NotificationContext,
    SecurityIncidentContext,
)
from app.modules.identity.application.dtos.request import CreatePermissionRequest
from app.modules.identity.application.dtos.response import PermissionResponse
from app.modules.identity.domain.entities import Permission
from app.modules.identity.domain.enums import (
    AuditAction,
    NotificationType,
    PermissionScope,
    PermissionType,
    RiskLevel,
    SecurityEventType,
)
from app.modules.identity.domain.events import PermissionCreated
from app.modules.identity.domain.exceptions import (
    ConflictingPermissionError,
    DuplicatePermissionError,
    InvalidPermissionError,
    UnauthorizedError,
)


class CreatePermissionCommand(Command[PermissionResponse]):
    """Command to create a new permission."""
    
    def __init__(self, params: PermissionCreationParams):
        self.params = params
        # Normalize name
        self.params.name = params.name.lower().replace(" ", "_")
        # Set default category if not provided
        if not self.params.category:
            self.params.category = self._determine_category(
                params.resource_type,
                params.action
            )
        # Initialize empty collections if None
        self.params.tags = params.tags or []
        self.params.prerequisites = params.prerequisites or {}
        self.params.implies = params.implies or []
        self.params.mutually_exclusive_with = params.mutually_exclusive_with or []
        self.params.conditions = params.conditions or {}
        self.params.metadata = params.metadata or {}
    
    def _determine_category(self, resource_type: str, action: str) -> str:
        """Determine permission category based on resource and action."""
        # Security categories
        if resource_type in ["auth", "session", "mfa", "security"]:
            return "security"
        if resource_type in ["user", "role", "permission"]:
            return "identity"
        # Data categories
        if resource_type in ["data", "file", "document"]:
            return "data"
        # System categories
        if resource_type in ["system", "config", "setting"]:
            return "system"
        # Administrative categories
        if action in ["admin", "manage", "configure"]:
            return "administrative"
        # Default
        return "general"


class CreatePermissionCommandHandler(CommandHandler[CreatePermissionCommand, PermissionResponse]):
    """Handler for creating new permissions."""
    
    def __init__(self, dependencies: CommandHandlerDependencies):
        self._permission_repository = dependencies.repositories.permission_repository
        self._role_repository = dependencies.repositories.role_repository
        self._authorization_service = dependencies.services.authorization_service
        self._validation_service = dependencies.services.validation_service
        self._notification_service = dependencies.services.notification_service
        self._audit_service = dependencies.services.audit_service
        self._event_bus = dependencies.infrastructure.event_bus
        self._unit_of_work = dependencies.infrastructure.unit_of_work
    
    @audit_action(
        action=AuditAction.PERMISSION_CREATED,
        resource_type="permission",
        include_request=True,
        include_response=True
    )
    @validate_request(CreatePermissionRequest)
    @rate_limit(
        max_requests=20,
        window_seconds=3600,
        strategy='user'
    )
    @require_permission("permissions.create")
    @require_mfa()
    async def handle(self, command: CreatePermissionCommand) -> PermissionResponse:
        """
        Create new permission with validation.
        
        Process:
        1. Validate creator privileges
        2. Check name uniqueness
        3. Validate permission structure
        4. Check conflicts
        5. Validate prerequisites
        6. Create permission
        7. Update indices
        8. Log if sensitive
        9. Send notifications
        
        Returns:
            PermissionResponse with created permission details
            
        Raises:
            UnauthorizedError: If lacks permission
            DuplicatePermissionError: If name exists
            InvalidPermissionError: If invalid structure
            ConflictingPermissionError: If conflicts exist
        """
        async with self._unit_of_work:
            # 1. Check if permission name already exists
            existing = await self._permission_repository.find_by_name(command.params.name)
            if existing:
                raise DuplicatePermissionError(
                    f"Permission with name '{command.params.name}' already exists"
                )
            
            # 2. Validate permission name format
            if not self._validate_permission_name(command.params.name):
                raise InvalidPermissionError(
                    "Permission name must follow format: resource_type:action[:sub_action]"
                )
            
            # 3. Validate creator can create system permissions
            if command.params.is_system:
                can_create_system = await self._authorization_service.has_permission(
                    command.params.created_by,
                    "permissions.create.system"
                )
                if not can_create_system:
                    raise UnauthorizedError("Cannot create system permissions")
            
            # 4. Validate implied permissions exist
            implied_permissions = []
            if command.params.implies:
                implied_permissions = await self._validate_implied_permissions(
                    command.params.implies
                )
            
            # 5. Validate mutual exclusions
            if command.params.mutually_exclusive_with:
                await self._validate_mutual_exclusions(
                    command.params.mutually_exclusive_with
                )
            
            # 6. Check for conflicts with existing permissions
            await self._check_permission_conflicts(
                command.params.resource_type,
                command.params.action,
                command.params.permission_type
            )
            
            # 7. Validate prerequisites format
            if command.params.prerequisites:
                self._validate_prerequisites_format(command.params.prerequisites)
            
            # 8. Create the permission
            permission = Permission(
                id=UUID(),
                name=command.params.name,
                display_name=command.params.display_name,
                description=command.params.description,
                resource_type=command.params.resource_type,
                action=command.params.action,
                type=command.params.permission_type,
                scope=command.params.scope,
                is_system=command.params.is_system,
                is_critical=command.params.is_critical,
                is_sensitive=command.params.is_sensitive,
                is_active=True,
                category=command.params.category,
                tags=command.params.tags,
                prerequisites=command.params.prerequisites,
                implies=command.params.implies,
                mutually_exclusive_with=command.params.mutually_exclusive_with,
                conditions=command.params.conditions,
                created_by=command.params.created_by,
                created_at=datetime.now(UTC),
                metadata=command.params.metadata
            )
            
            # 9. Calculate risk level
            risk_level = self._calculate_permission_risk(permission)
            permission.metadata["risk_level"] = risk_level.value
            
            # 10. Save permission
            await self._permission_repository.create(permission)
            
            # 11. Update search indices
            await self._update_permission_indices(permission)
            
            # 12. Log if high-risk permission
            if risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
                await self._log_high_risk_creation(permission, command)
            
            # 13. Publish domain event
            await self._event_bus.publish(
                PermissionCreated(
                    aggregate_id=permission.id,
                    permission_name=permission.name,
                    resource_type=permission.resource_type,
                    action=permission.action,
                    permission_type=permission.type,
                    is_system=permission.is_system,
                    created_by=command.params.created_by
                )
            )
            
            # 14. Send notifications
            await self._send_creation_notifications(permission, command)
            
            # 15. Commit transaction
            await self._unit_of_work.commit()
            
            # 16. Return response
            return PermissionResponse(
                id=permission.id,
                name=permission.name,
                display_name=permission.display_name,
                description=permission.description,
                resource_type=permission.resource_type,
                action=permission.action,
                permission_type=permission.type,
                scope=permission.scope,
                is_system=permission.is_system,
                is_critical=permission.is_critical,
                is_sensitive=permission.is_sensitive,
                is_active=permission.is_active,
                category=permission.category,
                tags=permission.tags,
                implied_permissions=[p.name for p in implied_permissions],
                risk_level=risk_level,
                created_at=permission.created_at,
                created_by=permission.created_by,
                message=f"Permission '{permission.name}' created successfully"
            )
    
    def _validate_permission_name(self, name: str) -> bool:
        """Validate permission name follows convention."""
        parts = name.split(":")
        
        # Must have at least resource_type:action
        if len(parts) < 2:
            return False
        
        # Resource type and action must not be empty
        if not parts[0] or not parts[1]:
            return False
        
        # All parts must be alphanumeric with underscores
        return all(part.replace("_", "").isalnum() for part in parts)
    
    async def _validate_implied_permissions(
        self,
        permission_ids: list[UUID]
    ) -> list[Permission]:
        """Validate all implied permissions exist."""
        permissions = []
        
        for perm_id in permission_ids:
            permission = await self._permission_repository.get_by_id(perm_id)
            if not permission:
                raise InvalidPermissionError(
                    f"Implied permission {perm_id} not found"
                )
            
            if not permission.is_active:
                raise InvalidPermissionError(
                    f"Cannot imply inactive permission '{permission.name}'"
                )
            
            permissions.append(permission)
        
        # Check for circular implications
        for perm in permissions:
            if perm.implies and any(pid in permission_ids for pid in perm.implies):
                raise InvalidPermissionError(
                    f"Circular implication detected with permission '{perm.name}'"
                )
        
        return permissions
    
    async def _validate_mutual_exclusions(
        self,
        permission_ids: list[UUID]
    ) -> None:
        """Validate mutual exclusion permissions exist."""
        for perm_id in permission_ids:
            permission = await self._permission_repository.get_by_id(perm_id)
            if not permission:
                raise InvalidPermissionError(
                    f"Mutually exclusive permission {perm_id} not found"
                )
    
    async def _check_permission_conflicts(
        self,
        resource_type: str,
        action: str,
        permission_type: PermissionType
    ) -> None:
        """Check for conflicts with existing permissions."""
        # Find permissions with same resource and action
        existing = await self._permission_repository.find_by_resource_and_action(
            resource_type,
            action
        )
        
        for perm in existing:
            # Check for ALLOW/DENY conflicts
            if perm.type != permission_type and perm.scope == PermissionScope.GLOBAL:
                raise ConflictingPermissionError(
                    f"Conflicting {perm.type.value} permission exists: {perm.name}"
                )
            
            # Check for duplicate with different names
            if perm.type == permission_type and perm.scope == PermissionScope.GLOBAL:
                raise DuplicatePermissionError(
                    f"Similar permission already exists: {perm.name}"
                )
    
    def _validate_prerequisites_format(self, prerequisites: dict[str, Any]) -> None:
        """Validate prerequisites dictionary format."""
        allowed_keys = [
            "required_permissions",
            "required_features",
            "required_attributes",
            "min_account_age_days",
            "min_reputation_score",
            "require_mfa",
            "require_verified_email"
        ]
        
        # Check for unknown keys
        unknown_keys = set(prerequisites.keys()) - set(allowed_keys)
        if unknown_keys:
            raise InvalidPermissionError(
                f"Unknown prerequisite keys: {', '.join(unknown_keys)}"
            )
        
        # Validate value types
        if "required_permissions" in prerequisites and not isinstance(prerequisites["required_permissions"], list):
            raise InvalidPermissionError(
                "required_permissions must be a list"
            )
        
        if "min_account_age_days" in prerequisites and not isinstance(prerequisites["min_account_age_days"], int | float):
            raise InvalidPermissionError(
                "min_account_age_days must be numeric"
            )
    
    def _calculate_permission_risk(self, permission: Permission) -> RiskLevel:
        """Calculate risk level of the permission."""
        # Critical permissions
        if permission.is_critical or permission.is_system:
            return RiskLevel.CRITICAL
        
        # High risk patterns
        high_risk_actions = ["delete", "admin", "system", "security", "grant", "revoke"]
        high_risk_resources = ["user", "role", "permission", "auth", "system"]
        
        if any(action in permission.action for action in high_risk_actions):
            return RiskLevel.HIGH
        
        if permission.resource_type in high_risk_resources:
            return RiskLevel.HIGH
        
        # Medium risk patterns
        medium_risk_actions = ["create", "update", "modify", "configure"]
        if any(action in permission.action for action in medium_risk_actions):
            return RiskLevel.MEDIUM
        
        # Sensitive data
        if permission.is_sensitive:
            return RiskLevel.MEDIUM
        
        # Default to low
        return RiskLevel.LOW
    
    async def _update_permission_indices(self, permission: Permission) -> None:
        """Update search indices for the permission."""
        # Update category index
        await self._permission_repository.add_to_category_index(
            permission.category,
            permission.id
        )
        
        # Update tag indices
        for tag in permission.tags:
            await self._permission_repository.add_to_tag_index(
                tag,
                permission.id
            )
        
        # Update resource type index
        await self._permission_repository.add_to_resource_index(
            permission.resource_type,
            permission.id
        )
    
    async def _log_high_risk_creation(
        self,
        permission: Permission,
        command: CreatePermissionCommand
    ) -> None:
        """Log creation of high-risk permissions."""
        await self._audit_service.log_security_incident(
            SecurityIncidentContext(
                incident_type=SecurityEventType.HIGH_RISK_PERMISSION_CREATED,
                severity=permission.metadata.get("risk_level", RiskLevel.MEDIUM),
                user_id=command.params.created_by,
                details={
                    "permission_id": str(permission.id),
                    "permission_name": permission.name,
                    "resource_type": permission.resource_type,
                    "action": permission.action,
                    "permission_type": permission.type.value,
                    "is_system": permission.is_system,
                    "is_critical": permission.is_critical,
                    "category": permission.category,
                    "implies": len(permission.implies),
                    "exclusions": len(permission.mutually_exclusive_with)
                },
                indicators=["high_risk_permission_creation"],
                recommended_actions=[
                    "Review permission scope",
                    "Validate usage patterns",
                    "Monitor assignments"
                ]
            )
        )
        
        # Notify security team
        if permission.is_system or permission.is_critical:
            await self._notification_service.notify_security_team(
                "Critical Permission Created",
                {
                    "permission_name": permission.name,
                    "created_by": str(command.params.created_by),
                    "resource_type": permission.resource_type,
                    "action": permission.action,
                    "risk_level": permission.metadata.get("risk_level")
                }
            )
    
    async def _send_creation_notifications(
        self,
        permission: Permission,
        command: CreatePermissionCommand
    ) -> None:
        """Send notifications about permission creation."""
        # Notify administrators
        await self._notification_service.notify_role(
            "administrator",
            NotificationContext(
                notification_id=UUID(),
                recipient_id=None,
                notification_type=NotificationType.PERMISSION_CREATED,
                channel="in_app",
                template_id="permission_created",
                template_data={
                    "permission_id": str(permission.id),
                    "permission_name": permission.name,
                    "display_name": permission.display_name,
                    "created_by": str(command.params.created_by),
                    "resource_type": permission.resource_type,
                    "action": permission.action,
                    "category": permission.category,
                    "risk_level": permission.metadata.get("risk_level", "low")
                },
                priority="medium" if permission.is_system else "low"
            )
        )
        
        # Notify compliance if sensitive
        if permission.is_sensitive:
            await self._notification_service.notify_compliance_team(
                "Sensitive Permission Created",
                {
                    "permission_name": permission.name,
                    "category": permission.category,
                    "created_by": str(command.params.created_by)
                }
            )