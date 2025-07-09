"""
Assign role command implementation.

Handles assigning roles to users with hierarchy validation.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    require_mfa,
    require_permission,
    validate_request,
)
from app.modules.identity.application.dtos.internal import (
    EmailContext,
    NotificationContext,
    SecurityIncidentContext,
)
from app.modules.identity.application.dtos.request import AssignRoleRequest
from app.modules.identity.application.dtos.response import RoleAssignmentResponse
from app.modules.identity.domain.entities import Role, User, UserRole
from app.modules.identity.domain.enums import (
    AuditAction,
    NotificationType,
    RiskLevel,
    SecurityEventType,
    UserStatus,
)
from app.modules.identity.domain.events import RoleAssigned
from app.modules.identity.domain.exceptions import (
    HierarchyViolationError,
    InvalidOperationError,
    RoleAlreadyAssignedError,
    RoleNotFoundError,
    UnauthorizedError,
    UserNotFoundError,
)
from app.modules.identity.domain.interfaces.repositories.role_repository import (
    IRoleRepository,
)
from app.modules.identity.domain.interfaces.repositories.user_repository import (
    IUserRepository,
)
from app.modules.identity.domain.interfaces.services.communication.notification_service import (
    IEmailService,
    INotificationService,
)
from app.modules.identity.domain.services import (
    AuthorizationService,
    SecurityService,
    ValidationService,
)


@dataclass
class AssignRoleOptions:
    """Options for role assignment."""
    expires_at: datetime | None = None
    scope: str | None = None
    notify_user: bool = True
    require_acceptance: bool = False
    conditions: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AssignRoleRepositoryDependencies:
    """Repository dependencies for assign role handler."""
    user_repository: IUserRepository
    role_repository: IRoleRepository
    user_role_repository: IUserRoleRepository


@dataclass
class AssignRoleServiceDependencies:
    """Service dependencies for assign role handler."""
    authorization_service: AuthorizationService
    security_service: SecurityService
    validation_service: ValidationService
    notification_service: INotificationService
    audit_service: IAuditService
    email_service: IEmailService


@dataclass
class AssignRoleInfrastructureDependencies:
    """Infrastructure dependencies for assign role handler."""
    event_bus: EventBus
    unit_of_work: UnitOfWork


class AssignRoleCommand(Command[RoleAssignmentResponse]):
    """Command to assign a role to a user."""
    
    def __init__(
        self,
        user_id: UUID,
        role_id: UUID,
        assigned_by: UUID,
        reason: str,
        options: AssignRoleOptions | None = None
    ):
        self.user_id = user_id
        self.role_id = role_id
        self.assigned_by = assigned_by
        self.reason = reason
        self.options = options or AssignRoleOptions()
        
        # For backward compatibility, expose commonly used options directly
        self.expires_at = self.options.expires_at
        self.scope = self.options.scope
        self.notify_user = self.options.notify_user
        self.require_acceptance = self.options.require_acceptance
        self.conditions = self.options.conditions
        self.metadata = self.options.metadata


class AssignRoleCommandHandler(CommandHandler[AssignRoleCommand, RoleAssignmentResponse]):
    """Handler for assigning roles to users."""
    
    def __init__(
        self,
        repositories: AssignRoleRepositoryDependencies,
        services: AssignRoleServiceDependencies,
        infrastructure: AssignRoleInfrastructureDependencies
    ):
        # Repository dependencies
        self._user_repository = repositories.user_repository
        self._role_repository = repositories.role_repository
        self._user_role_repository = repositories.user_role_repository
        
        # Service dependencies
        self._authorization_service = services.authorization_service
        self._security_service = services.security_service
        self._validation_service = services.validation_service
        self._notification_service = services.notification_service
        self._audit_service = services.audit_service
        self._email_service = services.email_service
        
        # Infrastructure dependencies
        self._event_bus = infrastructure.event_bus
        self._unit_of_work = infrastructure.unit_of_work
    
    @audit_action(
        action=AuditAction.ROLE_ASSIGNED,
        resource_type="user",
        include_request=True,
        include_response=True,
        include_reason=True
    )
    @validate_request(AssignRoleRequest)
    @rate_limit(
        max_requests=50,
        window_seconds=3600,
        strategy='user'
    )
    @require_permission(
        "roles.assign",
        resource_type="role",
        resource_id_param="role_id"
    )
    @require_mfa()
    async def handle(self, command: AssignRoleCommand) -> RoleAssignmentResponse:
        """
        Assign role to user with comprehensive validation.
        
        Process:
        1. Validate assignor privileges
        2. Load user and role
        3. Check hierarchy rules
        4. Verify no conflicts
        5. Check conditions
        6. Create assignment
        7. Send notifications
        8. Log security event
        
        Returns:
            RoleAssignmentResponse with assignment details
            
        Raises:
            UserNotFoundError: If user not found
            RoleNotFoundError: If role not found
            UnauthorizedError: If lacks permission
            RoleAlreadyAssignedError: If already assigned
            HierarchyViolationError: If violates hierarchy
        """
        async with self._unit_of_work:
            # 1. Load assignor (admin user)
            assignor = await self._user_repository.find_by_id(command.assigned_by)
            if not assignor:
                raise UnauthorizedError("Assignor not found")
            
            # 2. Load target user
            user = await self._user_repository.find_by_id(command.user_id)
            if not user:
                raise UserNotFoundError(f"User {command.user_id} not found")
            
            # 3. Load role
            role = await self._role_repository.find_by_id(command.role_id)
            if not role:
                raise RoleNotFoundError(f"Role {command.role_id} not found")
            
            # 4. Check if user is active
            if user.status != UserStatus.ACTIVE:
                raise InvalidOperationError(
                    f"Cannot assign role to user with status: {user.status.value}"
                )
            
            # 5. Check if already assigned
            existing = await self._user_role_repository.find_by_user_and_role(
                command.user_id,
                command.role_id,
                command.scope
            )
            
            if existing and existing.is_active:
                raise RoleAlreadyAssignedError(
                    f"User already has role '{role.name}'"
                    f"{' in scope ' + command.scope if command.scope else ''}"
                )
            
            # 6. Validate hierarchy
            await self._validate_hierarchy(assignor, user, role)
            
            # 7. Check role prerequisites
            if role.prerequisites:
                await self._check_prerequisites(user, role)
            
            # 8. Validate conditions if any
            if command.conditions:
                await self._validate_conditions(user, role, command.conditions)
            
            # 9. Create role assignment
            user_role = UserRole(
                user_id=command.user_id,
                role_id=command.role_id,
                assigned_by=command.assigned_by,
                assigned_at=datetime.now(UTC),
                expires_at=command.expires_at,
                scope=command.scope,
                reason=command.reason,
                require_acceptance=command.require_acceptance,
                accepted=not command.require_acceptance,
                conditions=command.conditions,
                metadata=command.metadata
            )
            
            # 10. Check for role limits
            if role.max_assignments:
                current_assignments = await self._user_role_repository.count_active_assignments(
                    command.role_id,
                    command.scope
                )
                if current_assignments >= role.max_assignments:
                    raise InvalidOperationError(
                        f"Role '{role.name}' has reached maximum assignments ({role.max_assignments})"
                    )
            
            # 11. Save assignment
            await self._user_role_repository.create(user_role)
            
            # 12. Update user's cached permissions
            await self._authorization_service.refresh_user_permissions(command.user_id)
            
            # 13. Send notifications
            if command.notify_user:
                await self._send_role_assignment_notification(
                    user,
                    role,
                    assignor,
                    command
                )
            
            # 14. Log high-privilege assignments
            if role.is_high_privilege():
                await self._log_high_privilege_assignment(
                    user,
                    role,
                    assignor,
                    command
                )
            
            # 15. Publish domain event
            await self._event_bus.publish(
                RoleAssigned(
                    aggregate_id=user.id,
                    role_id=role.id,
                    role_name=role.name,
                    assigned_by=assignor.id,
                    expires_at=command.expires_at,
                    scope=command.scope,
                    require_acceptance=command.require_acceptance
                )
            )
            
            # 16. Schedule expiration if needed
            if command.expires_at:
                await self._schedule_role_expiration(
                    user_role.id,
                    command.expires_at
                )
            
            # 17. Commit transaction
            await self._unit_of_work.commit()
            
            # 18. Send acceptance request if required
            if command.require_acceptance:
                await self._send_acceptance_request(user, role, user_role.id)
            
            return RoleAssignmentResponse(
                assignment_id=user_role.id,
                user_id=user.id,
                role_id=role.id,
                role_name=role.name,
                assigned_at=user_role.assigned_at,
                expires_at=user_role.expires_at,
                scope=user_role.scope,
                require_acceptance=user_role.require_acceptance,
                permissions=await self._get_role_permissions(role.id),
                message=f"Role '{role.name}' assigned successfully"
                        f"{' (pending acceptance)' if command.require_acceptance else ''}"
            )
    
    async def _validate_hierarchy(
        self,
        assignor: User,
        target_user: User,
        role: Role
    ) -> None:
        """Validate role assignment follows hierarchy rules."""
        # Get assignor's roles
        assignor_roles = await self._authorization_service.find_by_user(assignor.id)
        
        # Check if assignor can assign this role
        can_assign = False
        for assignor_role in assignor_roles:
            # Super admin can assign any role
            if assignor_role.name == "super_admin":
                can_assign = True
                break
            
            # Check if assignor's role can grant this role
            if role.id in assignor_role.grantable_roles:
                can_assign = True
                break
            
            # Check hierarchy level
            if assignor_role.hierarchy_level > role.hierarchy_level:
                can_assign = True
                break
        
        if not can_assign:
            raise HierarchyViolationError(
                f"You cannot assign role '{role.name}' - insufficient privileges"
            )
        
        # Check if target user would exceed assignor's level
        target_roles = await self._authorization_service.find_by_user(target_user.id)
        max(
            (r.hierarchy_level for r in target_roles),
            default=0
        )
        
        assignor_max_level = max(
            (r.hierarchy_level for r in assignor_roles),
            default=0
        )
        
        if role.hierarchy_level >= assignor_max_level > 0:
            # Allow if explicitly grantable
            grantable = any(
                role.id in r.grantable_roles
                for r in assignor_roles
            )
            if not grantable:
                raise HierarchyViolationError(
                    "Cannot assign role at or above your hierarchy level"
                )
    
    async def _check_prerequisites(self, user: User, role: Role) -> None:
        """Check if user meets role prerequisites."""
        if not role.prerequisites:
            return
        
        user_roles = await self._authorization_service.find_by_user(user.id)
        user_role_ids = {r.id for r in user_roles}
        
        # Check required roles
        required_roles = role.prerequisites.get("required_roles", [])
        missing_roles = [
            role_id for role_id in required_roles
            if role_id not in user_role_ids
        ]
        
        if missing_roles:
            role_names = []
            for role_id in missing_roles:
                prereq_role = await self._role_repository.find_by_id(role_id)
                if prereq_role:
                    role_names.append(prereq_role.name)
            
            raise InvalidOperationError(
                f"User missing prerequisite roles: {', '.join(role_names)}"
            )
        
        # Check account age
        min_account_age_days = role.prerequisites.get("min_account_age_days")
        if min_account_age_days:
            account_age = datetime.now(UTC) - user.created_at
            if account_age.days < min_account_age_days:
                raise InvalidOperationError(
                    f"Account must be at least {min_account_age_days} days old"
                )
        
        # Check MFA requirement
        if role.prerequisites.get("require_mfa"):
            mfa_enabled = await self._security_service.is_mfa_enabled(user.id)
            if not mfa_enabled:
                raise InvalidOperationError(
                    "Multi-factor authentication required for this role"
                )
    
    async def _validate_conditions(
        self,
        user: User,
        role: Role,
        conditions: dict[str, Any]
    ) -> None:
        """Validate role assignment conditions."""
        # Time-based conditions
        if "time_restrictions" in conditions:
            conditions["time_restrictions"]
            # Would validate time windows, days of week, etc.
        
        # Location-based conditions
        if "location_restrictions" in conditions:
            conditions["location_restrictions"]
            # Would validate IP ranges, countries, etc.
        
        # Resource-based conditions
        if "resource_restrictions" in conditions:
            conditions["resource_restrictions"]
            # Would validate specific resource access
    
    async def _get_role_permissions(self, role_id: UUID) -> list[str]:
        """Get permissions granted by role."""
        permissions = await self._authorization_service.find_by_role(role_id)
        return [p.name for p in permissions]
    
    async def _send_role_assignment_notification(
        self,
        user: User,
        role: Role,
        assignor: User,
        command: AssignRoleCommand
    ) -> None:
        """Send notification about role assignment."""
        # Email notification
        if user.email_verified:
            await self._email_service.send_email(
                EmailContext(
                    recipient=user.email,
                    template="role_assigned",
                    subject=f"New Role Assigned: {role.name}",
                    variables={
                        "username": user.username,
                        "role_name": role.name,
                        "role_description": role.description,
                        "assigned_by": f"{assignor.first_name} {assignor.last_name}",
                        "reason": command.reason,
                        "expires_at": command.expires_at.isoformat() if command.expires_at else None,
                        "scope": command.scope,
                        "require_acceptance": command.require_acceptance
                    }
                )
            )
        
        # In-app notification
        await self._notification_service.create_notification(
            NotificationContext(
                notification_id=UUID(),
                recipient_id=user.id,
                notification_type=NotificationType.ROLE_ASSIGNED,
                channel="in_app",
                template_id="role_assigned",
                template_data={
                    "role_id": str(role.id),
                    "role_name": role.name,
                    "assigned_by": str(assignor.id),
                    "require_acceptance": command.require_acceptance
                },
                priority="high"
            )
        )
    
    async def _log_high_privilege_assignment(
        self,
        user: User,
        role: Role,
        assignor: User,
        command: AssignRoleCommand
    ) -> None:
        """Log assignment of high-privilege roles."""
        await self._security_service.log_security_incident(
            SecurityIncidentContext(
                incident_type=SecurityEventType.HIGH_PRIVILEGE_GRANT,
                severity=RiskLevel.MEDIUM,
                user_id=user.id,
                details={
                    "role_id": str(role.id),
                    "role_name": role.name,
                    "assigned_by": str(assignor.id),
                    "assignor_name": assignor.username,
                    "reason": command.reason,
                    "expires_at": command.expires_at.isoformat() if command.expires_at else None,
                    "scope": command.scope
                },
                indicators=["high_privilege_role"],
                recommended_actions=[
                    "Monitor user activities",
                    "Review assignment justification"
                ]
            )
        )
        
        # Notify security team
        await self._notification_service.notify_security_team(
            "High-Privilege Role Assignment",
            {
                "user": user.username,
                "role": role.name,
                "assigned_by": assignor.username,
                "reason": command.reason
            }
        )
    
    async def _schedule_role_expiration(
        self,
        assignment_id: UUID,
        expires_at: datetime
    ) -> None:
        """Schedule automatic role expiration."""
        # This would use a job scheduler to revoke the role
        # when it expires
    
    async def _send_acceptance_request(
        self,
        user: User,
        role: Role,
        assignment_id: UUID
    ) -> None:
        """Send role acceptance request to user."""
        # Generate acceptance token
        acceptance_token = await self._security_service.generate_acceptance_token(
            assignment_id,
            expires_in=timedelta(days=7)
        )
        
        # Send email with acceptance link
        await self._email_service.send_email(
            EmailContext(
                recipient=user.email,
                template="role_acceptance_required",
                subject=f"Action Required: Accept Role '{role.name}'",
                variables={
                    "username": user.username,
                    "role_name": role.name,
                    "role_description": role.description,
                    "acceptance_link": f"https://app.example.com/accept-role/{acceptance_token}",
                    "expires_in_days": 7
                },
                priority="high"
            )
        )