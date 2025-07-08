"""
Impersonate user command implementation.

Handles secure user impersonation for administrative support and debugging.
"""

from datetime import UTC, datetime, timedelta
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    require_approval,
    require_mfa,
    require_permission,
    validate_request,
)
from app.modules.identity.application.dtos.administrative import (
    AdminContext,
    ImpersonationConfig,
    InfrastructureDependencies,
    ServiceDependencies,
)
from app.modules.identity.application.dtos.internal import (
    EmailContext,
    SecurityIncidentContext,
    SessionCreationContext,
    TokenGenerationContext,
)
from app.modules.identity.application.dtos.request import ImpersonateUserRequest
from app.modules.identity.application.dtos.response import ImpersonationResponse
from app.modules.identity.domain.entities import Session, User
from app.modules.identity.domain.enums import (
    AuditAction,
    NotificationType,
    RiskLevel,
    SecurityEventType,
    SessionType,
    UserStatus,
)
from app.modules.identity.domain.events import (
    UserImpersonationStarted,
)
from app.modules.identity.domain.exceptions import (
    ImpersonationNotAllowedError,
    InvalidOperationError,
    SelfModificationError,
    UnauthorizedError,
    UserNotActiveError,
    UserNotFoundError,
)


class ImpersonateUserCommand(Command[ImpersonationResponse]):
    """Command to impersonate another user."""
    
    def __init__(
        self,
        admin_context: AdminContext,
        impersonation_config: ImpersonationConfig,
        session_context: dict[str, str]
    ):
        self.admin_context = admin_context
        self.impersonation_config = impersonation_config
        self.session_context = session_context
        
        # For backward compatibility, expose common fields
        self.target_user_id = admin_context.target_user_id
        self.admin_user_id = admin_context.admin_user_id
        self.reason = impersonation_config.reason
        # Max 4 hours
        self.duration_minutes = min(
            impersonation_config.duration_minutes, 240
        )
        self.ip_address = session_context.get('ip_address', '')
        self.user_agent = session_context.get('user_agent', '')
        self.allowed_actions = impersonation_config.allowed_actions
        self.restricted_actions = [
            "change_password",
            "update_mfa",
            "delete_account",
            "update_emergency_contacts",
            "export_data"
        ]
        self.notify_user = True  # Always notify for impersonation
        self.require_audit_trail = impersonation_config.audit_level == "detailed"
        self.metadata = {**admin_context.metadata, **impersonation_config.metadata}


class ImpersonateUserCommandHandler(CommandHandler[ImpersonateUserCommand, ImpersonationResponse]):
    """Handler for user impersonation."""
    
    def __init__(
        self,
        services: ServiceDependencies,
        infrastructure: InfrastructureDependencies
    ):
        self._user_repository = services.user_repository
        self._session_repository = services.session_repository
        self._authorization_service = services.authorization_service
        self._security_service = services.security_service
        self._session_service = services.session_service
        self._token_service = services.token_service
        self._email_service = services.email_service
        self._notification_service = services.notification_service
        self._audit_service = services.audit_service
        self._event_bus = infrastructure.event_bus
        self._unit_of_work = infrastructure.unit_of_work
    
    @audit_action(
        action=AuditAction.USER_IMPERSONATION,
        resource_type="user",
        include_request=True,
        include_response=True,
        high_priority=True
    )
    @validate_request(ImpersonateUserRequest)
    @rate_limit(
        max_requests=10,
        window_seconds=3600,
        strategy='user'
    )
    @require_permission(
        "users.impersonate",
        resource_type="user",
        resource_id_param="target_user_id"
    )
    @require_mfa(
        methods=["totp", "hardware_token"]  # Only secure methods
    )
    @require_approval(
        approval_type="impersonation",
        approvers=["security_team", "admin_manager"]
    )
    async def handle(self, command: ImpersonateUserCommand) -> ImpersonationResponse:
        """
        Create secure impersonation session with comprehensive controls.
        
        Process:
        1. Validate permissions and hierarchy
        2. Check target user eligibility
        3. Verify security clearance
        4. Create restricted session
        5. Generate limited tokens
        6. Set up audit trail
        7. Send notifications
        8. Configure monitoring
        
        Returns:
            ImpersonationResponse with session details
            
        Raises:
            UserNotFoundError: If target user not found
            UnauthorizedError: If lacks permission
            SelfModificationError: If trying to impersonate self
            UserNotActiveError: If target user not active
            ImpersonationNotAllowedError: If target cannot be impersonated
        """
        async with self._unit_of_work:
            # 1. Prevent self-impersonation
            if command.target_user_id == command.admin_user_id:
                raise SelfModificationError(
                    "Cannot impersonate yourself"
                )
            
            # 2. Load admin user
            admin_user = await self._user_repository.get_by_id(command.admin_user_id)
            if not admin_user:
                raise UnauthorizedError("Admin user not found")
            
            # 3. Load target user
            target_user = await self._user_repository.get_by_id(command.target_user_id)
            if not target_user:
                raise UserNotFoundError(
                    f"User with ID {command.target_user_id} not found"
                )
            
            # 4. Check target user status
            if target_user.status != UserStatus.ACTIVE:
                raise UserNotActiveError(
                    f"Cannot impersonate user with status: {target_user.status.value}"
                )
            
            # 5. Check if target can be impersonated
            if not await self._can_impersonate_user(admin_user, target_user):
                raise ImpersonationNotAllowedError(
                    "Target user cannot be impersonated due to security policies"
                )
            
            # 6. Verify admin has active MFA
            if not await self._verify_admin_security(admin_user):
                raise UnauthorizedError(
                    "Admin must have active MFA for impersonation"
                )
            
            # 7. Check for concurrent impersonations
            active_impersonations = await self._get_active_impersonations(admin_user.id)
            if active_impersonations:
                raise InvalidOperationError(
                    "Cannot have multiple active impersonations"
                )
            
            # 8. Create impersonation session
            session_context = SessionCreationContext(
                user_id=target_user.id,
                ip_address=command.ip_address,
                user_agent=command.user_agent,
                session_type=SessionType.ADMIN,
                risk_score=0.8,  # High risk by default
                mfa_verified=True,
                metadata={
                    "impersonation": True,
                    "impersonated_by": str(admin_user.id),
                    "impersonation_reason": command.reason,
                    "allowed_actions": command.allowed_actions,
                    "restricted_actions": command.restricted_actions,
                    "expires_at": (
                        datetime.now(UTC) + timedelta(minutes=command.duration_minutes)
                    ).isoformat()
                }
            )
            
            session = await self._session_service.create_session(session_context)
            
            # 9. Generate restricted tokens
            access_token = await self._token_service.generate_token(
                TokenGenerationContext(
                    user_id=target_user.id,
                    session_id=session.id,
                    token_type="access",  # noqa: S106
                    expires_in=timedelta(minutes=command.duration_minutes),
                    scopes=self._calculate_scopes(
                        command.allowed_actions,
                        command.restricted_actions
                    ),
                    claims={
                        "impersonation": True,
                        "admin_id": str(admin_user.id),
                        "original_session": str(session.id),
                        "restrictions": command.restricted_actions
                    }
                )
            )
            
            
            # 10. Create audit trail entry
            audit_trail_id = await self._audit_service.create_impersonation_trail(
                impersonation_id=session.id,
                admin_user_id=admin_user.id,
                target_user_id=target_user.id,
                reason=command.reason,
                duration_minutes=command.duration_minutes,
                allowed_actions=command.allowed_actions,
                restricted_actions=command.restricted_actions
            )
            
            # 11. Send notifications
            if command.notify_user and target_user.email_verified:
                # Email notification
                await self._email_service.send_email(
                    EmailContext(
                        recipient=target_user.email,
                        template="admin_access_notification",
                        subject="Administrative Access to Your Account",
                        variables={
                            "username": target_user.username,
                            "admin_name": f"{admin_user.first_name} {admin_user.last_name}",
                            "reason": command.reason,
                            "duration": f"{command.duration_minutes} minutes",
                            "start_time": datetime.now(UTC).isoformat(),
                            "end_time": (
                                datetime.now(UTC) + timedelta(minutes=command.duration_minutes)
                            ).isoformat(),
                            "audit_link": f"https://app.example.com/audit/{audit_trail_id}"
                        },
                        priority="high"
                    )
                )
                
                # In-app notification
                await self._notification_service.create_notification(
                    user_id=target_user.id,
                    type=NotificationType.ADMIN_ACCESS,
                    title="Administrative Access Active",
                    message=f"An administrator is accessing your account for: {command.reason}",
                    priority="urgent",
                    data={
                        "session_id": str(session.id),
                        "admin_id": str(admin_user.id),
                        "expires_at": (
                            datetime.now(UTC) + timedelta(minutes=command.duration_minutes)
                        ).isoformat()
                    }
                )
            
            # 12. Log security event
            await self._security_service.log_security_incident(
                SecurityIncidentContext(
                    incident_type=SecurityEventType.ADMIN_IMPERSONATION,
                    severity=RiskLevel.MEDIUM,
                    user_id=target_user.id,
                    details={
                        "admin_user_id": str(admin_user.id),
                        "admin_username": admin_user.username,
                        "target_user_id": str(target_user.id),
                        "target_username": target_user.username,
                        "reason": command.reason,
                        "duration_minutes": command.duration_minutes,
                        "session_id": str(session.id),
                        "ip_address": command.ip_address
                    },
                    indicators=["admin_access", "impersonation"],
                    recommended_actions=[
                        "Monitor all actions during impersonation",
                        "Review audit trail after session ends"
                    ]
                )
            )
            
            # 13. Publish domain event
            await self._event_bus.publish(
                UserImpersonationStarted(
                    aggregate_id=target_user.id,
                    admin_user_id=admin_user.id,
                    session_id=session.id,
                    reason=command.reason,
                    duration_minutes=command.duration_minutes,
                    restricted_actions=command.restricted_actions
                )
            )
            
            # 14. Set up real-time monitoring
            await self._setup_monitoring(
                session.id,
                admin_user.id,
                target_user.id,
                command.duration_minutes
            )
            
            # 15. Commit transaction
            await self._unit_of_work.commit()
            
            # 16. Notify security team
            await self._notification_service.notify_security_team(
                "Admin impersonation started",
                {
                    "admin_user": admin_user.username,
                    "target_user": target_user.username,
                    "reason": command.reason,
                    "duration": f"{command.duration_minutes} minutes",
                    "session_id": str(session.id),
                    "audit_trail_id": str(audit_trail_id)
                }
            )
            
            return ImpersonationResponse(
                impersonation_id=session.id,
                actor_id=admin_user.id,
                target_user_id=target_user.id,
                session_id=session.id,
                expires_at=datetime.now(UTC) + timedelta(minutes=command.duration_minutes),
                allowed_actions=command.allowed_actions,
                restricted_actions=command.restricted_actions,
                audit_trail_id=audit_trail_id,
                access_token=access_token,
                token_type="Bearer",  # noqa: S106
                expires_in=command.duration_minutes * 60,  # seconds
                message="Impersonation session created successfully"
            )
    
    async def _can_impersonate_user(self, admin_user: User, target_user: User) -> bool:
        """Check if admin can impersonate target user."""
        # Get roles
        admin_roles = await self._authorization_service.get_user_roles(admin_user.id)
        target_roles = await self._authorization_service.get_user_roles(target_user.id)
        
        # Cannot impersonate users with certain roles
        protected_roles = ["super_admin", "security_admin", "compliance_officer"]
        if any(role.name in protected_roles for role in target_roles):
            return False
        
        # Check hierarchy
        admin_max_level = max(
            (role.get_hierarchy_level() for role in admin_roles),
            default=0
        )
        target_max_level = max(
            (role.get_hierarchy_level() for role in target_roles),
            default=0
        )
        
        # Must have higher privileges
        return admin_max_level > target_max_level
    
    async def _verify_admin_security(self, admin_user: User) -> bool:
        """Verify admin has required security measures."""
        # Check MFA status
        mfa_devices = await self._security_service.get_mfa_devices(admin_user.id)
        if not any(device.is_verified for device in mfa_devices):
            return False
        
        # Check recent authentication
        last_mfa = await self._security_service.get_last_mfa_verification(admin_user.id)
        if not last_mfa or (datetime.now(UTC) - last_mfa) > timedelta(hours=1):
            return False
        
        # Check account age (prevent new admin abuse)
        account_age = datetime.now(UTC) - admin_user.created_at
        return account_age >= timedelta(days=30)
    
    async def _get_active_impersonations(self, admin_user_id: UUID) -> list[Session]:
        """Get active impersonation sessions for admin."""
        sessions = await self._session_repository.find_by_metadata(
            {"impersonated_by": str(admin_user_id)}
        )
        
        return [
            s for s in sessions
            if s.is_active and s.metadata.get("impersonation")
        ]
    
    def _calculate_scopes(
        self,
        allowed_actions: list[str],
        restricted_actions: list[str]
    ) -> list[str]:
        """Calculate token scopes based on allowed/restricted actions."""
        # Start with basic read scopes
        scopes = [
            "profile:read",
            "settings:read",
            "data:read"
        ]
        
        # Add allowed action scopes
        action_scope_map = {
            "view_sensitive": ["sensitive:read"],
            "modify_settings": ["settings:write"],
            "view_security": ["security:read"],
            "view_audit": ["audit:read"]
        }
        
        for action in allowed_actions:
            if action in action_scope_map:
                scopes.extend(action_scope_map[action])
        
        # Remove restricted scopes
        restricted_scope_map = {
            "change_password": ["password:write"],
            "update_mfa": ["mfa:write"],
            "delete_account": ["account:delete"],
            "update_emergency_contacts": ["contacts:write"],
            "export_data": ["data:export"]
        }
        
        restricted_scopes = []
        for action in restricted_actions:
            if action in restricted_scope_map:
                restricted_scopes.extend(restricted_scope_map[action])
        
        # Filter out restricted scopes
        scopes = [s for s in scopes if s not in restricted_scopes]
        
        return list(set(scopes))  # Remove duplicates
    
    async def _setup_monitoring(
        self,
        session_id: UUID,
        admin_user_id: UUID,
        target_user_id: UUID,
        duration_minutes: int
    ) -> None:
        """Set up real-time monitoring for impersonation session."""
        # Configure activity monitoring
        await self._security_service.enable_session_monitoring(
            session_id,
            {
                "monitor_all_actions": True,
                "alert_on_restricted": True,
                "record_screen": False,  # Privacy consideration
                "log_api_calls": True,
                "track_data_access": True,
                "alert_recipients": ["security_team"],
                "auto_terminate_on_violation": True
            }
        )
        
        # Schedule session termination
        await self._session_service.schedule_termination(
            session_id,
            datetime.now(UTC) + timedelta(minutes=duration_minutes)
        )