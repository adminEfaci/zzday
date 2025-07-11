"""
Reactivate user command implementation.

Handles user account reactivation with verification.
"""

from datetime import UTC, datetime
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    require_permission,
)
from app.modules.identity.application.dtos.internal import (
    EmailContext,
    RiskAssessmentResult,
)
from app.modules.identity.application.dtos.response import BaseResponse
from app.modules.identity.domain.entities import User
from app.modules.identity.domain.enums import (
    AuditAction,
    DeactivationReason,
    RiskLevel,
    UserStatus,
)
from app.modules.identity.domain.events import UserReactivated
from app.modules.identity.domain.exceptions import (
    InvalidOperationError,
    UnauthorizedError,
    UserNotFoundError,
)
from app.modules.identity.domain.interfaces.repositories.user_repository import (
    IUserRepository,
)
from app.modules.identity.domain.interfaces.services.communication.notification_service import (
    IEmailService,
    INotificationService,
)
from app.modules.identity.domain.interfaces.services.infrastructure.cache_port import (
    ICachePort as ICacheService,
)
from app.modules.identity.domain.services import (
from app.modules.identity.domain.interfaces.services import (
    IAuditLogRepository,
    ICachePort,
)
    AuthorizationService,
    RiskAssessmentService,
    SecurityService,
)


class ReactivateUserCommand(Command[BaseResponse]):
    """Command to reactivate a deactivated user account."""
    
    def __init__(
        self,
        user_id: UUID,
        reason: str,
        reactivated_by: UUID,
        ip_address: str | None = None,
        require_password_reset: bool = False,
        require_mfa_setup: bool = False,
        notify_user: bool = True
    ):
        self.user_id = user_id
        self.reason = reason
        self.reactivated_by = reactivated_by
        self.ip_address = ip_address
        self.require_password_reset = require_password_reset
        self.require_mfa_setup = require_mfa_setup
        self.notify_user = notify_user


class ReactivateUserCommandHandler(CommandHandler[ReactivateUserCommand, BaseResponse]):
    """Handler for reactivating user accounts."""
    
    def __init__(
        self,
        user_repository: IUserRepository,
        authorization_service: AuthorizationService,
        security_service: SecurityService,
        risk_assessment_service: RiskAssessmentService,
        email_service: IEmailService,
        notification_service: INotificationService,
        audit_log_repository: IAuditLogRepository,
        cache_service: ICacheService,
        event_bus: EventBus,
        unit_of_work: UnitOfWork
    ):
        self._user_repository = user_repository
        self._authorization_service = authorization_service
        self._security_service = security_service
        self._risk_assessment_service = risk_assessment_service
        self._email_service = email_service
        self._notification_service = notification_service
        self._audit_log_repository = audit_log_repository
        self._cache_service = cache_service
        self._event_bus = event_bus
        self._unit_of_work = unit_of_work
    
    @audit_action(
        action=AuditAction.USER_REACTIVATED,
        resource_type="user",
        resource_id_attr="user_id",
        include_request=True
    )
    @rate_limit(
        max_requests=3,
        window_seconds=3600,
        strategy='user'
    )
    @require_permission(
        permission="users.reactivate",
        resource_type="user"
    )
    async def handle(self, command: ReactivateUserCommand) -> BaseResponse:
        """
        Reactivate deactivated user account with security checks.
        
        Process:
        1. Load and validate user
        2. Check deactivation history
        3. Assess reactivation risk
        4. Apply security requirements
        5. Update user status
        6. Send notifications
        7. Publish events
        
        Returns:
            BaseResponse indicating success
            
        Raises:
            UserNotFoundError: If user not found
            InvalidOperationError: If not deactivated
            UnauthorizedError: If reactivation blocked
        """
        async with self._unit_of_work:
            # 1. Load user
            user = await self._user_repository.find_by_id(command.user_id)
            if not user:
                raise UserNotFoundError(f"User {command.user_id} not found")
            
            # 2. Check if deactivated
            if user.status != UserStatus.DEACTIVATED:
                raise InvalidOperationError(
                    f"User is not deactivated. Current status: {user.status.value}"
                )
            
            # 3. Check deactivation history
            deactivation_info = await self._get_deactivation_info(user.id)
            
            # 4. Check if reactivation is allowed
            if not await self._can_reactivate(user, deactivation_info):
                raise UnauthorizedError(
                    "User account cannot be reactivated due to policy restrictions"
                )
            
            # 5. Assess risk of reactivation
            risk_assessment = await self._assess_reactivation_risk(
                user,
                deactivation_info,
                command.ip_address
            )
            
            if risk_assessment.risk_level == RiskLevel.CRITICAL:
                # Log and reject
                await self._security_service.log_security_event(
                    user_id=user.id,
                    event_type="reactivation_blocked",
                    details={
                        "risk_level": risk_assessment.risk_level.value,
                        "risk_factors": risk_assessment.risk_factors
                    }
                )
                
                raise UnauthorizedError(
                    "Reactivation blocked due to security concerns"
                )
            
            # 6. Apply security requirements based on risk
            if risk_assessment.risk_level == RiskLevel.HIGH:
                command.require_password_reset = True
                command.require_mfa_setup = True
            
            # 7. Reactivate user
            user.reactivate(
                reactivated_by=command.reactivated_by,
                reason=command.reason
            )
            
            # 8. Apply additional security flags
            if command.require_password_reset:
                user.require_password_change = True
            
            if command.require_mfa_setup:
                user.require_mfa_setup = True
            
            # 9. Save changes
            await self._user_repository.update(user)
            
            # 10. Clear user caches
            await self._cache_service.delete(f"user:{user.id}")
            
            # 11. Send notifications
            if command.notify_user:
                await self._send_reactivation_notification(
                    user=user,
                    require_password_reset=command.require_password_reset,
                    require_mfa_setup=command.require_mfa_setup
                )
            
            # 12. Notify security team for high-risk reactivations
            if risk_assessment.risk_level in [RiskLevel.HIGH, RiskLevel.MEDIUM]:
                await self._notification_service.notify_security_team(
                    "High-risk account reactivation",
                    {
                        "user_id": str(user.id),
                        "username": user.username,
                        "risk_level": risk_assessment.risk_level.value,
                        "risk_factors": risk_assessment.risk_factors,
                        "security_requirements": {
                            "password_reset": command.require_password_reset,
                            "mfa_setup": command.require_mfa_setup
                        }
                    }
                )
            
            # 13. Publish domain event
            await self._event_bus.publish(
                UserReactivated(
                    aggregate_id=user.id,
                    reactivated_by=command.reactivated_by,
                    require_password_reset=command.require_password_reset,
                    require_mfa_setup=command.require_mfa_setup,
                    risk_level=risk_assessment.risk_level
                )
            )
            
            # 14. Commit transaction
            await self._unit_of_work.commit()
            
            message = "User account reactivated successfully."
            if command.require_password_reset:
                message += " Password reset required on next login."
            if command.require_mfa_setup:
                message += " MFA setup required on next login."
            
            return BaseResponse(
                success=True,
                message=message
            )
    
    async def _get_deactivation_info(self, user_id: UUID) -> dict:
        """Get user's deactivation history."""
        # Get last deactivation audit log
        audit_logs = await self._audit_log_repository.get_by_criteria(
            user_id=user_id,
            action=AuditAction.USER_DEACTIVATED,
            limit=1,
            order_by="created_at",
            order_desc=True
        )
        
        if not audit_logs:
            return {}
        
        last_deactivation = audit_logs[0]
        return {
            "deactivated_at": last_deactivation.created_at,
            "reason": last_deactivation.details.get("reason"),
            "deactivated_by": last_deactivation.actor_id,
            "days_deactivated": (datetime.now(UTC) - last_deactivation.created_at).days
        }
    
    async def _can_reactivate(self, user: User, deactivation_info: dict) -> bool:
        """Check if user can be reactivated based on policies."""
        reason = deactivation_info.get("reason")
        
        # Permanent deactivation reasons
        permanent_reasons = [
            DeactivationReason.FRAUD_DETECTED,
            DeactivationReason.LEGAL_REQUIREMENT,
            DeactivationReason.SECURITY_BREACH
        ]
        
        if reason in [r.value for r in permanent_reasons]:
            # Check if enough time has passed (e.g., 90 days)
            days_deactivated = deactivation_info.get("days_deactivated", 0)
            if days_deactivated < 90:
                return False
        
        # Check for multiple deactivations
        deactivation_count = await self._audit_log_repository.count_by_criteria(
            user_id=user.id,
            action=AuditAction.USER_DEACTIVATED
        )
        
        if deactivation_count >= 3:
            # Too many deactivations
            return False
        
        return True
    
    async def _assess_reactivation_risk(
        self,
        user: User,
        deactivation_info: dict,
        ip_address: str | None
    ) -> RiskAssessmentResult:
        """Assess risk of reactivating the account."""
        risk_factors = []
        risk_score = 0.0
        
        # Check deactivation reason
        high_risk_reasons = [
            DeactivationReason.SECURITY_BREACH.value,
            DeactivationReason.FRAUD_DETECTED.value,
            DeactivationReason.ABUSE_VIOLATION.value
        ]
        
        if deactivation_info.get("reason") in high_risk_reasons:
            risk_factors.append("high_risk_deactivation_reason")
            risk_score += 0.4
        
        # Check time since deactivation
        days_deactivated = deactivation_info.get("days_deactivated", 0)
        if days_deactivated > 180:  # 6 months
            risk_factors.append("long_deactivation_period")
            risk_score += 0.2
        
        # Check IP reputation
        if ip_address:
            ip_risk = await self._security_service.check_ip_reputation(ip_address)
            if ip_risk.risk_score > 0.5:
                risk_factors.append("suspicious_ip")
                risk_score += 0.3
        
        # Check account age
        account_age_days = (datetime.now(UTC) - user.created_at).days
        if account_age_days < 30:
            risk_factors.append("new_account")
            risk_score += 0.1
        
        # Determine risk level
        if risk_score >= 0.7:
            risk_level = RiskLevel.CRITICAL
        elif risk_score >= 0.5:
            risk_level = RiskLevel.HIGH
        elif risk_score >= 0.3:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.LOW
        
        return RiskAssessmentResult(
            risk_score=risk_score,
            risk_level=risk_level,
            risk_factors=risk_factors,
            requires_mfa=risk_score >= 0.5,
            requires_additional_verification=risk_score >= 0.7
        )
    
    async def _send_reactivation_notification(
        self,
        user: User,
        require_password_reset: bool,
        require_mfa_setup: bool
    ) -> None:
        """Send reactivation notification to user."""
        requirements = []
        if require_password_reset:
            requirements.append("Reset your password")
        if require_mfa_setup:
            requirements.append("Set up multi-factor authentication")
        
        await self._email_service.send_email(
            EmailContext(
                recipient=user.email,
                template="account_reactivated",
                subject="Your account has been reactivated",
                variables={
                    "username": user.username,
                    "requirements": requirements,
                    "login_url": "https://app.example.com/login",
                    "support_email": "support@example.com"
                },
                priority="high"
            )
        )