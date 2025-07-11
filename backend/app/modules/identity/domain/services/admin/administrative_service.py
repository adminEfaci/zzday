"""
Administrative Domain Service

Pure domain service for administrative business logic using policy objects.
No infrastructure concerns - only business rules coordination.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from ...enums import UserStatus
from ...errors import InsufficientPrivilegesError, ValidationError
from ...interfaces.repositories.user_repository import IUserRepository
from ...interfaces.services.security.administrative_service import (
    IAdministrativeService,
)
from ...rules.compliance_policy import CompliancePolicy
from ...rules.risk_policy import RiskAssessmentPolicy
from ...rules.user_status_policy import UserStatusPolicy
from ...value_objects.permission import Permission
from ...value_objects.user_id import UserId


@dataclass(frozen=True)
class PolicyEnforcementResult:
    """Domain value object for policy enforcement results."""
    allowed: bool
    violations: list[str]
    requirements: list[str]
    applied_policies: list[str]
    metadata: dict[str, Any]
    
    def has_violations(self) -> bool:
        """Check if there are any policy violations."""
        return len(self.violations) > 0
    
    def requires_additional_auth(self) -> bool:
        """Check if additional authentication is required."""
        return "mfa_required" in self.requirements


@dataclass(frozen=True)
class AdminPrivilegeCheck:
    """Domain value object for admin privilege validation."""
    user_id: UserId
    required_permissions: list[Permission]
    has_privileges: bool
    missing_permissions: list[Permission]
    
    @classmethod
    def create(cls, user_id: UserId, required_permissions: list[Permission], user_permissions: list[Permission]) -> 'AdminPrivilegeCheck':
        """Factory method to create privilege check result."""
        user_perm_names = {p.name for p in user_permissions}
        missing = [p for p in required_permissions if p.name not in user_perm_names]
        
        return cls(
            user_id=user_id,
            required_permissions=required_permissions,
            has_privileges=len(missing) == 0,
            missing_permissions=missing
        )


@dataclass(frozen=True)
class ComplianceReport:
    """Domain value object for compliance reports."""
    report_id: str
    report_type: str
    generated_at: datetime
    filters_applied: dict[str, Any]
    data: dict[str, Any]
    summary: dict[str, Any]
    
    def is_valid(self) -> bool:
        """Check if report has valid data."""
        return bool(self.data and self.summary)


class AdministrativeService(IAdministrativeService):
    """Pure domain service for administrative business logic.
    
    Coordinates policy objects and aggregates without infrastructure concerns.
    """
    
    def __init__(
        self,
        user_repository: IUserRepository,
        user_status_policy: UserStatusPolicy,
        compliance_policy: CompliancePolicy,
        risk_policy: RiskAssessmentPolicy
    ) -> None:
        self._user_repository = user_repository
        self._user_status_policy = user_status_policy
        self._compliance_policy = compliance_policy
        self._risk_policy = risk_policy
    
    async def enforce_user_policies(
        self,
        user_id: UUID,
        action: str,
        context: dict[str, Any]
    ) -> dict[str, Any]:
        """Enforce user policies using domain policy objects."""
        
        # Create domain value object
        user_id_vo = UserId(user_id)
        
        # Get user aggregate
        user = await self._user_repository.get_by_id(user_id_vo.value)
        if not user:
            raise ValidationError("User not found")
        
        # Apply policies using policy objects
        status_result = self._user_status_policy.can_perform_action(user, action)
        risk_result = self._risk_policy.assess_action_risk(user, action, context)
        
        # Combine policy results
        all_violations = []
        all_requirements = []
        applied_policies = []
        
        if not status_result.allowed:
            all_violations.extend(status_result.violations)
            applied_policies.append("user_status_policy")
        
        if risk_result.requires_additional_verification:
            all_requirements.append("mfa_required")
            applied_policies.append("risk_assessment_policy")
        
        # Create domain result
        result = PolicyEnforcementResult(
            allowed=len(all_violations) == 0,
            violations=all_violations,
            requirements=all_requirements,
            applied_policies=applied_policies,
            metadata={"risk_score": risk_result.score}
        )
        
        return {
            "allowed": result.allowed,
            "violations": result.violations,
            "requirements": result.requirements,
            "applied_policies": result.applied_policies,
            "metadata": result.metadata
        }
    
    async def audit_admin_action(
        self,
        admin_user_id: UUID,
        action: str,
        target_user_id: UUID | None,
        details: dict[str, Any]
    ) -> str:
        """Pure domain logic for admin action validation.
        
        Note: Actual audit logging is handled by Application Service.
        """
        
        # Create domain value objects
        admin_id_vo = UserId(admin_user_id)
        UserId(target_user_id) if target_user_id else None
        
        # Get admin user aggregate
        admin_user = await self._user_repository.get_by_id(admin_id_vo.value)
        if not admin_user:
            raise ValidationError("Admin user not found")
        
        # Validate admin can perform action using policies
        action_allowed = self._user_status_policy.can_perform_admin_action(admin_user, action)
        if not action_allowed.allowed:
            raise InsufficientPrivilegesError(f"Admin action not allowed: {action_allowed.reason}")
        
        # Check if action requires additional verification
        risk_assessment = self._risk_policy.assess_admin_action(admin_user, action, details)
        if risk_assessment.is_high_risk and not details.get("mfa_verified", False):
            raise ValidationError("MFA verification required for high-risk admin action")
        
        # Return domain identifier for audit trail
        from app.core.security import generate_token
        return generate_token(16)
    
    async def validate_admin_privileges(
        self,
        user_id: UUID,
        required_permissions: list[str]
    ) -> bool:
        """Pure domain validation of admin privileges."""
        
        # Create domain value objects
        user_id_vo = UserId(user_id)
        required_perms = [Permission(name=perm) for perm in required_permissions]
        
        # Get user aggregate
        user = await self._user_repository.get_by_id(user_id_vo.value)
        if not user:
            return False
        
        # Use domain logic on aggregate
        if not user.is_active():
            return False
        
        # Get user's permissions and create domain check
        user_permissions = user.get_all_permissions()
        privilege_check = AdminPrivilegeCheck.create(
            user_id=user_id_vo,
            required_permissions=required_perms,
            user_permissions=user_permissions
        )
        
        return privilege_check.has_privileges
    
    async def schedule_user_maintenance(
        self,
        user_id: UUID,
        maintenance_type: str,
        scheduled_at: datetime,
        metadata: dict[str, Any]
    ) -> str:
        """Domain validation for user maintenance scheduling.
        
        Note: Actual task scheduling handled by Application Service.
        """
        
        # Create domain value object
        user_id_vo = UserId(user_id)
        
        # Validate business rules
        if scheduled_at <= datetime.utcnow():
            raise ValidationError("Scheduled time must be in the future")
        
        # Get user and validate maintenance can be scheduled
        user = await self._user_repository.get_by_id(user_id_vo.value)
        if not user:
            raise ValidationError("User not found")
        
        # Business rule: Can't schedule maintenance for suspended users
        if user.status == UserStatus.SUSPENDED:
            raise ValidationError("Cannot schedule maintenance for suspended users")
        
        # Business rule: Validate maintenance type is allowed
        allowed_types = ["password_reset", "account_cleanup", "data_export", "account_verification"]
        if maintenance_type not in allowed_types:
            raise ValidationError(f"Invalid maintenance type: {maintenance_type}")
        
        # Return domain identifier
        from app.core.security import generate_token
        return generate_token(16)
    
    async def generate_compliance_report(
        self,
        report_type: str,
        filters: dict[str, Any],
        format_type: str = "json"
    ) -> dict[str, Any]:
        """Domain logic for compliance report generation.
        
        Note: Actual report generation handled by Application Service.
        """
        
        # Validate using domain policy
        compliance_check = self._compliance_policy.validate_report_request(
            report_type=report_type,
            filters=filters,
            format_type=format_type
        )
        
        if not compliance_check.allowed:
            raise ValidationError(f"Report request not allowed: {compliance_check.reason}")
        
        # Generate domain report structure
        from app.core.security import generate_token
        report_id = generate_token(16)
        
        # Create domain value object
        report = ComplianceReport(
            report_id=report_id,
            report_type=report_type,
            generated_at=datetime.utcnow(),
            filters_applied=filters,
            data={},  # Data populated by Application Service
            summary={}  # Summary populated by Application Service
        )
        
        return {
            "report_id": report.report_id,
            "report_type": report.report_type,
            "generated_at": report.generated_at.isoformat(),
            "filters_applied": report.filters_applied,
            "data": report.data,
            "summary": report.summary,
            "format_type": format_type
        }
    
    # Pure domain helper methods - no infrastructure concerns
    
    def _validate_maintenance_type(self, maintenance_type: str) -> bool:
        """Domain validation for maintenance types."""
        allowed_types = ["password_reset", "account_cleanup", "data_export", "account_verification"]
        return maintenance_type in allowed_types
    
    def _is_future_date(self, scheduled_at: datetime) -> bool:
        """Domain validation for scheduling."""
        return scheduled_at > datetime.utcnow()