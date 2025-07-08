"""
User Status Policy

Business rules for user status transitions and lifecycle management.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any

from .base import BusinessRule, PolicyViolation


class UserStatusTransition(Enum):
    """Valid user status transitions."""
    PENDING_TO_ACTIVE = "pending_to_active"
    ACTIVE_TO_SUSPENDED = "active_to_suspended"
    ACTIVE_TO_LOCKED = "active_to_locked"
    ACTIVE_TO_INACTIVE = "active_to_inactive"
    SUSPENDED_TO_ACTIVE = "suspended_to_active"
    LOCKED_TO_ACTIVE = "locked_to_active"
    INACTIVE_TO_ACTIVE = "inactive_to_active"
    ANY_TO_DELETED = "any_to_deleted"


@dataclass
class UserStatusPolicy(BusinessRule):
    """Policy for user status management and transitions."""
    
    # Configuration parameters
    auto_lock_after_failed_attempts: int = 5
    auto_suspend_after_days_inactive: int = 90
    require_admin_approval_for_reactivation: bool = True
    allow_self_reactivation_within_days: int = 30
    permanent_deletion_after_days: int = 365
    require_mfa_after_reactivation: bool = True
    notify_before_auto_suspension_days: int = 7
    
    # Valid status transitions
    allowed_transitions: dict[str, set[str]] = None
    
    def __post_init__(self):
        """Initialize allowed transitions if not provided."""
        if self.allowed_transitions is None:
            self.allowed_transitions = {
                'pending': {'active', 'deleted'},
                'active': {'suspended', 'locked', 'inactive', 'deleted'},
                'suspended': {'active', 'deleted'},
                'locked': {'active', 'deleted'},
                'inactive': {'active', 'deleted'},
                'deleted': set()  # No transitions from deleted
            }
    
    def validate(self, **kwargs) -> list[PolicyViolation]:
        """Validate user status policy."""
        violations = []
        
        # Extract parameters
        current_status = kwargs.get('current_status')
        new_status = kwargs.get('new_status')
        user_data = kwargs.get('user_data', {})
        actor_role = kwargs.get('actor_role')
        
        # Validate status transition
        if current_status and new_status:
            if not self._is_valid_transition(current_status, new_status):
                violations.append(PolicyViolation(
                    rule_name="UserStatusPolicy",
                    description=f"Invalid status transition from '{current_status}' to '{new_status}'",
                    severity="error",
                    current_value=current_status,
                    expected_value=f"one of {self.allowed_transitions.get(current_status, set())}",
                    context={"transition": f"{current_status}_to_{new_status}"}
                ))
        
        # Check reactivation requirements
        if current_status in ['suspended', 'inactive'] and new_status == 'active':
            violations.extend(self._validate_reactivation(user_data, actor_role))
        
        # Check auto-suspension criteria
        if current_status == 'active' and new_status == 'suspended':
            violations.extend(self._validate_suspension(user_data))
        
        # Check deletion requirements
        if new_status == 'deleted':
            violations.extend(self._validate_deletion(user_data, actor_role))
        
        return violations
    
    def is_compliant(self, **kwargs) -> bool:
        """Check if status transition is compliant."""
        violations = self.validate(**kwargs)
        return not self.has_blocking_violations(violations)
    
    def _is_valid_transition(self, from_status: str, to_status: str) -> bool:
        """Check if a status transition is valid."""
        return to_status in self.allowed_transitions.get(from_status, set())
    
    def _validate_reactivation(
        self,
        user_data: dict[str, Any],
        actor_role: str | None
    ) -> list[PolicyViolation]:
        """Validate reactivation requirements."""
        violations = []
        
        # Check if admin approval is required
        if self.require_admin_approval_for_reactivation and actor_role != 'admin':
            deactivated_at = user_data.get('deactivated_at')
            if deactivated_at:
                days_inactive = (datetime.utcnow() - deactivated_at).days
                
                if days_inactive > self.allow_self_reactivation_within_days:
                    violations.append(PolicyViolation(
                        rule_name="UserStatusPolicy",
                        description="Admin approval required for reactivation",
                        severity="error",
                        current_value=actor_role,
                        expected_value="admin",
                        context={
                            "days_inactive": days_inactive,
                            "self_reactivation_window": self.allow_self_reactivation_within_days
                        }
                    ))
        
        # Check if MFA setup is required
        if self.require_mfa_after_reactivation and not user_data.get('mfa_enabled'):
            violations.append(PolicyViolation(
                rule_name="UserStatusPolicy",
                description="MFA setup required after reactivation",
                severity="warning",
                current_value="mfa_disabled",
                expected_value="mfa_enabled",
                context={"user_id": user_data.get('id')}
            ))
        
        return violations
    
    def _validate_suspension(self, user_data: dict[str, Any]) -> list[PolicyViolation]:
        """Validate suspension requirements."""
        violations = []
        
        # Check if user has been notified
        last_activity = user_data.get('last_activity_at')
        if last_activity:
            days_inactive = (datetime.utcnow() - last_activity).days
            
            if days_inactive < self.auto_suspend_after_days_inactive:
                violations.append(PolicyViolation(
                    rule_name="UserStatusPolicy",
                    description="User has not met auto-suspension criteria",
                    severity="info",
                    current_value=days_inactive,
                    expected_value=self.auto_suspend_after_days_inactive,
                    context={"last_activity": last_activity.isoformat()}
                ))
        
        return violations
    
    def _validate_deletion(
        self,
        user_data: dict[str, Any],
        actor_role: str | None
    ) -> list[PolicyViolation]:
        """Validate deletion requirements."""
        violations = []
        
        # Only admins can delete users
        if actor_role != 'admin':
            violations.append(PolicyViolation(
                rule_name="UserStatusPolicy",
                description="Only administrators can delete users",
                severity="error",
                current_value=actor_role,
                expected_value="admin",
                context={"user_id": user_data.get('id')}
            ))
        
        # Check if user has pending obligations
        if user_data.get('has_pending_obligations'):
            violations.append(PolicyViolation(
                rule_name="UserStatusPolicy",
                description="Cannot delete user with pending obligations",
                severity="error",
                current_value="has_obligations",
                expected_value="no_obligations",
                context={"user_id": user_data.get('id')}
            ))
        
        return violations
    
    def should_auto_suspend(self, last_activity: datetime) -> bool:
        """Check if user should be auto-suspended due to inactivity."""
        days_inactive = (datetime.utcnow() - last_activity).days
        return days_inactive >= self.auto_suspend_after_days_inactive
    
    def should_notify_before_suspension(self, last_activity: datetime) -> bool:
        """Check if user should be notified about pending suspension."""
        days_inactive = (datetime.utcnow() - last_activity).days
        days_until_suspension = self.auto_suspend_after_days_inactive - days_inactive
        
        return 0 < days_until_suspension <= self.notify_before_auto_suspension_days
    
    def get_status_transition_requirements(
        self,
        from_status: str,
        to_status: str
    ) -> dict[str, Any]:
        """Get requirements for a specific status transition."""
        requirements = {
            'allowed': self._is_valid_transition(from_status, to_status),
            'admin_required': False,
            'mfa_required': False,
            'notification_required': True
        }
        
        # Special requirements for specific transitions
        if from_status in ['suspended', 'inactive'] and to_status == 'active':
            requirements['admin_required'] = self.require_admin_approval_for_reactivation
            requirements['mfa_required'] = self.require_mfa_after_reactivation
        
        if to_status == 'deleted':
            requirements['admin_required'] = True
            requirements['notification_required'] = True
        
        return requirements
    
    def calculate_auto_action_date(
        self,
        user_status: str,
        last_activity: datetime
    ) -> datetime | None:
        """Calculate when automatic action should be taken."""
        if user_status == 'active':
            # Calculate auto-suspension date
            return last_activity + timedelta(days=self.auto_suspend_after_days_inactive)
        
        if user_status in ['suspended', 'inactive']:
            # Calculate permanent deletion date
            return last_activity + timedelta(days=self.permanent_deletion_after_days)
        
        return None