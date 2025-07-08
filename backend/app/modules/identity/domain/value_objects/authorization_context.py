"""
Authorization Context Value Object

Immutable representation of the context for authorization decisions.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any

from .base import ValueObject


class AuthorizationDecision(Enum):
    """Authorization decision outcomes."""
    
    ALLOW = "allow"
    DENY = "deny"
    CONDITIONAL = "conditional"
    NOT_APPLICABLE = "not_applicable"


class AuthorizationFactor(Enum):
    """Factors that influence authorization decisions."""
    
    USER_ROLE = "user_role"
    USER_PERMISSION = "user_permission"
    GROUP_MEMBERSHIP = "group_membership"
    RESOURCE_OWNERSHIP = "resource_ownership"
    TIME_BASED = "time_based"
    LOCATION_BASED = "location_based"
    DEVICE_TRUST = "device_trust"
    MFA_STATUS = "mfa_status"
    SESSION_TYPE = "session_type"
    RISK_LEVEL = "risk_level"
    COMPLIANCE_STATUS = "compliance_status"
    DELEGATION = "delegation"
    EMERGENCY_ACCESS = "emergency_access"


@dataclass(frozen=True)
class AuthorizationContext(ValueObject):
    """
    Value object representing the context for an authorization decision.
    
    Captures all relevant information needed to make and audit
    authorization decisions.
    """
    
    # Core identifiers
    user_id: str
    action: str
    resource_type: str
    resource_id: str | None = None
    
    # User context
    user_roles: list[str] = field(default_factory=list)
    user_permissions: set[str] = field(default_factory=set)
    group_memberships: list[str] = field(default_factory=list)
    
    # Session context
    session_id: str | None = None
    session_type: str | None = None
    authentication_method: str | None = None
    mfa_verified: bool = False
    
    # Device and location context
    device_id: str | None = None
    device_trusted: bool = False
    ip_address: str | None = None
    location_country: str | None = None
    location_region: str | None = None
    
    # Risk and compliance context
    risk_level: str | None = None
    compliance_flags: dict[str, bool] = field(default_factory=dict)
    
    # Time context
    request_time: datetime | None = None
    
    # Additional context
    delegation_from: str | None = None  # User ID if delegated
    emergency_access: bool = False
    additional_context: dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate authorization context."""
        if not self.user_id:
            raise ValueError("User ID is required")
        
        if not self.action:
            raise ValueError("Action is required")
        
        if not self.resource_type:
            raise ValueError("Resource type is required")
        
        # Ensure request_time is timezone-aware if provided
        if self.request_time and self.request_time.tzinfo is None:
            object.__setattr__(self, 'request_time', self.request_time.replace(tzinfo=UTC))
        
        # Ensure immutability of mutable defaults
        if self.user_roles:
            object.__setattr__(self, 'user_roles', tuple(self.user_roles))
        
        if self.user_permissions:
            object.__setattr__(self, 'user_permissions', frozenset(self.user_permissions))
        
        if self.group_memberships:
            object.__setattr__(self, 'group_memberships', tuple(self.group_memberships))
        
        if self.compliance_flags:
            object.__setattr__(self, 'compliance_flags', dict(self.compliance_flags))
        
        if self.additional_context:
            object.__setattr__(self, 'additional_context', dict(self.additional_context))
    
    @property
    def is_authenticated(self) -> bool:
        """Check if user is authenticated."""
        return bool(self.session_id)
    
    @property
    def is_multi_factor_authenticated(self) -> bool:
        """Check if user has completed MFA."""
        return self.is_authenticated and self.mfa_verified
    
    @property
    def is_trusted_context(self) -> bool:
        """Check if this is a trusted context."""
        return (
            self.device_trusted and
            self.mfa_verified and
            self.risk_level in (None, 'low')
        )
    
    @property
    def is_delegated(self) -> bool:
        """Check if this is a delegated action."""
        return self.delegation_from is not None
    
    @property
    def is_emergency(self) -> bool:
        """Check if this is emergency access."""
        return self.emergency_access
    
    @property
    def has_elevated_privileges(self) -> bool:
        """Check if context has elevated privileges."""
        return self.is_emergency or 'admin' in self.user_roles
    
    def has_permission(self, permission: str) -> bool:
        """Check if context has a specific permission."""
        return permission in self.user_permissions
    
    def has_role(self, role: str) -> bool:
        """Check if context has a specific role."""
        return role in self.user_roles
    
    def is_member_of_group(self, group_id: str) -> bool:
        """Check if user is member of a specific group."""
        return group_id in self.group_memberships
    
    def get_factors(self) -> set[AuthorizationFactor]:
        """Get all authorization factors present in this context."""
        factors = set()
        
        if self.user_roles:
            factors.add(AuthorizationFactor.USER_ROLE)
        
        if self.user_permissions:
            factors.add(AuthorizationFactor.USER_PERMISSION)
        
        if self.group_memberships:
            factors.add(AuthorizationFactor.GROUP_MEMBERSHIP)
        
        if self.request_time:
            factors.add(AuthorizationFactor.TIME_BASED)
        
        if self.ip_address or self.location_country:
            factors.add(AuthorizationFactor.LOCATION_BASED)
        
        if self.device_id:
            factors.add(AuthorizationFactor.DEVICE_TRUST)
        
        if self.mfa_verified:
            factors.add(AuthorizationFactor.MFA_STATUS)
        
        if self.session_type:
            factors.add(AuthorizationFactor.SESSION_TYPE)
        
        if self.risk_level:
            factors.add(AuthorizationFactor.RISK_LEVEL)
        
        if self.compliance_flags:
            factors.add(AuthorizationFactor.COMPLIANCE_STATUS)
        
        if self.delegation_from:
            factors.add(AuthorizationFactor.DELEGATION)
        
        if self.emergency_access:
            factors.add(AuthorizationFactor.EMERGENCY_ACCESS)
        
        return factors
    
    def with_decision(
        self,
        decision: AuthorizationDecision,
        reason: str | None = None,
        applied_policies: list[str] | None = None
    ) -> dict[str, Any]:
        """
        Create an authorization decision based on this context.
        
        Note: This would typically return a separate AuthorizationDecision
        value object, but keeping it simple for this example.
        """
        return {
            'decision': decision,
            'reason': reason,
            'applied_policies': applied_policies or [],
            'context_factors': [f.value for f in self.get_factors()],
            'timestamp': datetime.now(UTC).isoformat()
        }
    
    def to_audit_log(self) -> dict[str, Any]:
        """Convert to format suitable for audit logging."""
        return {
            'user_id': self.user_id,
            'action': self.action,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'session_id': self.session_id,
            'roles': list(self.user_roles),
            'permissions': list(self.user_permissions),
            'groups': list(self.group_memberships),
            'mfa_verified': self.mfa_verified,
            'device_trusted': self.device_trusted,
            'ip_address': self.ip_address,
            'location': {
                'country': self.location_country,
                'region': self.location_region
            },
            'risk_level': self.risk_level,
            'is_delegated': self.is_delegated,
            'delegation_from': self.delegation_from,
            'is_emergency': self.is_emergency,
            'factors': [f.value for f in self.get_factors()],
            'request_time': self.request_time.isoformat() if self.request_time else None
        }
    
    def anonymize(self) -> 'AuthorizationContext':
        """Create anonymized context for analytics."""
        return AuthorizationContext(
            user_id='anonymous',
            action=self.action,
            resource_type=self.resource_type,
            resource_id=None,
            user_roles=list(self.user_roles),
            user_permissions=set(),  # Don't expose specific permissions
            group_memberships=[],  # Don't expose groups
            session_id=None,
            session_type=self.session_type,
            authentication_method=self.authentication_method,
            mfa_verified=self.mfa_verified,
            device_trusted=self.device_trusted,
            location_country=self.location_country,
            risk_level=self.risk_level,
            request_time=None
        )
    
    def __str__(self) -> str:
        """String representation."""
        return f"AuthorizationContext(user={self.user_id}, action={self.action}, resource={self.resource_type})"
    
    def __repr__(self) -> str:
        """Debug representation."""
        factors = len(self.get_factors())
        return f"AuthorizationContext(factors={factors}, mfa={self.mfa_verified}, trusted={self.is_trusted_context})"