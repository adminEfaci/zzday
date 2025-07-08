"""
Identity Domain Specifications Package

Business rule specifications for user-related operations.
"""

# Base Specifications
from .base import (
    AndSpecification,
    BaseSpecification,
    CachedSpecification,
    NotSpecification,
    OrSpecification,
    ParameterizedSpecification,
    TimeBasedSpecification,
)

# Composite Specifications
from .composite_specs import (
    ComplianceReadyUserSpecification,
    HighRiskLoginSpecification,
    SecureUserSpecification,
    TrustedSessionSpecification,
)

# Additional specifications from other files
from .inactive_user_spec import InactiveUserSpecification

# Permission Specifications
from .permission_specs import (
    ActionPermissionSpecification,
    ConditionalPermissionSpecification,
    DeprecatedPermissionSpecification,
    EffectivePermissionSpecification,
    ExclusivePermissionSpecification,
    HasPermissionSpecification,
    PermissionByCategorySpecification,
    PermissionInheritanceSpecification,
    PermissionScopeSpecification,
    ResourcePermissionSpecification,
    SystemPermissionSpecification,
    TemporaryPermissionSpecification,
    WildcardPermissionSpecification,
)

# Role Specifications  
from .role_specs import (
    AssignableRoleSpecification,
    ConditionalRoleSpecification,
    DepartmentRoleSpecification,
    ElevatedRoleSpecification,
    InheritableRoleSpecification,
    MaxUsersRoleSpecification,
    RoleActiveSpecification,
    RoleByLevelSpecification,
    RoleConflictSpecification,
    RoleHierarchySpecification,
    RoleInUseSpecification,
    RolePermissionSpecification,
    SystemRoleSpecification,
    TemporaryRoleSpecification,
)

# Security Specifications
from .security_specs import (
    AccountLockedSpecification,
    AccountTakeoverSpecification,
    AnomalousLocationSpecification,
    BotActivitySpecification,
    BruteForceSpecification,
    CredentialStuffingSpecification,
    DistributedAttackSpecification,
    GeographicAnomalySpecification,
    HighRiskSpecification,
    MultipleFailedLoginsSpecification,
    OffHoursActivitySpecification,
    SecurityEventSpecification,
    SuspiciousActivitySpecification,
    SuspiciousIpSpecification,
    VelocityAttackSpecification,
)

# Session Specifications
from .session_specs import (
    ActiveSessionSpecification,
    ConcurrentSessionSpecification,
    ElevatedPrivilegeSessionSpecification,
    ExpiredSessionSpecification,
    HighVelocitySessionSpecification,
    InactiveSessionSpecification,
    LongRunningSessionSpecification,
    RequiresMFASessionSpecification,
    SessionByRiskLevelSpecification,
    SessionByTypeSpecification,
    SessionDeviceMismatchSpecification,
    SessionFromUnknownLocationSpecification,
    SessionIpChangeSpecification,
    SessionRequiresRefreshSpecification,
    StaleSessionSpecification,
    SuspiciousSessionSpecification,
    TrustedSessionSpecification,
)

# User Specifications
from .user_specs import (
    ActiveUserSpecification,
    AdminUserSpecification,
    CanLoginSpecification,
    ComplianceSpecification,
    CompliantUserSpecification,
    FailedLoginSpecification,
    HighPrivilegeUserSpecification,
    MFAEnabledSpecification,
    PasswordExpiredSpecification,
    PendingVerificationSpecification,
    RecentlyActiveUsersSpecification,
    RequiresMFASpecification,
    SuspendedUserSpecification,
    UserByRoleSpecification,
    UsersByDepartmentSpecification,
    VerifiedEmailSpecification,
)

__all__ = [
    # Security Specifications
    "AccountLockedSpecification",
    "AccountTakeoverSpecification",
    # Permission Specifications
    "ActionPermissionSpecification",
    # Session Specifications
    "ActiveSessionSpecification",
    # User Specifications
    "ActiveUserSpecification",
    "AdminUserSpecification",
    "AndSpecification",
    "AnomalousLocationSpecification",
    # Role Specifications
    "AssignableRoleSpecification",
    # Base Specifications
    "BaseSpecification",
    "BotActivitySpecification",
    "BruteForceSpecification",
    "CachedSpecification",
    "CanLoginSpecification",
    "ComplianceReadyUserSpecification",
    "ComplianceSpecification",
    "CompliantUserSpecification",
    "ConcurrentSessionSpecification",
    "ConditionalPermissionSpecification",
    "ConditionalRoleSpecification",
    "CredentialStuffingSpecification",
    "DepartmentRoleSpecification",
    "DeprecatedPermissionSpecification",
    "DistributedAttackSpecification",
    "EffectivePermissionSpecification",
    "ElevatedPrivilegeSessionSpecification",
    "ElevatedRoleSpecification",
    "ExclusivePermissionSpecification",
    "ExpiredSessionSpecification",
    "FailedLoginSpecification",
    "GeographicAnomalySpecification",
    "HasPermissionSpecification",
    "HighPrivilegeUserSpecification",
    "HighRiskLoginSpecification",
    "HighRiskSpecification",
    "HighVelocitySessionSpecification",
    "InactiveSessionSpecification",
    "InactiveUserSpecification",
    "InheritableRoleSpecification",
    "LongRunningSessionSpecification",
    "MFAEnabledSpecification",
    "MaxUsersRoleSpecification",
    "MultipleFailedLoginsSpecification",
    "NotSpecification",
    "OffHoursActivitySpecification",
    "OrSpecification",
    "ParameterizedSpecification",
    "PasswordExpiredSpecification",
    "PendingVerificationSpecification",
    "PermissionByCategorySpecification",
    "PermissionInheritanceSpecification",
    "PermissionScopeSpecification",
    "RecentlyActiveUsersSpecification",
    "RequiresMFASessionSpecification",
    "RequiresMFASpecification",
    "ResourcePermissionSpecification",
    "RoleActiveSpecification",
    "RoleByLevelSpecification",
    "RoleConflictSpecification",
    "RoleHierarchySpecification",
    "RoleInUseSpecification",
    "RolePermissionSpecification",
    # Composite Specifications
    "SecureUserSpecification",
    "SecurityEventSpecification",
    "SessionByRiskLevelSpecification",
    "SessionByTypeSpecification",
    "SessionDeviceMismatchSpecification",
    "SessionFromUnknownLocationSpecification",
    "SessionIpChangeSpecification",
    "SessionRequiresRefreshSpecification",
    "StaleSessionSpecification",
    "SuspendedUserSpecification",
    "SuspiciousActivitySpecification",
    "SuspiciousIpSpecification",
    "SuspiciousSessionSpecification",
    "SystemPermissionSpecification",
    "SystemRoleSpecification",
    "TemporaryPermissionSpecification",
    "TemporaryRoleSpecification",
    "TimeBasedSpecification",
    "TrustedSessionSpecification",
    "TrustedSessionSpecification",
    "UserByRoleSpecification",
    "UsersByDepartmentSpecification",
    "VelocityAttackSpecification",
    "VerifiedEmailSpecification",
    "WildcardPermissionSpecification",
]
