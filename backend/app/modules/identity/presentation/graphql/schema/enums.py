"""
GraphQL Enum Definitions for Identity Module

This module contains all GraphQL enum type definitions that correspond to
domain enums used throughout the identity module.
"""


import graphene

from app.modules.identity.domain.entities.role.role_enums import (
    InheritanceMode as DomainInheritanceMode,
)
from app.modules.identity.domain.entities.role.role_enums import (
    PermissionEffect as DomainPermissionEffect,
)
from app.modules.identity.domain.entities.role.role_enums import (
    PermissionScope as DomainRolePermissionScope,
)
from app.modules.identity.domain.entities.role.role_enums import (
    PermissionType as DomainPermissionType,
)
from app.modules.identity.domain.entities.role.role_enums import (
    ResourceType as DomainResourceType,
)
from app.modules.identity.domain.entities.role.role_enums import (
    UserRole as DomainUserRole,
)
from app.modules.identity.domain.entities.session.session_enums import (
    SessionStatus as DomainSessionStatus,
)
from app.modules.identity.domain.entities.session.session_enums import (
    SessionType as DomainSessionType,
)
from app.modules.identity.domain.entities.user.user_enums import (
    DateFormat as DomainDateFormat,
)
from app.modules.identity.domain.entities.user.user_enums import (
    Department as DomainDepartment,
)
from app.modules.identity.domain.entities.user.user_enums import (
    Language as DomainLanguage,
)
from app.modules.identity.domain.entities.user.user_enums import (
    MFAMethod as DomainUserMFAMethod,
)
from app.modules.identity.domain.entities.user.user_enums import (
    NotificationChannel as DomainNotificationChannel,
)
from app.modules.identity.domain.entities.user.user_enums import (
    Relationship as DomainRelationship,
)
from app.modules.identity.domain.entities.user.user_enums import (
    TimeFormat as DomainTimeFormat,
)
from app.modules.identity.domain.entities.user.user_enums import (
    UserStatus as DomainUserEntityStatus,
)
from app.modules.identity.domain.enums import (
    AccountType as DomainAccountType,
)
from app.modules.identity.domain.enums import (
    AuditAction as DomainAuditAction,
)
from app.modules.identity.domain.enums import (
    AuthenticationMethod as DomainAuthenticationMethod,
)
from app.modules.identity.domain.enums import (
    ComplianceStatus as DomainComplianceStatus,
)
from app.modules.identity.domain.enums import (
    DeviceType as DomainDeviceType,
)
from app.modules.identity.domain.enums import (
    LoginFailureReason as DomainLoginFailureReason,
)
from app.modules.identity.domain.enums import (
    NotificationType as DomainNotificationType,
)
from app.modules.identity.domain.enums import (
    RiskLevel as DomainRiskLevel,
)
from app.modules.identity.domain.enums import (
    SecurityEventType as DomainSecurityEventType,
)
from app.modules.identity.domain.enums import (
    VerificationStatus as DomainVerificationStatus,
)


class UserStatusEnum(graphene.Enum):
    """User account status enumeration."""
    
    class Meta:
        description = "Status of a user account"
    
    PENDING_VERIFICATION = "pending_verification"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    DEACTIVATED = "deactivated"
    LOCKED = "locked"
    TERMINATED = "terminated"
    
    @classmethod
    def from_domain(cls, domain_enum: DomainUserEntityStatus) -> "UserStatusEnum":
        """Convert from domain enum to GraphQL enum."""
        return cls(domain_enum.value)


class MFAMethodEnum(graphene.Enum):
    """Multi-factor authentication method enumeration."""
    
    class Meta:
        description = "Available multi-factor authentication methods"
    
    TOTP = "totp"
    SMS = "sms"
    EMAIL = "email"
    HARDWARE_TOKEN = "hardware_token"  # noqa: S105
    BIOMETRIC = "biometric"
    BACKUP_CODES = "backup_codes"
    PUSH_NOTIFICATION = "push_notification"
    
    @classmethod
    def from_domain(cls, domain_enum: DomainUserMFAMethod) -> "MFAMethodEnum":
        """Convert from domain enum to GraphQL enum."""
        return cls(domain_enum.value)


class SessionStatusEnum(graphene.Enum):
    """Session status enumeration."""
    
    class Meta:
        description = "Status of a user session"
    
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    TERMINATED = "terminated"
    REFRESHING = "refreshing"
    
    @classmethod
    def from_domain(cls, domain_enum: DomainSessionStatus) -> "SessionStatusEnum":
        """Convert from domain enum to GraphQL enum."""
        return cls(domain_enum.value)


class SessionTypeEnum(graphene.Enum):
    """Session type enumeration."""
    
    class Meta:
        description = "Type of user session"
    
    WEB = "web"
    MOBILE = "mobile"
    API = "api"
    SERVICE = "service"
    ADMIN = "admin"
    
    @classmethod
    def from_domain(cls, domain_enum: DomainSessionType) -> "SessionTypeEnum":
        """Convert from domain enum to GraphQL enum."""
        return cls(domain_enum.value)


class UserRoleEnum(graphene.Enum):
    """User role enumeration."""
    
    class Meta:
        description = "Available user roles with different permission levels"
    
    SUPER_ADMIN = "super_admin"
    ADMIN = "admin"
    MANAGER = "manager"
    USER = "user"
    GUEST = "guest"
    SERVICE_ACCOUNT = "service_account"
    SUPERVISOR = "supervisor"
    DISPATCHER = "dispatcher"
    DRIVER = "driver"
    LOADER = "loader"
    AUDITOR = "auditor"
    
    @classmethod
    def from_domain(cls, domain_enum: DomainUserRole) -> "UserRoleEnum":
        """Convert from domain enum to GraphQL enum."""
        return cls(domain_enum.value)


class PermissionTypeEnum(graphene.Enum):
    """Permission type enumeration."""
    
    class Meta:
        description = "Types of permissions that can be granted"
    
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    EXECUTE = "execute"
    APPROVE = "approve"
    REJECT = "reject"
    DELEGATE = "delegate"
    AUDIT = "audit"
    CONFIGURE = "configure"
    
    @classmethod
    def from_domain(cls, domain_enum: DomainPermissionType) -> "PermissionTypeEnum":
        """Convert from domain enum to GraphQL enum."""
        return cls(domain_enum.value)


class PermissionScopeEnum(graphene.Enum):
    """Permission scope enumeration."""
    
    class Meta:
        description = "Scope levels for permissions"
    
    GLOBAL = "global"
    ORGANIZATION = "organization"
    DEPARTMENT = "department"
    TEAM = "team"
    USER = "user"
    RESOURCE = "resource"
    
    @classmethod
    def from_domain(
        cls, domain_enum: DomainRolePermissionScope
    ) -> "PermissionScopeEnum":
        """Convert from domain enum to GraphQL enum."""
        return cls(domain_enum.value)


class ResourceTypeEnum(graphene.Enum):
    """Resource type enumeration for permissions."""
    
    class Meta:
        description = "Types of resources that permissions can be applied to"
    
    USER = "user"
    ROLE = "role"
    PERMISSION = "permission"
    GROUP = "group"
    AUDIT_LOG = "audit_log"
    CONFIGURATION = "configuration"
    API_KEY = "api_key"
    SESSION = "session"
    REPORT = "report"
    NOTIFICATION = "notification"
    ROUTE = "route"
    VEHICLE = "vehicle"
    FACILITY = "facility"
    CUSTOMER = "customer"
    CONTRACT = "contract"
    INVOICE = "invoice"
    PICKUP = "pickup"
    DELIVERY = "delivery"
    
    @classmethod
    def from_domain(cls, domain_enum: DomainResourceType) -> "ResourceTypeEnum":
        """Convert from domain enum to GraphQL enum."""
        return cls(domain_enum.value)


class PermissionEffectEnum(graphene.Enum):
    """Permission effect enumeration."""
    
    class Meta:
        description = "Effect of a permission (allow or deny)"
    
    ALLOW = "allow"
    DENY = "deny"
    
    @classmethod
    def from_domain(cls, domain_enum: DomainPermissionEffect) -> "PermissionEffectEnum":
        """Convert from domain enum to GraphQL enum."""
        return cls(domain_enum.value)


class AuditActionEnum(graphene.Enum):
    """Audit action enumeration."""
    
    class Meta:
        description = "Types of actions that can be audited"
    
    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    LOGIN = "login"
    LOGOUT = "logout"
    PERMISSION_GRANT = "permission_grant"
    PERMISSION_REVOKE = "permission_revoke"
    ROLE_ASSIGN = "role_assign"
    ROLE_UNASSIGN = "role_unassign"
    PASSWORD_CHANGE = "password_change"  # noqa: S105
    MFA_ENABLE = "mfa_enable"
    MFA_DISABLE = "mfa_disable"
    SECURITY_ALERT = "security_alert"
    
    @classmethod
    def from_domain(cls, domain_enum: DomainAuditAction) -> "AuditActionEnum":
        """Convert from domain enum to GraphQL enum."""
        return cls(domain_enum.value)


class NotificationTypeEnum(graphene.Enum):
    """Notification type enumeration."""
    
    class Meta:
        description = "Types of notifications that can be sent"
    
    SECURITY_ALERT = "security_alert"
    PASSWORD_EXPIRY = "password_expiry"  # noqa: S105
    LOGIN_FROM_NEW_DEVICE = "login_from_new_device"
    PERMISSION_CHANGE = "permission_change"
    ACCOUNT_LOCKED = "account_locked"
    MFA_BACKUP_CODES = "mfa_backup_codes"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    COMPLIANCE_VIOLATION = "compliance_violation"
    SYSTEM_MAINTENANCE = "system_maintenance"
    
    @classmethod
    def from_domain(cls, domain_enum: DomainNotificationType) -> "NotificationTypeEnum":
        """Convert from domain enum to GraphQL enum."""
        return cls(domain_enum.value)


class SecurityEventTypeEnum(graphene.Enum):
    """Security event type enumeration."""
    
    class Meta:
        description = "Types of security events that can be detected"
    
    BRUTE_FORCE_ATTACK = "brute_force_attack"
    CREDENTIAL_STUFFING = "credential_stuffing"
    SUSPICIOUS_LOGIN = "suspicious_login"
    ANOMALOUS_BEHAVIOR = "anomalous_behavior"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    MALWARE_DETECTION = "malware_detection"
    MULTIPLE_FAILED_ATTEMPTS = "multiple_failed_attempts"
    UNUSUAL_LOCATION = "unusual_location"
    IMPOSSIBLE_TRAVEL = "impossible_travel"
    NEW_DEVICE = "new_device"
    
    @classmethod
    def from_domain(
        cls, domain_enum: DomainSecurityEventType
    ) -> "SecurityEventTypeEnum":
        """Convert from domain enum to GraphQL enum."""
        return cls(domain_enum.value)


class DeviceTypeEnum(graphene.Enum):
    """Device type enumeration."""
    
    class Meta:
        description = "Types of devices that can access the system"
    
    DESKTOP = "desktop"
    LAPTOP = "laptop"
    SMARTPHONE = "smartphone"
    TABLET = "tablet"
    MOBILE_IOS = "mobile_ios"
    MOBILE_ANDROID = "mobile_android"
    MOBILE_OTHER = "mobile_other"
    TABLET_IOS = "tablet_ios"
    TABLET_ANDROID = "tablet_android"
    TABLET_OTHER = "tablet_other"
    IOT_DEVICE = "iot_device"
    SERVER = "server"
    UNKNOWN = "unknown"
    OTHER = "other"
    
    @classmethod
    def from_domain(cls, domain_enum: DomainDeviceType) -> "DeviceTypeEnum":
        """Convert from domain enum to GraphQL enum."""
        return cls(domain_enum.value)


class RiskLevelEnum(graphene.Enum):
    """Risk level enumeration."""
    
    class Meta:
        description = "Risk assessment levels"
    
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    
    @classmethod
    def from_domain(cls, domain_enum: DomainRiskLevel) -> "RiskLevelEnum":
        """Convert from domain enum to GraphQL enum."""
        return cls(domain_enum.value)


class VerificationStatusEnum(graphene.Enum):
    """Verification status enumeration."""
    
    class Meta:
        description = "Status of verification processes"
    
    PENDING = "pending"
    VERIFIED = "verified"
    FAILED = "failed"
    EXPIRED = "expired"
    
    @classmethod
    def from_domain(
        cls, domain_enum: DomainVerificationStatus
    ) -> "VerificationStatusEnum":
        """Convert from domain enum to GraphQL enum."""
        return cls(domain_enum.value)


class LoginFailureReasonEnum(graphene.Enum):
    """Login failure reason enumeration."""
    
    class Meta:
        description = "Reasons why a login attempt might fail"
    
    INVALID_CREDENTIALS = "invalid_credentials"
    INVALID_EMAIL = "invalid_email"
    INVALID_PASSWORD = "invalid_password"  # noqa: S105
    ACCOUNT_NOT_FOUND = "account_not_found"
    ACCOUNT_INACTIVE = "account_inactive"
    ACCOUNT_LOCKED = "account_locked"
    ACCOUNT_SUSPENDED = "account_suspended"
    ACCOUNT_DEACTIVATED = "account_deactivated"
    EMAIL_NOT_VERIFIED = "email_not_verified"
    MFA_REQUIRED = "mfa_required"
    MFA_FAILED = "mfa_failed"
    PASSWORD_EXPIRED = "password_expired"  # noqa: S105
    TOO_MANY_ATTEMPTS = "too_many_attempts"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    IP_BLOCKED = "ip_blocked"
    RATE_LIMITED = "rate_limited"
    MAINTENANCE_MODE = "maintenance_mode"
    UNKNOWN = "unknown"
    
    @classmethod
    def from_domain(
        cls, domain_enum: DomainLoginFailureReason
    ) -> "LoginFailureReasonEnum":
        """Convert from domain enum to GraphQL enum."""
        return cls(domain_enum.value)


class AccountTypeEnum(graphene.Enum):
    """Account type enumeration."""
    
    class Meta:
        description = "Types of user accounts"
    
    INDIVIDUAL = "individual"
    BUSINESS = "business"
    ENTERPRISE = "enterprise"
    GOVERNMENT = "government"
    NON_PROFIT = "non_profit"
    EDUCATIONAL = "educational"
    
    @classmethod
    def from_domain(cls, domain_enum: DomainAccountType) -> "AccountTypeEnum":
        """Convert from domain enum to GraphQL enum."""
        return cls(domain_enum.value)


class AuthenticationMethodEnum(graphene.Enum):
    """Authentication method enumeration."""
    
    class Meta:
        description = "Methods of authentication supported by the system"
    
    PASSWORD = "password"  # noqa: S105
    MFA = "mfa"
    SSO = "sso"
    OAUTH = "oauth"
    BIOMETRIC = "biometric"
    API_KEY = "api_key"
    CERTIFICATE = "certificate"
    
    @classmethod
    def from_domain(
        cls, domain_enum: DomainAuthenticationMethod
    ) -> "AuthenticationMethodEnum":
        """Convert from domain enum to GraphQL enum."""
        return cls(domain_enum.value)


class ComplianceStatusEnum(graphene.Enum):
    """Compliance status enumeration."""
    
    class Meta:
        description = "Compliance status levels"
    
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    UNDER_REVIEW = "under_review"
    REMEDIATION_REQUIRED = "remediation_required"
    
    @classmethod
    def from_domain(cls, domain_enum: DomainComplianceStatus) -> "ComplianceStatusEnum":
        """Convert from domain enum to GraphQL enum."""
        return cls(domain_enum.value)


class RelationshipEnum(graphene.Enum):
    """Emergency contact relationship enumeration."""
    
    class Meta:
        description = "Types of relationships for emergency contacts"
    
    SPOUSE = "spouse"
    PARENT = "parent"
    CHILD = "child"
    SIBLING = "sibling"
    RELATIVE = "relative"
    FRIEND = "friend"
    COLLEAGUE = "colleague"
    GUARDIAN = "guardian"
    OTHER = "other"
    
    @classmethod
    def from_domain(cls, domain_enum: DomainRelationship) -> "RelationshipEnum":
        """Convert from domain enum to GraphQL enum."""
        return cls(domain_enum.value)


class DepartmentEnum(graphene.Enum):
    """Department enumeration."""
    
    class Meta:
        description = "Available departments in the organization"
    
    OPERATIONS = "operations"
    DISPATCH = "dispatch"
    MAINTENANCE = "maintenance"
    CUSTOMER_SERVICE = "customer_service"
    BILLING = "billing"
    COMPLIANCE = "compliance"
    IT = "it"
    HR = "hr"
    FINANCE = "finance"
    MANAGEMENT = "management"
    
    @classmethod
    def from_domain(cls, domain_enum: DomainDepartment) -> "DepartmentEnum":
        """Convert from domain enum to GraphQL enum."""
        return cls(domain_enum.value)


class LanguageEnum(graphene.Enum):
    """Language preference enumeration."""
    
    class Meta:
        description = "Supported languages for user preferences"
    
    EN = "en"
    ES = "es"
    FR = "fr"
    DE = "de"
    IT = "it"
    PT = "pt"
    ZH = "zh"
    JA = "ja"
    KO = "ko"
    AR = "ar"
    
    @classmethod
    def from_domain(cls, domain_enum: DomainLanguage) -> "LanguageEnum":
        """Convert from domain enum to GraphQL enum."""
        return cls(domain_enum.value)


class DateFormatEnum(graphene.Enum):
    """Date format preference enumeration."""
    
    class Meta:
        description = "Available date format preferences"
    
    MM_DD_YYYY = "MM/DD/YYYY"
    DD_MM_YYYY = "DD/MM/YYYY"
    YYYY_MM_DD = "YYYY-MM-DD"
    DD_MON_YYYY = "DD-MON-YYYY"
    
    @classmethod
    def from_domain(cls, domain_enum: DomainDateFormat) -> "DateFormatEnum":
        """Convert from domain enum to GraphQL enum."""
        return cls(domain_enum.value)


class TimeFormatEnum(graphene.Enum):
    """Time format preference enumeration."""
    
    class Meta:
        description = "Available time format preferences"
    
    TWELVE_HOUR = "12h"
    TWENTY_FOUR_HOUR = "24h"
    
    @classmethod
    def from_domain(cls, domain_enum: DomainTimeFormat) -> "TimeFormatEnum":
        """Convert from domain enum to GraphQL enum."""
        return cls(domain_enum.value)


class NotificationChannelEnum(graphene.Enum):
    """Notification channel preference enumeration."""
    
    class Meta:
        description = "Available notification delivery channels"
    
    EMAIL = "email"
    SMS = "sms"
    PUSH = "push"
    IN_APP = "in_app"
    WEBHOOK = "webhook"
    
    @classmethod
    def from_domain(
        cls, domain_enum: DomainNotificationChannel
    ) -> "NotificationChannelEnum":
        """Convert from domain enum to GraphQL enum."""
        return cls(domain_enum.value)


class InheritanceModeEnum(graphene.Enum):
    """Role inheritance mode enumeration."""
    
    class Meta:
        description = "How role permissions are inherited"
    
    ADDITIVE = "additive"
    OVERRIDE = "override"
    MERGE = "merge"
    
    @classmethod
    def from_domain(cls, domain_enum: DomainInheritanceMode) -> "InheritanceModeEnum":
        """Convert from domain enum to GraphQL enum."""
        return cls(domain_enum.value)


# Order directions for sorting
class SortDirection(graphene.Enum):
    """Sort direction enumeration."""
    
    class Meta:
        description = "Direction for sorting results"
    
    ASC = "asc"
    DESC = "desc"


# Export all enums
__all__ = [
    "AccountTypeEnum",
    "AuditActionEnum",
    "AuthenticationMethodEnum",
    "ComplianceStatusEnum",
    "DateFormatEnum",
    "DepartmentEnum",
    "DeviceTypeEnum",
    "InheritanceModeEnum",
    "LanguageEnum",
    "LoginFailureReasonEnum",
    "MFAMethodEnum",
    "NotificationChannelEnum",
    "NotificationTypeEnum",
    "PermissionEffectEnum",
    "PermissionScopeEnum",
    "PermissionTypeEnum",
    "RelationshipEnum",
    "ResourceTypeEnum",
    "RiskLevelEnum",
    "SecurityEventTypeEnum",
    "SessionStatusEnum",
    "SessionTypeEnum",
    "SortDirection",
    "TimeFormatEnum",
    "UserRoleEnum",
    "UserStatusEnum",
    "VerificationStatusEnum",
]