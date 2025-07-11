"""
Identity Domain Enumerations

Consolidated enums for the entire identity domain with consistent utility methods.
"""

from enum import Enum, IntEnum
from typing import Any


class RiskLevel(IntEnum):
    """Risk level enumeration with numeric values."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    
    def get_display_name(self) -> str:
        """Get human-readable display name."""
        display_names = {
            RiskLevel.LOW: "Low Risk",
            RiskLevel.MEDIUM: "Medium Risk", 
            RiskLevel.HIGH: "High Risk",
            RiskLevel.CRITICAL: "Critical Risk"
        }
        return display_names.get(self, f"Risk Level {self.value}")
    
    def get_color_code(self) -> str:
        """Get color code for UI display."""
        colors = {
            RiskLevel.LOW: "#28a745",      # Green
            RiskLevel.MEDIUM: "#ffc107",   # Yellow
            RiskLevel.HIGH: "#fd7e14",     # Orange
            RiskLevel.CRITICAL: "#dc3545"  # Red
        }
        return colors.get(self, "#6c757d")  # Gray default


# =============================================================================
# User and Account Management
# =============================================================================

class UserStatus(Enum):
    """User account status enumeration."""
    PENDING_VERIFICATION = "pending_verification"
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    DEACTIVATED = "deactivated"
    LOCKED = "locked"
    TERMINATED = "terminated"
    DELETED = "deleted"
    
    def get_display_name(self) -> str:
        """Get human-readable display name."""
        display_names = {
            self.PENDING_VERIFICATION: "Pending Verification",
            self.ACTIVE: "Active",
            self.INACTIVE: "Inactive",
            self.SUSPENDED: "Suspended",
            self.DEACTIVATED: "Deactivated", 
            self.LOCKED: "Locked",
            self.TERMINATED: "Terminated",
            self.DELETED: "Deleted"
        }
        return display_names.get(self, str(self.value).title())
    
    @property
    def is_active(self) -> bool:
        """Check if status allows user activity."""
        return self == self.ACTIVE
    
    @property
    def can_login(self) -> bool:
        """Check if user can log in with this status."""
        return self in {self.ACTIVE}
    
    @property
    def requires_verification(self) -> bool:
        """Check if status requires verification."""
        return self == self.PENDING_VERIFICATION
    
    @property
    def is_recoverable(self) -> bool:
        """Check if account can be recovered/reactivated."""
        return self in {self.INACTIVE, self.SUSPENDED, self.DEACTIVATED}


class AccountType(Enum):
    """Account type enumeration."""
    PERSONAL = "personal"
    BUSINESS = "business"
    ENTERPRISE = "enterprise"
    ADMIN = "admin"
    SERVICE = "service"
    GUEST = "guest"
    
    def get_display_name(self) -> str:
        """Get human-readable display name."""
        display_names = {
            self.PERSONAL: "Personal Account",
            self.BUSINESS: "Business Account",
            self.ENTERPRISE: "Enterprise Account",
            self.ADMIN: "Administrator Account",
            self.SERVICE: "Service Account",
            self.GUEST: "Guest Account"
        }
        return display_names.get(self, str(self.value).title())
    
    @property
    def is_privileged(self) -> bool:
        """Check if account type has elevated privileges."""
        return self in {self.ADMIN, self.SERVICE}


# =============================================================================
# Role Management
# =============================================================================

class RoleStatus(Enum):
    """Role status enumeration."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    DELETED = "deleted"
    
    def get_display_name(self) -> str:
        display_names = {
            self.ACTIVE: "Active",
            self.INACTIVE: "Inactive", 
            self.DELETED: "Deleted"
        }
        return display_names.get(self, self.value)
    
    def is_usable(self) -> bool:
        return self == self.ACTIVE


class RoleType(Enum):
    """Role type enumeration."""
    SYSTEM = "system"
    BUSINESS = "business"
    FUNCTIONAL = "functional"
    TECHNICAL = "technical"
    ADMINISTRATIVE = "administrative"
    TEMPORARY = "temporary"
    
    def get_display_name(self) -> str:
        display_names = {
            self.SYSTEM: "System Role",
            self.BUSINESS: "Business Role",
            self.FUNCTIONAL: "Functional Role", 
            self.TECHNICAL: "Technical Role",
            self.ADMINISTRATIVE: "Administrative Role",
            self.TEMPORARY: "Temporary Role"
        }
        return display_names.get(self, self.value)
    
    def is_system_managed(self) -> bool:
        return self in [self.SYSTEM, self.TECHNICAL]


class UserRole(Enum):
    """User role enumeration."""
    SUPER_ADMIN = "super_admin"
    ADMIN = "admin"
    MANAGER = "manager"
    USER = "user"
    GUEST = "guest"
    SERVICE_ACCOUNT = "service_account"
    # Waste management specific roles
    SUPERVISOR = "supervisor"
    DISPATCHER = "dispatcher"
    DRIVER = "driver"
    LOADER = "loader"
    AUDITOR = "auditor"
    
    def get_display_name(self) -> str:
        display_names = {
            self.SUPER_ADMIN: "Super Administrator",
            self.ADMIN: "Administrator",
            self.MANAGER: "Manager",
            self.USER: "User",
            self.GUEST: "Guest",
            self.SERVICE_ACCOUNT: "Service Account",
            self.SUPERVISOR: "Supervisor",
            self.DISPATCHER: "Dispatcher",
            self.DRIVER: "Driver",
            self.LOADER: "Loader",
            self.AUDITOR: "Auditor"
        }
        return display_names.get(self, self.value)
    
    def get_hierarchy_level(self) -> int:
        levels = {
            self.GUEST: 1,
            self.USER: 2,
            self.LOADER: 2,
            self.DRIVER: 2,
            self.DISPATCHER: 3,
            self.SUPERVISOR: 3,
            self.MANAGER: 3,
            self.AUDITOR: 3,
            self.ADMIN: 4,
            self.SUPER_ADMIN: 5,
            self.SERVICE_ACCOUNT: 0
        }
        return levels.get(self, 0)
    
    def to_role_type(self) -> RoleType:
        """Convert to RoleType."""
        mapping = {
            self.SUPER_ADMIN: RoleType.SYSTEM,
            self.ADMIN: RoleType.ADMINISTRATIVE,
            self.SERVICE_ACCOUNT: RoleType.TECHNICAL,
            self.GUEST: RoleType.SYSTEM
        }
        return mapping.get(self, RoleType.BUSINESS)
    
    @property
    def is_privileged(self) -> bool:
        """Check if role has elevated privileges."""
        return self in {self.ADMIN, self.SUPER_ADMIN, self.MANAGER, self.SUPERVISOR}
    
    @property
    def is_service_account(self) -> bool:
        """Check if this is a service account role."""
        return self == self.SERVICE_ACCOUNT
    
    def get_permissions_level(self) -> int:
        """Get numeric permission level for comparison."""
        levels = {
            self.GUEST: 0,
            self.USER: 10,
            self.LOADER: 15,
            self.DRIVER: 15,
            self.DISPATCHER: 30,
            self.SUPERVISOR: 40,
            self.AUDITOR: 35,
            self.MANAGER: 50,
            self.ADMIN: 80,
            self.SUPER_ADMIN: 100,
            self.SERVICE_ACCOUNT: 90
        }
        return levels.get(self, 0)


class InheritanceMode(Enum):
    """Role inheritance mode enumeration."""
    FULL = "full"
    SELECTIVE = "selective"
    ADDITIVE = "additive"
    SUBTRACTIVE = "subtractive"
    
    def get_display_name(self) -> str:
        display_names = {
            self.FULL: "Full (inherits all parent permissions)",
            self.SELECTIVE: "Selective (inherits selected permissions)",
            self.ADDITIVE: "Additive (adds to parent permissions)",
            self.SUBTRACTIVE: "Subtractive (removes from parent permissions)"
        }
        return display_names.get(self, self.value)


# =============================================================================
# Role Assignment Management
# =============================================================================

class AssignmentStatus(Enum):
    """Role assignment status."""
    ACTIVE = "active"
    PENDING = "pending"
    EXPIRED = "expired"
    REVOKED = "revoked"
    SUSPENDED = "suspended"
    
    def is_effective(self) -> bool:
        """Check if assignment is currently effective."""
        return self == self.ACTIVE


class AssignmentType(Enum):
    """Type of role assignment."""
    DIRECT = "direct"
    INHERITED = "inherited"
    TEMPORARY = "temporary"
    CONDITIONAL = "conditional"
    
    def is_revocable(self) -> bool:
        """Check if assignment can be revoked."""
        return self in {self.DIRECT, self.TEMPORARY, self.CONDITIONAL}


# =============================================================================
# Permission Management
# =============================================================================

class PermissionType(Enum):
    """Permission type enumeration."""
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
    EXPORT = "export"
    IMPORT = "import"
    CUSTOM = "custom"
    
    def get_display_name(self) -> str:
        display_names = {
            self.CREATE: "Create",
            self.READ: "Read",
            self.UPDATE: "Update",
            self.DELETE: "Delete",
            self.EXECUTE: "Execute",
            self.APPROVE: "Approve",
            self.REJECT: "Reject",
            self.DELEGATE: "Delegate",
            self.AUDIT: "Audit",
            self.CONFIGURE: "Configure",
            self.EXPORT: "Export",
            self.IMPORT: "Import",
            self.CUSTOM: "Custom"
        }
        return display_names.get(self, self.value)
    
    def is_write_operation(self) -> bool:
        """Check if permission type is a write operation."""
        write_ops = {self.CREATE, self.UPDATE, self.DELETE, self.IMPORT, self.CONFIGURE}
        return self in write_ops
    
    def is_read_operation(self) -> bool:
        """Check if permission type is a read operation."""
        return self in {self.READ, self.AUDIT, self.EXPORT}
    
    def is_dangerous(self) -> bool:
        """Check if permission type is potentially dangerous."""
        return self in {self.DELETE, self.CONFIGURE, self.EXECUTE}


class ResourceType(Enum):
    """Resource type enumeration for permissions."""
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
    # WMS specific resources
    ROUTE = "route"
    VEHICLE = "vehicle"
    FACILITY = "facility"
    CUSTOMER = "customer"
    CONTRACT = "contract"
    INVOICE = "invoice"
    PICKUP = "pickup"
    DELIVERY = "delivery"
    
    def get_display_name(self) -> str:
        display_names = {
            self.USER: "User",
            self.ROLE: "Role",
            self.PERMISSION: "Permission",
            self.GROUP: "Group",
            self.AUDIT_LOG: "Audit Log",
            self.CONFIGURATION: "Configuration",
            self.API_KEY: "API Key",
            self.SESSION: "Session",
            self.REPORT: "Report",
            self.NOTIFICATION: "Notification",
            self.ROUTE: "Route",
            self.VEHICLE: "Vehicle",
            self.FACILITY: "Facility",
            self.CUSTOMER: "Customer",
            self.CONTRACT: "Contract",
            self.INVOICE: "Invoice",
            self.PICKUP: "Pickup",
            self.DELIVERY: "Delivery"
        }
        return display_names.get(self, self.value)
    
    def get_category(self) -> str:
        """Get resource category."""
        identity_resources = {self.USER, self.ROLE, self.PERMISSION, self.GROUP, self.SESSION}
        system_resources = {self.AUDIT_LOG, self.CONFIGURATION, self.API_KEY, self.REPORT, self.NOTIFICATION}
        business_resources = {self.ROUTE, self.VEHICLE, self.FACILITY, self.CUSTOMER, self.CONTRACT, self.INVOICE, self.PICKUP, self.DELIVERY}
        
        if self in identity_resources:
            return "identity"
        if self in system_resources:
            return "system"
        if self in business_resources:
            return "business"
        return "other"
    
    def is_sensitive(self) -> bool:
        """Check if resource type contains sensitive data."""
        sensitive = {self.USER, self.AUDIT_LOG, self.CONFIGURATION, self.API_KEY, self.SESSION}
        return self in sensitive


class PermissionEffect(Enum):
    """Permission effect (allow/deny) for fine-grained control."""
    ALLOW = "allow"
    DENY = "deny"
    
    def get_display_name(self) -> str:
        return self.value.title()


class PermissionScope(Enum):
    """Permission scope enumeration."""
    GLOBAL = "global"
    ORGANIZATION = "organization"
    DEPARTMENT = "department"
    TEAM = "team"
    PROJECT = "project"
    RESOURCE = "resource"
    SELF = "self"
    
    def get_display_name(self) -> str:
        """Get human-readable display name."""
        return self.value.title()
    
    def get_hierarchy_level(self) -> int:
        """Get hierarchy level for scope comparison."""
        levels = {
            self.SELF: 0,
            self.RESOURCE: 1,
            self.PROJECT: 2,
            self.TEAM: 3,
            self.DEPARTMENT: 4,
            self.ORGANIZATION: 5,
            self.GLOBAL: 6
        }
        return levels.get(self, 0)


# =============================================================================
# Authentication and Security
# =============================================================================

class MFAMethod(Enum):
    """Multi-factor authentication method enumeration."""
    TOTP = "totp"  # Time-based One-Time Password
    SMS = "sms"
    EMAIL = "email"
    HARDWARE_TOKEN = "hardware_token"
    BIOMETRIC = "biometric"
    BACKUP_CODES = "backup_codes"
    PUSH_NOTIFICATION = "push_notification"
    API_KEY = "api_key"
    CERTIFICATE = "certificate"
    
    def get_display_name(self) -> str:
        """Get human-readable display name."""
        display_names = {
            self.TOTP: "Authenticator App (TOTP)",
            self.SMS: "SMS Text Message",
            self.EMAIL: "Email Verification",
            self.HARDWARE_TOKEN: "Hardware Security Key",
            self.BIOMETRIC: "Biometric Authentication",
            self.BACKUP_CODES: "Backup Recovery Codes",
            self.PUSH_NOTIFICATION: "Push Notification",
            self.API_KEY: "API Key",
            self.CERTIFICATE: "Digital Certificate"
        }
        return display_names.get(self, str(self.value).title())
    
    def is_secure_method(self) -> bool:
        """Check if this is considered a secure MFA method."""
        secure_methods = [self.TOTP, self.HARDWARE_TOKEN, self.BIOMETRIC, self.CERTIFICATE]
        return self in secure_methods
    
    @property
    def requires_device(self) -> bool:
        """Check if method requires a physical device."""
        return self in {self.TOTP, self.HARDWARE_TOKEN, self.BIOMETRIC}
    
    @property
    def is_phishing_resistant(self) -> bool:
        """Check if method is resistant to phishing attacks."""
        return self in {self.HARDWARE_TOKEN, self.BIOMETRIC, self.CERTIFICATE}
    
    @property
    def security_level(self) -> int:
        """Get numeric security level for comparison."""
        levels = {
            self.SMS: 1,
            self.EMAIL: 2,
            self.PUSH_NOTIFICATION: 3,
            self.BACKUP_CODES: 4,
            self.TOTP: 5,
            self.API_KEY: 6,
            self.BIOMETRIC: 7,
            self.CERTIFICATE: 8,
            self.HARDWARE_TOKEN: 9
        }
        return levels.get(self, 0)


class AuthenticationMethod(Enum):
    """Authentication method enumeration."""
    PASSWORD = "password"
    MFA = "mfa"
    SSO = "sso"
    OAUTH = "oauth"
    BIOMETRIC = "biometric"
    API_KEY = "api_key"
    CERTIFICATE = "certificate"
    
    def get_display_name(self) -> str:
        """Get human-readable display name."""
        display_names = {
            self.PASSWORD: "Password",
            self.MFA: "Multi-Factor Authentication",
            self.SSO: "Single Sign-On",
            self.OAUTH: "OAuth",
            self.BIOMETRIC: "Biometric",
            self.API_KEY: "API Key",
            self.CERTIFICATE: "Certificate"
        }
        return display_names.get(self, str(self.value))


class LoginFailureReason(Enum):
    """Login failure reason enumeration."""
    INVALID_CREDENTIALS = "invalid_credentials"
    INVALID_EMAIL = "invalid_email"
    INVALID_PASSWORD = "invalid_password"
    ACCOUNT_NOT_FOUND = "account_not_found"
    ACCOUNT_INACTIVE = "account_inactive"
    ACCOUNT_LOCKED = "account_locked"
    ACCOUNT_SUSPENDED = "account_suspended"
    ACCOUNT_DEACTIVATED = "account_deactivated"
    EMAIL_NOT_VERIFIED = "email_not_verified"
    MFA_REQUIRED = "mfa_required"
    MFA_FAILED = "mfa_failed"
    PASSWORD_EXPIRED = "password_expired"
    TOO_MANY_ATTEMPTS = "too_many_attempts"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    IP_BLOCKED = "ip_blocked"
    RATE_LIMITED = "rate_limited"
    MAINTENANCE_MODE = "maintenance_mode"
    UNKNOWN = "unknown"
    
    def get_display_name(self) -> str:
        """Get human-readable display name."""
        display_names = {
            self.INVALID_CREDENTIALS: "Invalid Credentials",
            self.INVALID_EMAIL: "Invalid Email",
            self.INVALID_PASSWORD: "Invalid Password",
            self.ACCOUNT_NOT_FOUND: "Account Not Found",
            self.ACCOUNT_INACTIVE: "Account Inactive",
            self.ACCOUNT_LOCKED: "Account Locked",
            self.ACCOUNT_SUSPENDED: "Account Suspended",
            self.ACCOUNT_DEACTIVATED: "Account Deactivated",
            self.EMAIL_NOT_VERIFIED: "Email Not Verified",
            self.MFA_REQUIRED: "MFA Required",
            self.MFA_FAILED: "MFA Failed",
            self.PASSWORD_EXPIRED: "Password Expired",
            self.TOO_MANY_ATTEMPTS: "Too Many Attempts",
            self.SUSPICIOUS_ACTIVITY: "Suspicious Activity",
            self.IP_BLOCKED: "IP Blocked",
            self.RATE_LIMITED: "Rate Limited",
            self.MAINTENANCE_MODE: "Maintenance Mode",
            self.UNKNOWN: "Unknown Error"
        }
        return display_names.get(self, str(self.value).title())
    
    @property
    def is_security_related(self) -> bool:
        """Check if failure reason is security-related."""
        return self in {
            self.SUSPICIOUS_ACTIVITY, self.IP_BLOCKED,
            self.TOO_MANY_ATTEMPTS, self.ACCOUNT_LOCKED
        }
    
    @property
    def is_user_error(self) -> bool:
        """Check if failure is due to user error."""
        return self in {
            self.INVALID_CREDENTIALS, self.INVALID_EMAIL,
            self.INVALID_PASSWORD, self.MFA_FAILED
        }


class LoginAttemptStatus(Enum):
    """Login attempt status enumeration."""
    SUCCESS = "success"
    FAILED = "failed"
    BLOCKED = "blocked"
    CHALLENGED = "challenged"
    EXPIRED = "expired"
    
    def get_display_name(self) -> str:
        """Get human-readable display name."""
        display_names = {
            self.SUCCESS: "Successful",
            self.FAILED: "Failed",
            self.BLOCKED: "Blocked",
            self.CHALLENGED: "MFA Challenged",
            self.EXPIRED: "Expired"
        }
        return display_names.get(self, str(self.value).title())


class VerificationStatus(Enum):
    """Verification status enumeration."""
    PENDING = "pending"
    VERIFIED = "verified"
    FAILED = "failed"
    EXPIRED = "expired"
    
    def get_display_name(self) -> str:
        """Get human-readable display name."""
        display_names = {
            self.PENDING: "Pending Verification",
            self.VERIFIED: "Verified",
            self.FAILED: "Verification Failed",
            self.EXPIRED: "Verification Expired"
        }
        return display_names.get(self, str(self.value))


# =============================================================================
# Sessions and Tokens
# =============================================================================

class SessionStatus(Enum):
    """Session status enumeration."""
    ACTIVE = "active"
    EXPIRED = "expired"
    TERMINATED = "terminated"
    SUSPENDED = "suspended"
    
    def get_display_name(self) -> str:
        """Get human-readable display name."""
        return self.value.title()


class SessionType(Enum):
    """Session type enumeration."""
    WEB = "web"
    MOBILE = "mobile"
    API = "api"
    ADMIN = "admin"
    SERVICE = "service"
    
    def get_display_name(self) -> str:
        """Get human-readable display name."""
        display_names = {
            self.WEB: "Web Browser",
            self.MOBILE: "Mobile App",
            self.API: "API Client",
            self.ADMIN: "Admin Panel",
            self.SERVICE: "Service Account"
        }
        return display_names.get(self, str(self.value).title())


class TokenStatus(Enum):
    """Token status enumeration."""
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    SUSPENDED = "suspended"
    
    def get_display_name(self) -> str:
        """Get human-readable display name."""
        return self.value.title()
    
    @property
    def is_active(self) -> bool:
        """Check if status allows token usage."""
        return self == self.ACTIVE
    
    @property
    def is_terminal(self) -> bool:
        """Check if status is terminal (cannot be changed)."""
        return self in {self.EXPIRED, self.REVOKED}


class RefreshStrategy(Enum):
    """Refresh token strategy enumeration."""
    ROTATE = "rotate"  # Generate new refresh token on each use
    REUSE = "reuse"    # Reuse refresh token until expiry
    FAMILY = "family"  # Token family tracking with automatic revocation
    
    def get_display_name(self) -> str:
        """Get human-readable display name."""
        display_names = {
            self.ROTATE: "Rotate Token",
            self.REUSE: "Reuse Token",
            self.FAMILY: "Family Tracking"
        }
        return display_names.get(self, str(self.value).title())
    
    def get_description(self) -> str:
        """Get strategy description."""
        descriptions = {
            self.ROTATE: "Generate new refresh token on each use",
            self.REUSE: "Reuse refresh token until expiry",
            self.FAMILY: "Token family tracking with automatic revocation"
        }
        return descriptions.get(self, "")


# =============================================================================
# Security Events and Monitoring
# =============================================================================

class SecurityEventType(Enum):
    """Security event type enumeration."""
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
    
    def get_display_name(self) -> str:
        """Get human-readable display name."""
        display_names = {
            self.BRUTE_FORCE_ATTACK: "Brute Force Attack",
            self.CREDENTIAL_STUFFING: "Credential Stuffing",
            self.SUSPICIOUS_LOGIN: "Suspicious Login",
            self.ANOMALOUS_BEHAVIOR: "Anomalous Behavior",
            self.PRIVILEGE_ESCALATION: "Privilege Escalation",
            self.DATA_EXFILTRATION: "Data Exfiltration",
            self.UNAUTHORIZED_ACCESS: "Unauthorized Access",
            self.MALWARE_DETECTION: "Malware Detection",
            self.MULTIPLE_FAILED_ATTEMPTS: "Multiple Failed Attempts",
            self.UNUSUAL_LOCATION: "Unusual Location",
            self.IMPOSSIBLE_TRAVEL: "Impossible Travel",
            self.NEW_DEVICE: "New Device"
        }
        return display_names.get(self, str(self.value))


class SecurityEventStatus(Enum):
    """Security event status enumeration."""
    PENDING = "pending"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    ESCALATED = "escalated"
    MITIGATED = "mitigated"
    
    def get_display_name(self) -> str:
        """Get human-readable display name."""
        display_names = {
            self.PENDING: "Pending Review",
            self.INVESTIGATING: "Under Investigation",
            self.RESOLVED: "Resolved",
            self.FALSE_POSITIVE: "False Positive",
            self.ESCALATED: "Escalated",
            self.MITIGATED: "Mitigated"
        }
        return display_names.get(self, str(self.value))


# =============================================================================
# Devices and Platforms
# =============================================================================

class DeviceType(Enum):
    """Device type enumeration."""
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
    
    def get_display_name(self) -> str:
        """Get human-readable display name."""
        display_names = {
            self.DESKTOP: "Desktop Computer",
            self.LAPTOP: "Laptop",
            self.SMARTPHONE: "Smartphone",
            self.TABLET: "Tablet",
            self.MOBILE_IOS: "iOS Mobile",
            self.MOBILE_ANDROID: "Android Mobile",
            self.MOBILE_OTHER: "Other Mobile",
            self.TABLET_IOS: "iPad",
            self.TABLET_ANDROID: "Android Tablet",
            self.TABLET_OTHER: "Other Tablet",
            self.IOT_DEVICE: "IoT Device",
            self.SERVER: "Server",
            self.UNKNOWN: "Unknown Device",
            self.OTHER: "Other"
        }
        return display_names.get(self, str(self.value))


class DevicePlatform(Enum):
    """Device platform enumeration."""
    IOS = "ios"
    ANDROID = "android"
    WINDOWS = "windows"
    MACOS = "macos"
    LINUX = "linux"
    WEB = "web"
    UNKNOWN = "unknown"
    
    def get_display_name(self) -> str:
        """Get human-readable display name."""
        display_names = {
            self.IOS: "iOS",
            self.ANDROID: "Android",
            self.WINDOWS: "Windows",
            self.MACOS: "macOS",
            self.LINUX: "Linux",
            self.WEB: "Web",
            self.UNKNOWN: "Unknown"
        }
        return display_names.get(self, str(self.value))


# =============================================================================
# Compliance and Data Classification
# =============================================================================

class ComplianceStatus(Enum):
    """Compliance status enumeration."""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    UNDER_REVIEW = "under_review"
    REMEDIATION_REQUIRED = "remediation_required"
    
    def get_display_name(self) -> str:
        """Get human-readable display name."""
        display_names = {
            self.COMPLIANT: "Compliant",
            self.NON_COMPLIANT: "Non-Compliant",
            self.UNDER_REVIEW: "Under Review",
            self.REMEDIATION_REQUIRED: "Remediation Required"
        }
        return display_names.get(self, str(self.value))


class DataClassification(Enum):
    """Data classification levels."""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    TOP_SECRET = "top_secret"
    
    def get_display_name(self) -> str:
        """Get human-readable display name."""
        display_names = {
            self.PUBLIC: "Public",
            self.INTERNAL: "Internal Use",
            self.CONFIDENTIAL: "Confidential",
            self.RESTRICTED: "Restricted",
            self.TOP_SECRET: "Top Secret"
        }
        return display_names.get(self, str(self.value).title())
    
    def get_security_level(self) -> int:
        """Get numeric security level."""
        levels = {
            self.PUBLIC: 0,
            self.INTERNAL: 1,
            self.CONFIDENTIAL: 2,
            self.RESTRICTED: 3,
            self.TOP_SECRET: 4
        }
        return levels.get(self, 0)


# =============================================================================
# Audit and Notifications
# =============================================================================

class AuditAction(Enum):
    """Audit action enumeration."""
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
    PASSWORD_CHANGE = "password_change"
    MFA_ENABLE = "mfa_enable"
    MFA_DISABLE = "mfa_disable"
    SECURITY_ALERT = "security_alert"
    
    def get_display_name(self) -> str:
        """Get human-readable display name."""
        display_names = {
            self.CREATE: "Created",
            self.READ: "Viewed",
            self.UPDATE: "Updated",
            self.DELETE: "Deleted",
            self.LOGIN: "Logged In",
            self.LOGOUT: "Logged Out",
            self.PERMISSION_GRANT: "Permission Granted",
            self.PERMISSION_REVOKE: "Permission Revoked",
            self.ROLE_ASSIGN: "Role Assigned",
            self.ROLE_UNASSIGN: "Role Unassigned",
            self.PASSWORD_CHANGE: "Password Changed",
            self.MFA_ENABLE: "MFA Enabled",
            self.MFA_DISABLE: "MFA Disabled",
            self.SECURITY_ALERT: "Security Alert"
        }
        return display_names.get(self, str(self.value))


class NotificationType(Enum):
    """Notification type enumeration."""
    SECURITY_ALERT = "security_alert"
    PASSWORD_EXPIRY = "password_expiry"
    LOGIN_FROM_NEW_DEVICE = "login_from_new_device"
    PERMISSION_CHANGE = "permission_change"
    ACCOUNT_LOCKED = "account_locked"
    MFA_BACKUP_CODES = "mfa_backup_codes"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    COMPLIANCE_VIOLATION = "compliance_violation"
    SYSTEM_MAINTENANCE = "system_maintenance"
    
    def get_display_name(self) -> str:
        """Get human-readable display name."""
        display_names = {
            self.SECURITY_ALERT: "Security Alert",
            self.PASSWORD_EXPIRY: "Password Expiry Warning",
            self.LOGIN_FROM_NEW_DEVICE: "Login from New Device",
            self.PERMISSION_CHANGE: "Permission Change",
            self.ACCOUNT_LOCKED: "Account Locked",
            self.MFA_BACKUP_CODES: "MFA Backup Codes",
            self.SUSPICIOUS_ACTIVITY: "Suspicious Activity",
            self.COMPLIANCE_VIOLATION: "Compliance Violation",
            self.SYSTEM_MAINTENANCE: "System Maintenance"
        }
        return display_names.get(self, str(self.value))


# =============================================================================
# Utility Functions
# =============================================================================

def get_all_enum_values(enum_class) -> dict[str, str]:
    """Get all enum values as a dictionary."""
    return {member.value: member.get_display_name() for member in enum_class}


def validate_enum_value(enum_class, value: Any) -> bool:
    """Validate if a value is a valid enum member."""
    try:
        enum_class(value)
        return True
    except ValueError:
        return False


def get_enum_by_value(enum_class, value: Any) -> Enum | None:
    """Get enum member by value, returns None if not found."""
    try:
        return enum_class(value)
    except ValueError:
        return None


def get_enum_choices(enum_class) -> list[tuple[str, str]]:
    """Get enum choices as list of (value, display_name) tuples."""
    return [(member.value, member.get_display_name()) for member in enum_class]


def compare_enum_hierarchy(enum_class, value1: Any, value2: Any, hierarchy_method: str = "get_hierarchy_level") -> int:
    """Compare two enum values by their hierarchy level.
    
    Returns:
        -1 if value1 < value2
        0 if value1 == value2  
        1 if value1 > value2
    """
    try:
        member1 = enum_class(value1)
        member2 = enum_class(value2)
        
        if hasattr(member1, hierarchy_method) and hasattr(member2, hierarchy_method):
            level1 = getattr(member1, hierarchy_method)()
            level2 = getattr(member2, hierarchy_method)()
            
            if level1 < level2:
                return -1
            if level1 > level2:
                return 1
            return 0
        # Fallback to string comparison
        return -1 if value1 < value2 else (1 if value1 > value2 else 0)
    except ValueError:
        return 0


# Export all enums (organized by category)
__all__ = [
    # Base Types
    'RiskLevel',
    
    # User and Account Management
    'AccountType',
    'UserRole',
    'UserStatus',
    
    # Role Management
    'AssignmentStatus',
    'AssignmentType',
    'InheritanceMode',
    'RoleStatus',
    'RoleType',
    
    # Permission Management
    'PermissionEffect',
    'PermissionScope',
    'PermissionType',
    'ResourceType',
    
    # Authentication and Security
    'AuthenticationMethod',
    'LoginAttemptStatus',
    'LoginFailureReason',
    'MFAMethod',
    'VerificationStatus',
    
    # Sessions and Tokens
    'RefreshStrategy',
    'SessionStatus',
    'SessionType',
    'TokenStatus',
    
    # Security Events and Monitoring
    'SecurityEventStatus',
    'SecurityEventType',
    
    # Devices and Platforms
    'DevicePlatform',
    'DeviceType',
    
    # Compliance and Data Classification
    'ComplianceStatus',
    'DataClassification',
    
    # Audit and Notifications
    'AuditAction',
    'NotificationType',
    
    # Utility functions
    'compare_enum_hierarchy',
    'get_all_enum_values',
    'get_enum_by_value',
    'get_enum_choices',
    'validate_enum_value'
]