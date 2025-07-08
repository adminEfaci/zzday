"""Audit domain enumerations.

This module defines enumerations used throughout the audit domain,
providing type-safe constants for audit severity, categories, policies, and status.
"""

from enum import Enum


class RiskLevel(Enum):
    """
    Risk assessment levels.

    Used to classify the risk level of audit events,
    enabling risk-based monitoring and response.
    """

    MINIMAL = "minimal"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_score(cls, score: int) -> "RiskLevel":
        """Create risk level from numeric score (0-100)."""
        if score < 0 or score > 100:
            raise ValueError("Risk score must be between 0 and 100")
        
        if score < 20:
            return cls.MINIMAL
        if score < 40:
            return cls.LOW
        if score < 60:
            return cls.MEDIUM
        if score < 80:
            return cls.HIGH
        return cls.CRITICAL

    @classmethod
    def from_string(cls, value: str) -> "RiskLevel":
        """Create risk level from string value."""
        try:
            return cls(value.lower())
        except ValueError:
            raise ValueError(f"Invalid risk level: {value}")

    def __str__(self) -> str:
        """String representation."""
        return self.value

    def __lt__(self, other: "RiskLevel") -> bool:
        """Compare risk levels."""
        risk_order = {
            RiskLevel.MINIMAL: 1,
            RiskLevel.LOW: 2,
            RiskLevel.MEDIUM: 3,
            RiskLevel.HIGH: 4,
            RiskLevel.CRITICAL: 5,
        }
        return risk_order[self] < risk_order[other]

    def get_score_range(self) -> tuple[int, int]:
        """Get the score range for this risk level."""
        ranges = {
            RiskLevel.MINIMAL: (0, 19),
            RiskLevel.LOW: (20, 39),
            RiskLevel.MEDIUM: (40, 59),
            RiskLevel.HIGH: (60, 79),
            RiskLevel.CRITICAL: (80, 100),
        }
        return ranges[self]

    def requires_immediate_attention(self) -> bool:
        """Check if risk level requires immediate attention."""
        return self in (RiskLevel.HIGH, RiskLevel.CRITICAL)


class AuditSeverity(Enum):
    """
    Audit event severity levels.

    Used to classify the importance and impact of audit events,
    enabling prioritized monitoring and alerting.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_string(cls, value: str) -> "AuditSeverity":
        """Create severity from string value."""
        try:
            return cls(value.lower())
        except ValueError:
            raise ValueError(f"Invalid audit severity: {value}")

    def __str__(self) -> str:
        """String representation."""
        return self.value

    def __lt__(self, other: "AuditSeverity") -> bool:
        """Compare severity levels."""
        severity_order = {
            AuditSeverity.LOW: 1,
            AuditSeverity.MEDIUM: 2,
            AuditSeverity.HIGH: 3,
            AuditSeverity.CRITICAL: 4,
        }
        return severity_order[self] < severity_order[other]

    def requires_immediate_attention(self) -> bool:
        """Check if severity requires immediate attention."""
        return self in (AuditSeverity.HIGH, AuditSeverity.CRITICAL)

    def requires_notification(self) -> bool:
        """Check if severity requires notification."""
        return self in (AuditSeverity.MEDIUM, AuditSeverity.HIGH, AuditSeverity.CRITICAL)

    def get_priority_score(self) -> int:
        """Get numeric priority score (1-4)."""
        priority_map = {
            AuditSeverity.LOW: 1,
            AuditSeverity.MEDIUM: 2,
            AuditSeverity.HIGH: 3,
            AuditSeverity.CRITICAL: 4,
        }
        return priority_map[self]

    def get_escalation_timeout_minutes(self) -> int:
        """Get escalation timeout in minutes."""
        timeout_map = {
            AuditSeverity.LOW: 1440,      # 24 hours
            AuditSeverity.MEDIUM: 240,    # 4 hours
            AuditSeverity.HIGH: 60,       # 1 hour
            AuditSeverity.CRITICAL: 15,   # 15 minutes
        }
        return timeout_map[self]


class DataClassification(Enum):
    """
    Data classification levels.

    Defines the sensitivity level of data involved in audit events,
    supporting compliance and access control requirements.
    """

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    TOP_SECRET = "top_secret"

    @classmethod
    def from_string(cls, value: str) -> "DataClassification":
        """Create classification from string value."""
        try:
            return cls(value.lower())
        except ValueError:
            raise ValueError(f"Invalid data classification: {value}")

    def __str__(self) -> str:
        """String representation."""
        return self.value

    def __lt__(self, other: "DataClassification") -> bool:
        """Compare classification levels."""
        classification_order = {
            DataClassification.PUBLIC: 1,
            DataClassification.INTERNAL: 2,
            DataClassification.CONFIDENTIAL: 3,
            DataClassification.RESTRICTED: 4,
            DataClassification.TOP_SECRET: 5,
        }
        return classification_order[self] < classification_order[other]

    def requires_encryption(self) -> bool:
        """Check if classification requires encryption."""
        return self in (
            DataClassification.CONFIDENTIAL,
            DataClassification.RESTRICTED,
            DataClassification.TOP_SECRET,
        )

    def requires_approval_for_access(self) -> bool:
        """Check if classification requires approval for access."""
        return self in (
            DataClassification.RESTRICTED,
            DataClassification.TOP_SECRET,
        )

    def get_retention_years(self) -> int:
        """Get recommended retention period in years."""
        retention_map = {
            DataClassification.PUBLIC: 1,
            DataClassification.INTERNAL: 3,
            DataClassification.CONFIDENTIAL: 7,
            DataClassification.RESTRICTED: 10,
            DataClassification.TOP_SECRET: 25,
        }
        return retention_map[self]


class ActionType(Enum):
    """
    Audit action types.

    Defines the type of action being audited,
    providing standardized action classification.
    """

    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    EXECUTE = "execute"
    EXPORT = "export"
    IMPORT = "import"
    LOGIN = "login"
    LOGOUT = "logout"
    APPROVE = "approve"
    REJECT = "reject"
    ESCALATE = "escalate"
    ARCHIVE = "archive"
    RESTORE = "restore"

    @classmethod
    def from_string(cls, value: str) -> "ActionType":
        """Create action type from string value."""
        try:
            return cls(value.lower())
        except ValueError:
            raise ValueError(f"Invalid action type: {value}")

    def __str__(self) -> str:
        """String representation."""
        return self.value

    def is_destructive(self) -> bool:
        """Check if action type is destructive."""
        return self in (ActionType.DELETE, ActionType.ARCHIVE)

    def is_read_only(self) -> bool:
        """Check if action type is read-only."""
        return self in (ActionType.READ, ActionType.EXPORT)

    def is_write_operation(self) -> bool:
        """Check if action type is a write operation."""
        return self in (
            ActionType.CREATE,
            ActionType.UPDATE,
            ActionType.DELETE,
            ActionType.IMPORT,
            ActionType.ARCHIVE,
            ActionType.RESTORE,
        )

    def requires_approval(self) -> bool:
        """Check if action type typically requires approval."""
        return self in (
            ActionType.DELETE,
            ActionType.EXECUTE,
            ActionType.EXPORT,
            ActionType.ESCALATE,
            ActionType.ARCHIVE,
        )

    def get_default_severity(self) -> "AuditSeverity":
        """Get default severity for this action type."""
        severity_map = {
            ActionType.CREATE: AuditSeverity.MEDIUM,
            ActionType.READ: AuditSeverity.LOW,
            ActionType.UPDATE: AuditSeverity.MEDIUM,
            ActionType.DELETE: AuditSeverity.HIGH,
            ActionType.EXECUTE: AuditSeverity.HIGH,
            ActionType.EXPORT: AuditSeverity.HIGH,
            ActionType.IMPORT: AuditSeverity.MEDIUM,
            ActionType.LOGIN: AuditSeverity.LOW,
            ActionType.LOGOUT: AuditSeverity.LOW,
            ActionType.APPROVE: AuditSeverity.MEDIUM,
            ActionType.REJECT: AuditSeverity.MEDIUM,
            ActionType.ESCALATE: AuditSeverity.HIGH,
            ActionType.ARCHIVE: AuditSeverity.MEDIUM,
            ActionType.RESTORE: AuditSeverity.HIGH,
        }
        return severity_map[self]


class AuditCategory(Enum):
    """
    Audit event categories.

    Classifies audit events by their functional area,
    enabling filtered queries and compliance reporting.
    """

    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    DATA_ACCESS = "data_access"
    DATA_MODIFICATION = "data_modification"
    DATA_EXPORT = "data_export"
    CONFIGURATION = "configuration"
    SYSTEM = "system"
    SECURITY = "security"
    COMPLIANCE = "compliance"
    INTEGRATION = "integration"
    USER_MANAGEMENT = "user_management"
    SESSION_MANAGEMENT = "session_management"
    API_ACCESS = "api_access"
    BACKUP_RESTORE = "backup_restore"
    MONITORING = "monitoring"

    @classmethod
    def from_string(cls, value: str) -> "AuditCategory":
        """Create category from string value."""
        try:
            return cls(value.lower())
        except ValueError:
            raise ValueError(f"Invalid audit category: {value}")

    def __str__(self) -> str:
        """String representation."""
        return self.value

    def is_security_related(self) -> bool:
        """Check if category is security-related."""
        return self in (
            AuditCategory.AUTHENTICATION,
            AuditCategory.AUTHORIZATION,
            AuditCategory.SECURITY,
            AuditCategory.SESSION_MANAGEMENT,
        )

    def is_data_related(self) -> bool:
        """Check if category is data-related."""
        return self in (
            AuditCategory.DATA_ACCESS,
            AuditCategory.DATA_MODIFICATION,
            AuditCategory.DATA_EXPORT,
            AuditCategory.BACKUP_RESTORE,
        )

    def requires_enhanced_logging(self) -> bool:
        """Check if category requires enhanced logging."""
        return self in (
            AuditCategory.SECURITY,
            AuditCategory.COMPLIANCE,
            AuditCategory.DATA_EXPORT,
            AuditCategory.USER_MANAGEMENT,
        )

    def get_default_severity(self) -> "AuditSeverity":
        """Get default severity for this category."""
        severity_map = {
            AuditCategory.AUTHENTICATION: AuditSeverity.MEDIUM,
            AuditCategory.AUTHORIZATION: AuditSeverity.HIGH,
            AuditCategory.DATA_ACCESS: AuditSeverity.MEDIUM,
            AuditCategory.DATA_MODIFICATION: AuditSeverity.HIGH,
            AuditCategory.DATA_EXPORT: AuditSeverity.HIGH,
            AuditCategory.CONFIGURATION: AuditSeverity.MEDIUM,
            AuditCategory.SYSTEM: AuditSeverity.LOW,
            AuditCategory.SECURITY: AuditSeverity.HIGH,
            AuditCategory.COMPLIANCE: AuditSeverity.HIGH,
            AuditCategory.INTEGRATION: AuditSeverity.LOW,
            AuditCategory.USER_MANAGEMENT: AuditSeverity.MEDIUM,
            AuditCategory.SESSION_MANAGEMENT: AuditSeverity.MEDIUM,
            AuditCategory.API_ACCESS: AuditSeverity.LOW,
            AuditCategory.BACKUP_RESTORE: AuditSeverity.HIGH,
            AuditCategory.MONITORING: AuditSeverity.LOW,
        }
        return severity_map[self]

    def get_retention_policy(self) -> "RetentionPolicy":
        """Get recommended retention policy for this category."""
        retention_map = {
            AuditCategory.AUTHENTICATION: RetentionPolicy.YEARS_1,
            AuditCategory.AUTHORIZATION: RetentionPolicy.YEARS_7,
            AuditCategory.DATA_ACCESS: RetentionPolicy.YEARS_7,
            AuditCategory.DATA_MODIFICATION: RetentionPolicy.YEARS_7,
            AuditCategory.DATA_EXPORT: RetentionPolicy.YEARS_7,
            AuditCategory.CONFIGURATION: RetentionPolicy.YEARS_1,
            AuditCategory.SYSTEM: RetentionPolicy.DAYS_90,
            AuditCategory.SECURITY: RetentionPolicy.YEARS_7,
            AuditCategory.COMPLIANCE: RetentionPolicy.PERMANENT,
            AuditCategory.INTEGRATION: RetentionPolicy.DAYS_90,
            AuditCategory.USER_MANAGEMENT: RetentionPolicy.YEARS_7,
            AuditCategory.SESSION_MANAGEMENT: RetentionPolicy.YEARS_1,
            AuditCategory.API_ACCESS: RetentionPolicy.DAYS_90,
            AuditCategory.BACKUP_RESTORE: RetentionPolicy.YEARS_7,
            AuditCategory.MONITORING: RetentionPolicy.DAYS_30,
        }
        return retention_map[self]


class RetentionPolicy(Enum):
    """
    Audit retention policies.

    Defines how long audit records should be retained,
    supporting compliance requirements and storage management.
    """

    DAYS_30 = ("30_days", 30)
    DAYS_90 = ("90_days", 90)
    YEARS_1 = ("1_year", 365)
    YEARS_7 = ("7_years", 2555)
    PERMANENT = ("permanent", -1)

    def __init__(self, label: str, days: int):
        """Initialize retention policy with label and days."""
        self.label = label
        self.days = days

    @classmethod
    def from_string(cls, value: str) -> "RetentionPolicy":
        """Create retention policy from string value."""
        for policy in cls:
            if policy.label == value or policy.name == value.upper():
                return policy
        raise ValueError(f"Invalid retention policy: {value}")

    def __str__(self) -> str:
        """String representation."""
        return self.label

    def is_permanent(self) -> bool:
        """Check if this is a permanent retention policy."""
        return self.days == -1

    def get_retention_days(self) -> int:
        """Get retention period in days."""
        return self.days


class AuditOutcome(Enum):
    """
    Audit event outcomes.

    Represents the result of an audited action,
    enabling success/failure analysis and alerting.
    """

    SUCCESS = "success"
    FAILURE = "failure"
    PARTIAL = "partial"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    ERROR = "error"
    BLOCKED = "blocked"
    PENDING = "pending"

    @classmethod
    def from_string(cls, value: str) -> "AuditOutcome":
        """Create outcome from string value."""
        try:
            return cls(value.lower())
        except ValueError:
            raise ValueError(f"Invalid audit outcome: {value}")

    def __str__(self) -> str:
        """String representation."""
        return self.value

    def is_successful(self) -> bool:
        """Check if outcome represents success."""
        return self == AuditOutcome.SUCCESS

    def is_failed(self) -> bool:
        """Check if outcome represents failure."""
        return self in (
            AuditOutcome.FAILURE,
            AuditOutcome.ERROR,
            AuditOutcome.TIMEOUT,
            AuditOutcome.BLOCKED,
        )

    def is_incomplete(self) -> bool:
        """Check if outcome represents incomplete action."""
        return self in (
            AuditOutcome.PARTIAL,
            AuditOutcome.CANCELLED,
            AuditOutcome.PENDING,
        )

    def requires_investigation(self) -> bool:
        """Check if outcome requires investigation."""
        return self in (
            AuditOutcome.FAILURE,
            AuditOutcome.ERROR,
            AuditOutcome.TIMEOUT,
            AuditOutcome.BLOCKED,
        )


class AuditStatus(Enum):
    """
    Audit record status.

    Tracks the lifecycle state of audit records,
    supporting archival and deletion workflows.
    """

    ACTIVE = "active"
    ARCHIVED = "archived"
    DELETED = "deleted"
    PENDING_ARCHIVE = "pending_archive"
    PENDING_DELETE = "pending_delete"

    @classmethod
    def from_string(cls, value: str) -> "AuditStatus":
        """Create status from string value."""
        try:
            return cls(value.lower())
        except ValueError:
            raise ValueError(f"Invalid audit status: {value}")

    def __str__(self) -> str:
        """String representation."""
        return self.value

    def is_active(self) -> bool:
        """Check if status represents an active record."""
        return self == AuditStatus.ACTIVE

    def is_archived(self) -> bool:
        """Check if status represents an archived record."""
        return self in (AuditStatus.ARCHIVED, AuditStatus.PENDING_ARCHIVE)

    def is_deleted(self) -> bool:
        """Check if status represents a deleted record."""
        return self in (AuditStatus.DELETED, AuditStatus.PENDING_DELETE)

    def can_transition_to(self, new_status: "AuditStatus") -> bool:
        """Check if transition to new status is valid."""
        valid_transitions = {
            AuditStatus.ACTIVE: [
                AuditStatus.PENDING_ARCHIVE,
                AuditStatus.PENDING_DELETE,
            ],
            AuditStatus.PENDING_ARCHIVE: [AuditStatus.ARCHIVED, AuditStatus.ACTIVE],
            AuditStatus.PENDING_DELETE: [AuditStatus.DELETED, AuditStatus.ACTIVE],
            AuditStatus.ARCHIVED: [AuditStatus.PENDING_DELETE],
            AuditStatus.DELETED: [],
        }
        return new_status in valid_transitions.get(self, [])


class Environment(Enum):
    """
    Environment types.

    Defines the environment where audit events occur,
    enabling environment-specific analysis and filtering.
    """

    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    TESTING = "testing"
    LOCAL = "local"
    DEMO = "demo"
    SANDBOX = "sandbox"

    @classmethod
    def from_string(cls, value: str) -> "Environment":
        """Create environment from string value."""
        # Handle common aliases
        aliases = {
            "prod": cls.PRODUCTION,
            "stage": cls.STAGING,
            "dev": cls.DEVELOPMENT,
            "test": cls.TESTING,
        }
        
        normalized = value.lower()
        if normalized in aliases:
            return aliases[normalized]
        
        try:
            return cls(normalized)
        except ValueError:
            raise ValueError(f"Invalid environment: {value}")

    def __str__(self) -> str:
        """String representation."""
        return self.value

    def is_production(self) -> bool:
        """Check if this is a production environment."""
        return self == Environment.PRODUCTION

    def is_non_production(self) -> bool:
        """Check if this is a non-production environment."""
        return self != Environment.PRODUCTION

    def requires_enhanced_monitoring(self) -> bool:
        """Check if environment requires enhanced monitoring."""
        return self in (Environment.PRODUCTION, Environment.STAGING)

    def allows_test_data(self) -> bool:
        """Check if environment allows test data."""
        return self in (
            Environment.DEVELOPMENT,
            Environment.TESTING,
            Environment.LOCAL,
            Environment.DEMO,
            Environment.SANDBOX,
        )

    def get_retention_multiplier(self) -> float:
        """Get retention period multiplier for this environment."""
        multipliers = {
            Environment.PRODUCTION: 1.0,
            Environment.STAGING: 0.5,
            Environment.DEVELOPMENT: 0.25,
            Environment.TESTING: 0.25,
            Environment.LOCAL: 0.1,
            Environment.DEMO: 0.5,
            Environment.SANDBOX: 0.1,
        }
        return multipliers[self]


class ComplianceRegulation(Enum):
    """
    Compliance regulations.

    Defines the regulatory frameworks that audit events
    must comply with for legal and business requirements.
    """

    GDPR = "gdpr"
    CCPA = "ccpa"
    HIPAA = "hipaa"
    SOX = "sox"
    PCI_DSS = "pci_dss"
    ISO_27001 = "iso_27001"
    SOC2 = "soc2"
    PIPEDA = "pipeda"
    LGPD = "lgpd"
    CUSTOM = "custom"

    @classmethod
    def from_string(cls, value: str) -> "ComplianceRegulation":
        """Create regulation from string value."""
        try:
            return cls(value.lower())
        except ValueError:
            raise ValueError(f"Invalid compliance regulation: {value}")

    def __str__(self) -> str:
        """String representation."""
        return self.value

    def get_display_name(self) -> str:
        """Get human-readable display name."""
        display_names = {
            ComplianceRegulation.GDPR: "General Data Protection Regulation",
            ComplianceRegulation.CCPA: "California Consumer Privacy Act",
            ComplianceRegulation.HIPAA: "Health Insurance Portability and Accountability Act",
            ComplianceRegulation.SOX: "Sarbanes-Oxley Act",
            ComplianceRegulation.PCI_DSS: "Payment Card Industry Data Security Standard",
            ComplianceRegulation.ISO_27001: "ISO/IEC 27001",
            ComplianceRegulation.SOC2: "Service Organization Control 2",
            ComplianceRegulation.PIPEDA: "Personal Information Protection and Electronic Documents Act",
            ComplianceRegulation.LGPD: "Lei Geral de Proteção de Dados",
            ComplianceRegulation.CUSTOM: "Custom Regulation",
        }
        return display_names[self]

    def requires_data_retention(self) -> bool:
        """Check if regulation requires specific data retention."""
        return self in (
            ComplianceRegulation.GDPR,
            ComplianceRegulation.CCPA,
            ComplianceRegulation.HIPAA,
            ComplianceRegulation.SOX,
            ComplianceRegulation.PIPEDA,
            ComplianceRegulation.LGPD,
        )

    def requires_right_to_deletion(self) -> bool:
        """Check if regulation requires right to deletion."""
        return self in (
            ComplianceRegulation.GDPR,
            ComplianceRegulation.CCPA,
            ComplianceRegulation.PIPEDA,
            ComplianceRegulation.LGPD,
        )

    def get_retention_period_years(self) -> int:
        """Get required retention period in years."""
        retention_periods = {
            ComplianceRegulation.GDPR: 6,
            ComplianceRegulation.CCPA: 2,
            ComplianceRegulation.HIPAA: 6,
            ComplianceRegulation.SOX: 7,
            ComplianceRegulation.PCI_DSS: 1,
            ComplianceRegulation.ISO_27001: 3,
            ComplianceRegulation.SOC2: 1,
            ComplianceRegulation.PIPEDA: 1,
            ComplianceRegulation.LGPD: 6,
            ComplianceRegulation.CUSTOM: 7,
        }
        return retention_periods[self]


class ResourceType(Enum):
    """
    Resource types.

    Defines the types of resources that can be audited,
    providing standardized resource classification.
    """

    USER = "user"
    ROLE = "role"
    PERMISSION = "permission"
    SESSION = "session"
    API_KEY = "api_key"
    DEVICE = "device"
    ORGANIZATION = "organization"
    GROUP = "group"
    POLICY = "policy"
    CONFIGURATION = "configuration"
    FILE = "file"
    DATABASE = "database"
    SYSTEM = "system"
    APPLICATION = "application"
    SERVICE = "service"
    INTEGRATION = "integration"
    REPORT = "report"
    AUDIT_LOG = "audit_log"
    BACKUP = "backup"
    CERTIFICATE = "certificate"

    @classmethod
    def from_string(cls, value: str) -> "ResourceType":
        """Create resource type from string value."""
        try:
            return cls(value.lower())
        except ValueError:
            raise ValueError(f"Invalid resource type: {value}")

    def __str__(self) -> str:
        """String representation."""
        return self.value

    def is_security_sensitive(self) -> bool:
        """Check if resource type is security sensitive."""
        return self in (
            ResourceType.USER,
            ResourceType.ROLE,
            ResourceType.PERMISSION,
            ResourceType.API_KEY,
            ResourceType.POLICY,
            ResourceType.CERTIFICATE,
        )

    def is_data_resource(self) -> bool:
        """Check if resource type represents data."""
        return self in (
            ResourceType.FILE,
            ResourceType.DATABASE,
            ResourceType.BACKUP,
            ResourceType.REPORT,
            ResourceType.AUDIT_LOG,
        )

    def is_system_resource(self) -> bool:
        """Check if resource type is a system resource."""
        return self in (
            ResourceType.SYSTEM,
            ResourceType.APPLICATION,
            ResourceType.SERVICE,
            ResourceType.CONFIGURATION,
        )

    def get_default_classification(self) -> "DataClassification":
        """Get default data classification for this resource type."""
        classification_map = {
            ResourceType.USER: DataClassification.CONFIDENTIAL,
            ResourceType.ROLE: DataClassification.INTERNAL,
            ResourceType.PERMISSION: DataClassification.INTERNAL,
            ResourceType.SESSION: DataClassification.CONFIDENTIAL,
            ResourceType.API_KEY: DataClassification.RESTRICTED,
            ResourceType.DEVICE: DataClassification.INTERNAL,
            ResourceType.ORGANIZATION: DataClassification.INTERNAL,
            ResourceType.GROUP: DataClassification.INTERNAL,
            ResourceType.POLICY: DataClassification.CONFIDENTIAL,
            ResourceType.CONFIGURATION: DataClassification.CONFIDENTIAL,
            ResourceType.FILE: DataClassification.INTERNAL,
            ResourceType.DATABASE: DataClassification.CONFIDENTIAL,
            ResourceType.SYSTEM: DataClassification.INTERNAL,
            ResourceType.APPLICATION: DataClassification.INTERNAL,
            ResourceType.SERVICE: DataClassification.INTERNAL,
            ResourceType.INTEGRATION: DataClassification.INTERNAL,
            ResourceType.REPORT: DataClassification.INTERNAL,
            ResourceType.AUDIT_LOG: DataClassification.CONFIDENTIAL,
            ResourceType.BACKUP: DataClassification.CONFIDENTIAL,
            ResourceType.CERTIFICATE: DataClassification.RESTRICTED,
        }
        return classification_map[self]

    def requires_approval_for_deletion(self) -> bool:
        """Check if resource type requires approval for deletion."""
        return self in (
            ResourceType.USER,
            ResourceType.DATABASE,
            ResourceType.BACKUP,
            ResourceType.CERTIFICATE,
            ResourceType.AUDIT_LOG,
        )


__all__ = [
    "ActionType",
    "AuditCategory",
    "AuditOutcome", 
    "AuditSeverity",
    "AuditStatus",
    "ComplianceRegulation",
    "DataClassification",
    "Environment",
    "ResourceType",
    "RetentionPolicy",
    "RiskLevel",
]
