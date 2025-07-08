"""GraphQL enums for audit module."""

import strawberry


@strawberry.enum
class AuditSeverityEnum:
    """Enum for audit entry severity levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@strawberry.enum
class AuditCategoryEnum:
    """Enum for audit entry categories."""

    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    DATA_ACCESS = "data_access"
    CONFIGURATION = "configuration"
    SYSTEM = "system"
    SECURITY = "security"
    COMPLIANCE = "compliance"
    INTEGRATION = "integration"


@strawberry.enum
class AuditOutcomeEnum:
    """Enum for audit entry outcomes."""

    SUCCESS = "success"
    FAILURE = "failure"
    ERROR = "error"
    PARTIAL = "partial"
    TIMEOUT = "timeout"
    DENIED = "denied"


@strawberry.enum
class SortOrderEnum:
    """Enum for sort order options."""

    ASC = "asc"
    DESC = "desc"


@strawberry.enum
class ReportTypeEnum:
    """Enum for audit report types."""

    SUMMARY = "summary"
    DETAILED = "detailed"
    COMPLIANCE = "compliance"
    SECURITY = "security"
    PERFORMANCE = "performance"
    CUSTOM = "custom"


@strawberry.enum
class ComplianceFrameworkEnum:
    """Enum for compliance frameworks."""

    SOC2 = "SOC2"
    HIPAA = "HIPAA"
    GDPR = "GDPR"
    PCI_DSS = "PCI-DSS"
    ISO27001 = "ISO27001"
    NIST = "NIST"
    CUSTOM = "custom"


@strawberry.enum
class ComplianceStatusEnum:
    """Enum for compliance status values."""

    COMPLIANT = "compliant"
    NON_COMPLIANT = "non-compliant"
    PARTIAL = "partial"
    NOT_APPLICABLE = "not-applicable"


@strawberry.enum
class RiskLevelEnum:
    """Enum for risk levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@strawberry.enum
class TrendDirectionEnum:
    """Enum for trend directions."""

    INCREASING = "increasing"
    DECREASING = "decreasing"
    STABLE = "stable"


@strawberry.enum
class ExportFormatEnum:
    """Enum for export formats."""

    JSON = "json"
    CSV = "csv"
    PDF = "pdf"
    XLSX = "xlsx"
    DOCX = "docx"


@strawberry.enum
class AuditActionTypeEnum:
    """Enum for audit action types."""

    CREATE = "create"
    READ = "read"
    UPDATE = "update"
    DELETE = "delete"
    LOGIN = "login"
    LOGOUT = "logout"
    EXPORT = "export"
    IMPORT = "import"
    CONFIGURE = "configure"
    EXECUTE = "execute"


@strawberry.enum
class AuditResourceTypeEnum:
    """Enum for audit resource types."""

    USER = "user"
    ROLE = "role"
    PERMISSION = "permission"
    DOCUMENT = "document"
    REPORT = "report"
    CONFIGURATION = "configuration"
    INTEGRATION = "integration"
    WEBHOOK = "webhook"
    API_KEY = "api_key"
    SESSION = "session"
