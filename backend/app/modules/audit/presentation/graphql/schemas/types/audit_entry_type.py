"""GraphQL types for audit entries."""

from datetime import datetime

import strawberry

from ..enums import AuditCategoryEnum, AuditOutcomeEnum, AuditSeverityEnum


@strawberry.type
class AuditFieldChangeType:
    """GraphQL type for audit field changes."""

    field_name: str
    old_value: str | None = None
    new_value: str | None = None
    field_type: str


@strawberry.type
class AuditActionType:
    """GraphQL type for audit action details."""

    action_type: str
    operation: str
    description: str


@strawberry.type
class AuditResourceType:
    """GraphQL type for audit resource details."""

    resource_type: str
    resource_id: str
    resource_name: str


@strawberry.type
class AuditContextType:
    """GraphQL type for audit context information."""

    ip_address: str | None = None
    user_agent: str | None = None
    session_id: strawberry.ID | None = None
    correlation_id: str | None = None


@strawberry.type
class AuditResultType:
    """GraphQL type for audit result information."""

    outcome: AuditOutcomeEnum
    severity: AuditSeverityEnum
    category: AuditCategoryEnum
    duration_ms: int | None = None
    error_details: str | None = None


@strawberry.type
class AuditUserType:
    """GraphQL type for audit user information."""

    user_id: strawberry.ID | None = None
    user_email: str | None = None
    user_name: str | None = None


@strawberry.type
class AuditMetadataType:
    """GraphQL type for audit metadata."""

    tags: list[str]
    compliance_tags: list[str] = strawberry.field(default_factory=list)
    custom_fields: str | None = None


@strawberry.type
class AuditEntryType:
    """GraphQL type for audit entries."""

    # Identity
    id: strawberry.ID
    audit_log_id: strawberry.ID

    # User information
    user: AuditUserType

    # Action details
    action: AuditActionType

    # Resource details
    resource: AuditResourceType

    # Context information
    context: AuditContextType

    # Result information
    result: AuditResultType

    # Changes (for update operations)
    changes: list[AuditFieldChangeType] = strawberry.field(default_factory=list)

    # Metadata
    metadata: AuditMetadataType

    # Timestamps
    created_at: datetime

    @strawberry.field
    def formatted_created_at(self) -> str:
        """Return formatted creation timestamp."""
        return self.created_at.isoformat()

    @strawberry.field
    def risk_score(self) -> float:
        """Calculate risk score based on severity and category."""
        severity_weights = {
            AuditSeverityEnum.LOW: 1.0,
            AuditSeverityEnum.MEDIUM: 2.5,
            AuditSeverityEnum.HIGH: 4.0,
            AuditSeverityEnum.CRITICAL: 5.0,
        }

        category_multipliers = {
            AuditCategoryEnum.SECURITY: 1.5,
            AuditCategoryEnum.COMPLIANCE: 1.3,
            AuditCategoryEnum.AUTHENTICATION: 1.4,
            AuditCategoryEnum.AUTHORIZATION: 1.4,
            AuditCategoryEnum.DATA_ACCESS: 1.2,
            AuditCategoryEnum.CONFIGURATION: 1.1,
            AuditCategoryEnum.SYSTEM: 1.0,
            AuditCategoryEnum.INTEGRATION: 1.0,
        }

        base_score = severity_weights.get(self.result.severity, 1.0)
        multiplier = category_multipliers.get(self.result.category, 1.0)

        # Additional factors
        if self.result.outcome == AuditOutcomeEnum.FAILURE:
            multiplier *= 1.2
        elif self.result.outcome == AuditOutcomeEnum.ERROR:
            multiplier *= 1.3
        elif self.result.outcome == AuditOutcomeEnum.DENIED:
            multiplier *= 1.4

        return min(10.0, base_score * multiplier)

    @strawberry.field
    def has_changes(self) -> bool:
        """Check if entry has field changes."""
        return len(self.changes) > 0

    @strawberry.field
    def change_count(self) -> int:
        """Return number of field changes."""
        return len(self.changes)

    @strawberry.field
    def is_security_relevant(self) -> bool:
        """Check if entry is security-relevant."""
        security_categories = [
            AuditCategoryEnum.SECURITY,
            AuditCategoryEnum.AUTHENTICATION,
            AuditCategoryEnum.AUTHORIZATION,
        ]

        security_tags = ["security", "authentication", "authorization", "access"]

        return (
            self.result.category in security_categories
            or any(tag in self.metadata.tags for tag in security_tags)
            or self.result.severity
            in [AuditSeverityEnum.HIGH, AuditSeverityEnum.CRITICAL]
        )

    @strawberry.field
    def compliance_frameworks(self) -> list[str]:
        """Return applicable compliance frameworks."""
        frameworks = []

        # Extract frameworks from compliance tags
        for tag in self.metadata.compliance_tags:
            if tag.upper() in ["SOC2", "HIPAA", "GDPR", "PCI-DSS", "ISO27001", "NIST"]:
                frameworks.append(tag.upper())

        # Infer frameworks based on category
        if self.result.category == AuditCategoryEnum.COMPLIANCE:
            if "SOC2" not in frameworks:
                frameworks.append("SOC2")

        return frameworks


@strawberry.type
class AuditEntryConnection:
    """GraphQL connection type for paginated audit entries."""

    @strawberry.type
    class PageInfo:
        has_next_page: bool
        has_previous_page: bool
        start_cursor: str | None = None
        end_cursor: str | None = None

    @strawberry.type
    class Edge:
        node: AuditEntryType
        cursor: str

    edges: list[Edge]
    page_info: PageInfo
    total_count: int


@strawberry.type
class AuditEntryAggregation:
    """GraphQL type for audit entry aggregations."""

    field: str
    value: str
    count: int
    percentage: float
