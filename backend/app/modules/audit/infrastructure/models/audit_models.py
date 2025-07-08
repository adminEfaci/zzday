"""Audit database models with time-based partitioning support.

This module defines SQLAlchemy models for the audit system with support
for time-based partitioning, optimized indexes, and immutability constraints.
"""

from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import relationship, validates
from sqlalchemy.sql import func

from app.core.database import Base
from app.modules.audit.domain.enums.audit_enums import (
    AuditCategory,
    AuditSeverity,
    AuditStatus,
    RetentionPolicy,
)


class TimestampMixin:
    """Mixin for timestamp fields."""

    created_at = Column(DateTime, nullable=False, default=func.now())
    updated_at = Column(
        DateTime, nullable=False, default=func.now(), onupdate=func.now()
    )


class AuditLogModel(Base, TimestampMixin):
    """
    Database model for audit logs with partitioning support.

    Supports monthly partitioning by created_at for performance.
    """

    __tablename__ = "audit_logs"
    __table_args__ = (
        # Composite indexes for common queries
        Index("idx_audit_logs_status_created", "status", "created_at"),
        Index("idx_audit_logs_retention_status", "retention_policy", "status"),
        Index("idx_audit_logs_archived", "archived_at", "archive_location"),
        # Partitioning by created_at (monthly)
        {"postgresql_partition_by": "RANGE (created_at)"},
    )

    # Primary key
    id = Column(PG_UUID(as_uuid=True), primary_key=True)

    # Basic fields
    title = Column(String(255), nullable=False)
    description = Column(Text)
    retention_policy = Column(
        Enum(RetentionPolicy, name="retention_policy_enum"), nullable=False
    )
    status = Column(
        Enum(AuditStatus, name="audit_status_enum"),
        nullable=False,
        default=AuditStatus.ACTIVE,
    )

    # Statistics
    entry_count = Column(Integer, nullable=False, default=0)
    last_entry_at = Column(DateTime)

    # Archive fields
    archived_at = Column(DateTime)
    archive_location = Column(Text)
    archive_size_bytes = Column(BigInteger)

    # Metadata
    created_by = Column(PG_UUID(as_uuid=True))

    # Relationships
    entries = relationship(
        "AuditEntryModel",
        back_populates="audit_log",
        cascade="all, delete-orphan",
        lazy="dynamic",
    )

    @validates("status")
    def validate_status_transition(self, key, value):
        """Validate status transitions."""
        if self.status is not None:
            # Validate allowed transitions
            allowed_transitions = {
                AuditStatus.ACTIVE: [AuditStatus.PENDING_ARCHIVE],
                AuditStatus.PENDING_ARCHIVE: [AuditStatus.ARCHIVED, AuditStatus.ACTIVE],
                AuditStatus.ARCHIVED: [],  # No transitions from archived
            }

            if value not in allowed_transitions.get(self.status, []):
                raise ValueError(
                    f"Invalid status transition from {self.status} to {value}"
                )

        return value


class AuditSessionModel(Base, TimestampMixin):
    """
    Database model for audit sessions.

    Groups related audit entries within a user session.
    """

    __tablename__ = "audit_sessions"
    __table_args__ = (
        Index("idx_audit_sessions_user_created", "user_id", "created_at"),
        Index("idx_audit_sessions_correlation", "correlation_id"),
        Index("idx_audit_sessions_active", "is_active", "last_activity_at"),
    )

    # Primary key
    id = Column(PG_UUID(as_uuid=True), primary_key=True)

    # Session fields
    user_id = Column(PG_UUID(as_uuid=True), nullable=False)
    correlation_id = Column(String(255), nullable=False)

    # Session metadata
    session_type = Column(String(50), nullable=False)  # 'web', 'api', 'mobile', etc.
    ip_address = Column(String(45))  # Support IPv6
    user_agent = Column(Text)

    # Activity tracking
    is_active = Column(Boolean, nullable=False, default=True)
    started_at = Column(DateTime, nullable=False, default=func.now())
    last_activity_at = Column(DateTime, nullable=False, default=func.now())
    ended_at = Column(DateTime)

    # Statistics
    entry_count = Column(Integer, nullable=False, default=0)
    error_count = Column(Integer, nullable=False, default=0)

    # Additional context
    context_data = Column(JSONB)

    # Relationships
    entries = relationship("AuditEntryModel", back_populates="session", lazy="dynamic")


class AuditEntryModel(Base):
    """
    Database model for audit entries with immutability.

    Partitioned by created_at for performance at scale.
    """

    __tablename__ = "audit_entries"
    __table_args__ = (
        # Composite indexes for search performance
        Index("idx_audit_entries_log_created", "audit_log_id", "created_at"),
        Index("idx_audit_entries_user_created", "user_id", "created_at"),
        Index(
            "idx_audit_entries_resource", "resource_type", "resource_id", "created_at"
        ),
        Index("idx_audit_entries_action", "action_type", "operation", "created_at"),
        Index(
            "idx_audit_entries_severity_category", "severity", "category", "created_at"
        ),
        Index("idx_audit_entries_session", "session_id", "created_at"),
        Index("idx_audit_entries_correlation", "correlation_id", "created_at"),
        # Full-text search index (PostgreSQL specific)
        Index("idx_audit_entries_search", "action_description", postgresql_using="gin"),
        # Ensure immutability
        CheckConstraint("created_at = created_at", name="audit_entry_immutable"),
        # Partitioning by created_at (daily for high volume)
        {"postgresql_partition_by": "RANGE (created_at)"},
    )

    # Primary key
    id = Column(PG_UUID(as_uuid=True), primary_key=True)

    # Foreign keys
    audit_log_id = Column(
        PG_UUID(as_uuid=True), ForeignKey("audit_logs.id"), nullable=False
    )
    session_id = Column(PG_UUID(as_uuid=True), ForeignKey("audit_sessions.id"))

    # User information
    user_id = Column(PG_UUID(as_uuid=True))  # Nullable for system actions

    # Action information
    action_type = Column(
        String(50), nullable=False
    )  # 'create', 'update', 'delete', etc.
    operation = Column(String(100), nullable=False)  # Specific operation name
    action_description = Column(Text, nullable=False)

    # Resource information
    resource_type = Column(String(100), nullable=False)
    resource_id = Column(String(255))
    resource_name = Column(String(255))

    # Context information
    ip_address = Column(String(45))
    user_agent = Column(Text)
    request_id = Column(String(255))

    # Classification
    severity = Column(Enum(AuditSeverity, name="audit_severity_enum"), nullable=False)
    category = Column(Enum(AuditCategory, name="audit_category_enum"), nullable=False)

    # Outcome
    outcome = Column(String(20), nullable=False)  # 'success', 'failure', 'partial'
    error_details = Column(JSONB)

    # Performance
    duration_ms = Column(Integer)

    # Correlation
    correlation_id = Column(String(255), nullable=False)

    # Metadata
    metadata = Column(JSONB)

    # Immutable timestamp
    created_at = Column(DateTime, nullable=False, default=func.now())

    # Relationships
    audit_log = relationship("AuditLogModel", back_populates="entries")
    session = relationship("AuditSessionModel", back_populates="entries")
    fields = relationship(
        "AuditFieldModel",
        back_populates="entry",
        cascade="all, delete-orphan",
        lazy="joined",
    )

    def __init__(self, **kwargs):
        """Initialize with immutability check."""
        super().__init__(**kwargs)
        self._original_created_at = self.created_at

    @validates("created_at")
    def validate_immutable_timestamp(self, key, value):
        """Ensure created_at cannot be modified."""
        if (
            hasattr(self, "_original_created_at")
            and self._original_created_at is not None
        ) and value != self._original_created_at:
            raise ValueError(
                "Audit entries are immutable - created_at cannot be modified"
            )
        return value


class AuditFieldModel(Base):
    """
    Database model for field-level changes in audit entries.
    """

    __tablename__ = "audit_fields"
    __table_args__ = (
        Index("idx_audit_fields_entry", "audit_entry_id"),
        Index("idx_audit_fields_name", "field_name"),
    )

    # Primary key
    id = Column(PG_UUID(as_uuid=True), primary_key=True)

    # Foreign key
    audit_entry_id = Column(
        PG_UUID(as_uuid=True), ForeignKey("audit_entries.id"), nullable=False
    )

    # Field information
    field_name = Column(String(255), nullable=False)
    field_path = Column(String(500))  # For nested fields

    # Values (stored as JSON for flexibility)
    old_value = Column(JSONB)
    new_value = Column(JSONB)

    # Metadata
    value_type = Column(String(50))
    is_sensitive = Column(Boolean, nullable=False, default=False)

    # Relationship
    entry = relationship("AuditEntryModel", back_populates="fields")


class AuditReportModel(Base, TimestampMixin):
    """
    Database model for generated audit reports.
    """

    __tablename__ = "audit_reports"
    __table_args__ = (
        Index("idx_audit_reports_type_created", "report_type", "created_at"),
        Index("idx_audit_reports_period", "period_start", "period_end"),
        Index("idx_audit_reports_status", "status", "created_at"),
    )

    # Primary key
    id = Column(PG_UUID(as_uuid=True), primary_key=True)

    # Report metadata
    title = Column(String(255), nullable=False)
    description = Column(Text)
    report_type = Column(
        String(50), nullable=False
    )  # 'compliance', 'security', 'user_activity', etc.

    # Time period
    period_start = Column(DateTime, nullable=False)
    period_end = Column(DateTime, nullable=False)

    # Generation details
    generated_by = Column(PG_UUID(as_uuid=True), nullable=False)
    generation_duration_ms = Column(Integer)

    # Report data
    summary_data = Column(JSONB, nullable=False)
    detailed_data = Column(JSONB)

    # Status
    status = Column(String(20), nullable=False, default="completed")
    error_message = Column(Text)

    # Storage
    file_location = Column(Text)  # If exported to file
    file_size_bytes = Column(BigInteger)
    file_format = Column(String(20))  # 'json', 'csv', 'pdf', etc.

    # Access tracking
    access_count = Column(Integer, nullable=False, default=0)
    last_accessed_at = Column(DateTime)

    # Retention
    expires_at = Column(DateTime)
    is_archived = Column(Boolean, nullable=False, default=False)


# Create partition tables for time-based partitioning
def create_partition_tables(engine, start_date: datetime, end_date: datetime):
    """
    Create partition tables for audit_entries and audit_logs.

    Creates monthly partitions for audit_logs and daily partitions for audit_entries.
    """
    from sqlalchemy import text

    # Generate partition SQL for audit_logs (monthly)
    current = start_date
    while current < end_date:
        next_month = (current.replace(day=1) + timedelta(days=32)).replace(day=1)
        partition_name = f"audit_logs_{current.year}_{current.month:02d}"

        sql = text(
            f"""
            CREATE TABLE IF NOT EXISTS {partition_name} PARTITION OF audit_logs
            FOR VALUES FROM ('{current.strftime('%Y-%m-%d')}') 
            TO ('{next_month.strftime('%Y-%m-%d')}');
        """
        )

        engine.execute(sql)
        current = next_month

    # Generate partition SQL for audit_entries (daily)
    current = start_date
    while current < end_date:
        next_day = current + timedelta(days=1)
        partition_name = (
            f"audit_entries_{current.year}_{current.month:02d}_{current.day:02d}"
        )

        sql = text(
            f"""
            CREATE TABLE IF NOT EXISTS {partition_name} PARTITION OF audit_entries
            FOR VALUES FROM ('{current.strftime('%Y-%m-%d')}') 
            TO ('{next_day.strftime('%Y-%m-%d')}');
        """
        )

        engine.execute(sql)
        current = next_day


# Index creation for search optimization
def create_search_indexes(engine):
    """Create additional indexes for search optimization."""
    from sqlalchemy import text

    indexes = [
        # Trigram indexes for text search (requires pg_trgm extension)
        """
        CREATE INDEX IF NOT EXISTS idx_audit_entries_action_desc_trgm 
        ON audit_entries USING gin (action_description gin_trgm_ops);
        """,
        # BRIN indexes for time-series data
        """
        CREATE INDEX IF NOT EXISTS idx_audit_entries_created_brin 
        ON audit_entries USING brin (created_at);
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_audit_logs_created_brin 
        ON audit_logs USING brin (created_at);
        """,
        # Partial indexes for common queries
        """
        CREATE INDEX IF NOT EXISTS idx_audit_entries_failures 
        ON audit_entries (created_at, severity) 
        WHERE outcome = 'failure';
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_audit_entries_high_severity 
        ON audit_entries (created_at, user_id) 
        WHERE severity IN ('high', 'critical');
        """,
    ]

    for index_sql in indexes:
        engine.execute(text(index_sql))


__all__ = [
    "AuditEntryModel",
    "AuditFieldModel",
    "AuditLogModel",
    "AuditReportModel",
    "AuditSessionModel",
    "create_partition_tables",
    "create_search_indexes",
]
