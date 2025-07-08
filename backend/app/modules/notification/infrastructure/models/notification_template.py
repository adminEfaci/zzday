"""SQLAlchemy model for NotificationTemplate aggregate."""

from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Enum,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import UUID as PostgresUUID

from app.core.infrastructure.database import Base
from app.modules.notification.domain.enums import TemplateType


class NotificationTemplateModel(Base):
    """Database model for notification templates."""

    __tablename__ = "notification_templates"

    # Primary key
    id = Column(PostgresUUID(as_uuid=True), primary_key=True)

    # Basic fields
    name = Column(String(100), nullable=False, unique=True, index=True)
    template_type = Column(Enum(TemplateType), nullable=False, index=True)
    description = Column(Text, nullable=True)
    tags = Column(JSON, nullable=False, default=list)

    # Channel contents stored as JSON
    # Format: {"email": {"subject": "...", "body": "...", "html_body": "..."}, ...}
    channel_contents = Column(JSON, nullable=False, default=dict)

    # Variable definitions stored as JSON
    # Format: {"var_name": {"type": "string", "required": true, ...}, ...}
    variables = Column(JSON, nullable=False, default=dict)

    # Version control
    version = Column(Integer, nullable=False, default=1)
    version_history = Column(JSON, nullable=False, default=list)

    # Status fields
    is_active = Column(Boolean, nullable=False, default=True, index=True)
    is_default = Column(Boolean, nullable=False, default=False)

    # Usage tracking
    usage_count = Column(Integer, nullable=False, default=0)
    last_used_at = Column(DateTime, nullable=True)

    # Configuration
    required_channels = Column(JSON, nullable=False, default=list)
    validation_rules = Column(JSON, nullable=True)

    # Metadata
    metadata = Column(JSON, nullable=True)

    # Audit fields
    created_by = Column(PostgresUUID(as_uuid=True), nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(
        DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    # Indexes for common queries
    __table_args__ = (
        Index("idx_templates_type_active", "template_type", "is_active"),
        Index("idx_templates_default", "template_type", "is_default"),
        Index("idx_templates_tags", "tags"),  # GIN index for JSON
    )

    def to_dict(self) -> dict:
        """Convert model to dictionary."""
        return {
            "id": str(self.id),
            "name": self.name,
            "template_type": self.template_type.value if self.template_type else None,
            "description": self.description,
            "tags": self.tags,
            "channel_contents": self.channel_contents,
            "variables": self.variables,
            "version": self.version,
            "version_history": self.version_history,
            "is_active": self.is_active,
            "is_default": self.is_default,
            "usage_count": self.usage_count,
            "last_used_at": self.last_used_at.isoformat()
            if self.last_used_at
            else None,
            "required_channels": self.required_channels,
            "validation_rules": self.validation_rules,
            "metadata": self.metadata,
            "created_by": str(self.created_by),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
