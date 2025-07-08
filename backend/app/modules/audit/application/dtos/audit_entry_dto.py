"""Audit entry DTO.

This module defines the Data Transfer Object for audit entries,
providing a structured format for exchanging audit data between layers.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import UUID


@dataclass(frozen=True)
class AuditFieldChangeDTO:
    """DTO for field-level changes."""

    field_name: str
    old_value: Any | None
    new_value: Any | None
    field_type: str


@dataclass(frozen=True)
class AuditEntryDTO:
    """
    Data Transfer Object for audit entries.

    Provides a flat, serializable representation of audit entries
    for API responses and inter-layer communication.
    """

    # Identity
    id: UUID
    audit_log_id: UUID

    # Actor
    user_id: UUID | None
    user_email: str | None
    user_name: str | None

    # Action
    action_type: str
    operation: str
    description: str

    # Resource
    resource_type: str
    resource_id: str
    resource_name: str

    # Context
    ip_address: str | None
    user_agent: str | None
    session_id: UUID | None
    correlation_id: str | None

    # Result
    outcome: str
    severity: str
    category: str
    duration_ms: int | None
    error_details: dict[str, Any] | None

    # Changes
    changes: list[AuditFieldChangeDTO] = field(default_factory=list)

    # Metadata
    metadata: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)

    # Timestamps
    created_at: datetime

    @classmethod
    def from_domain(
        cls, entry: Any, user_info: dict[str, Any] | None = None
    ) -> "AuditEntryDTO":
        """
        Create DTO from domain entity.

        Args:
            entry: Domain audit entry
            user_info: Optional user information

        Returns:
            AuditEntryDTO instance
        """
        # Extract field changes
        changes = []
        if entry.changes:
            for change in entry.changes:
                changes.append(
                    AuditFieldChangeDTO(
                        field_name=change.field_name,
                        old_value=change.old_value,
                        new_value=change.new_value,
                        field_type=change.field_type,
                    )
                )

        # Build metadata
        metadata = {}
        if entry.metadata:
            metadata.update(
                {
                    "tags": entry.metadata.tags,
                    "custom_fields": entry.metadata.custom_fields,
                    "compliance_tags": entry.metadata.compliance_tags,
                }
            )

        return cls(
            id=entry.id,
            audit_log_id=entry.audit_log_id if hasattr(entry, "audit_log_id") else None,
            user_id=entry.user_id,
            user_email=user_info.get("email") if user_info else None,
            user_name=user_info.get("name") if user_info else None,
            action_type=entry.action.action_type,
            operation=entry.action.operation,
            description=entry.action.description,
            resource_type=entry.resource.resource_type,
            resource_id=entry.resource.resource_id,
            resource_name=entry.resource.resource_name or entry.resource.resource_id,
            ip_address=entry.context.ip_address,
            user_agent=entry.context.user_agent,
            session_id=entry.session_id,
            correlation_id=entry.correlation_id,
            outcome=entry.outcome,
            severity=entry.severity.value,
            category=entry.category.value,
            duration_ms=entry.duration_ms,
            error_details=entry.error_details,
            changes=changes,
            metadata=metadata,
            tags=entry.metadata.tags if entry.metadata else [],
            created_at=entry.created_at,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "id": str(self.id),
            "audit_log_id": str(self.audit_log_id),
            "user_id": str(self.user_id) if self.user_id else None,
            "user_email": self.user_email,
            "user_name": self.user_name,
            "action": {
                "type": self.action_type,
                "operation": self.operation,
                "description": self.description,
            },
            "resource": {
                "type": self.resource_type,
                "id": self.resource_id,
                "name": self.resource_name,
            },
            "context": {
                "ip_address": self.ip_address,
                "user_agent": self.user_agent,
                "session_id": str(self.session_id) if self.session_id else None,
                "correlation_id": self.correlation_id,
            },
            "result": {
                "outcome": self.outcome,
                "severity": self.severity,
                "category": self.category,
                "duration_ms": self.duration_ms,
                "error_details": self.error_details,
            },
            "changes": [
                {
                    "field_name": c.field_name,
                    "old_value": c.old_value,
                    "new_value": c.new_value,
                    "field_type": c.field_type,
                }
                for c in self.changes
            ],
            "metadata": self.metadata,
            "tags": self.tags,
            "created_at": self.created_at.isoformat(),
        }


__all__ = ["AuditEntryDTO", "AuditFieldChangeDTO"]
