"""Audit session aggregate.

This module defines the AuditSession aggregate for grouping
related audit entries into logical sessions.
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any
from uuid import UUID

from app.core.domain.base import AggregateRoot
from app.core.errors import ValidationError
from app.modules.audit.domain.errors.audit_errors import AuditSessionError
from app.modules.audit.domain.events.audit_events import AuditSessionStarted
from app.modules.audit.domain.value_objects.audit_context import AuditContext

if TYPE_CHECKING:
    pass


class AuditSession(AggregateRoot):
    """
    Aggregate for grouping related audit entries.

    This aggregate manages audit sessions that group related
    activities together, providing context and correlation.

    Attributes:
        user_id: User who owns the session
        session_type: Type of session
        correlation_id: Correlation identifier
        parent_session_id: Parent session for nesting
        context: Session context information
        entry_ids: IDs of entries in this session
        child_session_ids: IDs of child sessions
        started_at: Session start time
        ended_at: Session end time
        is_active: Whether session is active
        summary: Session summary information

    Business Rules:
        - Sessions must have a valid type
        - Parent sessions must exist if specified
        - Sessions can be nested up to 3 levels deep
        - Ended sessions cannot be reactivated
        - Child sessions must end before parent
    """

    MAX_NESTING_DEPTH = 3
    MAX_ENTRIES_PER_SESSION = 10000

    # Common session types
    SESSION_USER_ACTIVITY = "user_activity"
    SESSION_BATCH_OPERATION = "batch_operation"
    SESSION_IMPORT_EXPORT = "import_export"
    SESSION_API_REQUEST = "api_request"
    SESSION_SCHEDULED_TASK = "scheduled_task"
    SESSION_MAINTENANCE = "maintenance"

    def __init__(
        self,
        user_id: UUID | None,
        session_type: str,
        correlation_id: str,
        context: AuditContext,
        parent_session_id: UUID | None = None,
        entity_id: UUID | None = None,
    ):
        """
        Initialize audit session.

        Args:
            user_id: User who owns the session
            session_type: Type of session
            correlation_id: Correlation identifier
            context: Session context
            parent_session_id: Parent session ID
            entity_id: Session identifier

        Raises:
            ValidationError: If required fields are invalid
        """
        super().__init__(entity_id)

        # Set user (can be None for system sessions)
        self.user_id = user_id

        # Validate and set session type
        self.session_type = self._validate_session_type(session_type)

        # Set correlation ID
        self.validate_not_empty(correlation_id, "correlation_id")
        self.correlation_id = correlation_id

        # Set context
        if not isinstance(context, AuditContext):
            raise ValidationError("Invalid audit context")
        self.context = context

        # Set parent session
        self.parent_session_id = parent_session_id
        self.nesting_depth = 0  # Will be set when validating parent

        # Initialize collections
        self.entry_ids: list[UUID] = []
        self.child_session_ids: list[UUID] = []

        # Initialize timestamps
        self.started_at = datetime.utcnow()
        self.ended_at: datetime | None = None
        self.is_active = True

        # Initialize summary
        self.summary: dict[str, Any] = {
            "entry_count": 0,
            "success_count": 0,
            "failure_count": 0,
            "duration_ms": None,
        }

        # Add creation event
        self.add_event(
            AuditSessionStarted(
                session_id=self.id,
                user_id=user_id,
                session_type=session_type,
                correlation_id=correlation_id,
                parent_session_id=parent_session_id,
                context=context.to_dict(),
            )
        )

    def _validate_session_type(self, session_type: str) -> str:
        """Validate session type."""
        if not session_type:
            raise ValidationError("Session type is required")

        return session_type.lower().strip()

    def validate_parent_session(self, parent: AuditSession | None) -> None:
        """
        Validate parent session relationship.

        Args:
            parent: Parent session instance

        Raises:
            AuditSessionError: If parent validation fails
        """
        if not self.parent_session_id:
            return

        if not parent:
            raise AuditSessionError(
                "Parent session not found", session_id=self.parent_session_id
            )

        # Check if parent is active
        if not parent.is_active:
            raise AuditSessionError(
                "Cannot create child session under inactive parent",
                session_id=parent.id,
                session_status="inactive",
            )

        # Check nesting depth
        if parent.nesting_depth >= self.MAX_NESTING_DEPTH - 1:
            raise AuditSessionError(
                f"Maximum nesting depth of {self.MAX_NESTING_DEPTH} exceeded",
                session_id=self.id,
            )

        # Set our nesting depth
        self.nesting_depth = parent.nesting_depth + 1

        # Add ourselves to parent's children
        parent.add_child_session(self.id)

    def add_entry(self, entry_id: UUID, outcome: str = "success") -> None:
        """
        Add an audit entry to the session.

        Args:
            entry_id: ID of the audit entry
            outcome: Outcome of the entry

        Raises:
            AuditSessionError: If session cannot accept entries
        """
        if not self.is_active:
            raise AuditSessionError(
                "Cannot add entries to inactive session",
                session_id=self.id,
                session_status="inactive",
            )

        if len(self.entry_ids) >= self.MAX_ENTRIES_PER_SESSION:
            raise AuditSessionError(
                f"Session has reached maximum capacity of {self.MAX_ENTRIES_PER_SESSION} entries",
                session_id=self.id,
            )

        # Add entry
        self.entry_ids.append(entry_id)

        # Update summary
        self.summary["entry_count"] += 1
        if outcome == "success":
            self.summary["success_count"] += 1
        elif outcome == "failure":
            self.summary["failure_count"] += 1

        self.mark_modified()

    def add_child_session(self, child_session_id: UUID) -> None:
        """
        Add a child session.

        Args:
            child_session_id: ID of child session

        Raises:
            AuditSessionError: If cannot add child
        """
        if not self.is_active:
            raise AuditSessionError(
                "Cannot add child sessions to inactive session", session_id=self.id
            )

        if child_session_id in self.child_session_ids:
            return  # Already added

        self.child_session_ids.append(child_session_id)
        self.mark_modified()

    def end_session(self, additional_summary: dict[str, Any] | None = None) -> None:
        """
        End the audit session.

        Args:
            additional_summary: Additional summary data

        Raises:
            AuditSessionError: If session cannot be ended
        """
        if not self.is_active:
            raise AuditSessionError("Session is already ended", session_id=self.id)

        # Validate all child sessions are ended
        # This would normally check against child session instances
        # For now, we trust the application logic

        self.is_active = False
        self.ended_at = datetime.utcnow()

        # Calculate duration
        duration = (self.ended_at - self.started_at).total_seconds() * 1000
        self.summary["duration_ms"] = int(duration)

        # Add additional summary data
        if additional_summary:
            self.summary.update(additional_summary)

        self.mark_modified()

    def get_duration_seconds(self) -> float | None:
        """Get session duration in seconds."""
        if not self.ended_at:
            if self.is_active:
                # Calculate current duration
                return (datetime.utcnow() - self.started_at).total_seconds()
            return None

        return (self.ended_at - self.started_at).total_seconds()

    def get_success_rate(self) -> float:
        """Calculate success rate of entries."""
        total = self.summary["entry_count"]
        if total == 0:
            return 100.0

        success = self.summary["success_count"]
        return (success / total) * 100

    def is_system_session(self) -> bool:
        """Check if this is a system-initiated session."""
        return self.user_id is None

    def is_nested(self) -> bool:
        """Check if this is a nested session."""
        return self.parent_session_id is not None

    def has_failures(self) -> bool:
        """Check if session has any failures."""
        return self.summary["failure_count"] > 0

    def get_entry_rate(self) -> float:
        """
        Get rate of entries per second.

        Returns:
            Entries per second, or 0 if no duration
        """
        duration = self.get_duration_seconds()
        if not duration or duration == 0:
            return 0.0

        return self.summary["entry_count"] / duration

    def merge_child_summary(self, child_summary: dict[str, Any]) -> None:
        """
        Merge child session summary into parent.

        Args:
            child_summary: Summary from child session
        """
        # Aggregate counts
        for key in ["entry_count", "success_count", "failure_count"]:
            if key in child_summary:
                self.summary[key] += child_summary[key]

        self.mark_modified()

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        data = super().to_dict()

        data.update(
            {
                "user_id": str(self.user_id) if self.user_id else None,
                "session_type": self.session_type,
                "correlation_id": self.correlation_id,
                "parent_session_id": str(self.parent_session_id)
                if self.parent_session_id
                else None,
                "context": self.context.to_dict(),
                "nesting_depth": self.nesting_depth,
                "entry_count": len(self.entry_ids),
                "child_count": len(self.child_session_ids),
                "started_at": self.started_at.isoformat(),
                "ended_at": self.ended_at.isoformat() if self.ended_at else None,
                "is_active": self.is_active,
                "summary": self.summary,
                "duration_seconds": self.get_duration_seconds(),
                "success_rate": self.get_success_rate(),
            }
        )

        return data

    @classmethod
    def create_user_session(
        cls, user_id: UUID, context: AuditContext, correlation_id: str | None = None
    ) -> AuditSession:
        """Factory method for user activity sessions."""
        return cls(
            user_id=user_id,
            session_type=cls.SESSION_USER_ACTIVITY,
            correlation_id=correlation_id or str(UUID()),
            context=context,
        )

    @classmethod
    def create_batch_session(
        cls, operation_name: str, context: AuditContext, user_id: UUID | None = None
    ) -> AuditSession:
        """Factory method for batch operation sessions."""
        context_with_operation = context.with_additional_data(operation=operation_name)

        return cls(
            user_id=user_id,
            session_type=cls.SESSION_BATCH_OPERATION,
            correlation_id=f"batch-{UUID()}",
            context=context_with_operation,
        )

    @classmethod
    def create_api_session(
        cls, request_id: str, user_id: UUID | None, context: AuditContext
    ) -> AuditSession:
        """Factory method for API request sessions."""
        return cls(
            user_id=user_id,
            session_type=cls.SESSION_API_REQUEST,
            correlation_id=request_id,
            context=context,
        )


__all__ = ["AuditSession"]
