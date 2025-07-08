"""Audit service.

This module provides high-level audit operations and workflows,
orchestrating audit entry creation, session management, and log lifecycle.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from app.core.errors import DomainError
from app.core.logging import get_logger
from app.modules.audit.application.commands.create_audit_session_command import (
    CreateAuditSessionCommand,
)
from app.modules.audit.application.commands.record_audit_entry_command import (
    RecordAuditEntryCommand,
)
from app.modules.audit.domain.aggregates.audit_session import AuditSession

logger = get_logger(__name__)


class AuditService:
    """
    Application service for audit operations.

    Provides high-level audit functionality including automatic
    audit trail creation, session management, and event correlation.
    """

    def __init__(
        self,
        command_bus: Any,
        audit_repository: Any,
        session_repository: Any,
        event_publisher: Any,
    ):
        """
        Initialize audit service.

        Args:
            command_bus: Command bus for executing commands
            audit_repository: Repository for audit data
            session_repository: Repository for session data
            event_publisher: Event publisher for domain events
        """
        self.command_bus = command_bus
        self.audit_repository = audit_repository
        self.session_repository = session_repository
        self.event_publisher = event_publisher

    async def create_audit_trail(
        self,
        user_id: UUID | None,
        action_type: str,
        operation: str,
        description: str,
        resource_type: str,
        resource_id: str,
        context: dict[str, Any] | None = None,
        session_id: UUID | None = None,
        correlation_id: str | None = None,
        **kwargs,
    ) -> UUID:
        """
        Create a comprehensive audit trail entry.

        This is the primary method for recording audit events with
        automatic context enrichment and session correlation.

        Args:
            user_id: User performing the action
            action_type: Type of action
            operation: Specific operation
            description: Human-readable description
            resource_type: Type of resource affected
            resource_id: Resource identifier
            context: Additional context information
            session_id: Associated session ID
            correlation_id: Correlation identifier
            **kwargs: Additional parameters for audit entry

        Returns:
            UUID of created audit entry
        """
        logger.debug(
            "Creating audit trail",
            user_id=user_id,
            action_type=action_type,
            resource_type=resource_type,
        )

        # Enrich context if provided
        enriched_context = await self._enrich_audit_context(context, user_id)

        # Auto-detect session if not provided
        if not session_id and user_id:
            session_id = await self._get_or_create_user_session(
                user_id, enriched_context
            )

        # Create audit entry command
        command = RecordAuditEntryCommand(
            user_id=user_id,
            action_type=action_type,
            operation=operation,
            description=description,
            resource_type=resource_type,
            resource_id=resource_id,
            resource_name=kwargs.get("resource_name"),
            ip_address=enriched_context.get("ip_address"),
            user_agent=enriched_context.get("user_agent"),
            request_id=enriched_context.get("request_id"),
            outcome=kwargs.get("outcome", "success"),
            error_details=kwargs.get("error_details"),
            duration_ms=kwargs.get("duration_ms"),
            severity=kwargs.get("severity"),
            category=kwargs.get("category"),
            session_id=session_id,
            correlation_id=correlation_id,
            changes=kwargs.get("changes"),
            tags=kwargs.get("tags"),
            custom_fields=kwargs.get("custom_fields"),
            compliance_tags=kwargs.get("compliance_tags"),
        )

        # Execute command
        entry = await self.command_bus.execute(command)

        # Update session with new entry
        if session_id:
            await self._update_session_with_entry(session_id, entry.id, command.outcome)

        logger.info(
            "Audit trail created successfully", entry_id=entry.id, session_id=session_id
        )

        return entry.id

    async def start_audit_session(
        self,
        user_id: UUID | None,
        session_type: str,
        context: dict[str, Any] | None = None,
        parent_session_id: UUID | None = None,
    ) -> UUID:
        """
        Start a new audit session for grouping related activities.

        Args:
            user_id: User starting the session
            session_type: Type of session
            context: Session context
            parent_session_id: Parent session for nesting

        Returns:
            UUID of created session
        """
        logger.debug(
            "Starting audit session", user_id=user_id, session_type=session_type
        )

        # Create session command
        command = CreateAuditSessionCommand(
            user_id=user_id,
            session_type=session_type,
            correlation_id=context.get("correlation_id") if context else None,
            parent_session_id=parent_session_id,
            ip_address=context.get("ip_address") if context else None,
            user_agent=context.get("user_agent") if context else None,
            request_id=context.get("request_id") if context else None,
            additional_context=context or {},
        )

        # Execute command
        session = await self.command_bus.execute(command)

        logger.info(
            "Audit session started successfully", session_id=session.id, user_id=user_id
        )

        return session.id

    async def end_audit_session(
        self, session_id: UUID, summary: dict[str, Any] | None = None
    ) -> None:
        """
        End an audit session and finalize its summary.

        Args:
            session_id: Session to end
            summary: Additional summary information
        """
        logger.debug("Ending audit session", session_id=session_id)

        # Retrieve session
        session = await self.session_repository.find_by_id(session_id)
        if not session:
            raise DomainError(f"Session not found: {session_id}")

        # End the session
        session.end_session(summary)

        # Save session
        await self.session_repository.save(session)

        # Publish events
        for event in session.collect_events():
            await self.event_publisher.publish(event)

        logger.info("Audit session ended successfully", session_id=session_id)

    async def bulk_audit_trail(
        self, entries: list[dict[str, Any]], batch_correlation_id: str | None = None
    ) -> list[UUID]:
        """
        Create multiple audit trail entries in a batch.

        Args:
            entries: List of audit entry definitions
            batch_correlation_id: Correlation ID for the batch

        Returns:
            List of created entry IDs
        """
        logger.info("Creating bulk audit trail", entry_count=len(entries))

        entry_ids = []

        for entry_data in entries:
            # Use batch correlation ID if provided
            correlation_id = entry_data.get("correlation_id", batch_correlation_id)

            try:
                entry_id = await self.create_audit_trail(
                    correlation_id=correlation_id, **entry_data
                )
                entry_ids.append(entry_id)
            except Exception as e:
                logger.exception(
                    "Failed to create audit entry in batch",
                    entry_data=entry_data,
                    error=str(e),
                )
                # Continue with other entries
                continue

        logger.info(
            "Bulk audit trail completed",
            requested_count=len(entries),
            created_count=len(entry_ids),
        )

        return entry_ids

    async def correlate_audit_events(
        self, correlation_id: str, include_sessions: bool = True
    ) -> dict[str, Any]:
        """
        Retrieve and correlate audit events by correlation ID.

        Args:
            correlation_id: Correlation identifier
            include_sessions: Whether to include session information

        Returns:
            Correlated audit data
        """
        logger.debug("Correlating audit events", correlation_id=correlation_id)

        # Find all entries with this correlation ID
        entries = await self.audit_repository.find_by_correlation_id(correlation_id)

        # Find sessions if requested
        sessions = []
        if include_sessions:
            sessions = await self.session_repository.find_by_correlation_id(
                correlation_id
            )

        # Build correlation analysis
        return {
            "correlation_id": correlation_id,
            "entry_count": len(entries),
            "session_count": len(sessions),
            "time_span": self._calculate_time_span(entries),
            "involved_users": list({e.user_id for e in entries if e.user_id}),
            "involved_resources": list(
                {
                    f"{e.resource.resource_type}:{e.resource.resource_id}"
                    for e in entries
                }
            ),
            "outcome_summary": self._summarize_outcomes(entries),
            "entries": [entry.id for entry in entries],
            "sessions": [session.id for session in sessions]
            if include_sessions
            else [],
        }

    async def get_audit_statistics(
        self,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        filters: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Get comprehensive audit statistics.

        Args:
            start_date: Start of analysis period
            end_date: End of analysis period
            filters: Additional filters

        Returns:
            Audit statistics
        """
        # Use default time range if not provided
        if not start_date:
            start_date = datetime.utcnow().replace(
                hour=0, minute=0, second=0, microsecond=0
            )
        if not end_date:
            end_date = datetime.utcnow()

        # Get statistics from repository
        return await self.audit_repository.get_statistics(
            start_date=start_date, end_date=end_date, filters=filters or {}
        )

    async def _enrich_audit_context(
        self, context: dict[str, Any] | None, user_id: UUID | None
    ) -> dict[str, Any]:
        """
        Enrich audit context with additional information.

        Args:
            context: Base context
            user_id: User ID for enrichment

        Returns:
            Enriched context
        """
        enriched = context.copy() if context else {}

        # Add timestamp if not present
        if "timestamp" not in enriched:
            enriched["timestamp"] = datetime.utcnow().isoformat()

        # Add user context if available
        if user_id and "user_context" not in enriched:
            # In a real implementation, this would fetch user details
            enriched["user_context"] = {
                "user_id": str(user_id),
                "enriched_at": datetime.utcnow().isoformat(),
            }

        return enriched

    async def _get_or_create_user_session(
        self, user_id: UUID, context: dict[str, Any]
    ) -> UUID | None:
        """
        Get active user session or create a new one.

        Args:
            user_id: User ID
            context: Context for session creation

        Returns:
            Session ID or None
        """
        # Try to find active session for user
        active_session = await self.session_repository.find_active_user_session(user_id)

        if active_session:
            # Check if session is still valid (not too old)
            session_age = (
                datetime.utcnow() - active_session.started_at
            ).total_seconds()
            if session_age < 3600:  # 1 hour max session age
                return active_session.id

        # Create new session
        try:
            return await self.start_audit_session(
                user_id=user_id,
                session_type=AuditSession.SESSION_USER_ACTIVITY,
                context=context,
            )
        except Exception as e:
            logger.warning(
                "Failed to create user session", user_id=user_id, error=str(e)
            )
            return None

    async def _update_session_with_entry(
        self, session_id: UUID, entry_id: UUID, outcome: str
    ) -> None:
        """
        Update session with new entry.

        Args:
            session_id: Session to update
            entry_id: Entry to add
            outcome: Entry outcome
        """
        try:
            session = await self.session_repository.find_by_id(session_id)
            if session and session.is_active:
                session.add_entry(entry_id, outcome)
                await self.session_repository.save(session)
        except Exception as e:
            logger.warning(
                "Failed to update session with entry",
                session_id=session_id,
                entry_id=entry_id,
                error=str(e),
            )

    def _calculate_time_span(self, entries: list[Any]) -> dict[str, Any] | None:
        """Calculate time span for a list of entries."""
        if not entries:
            return None

        timestamps = [entry.created_at for entry in entries]
        start_time = min(timestamps)
        end_time = max(timestamps)

        return {
            "start": start_time.isoformat(),
            "end": end_time.isoformat(),
            "duration_seconds": (end_time - start_time).total_seconds(),
        }

    def _summarize_outcomes(self, entries: list[Any]) -> dict[str, int]:
        """Summarize entry outcomes."""
        summary = {}
        for entry in entries:
            outcome = entry.outcome
            summary[outcome] = summary.get(outcome, 0) + 1
        return summary


__all__ = ["AuditService"]
