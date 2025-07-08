"""Create audit session command.

This module implements the command and handler for creating audit sessions,
which group related audit entries together.
"""

from typing import Any
from uuid import UUID, uuid4

from app.core.cqrs.base import Command, CommandHandler
from app.core.errors import ValidationError
from app.core.logging import get_logger
from app.modules.audit.domain.aggregates.audit_session import AuditSession
from app.modules.audit.domain.value_objects.audit_context import AuditContext

logger = get_logger(__name__)


class CreateAuditSessionCommand(Command):
    """
    Command to create an audit session.

    Audit sessions group related audit entries together,
    typically representing a user's activity period.
    """

    def __init__(
        self,
        user_id: UUID | None,
        session_type: str,
        correlation_id: str | None = None,
        parent_session_id: UUID | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        request_id: str | None = None,
        additional_context: dict[str, Any] | None = None,
    ):
        """
        Initialize create audit session command.

        Args:
            user_id: User for whom the session is created (None for system)
            session_type: Type of session
            correlation_id: Correlation ID for tracking
            parent_session_id: Parent session for nesting
            ip_address: Client IP address
            user_agent: Client user agent string
            request_id: Request identifier
            additional_context: Additional context data
        """
        super().__init__()

        self.user_id = user_id  # Can be None for system sessions
        self.session_type = self._validate_session_type(session_type)
        self.correlation_id = correlation_id or str(uuid4())
        self.parent_session_id = parent_session_id
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.request_id = request_id
        self.additional_context = additional_context or {}

        self._freeze()

    def _validate_session_type(self, session_type: str) -> str:
        """Validate session type."""
        valid_types = [
            AuditSession.SESSION_USER_ACTIVITY,
            AuditSession.SESSION_BATCH_OPERATION,
            AuditSession.SESSION_IMPORT_EXPORT,
            AuditSession.SESSION_API_REQUEST,
            AuditSession.SESSION_SCHEDULED_TASK,
            AuditSession.SESSION_MAINTENANCE,
        ]
        if session_type not in valid_types:
            raise ValidationError(
                f"Invalid session type: {session_type}. Must be one of: {valid_types}"
            )
        return session_type


class CreateAuditSessionCommandHandler(
    CommandHandler[CreateAuditSessionCommand, AuditSession]
):
    """
    Handler for creating audit sessions.

    This handler manages the creation of audit sessions that group
    related audit entries together.
    """

    def __init__(self, audit_session_repository: Any, event_publisher: Any):
        """
        Initialize handler.

        Args:
            audit_session_repository: Repository for audit session persistence
            event_publisher: Event publisher for domain events
        """
        super().__init__()
        self.audit_session_repository = audit_session_repository
        self.event_publisher = event_publisher

    async def handle(self, command: CreateAuditSessionCommand) -> AuditSession:
        """
        Handle the create audit session command.

        Args:
            command: Command containing session details

        Returns:
            Created audit session
        """
        logger.info(
            "Creating audit session",
            user_id=command.user_id,
            session_type=command.session_type,
            correlation_id=command.correlation_id,
        )

        # Create audit context
        context = AuditContext(
            ip_address=command.ip_address,
            user_agent=command.user_agent,
            request_id=command.request_id,
            additional_data=command.additional_context,
        )

        # Handle parent session if specified
        parent_session = None
        if command.parent_session_id:
            parent_session = await self.audit_session_repository.find_by_id(
                command.parent_session_id
            )
            if not parent_session:
                raise ValidationError(
                    f"Parent session not found: {command.parent_session_id}"
                )

        # Create audit session
        session = AuditSession(
            user_id=command.user_id,
            session_type=command.session_type,
            correlation_id=command.correlation_id,
            context=context,
            parent_session_id=command.parent_session_id,
        )

        # Validate parent relationship if exists
        if parent_session:
            session.validate_parent_session(parent_session)
            await self.audit_session_repository.save(parent_session)

        # Save session
        await self.audit_session_repository.save(session)

        # Publish domain events
        for event in session.collect_events():
            await self.event_publisher.publish(event)

        if parent_session:
            for event in parent_session.collect_events():
                await self.event_publisher.publish(event)

        logger.info(
            "Audit session created successfully",
            session_id=session.id,
            user_id=session.user_id,
            parent_session_id=session.parent_session_id,
        )

        return session

    @property
    def command_type(self) -> type[CreateAuditSessionCommand]:
        """Get command type this handler processes."""
        return CreateAuditSessionCommand


__all__ = ["CreateAuditSessionCommand", "CreateAuditSessionCommandHandler"]
