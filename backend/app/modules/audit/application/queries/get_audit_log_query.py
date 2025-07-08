"""Get audit log query.

This module implements the query and handler for retrieving audit logs
with optional entry inclusion and filtering.
"""

from uuid import UUID

from app.core.cqrs.base import Query, QueryHandler
from app.core.errors import NotFoundError, ValidationError
from app.core.logging import get_logger
from app.modules.audit.application.dtos.audit_entry_dto import AuditEntryDTO

logger = get_logger(__name__)


class GetAuditLogQuery(Query):
    """
    Query to retrieve an audit log with optional entries.

    Supports retrieving audit log metadata and optionally
    including the associated audit entries.
    """

    def __init__(
        self,
        audit_log_id: UUID,
        include_entries: bool = False,
        entry_limit: int | None = None,
        entry_offset: int | None = None,
        include_statistics: bool = True,
    ):
        """
        Initialize get audit log query.

        Args:
            audit_log_id: ID of the audit log to retrieve
            include_entries: Whether to include audit entries
            entry_limit: Maximum number of entries to include
            entry_offset: Offset for entry pagination
            include_statistics: Whether to include log statistics
        """
        super().__init__()

        self.audit_log_id = self._validate_audit_log_id(audit_log_id)
        self.include_entries = include_entries
        self.entry_limit = self._validate_entry_limit(entry_limit)
        self.entry_offset = entry_offset or 0
        self.include_statistics = include_statistics

        self._freeze()

    def _validate_audit_log_id(self, audit_log_id: UUID) -> UUID:
        """Validate audit log ID."""
        if not isinstance(audit_log_id, UUID):
            raise ValidationError("Audit log ID must be a valid UUID")
        return audit_log_id

    def _validate_entry_limit(self, limit: int | None) -> int | None:
        """Validate entry limit."""
        if limit is not None and (limit < 1 or limit > 10000):
            raise ValidationError("Entry limit must be between 1 and 10000")
        return limit


class GetAuditLogQueryHandler(QueryHandler[GetAuditLogQuery, dict]):
    """
    Handler for retrieving audit logs.

    This handler fetches audit log data with optional
    entries and statistics.
    """

    def __init__(self, audit_repository: Any, user_service: Any):
        """
        Initialize handler.

        Args:
            audit_repository: Repository for audit data access
            user_service: Service for user information lookup
        """
        super().__init__()
        self.audit_repository = audit_repository
        self.user_service = user_service

    async def handle(self, query: GetAuditLogQuery) -> dict:
        """
        Handle the get audit log query.

        Args:
            query: Query containing retrieval parameters

        Returns:
            Dictionary containing audit log data

        Raises:
            NotFoundError: If audit log not found
        """
        logger.debug(
            "Retrieving audit log",
            audit_log_id=query.audit_log_id,
            include_entries=query.include_entries,
        )

        # Retrieve audit log
        audit_log = await self.audit_repository.find_by_id(query.audit_log_id)
        if not audit_log:
            raise NotFoundError(f"Audit log not found: {query.audit_log_id}")

        # Build response
        response = {"audit_log": audit_log.to_dict()}

        # Include statistics if requested
        if query.include_statistics:
            response["statistics"] = audit_log.get_statistics()

        # Include entries if requested
        if query.include_entries:
            entries = await self._get_audit_entries(
                query.audit_log_id, query.entry_limit, query.entry_offset
            )

            # Convert to DTOs with user information
            entry_dtos = []
            for entry in entries:
                user_info = None
                if entry.user_id:
                    user_info = await self.user_service.get_user_info(entry.user_id)

                entry_dto = AuditEntryDTO.from_domain(entry, user_info)
                entry_dtos.append(entry_dto.to_dict())

            response["entries"] = entry_dtos
            response["entry_metadata"] = {
                "count": len(entry_dtos),
                "limit": query.entry_limit,
                "offset": query.entry_offset,
                "has_more": len(entry_dtos) == query.entry_limit
                if query.entry_limit
                else False,
            }

        logger.debug(
            "Audit log retrieved successfully",
            audit_log_id=query.audit_log_id,
            entry_count=len(response.get("entries", [])),
        )

        return response

    async def _get_audit_entries(
        self, audit_log_id: UUID, limit: int | None, offset: int
    ) -> list[Any]:
        """
        Retrieve audit entries for the log.

        Args:
            audit_log_id: ID of the audit log
            limit: Maximum number of entries to retrieve
            offset: Number of entries to skip

        Returns:
            List of audit entries
        """
        # Apply default limit if not specified
        if limit is None:
            limit = 100

        # Fetch entries from repository
        return await self.audit_repository.get_entries(
            audit_log_id=audit_log_id,
            limit=limit,
            offset=offset,
            order_by="created_at",
            order_direction="desc",
        )

    @property
    def query_type(self) -> type[GetAuditLogQuery]:
        """Get query type this handler processes."""
        return GetAuditLogQuery


__all__ = ["GetAuditLogQuery", "GetAuditLogQueryHandler"]
