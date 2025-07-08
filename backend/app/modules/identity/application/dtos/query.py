"""
Query objects for repository interfaces.

Contains query objects to reduce function argument counts
in repository interface methods.
"""

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID


@dataclass(frozen=True)
class SessionQuery:
    """Query object for session-related operations."""
    
    user_id: UUID
    start_date: datetime | None = None
    end_date: datetime | None = None
    active_only: bool = False
    page: int = 1
    page_size: int = 20
    limit: int | None = None


@dataclass(frozen=True)
class ActivityQuery:
    """Query object for activity-related operations."""
    
    user_id: UUID
    start_date: datetime | None = None
    end_date: datetime | None = None
    activity_types: list[str] | None = None
    limit: int = 100


@dataclass(frozen=True)
class AccessLogQuery:
    """Query object for access log operations."""
    
    user_id: UUID | None = None
    resource: str | None = None
    start_date: datetime | None = None
    end_date: datetime | None = None
    event_types: list[str] | None = None
    page: int = 1
    page_size: int = 20
    limit: int = 100
    offset: int = 0


@dataclass(frozen=True)
class PaginationParams:
    """Common pagination parameters."""
    
    page: int = 1
    page_size: int = 20
    offset: int | None = None
    limit: int | None = None


@dataclass(frozen=True)
class DateRangeFilter:
    """Common date range filter."""
    
    start_date: datetime | None = None
    end_date: datetime | None = None