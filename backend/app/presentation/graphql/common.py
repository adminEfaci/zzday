"""
Common GraphQL Patterns and Types

This module provides reusable GraphQL types and patterns that are used across
all modules to ensure consistency and reduce duplication.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Generic, TypeVar

import strawberry

# Type variable for generic types
T = TypeVar("T")

# ============================================================================
# Connection/Edge Pattern for Pagination
# ============================================================================

@strawberry.type(description="Information about pagination in a connection.")
class PageInfo:
    """Relay-style pagination information"""
    
    has_next_page: bool = strawberry.field(
        description="Whether there are more pages after the current page"
    )
    has_previous_page: bool = strawberry.field(
        description="Whether there are pages before the current page"
    )
    start_cursor: str | None = strawberry.field(
        description="Cursor for the first item in the current page"
    )
    end_cursor: str | None = strawberry.field(
        description="Cursor for the last item in the current page"
    )


@strawberry.type(description="An edge in a connection.")
class Edge(Generic[T]):
    """Edge wrapper for items in a connection"""
    
    cursor: str = strawberry.field(
        description="A cursor for use in pagination"
    )
    node: T = strawberry.field(
        description="The item at the end of the edge"
    )


@strawberry.type(description="A connection to a list of items.")
class Connection(Generic[T]):
    """Relay-style connection for pagination"""
    
    edges: list[Edge[T]] = strawberry.field(
        description="List of edges containing the items"
    )
    page_info: PageInfo = strawberry.field(
        description="Information about the current page"
    )
    total_count: int = strawberry.field(
        description="Total number of items in the connection"
    )
    
    @staticmethod
    def from_list(  # noqa: PLR0913
        items: list[T],
        total_count: int,
        cursor_fn,
        has_next_page: bool = False,
        has_previous_page: bool = False,
        start_cursor: str | None = None,
        end_cursor: str | None = None
    ) -> "Connection[T]":
        """
        Create a connection from a list of items.
        
        Args:
            items: The items to include in the connection
            total_count: Total number of items (not just in this page)
            cursor_fn: Function to generate cursor from an item
            has_next_page: Whether there are more pages
            has_previous_page: Whether there are previous pages
            start_cursor: Override for start cursor
            end_cursor: Override for end cursor
        """
        edges = [
            Edge(
                cursor=cursor_fn(item),
                node=item
            )
            for item in items
        ]
        
        return Connection(
            edges=edges,
            page_info=PageInfo(
                has_next_page=has_next_page,
                has_previous_page=has_previous_page,
                start_cursor=start_cursor or (edges[0].cursor if edges else None),
                end_cursor=end_cursor or (edges[-1].cursor if edges else None)
            ),
            total_count=total_count
        )


# ============================================================================
# Common Input Types
# ============================================================================

@strawberry.input(description="Pagination parameters")
class PaginationInput:
    """Standard pagination input used across all modules"""
    
    first: int | None = strawberry.field(
        default=None,
        description="Number of items to fetch from the start"
    )
    after: str | None = strawberry.field(
        default=None,
        description="Cursor to start fetching items after"
    )
    last: int | None = strawberry.field(
        default=None,
        description="Number of items to fetch from the end"
    )
    before: str | None = strawberry.field(
        default=None,
        description="Cursor to start fetching items before"
    )
    
    def validate(self) -> list[str]:
        """Validate pagination parameters"""
        errors = []
        
        if self.first is not None and self.first < 0:
            errors.append("first must be non-negative")
        if self.last is not None and self.last < 0:
            errors.append("last must be non-negative")
        if self.first is not None and self.last is not None:
            errors.append("Cannot specify both first and last")
        if self.after is not None and self.before is not None:
            errors.append("Cannot specify both after and before")
        
        return errors


@strawberry.input(description="Date range filter")
class DateRangeInput:
    """Standard date range input used across all modules"""
    
    start_date: datetime | None = strawberry.field(
        default=None,
        description="Start date (inclusive)"
    )
    end_date: datetime | None = strawberry.field(
        default=None,
        description="End date (inclusive)"
    )
    
    def validate(self) -> list[str]:
        """Validate date range"""
        errors = []
        
        if self.start_date and self.end_date and self.start_date > self.end_date:
            errors.append("start_date must be before or equal to end_date")
        
        return errors


@strawberry.enum(description="Sort direction")
class SortDirection(Enum):
    """Standard sort direction enum"""
    ASC = "ASC"
    DESC = "DESC"


@strawberry.input(description="Sort parameters")
class SortInput:
    """Standard sort input used across all modules"""
    
    field: str = strawberry.field(
        description="Field to sort by"
    )
    direction: SortDirection = strawberry.field(
        default=SortDirection.ASC,
        description="Sort direction"
    )


# ============================================================================
# Error Handling Types
# ============================================================================

@strawberry.type(description="Field-level error information")
class FieldError:
    """Represents an error for a specific field"""
    
    field: str = strawberry.field(
        description="The field that caused the error"
    )
    message: str = strawberry.field(
        description="Human-readable error message"
    )
    code: str = strawberry.field(
        description="Machine-readable error code"
    )
    
    @staticmethod
    def from_validation_error(field: str, message: str) -> "FieldError":
        """Create a field error from validation"""
        return FieldError(
            field=field,
            message=message,
            code="VALIDATION_ERROR"
        )


@strawberry.type(description="Base type for operation results")
class OperationResult:
    """Base class for mutation/query results with error handling"""
    
    success: bool = strawberry.field(
        description="Whether the operation was successful"
    )
    message: str | None = strawberry.field(
        default=None,
        description="Human-readable message about the operation"
    )
    errors: list[FieldError] | None = strawberry.field(
        default=None,
        description="List of field-specific errors"
    )
    
    @property
    def has_errors(self) -> bool:
        """Check if there are any errors"""
        return bool(self.errors)


@strawberry.type(description="Generic mutation payload")
class MutationPayload(Generic[T], OperationResult):
    """Generic payload for mutations that return data"""
    
    data: T | None = strawberry.field(
        default=None,
        description="The data returned by the mutation"
    )
    
    @staticmethod
    def success(data: T, message: str | None = None) -> "MutationPayload[T]":
        """Create a successful payload"""
        return MutationPayload(
            success=True,
            data=data,
            message=message
        )
    
    @staticmethod
    def error(errors: list[FieldError], message: str | None = None) -> "MutationPayload[T]":
        """Create an error payload"""
        return MutationPayload(
            success=False,
            errors=errors,
            message=message or "Operation failed"
        )


# ============================================================================
# Common Error Codes
# ============================================================================

class ErrorCode(Enum):
    """Standard error codes used across the API"""
    
    # Authentication & Authorization
    UNAUTHENTICATED = "UNAUTHENTICATED"
    FORBIDDEN = "FORBIDDEN"
    INVALID_TOKEN = "INVALID_TOKEN"  # noqa: S105
    TOKEN_EXPIRED = "TOKEN_EXPIRED"  # noqa: S105
    
    # Validation
    VALIDATION_ERROR = "VALIDATION_ERROR"
    INVALID_INPUT = "INVALID_INPUT"
    MISSING_FIELD = "MISSING_FIELD"
    
    # Resource errors
    NOT_FOUND = "NOT_FOUND"
    ALREADY_EXISTS = "ALREADY_EXISTS"
    CONFLICT = "CONFLICT"
    
    # Rate limiting
    RATE_LIMITED = "RATE_LIMITED"
    QUOTA_EXCEEDED = "QUOTA_EXCEEDED"
    
    # System errors
    INTERNAL_ERROR = "INTERNAL_ERROR"
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"
    TIMEOUT = "TIMEOUT"


# ============================================================================
# Metadata Types
# ============================================================================

@strawberry.type(description="Metadata for any entity")
class Metadata:
    """Common metadata fields for entities"""
    
    created_at: datetime = strawberry.field(
        description="When the entity was created"
    )
    updated_at: datetime = strawberry.field(
        description="When the entity was last updated"
    )
    created_by: str | None = strawberry.field(
        default=None,
        description="ID of the user who created the entity"
    )
    updated_by: str | None = strawberry.field(
        default=None,
        description="ID of the user who last updated the entity"
    )
    version: int = strawberry.field(
        default=1,
        description="Version number for optimistic locking"
    )


# ============================================================================
# Cursor Utilities
# ============================================================================

def encode_cursor(value: Any) -> str:
    """
    Encode a value as a cursor.
    
    In production, this should use proper base64 encoding.
    """
    import base64
    import json
    
    # Convert to JSON string then base64 encode
    json_str = json.dumps(value, default=str)
    return base64.b64encode(json_str.encode()).decode()


def decode_cursor(cursor: str) -> Any:
    """
    Decode a cursor back to its original value.
    
    In production, this should handle errors gracefully.
    """
    import base64
    import json
    
    try:
        # Base64 decode then parse JSON
        json_str = base64.b64decode(cursor.encode()).decode()
        return json.loads(json_str)
    except Exception:
        raise ValueError(f"Invalid cursor: {cursor}") from None


# ============================================================================
# Export all common types
# ============================================================================

__all__ = [
    # Pagination
    "Connection",
    # Sorting and filtering
    "DateRangeInput",
    "Edge",
    # Error handling
    "ErrorCode",
    "FieldError",
    # Metadata
    "Metadata",
    "MutationPayload",
    "OperationResult",
    "PageInfo",
    "PaginationInput",
    "SortDirection",
    "SortInput",
    # Utilities
    "decode_cursor",
    "encode_cursor",
]