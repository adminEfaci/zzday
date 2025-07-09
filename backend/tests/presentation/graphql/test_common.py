"""
Tests for common GraphQL patterns and types.
"""

import pytest
from datetime import datetime
from app.presentation.graphql.common import (
    PageInfo,
    Edge,
    Connection,
    PaginationInput,
    DateRangeInput,
    SortDirection,
    SortInput,
    FieldError,
    OperationResult,
    MutationPayload,
    ErrorCode,
    Metadata,
    encode_cursor,
    decode_cursor,
)


class TestPaginationTypes:
    """Test pagination-related types."""
    
    def test_page_info_creation(self):
        """Test PageInfo creation."""
        page_info = PageInfo(
            has_next_page=True,
            has_previous_page=False,
            start_cursor="start",
            end_cursor="end"
        )
        
        assert page_info.has_next_page is True
        assert page_info.has_previous_page is False
        assert page_info.start_cursor == "start"
        assert page_info.end_cursor == "end"
    
    def test_edge_creation(self):
        """Test Edge creation."""
        edge = Edge(cursor="cursor123", node="test_node")
        
        assert edge.cursor == "cursor123"
        assert edge.node == "test_node"
    
    def test_connection_from_list(self):
        """Test creating Connection from list."""
        items = ["item1", "item2", "item3"]
        
        connection = Connection.from_list(
            items=items,
            total_count=10,
            cursor_fn=lambda item: f"cursor_{item}",
            has_next_page=True,
            has_previous_page=False
        )
        
        assert len(connection.edges) == 3
        assert connection.total_count == 10
        assert connection.page_info.has_next_page is True
        assert connection.page_info.has_previous_page is False
        assert connection.edges[0].cursor == "cursor_item1"
        assert connection.edges[0].node == "item1"
    
    def test_connection_from_empty_list(self):
        """Test creating Connection from empty list."""
        connection = Connection.from_list(
            items=[],
            total_count=0,
            cursor_fn=lambda item: f"cursor_{item}"
        )
        
        assert len(connection.edges) == 0
        assert connection.total_count == 0
        assert connection.page_info.start_cursor is None
        assert connection.page_info.end_cursor is None


class TestInputTypes:
    """Test input types."""
    
    def test_pagination_input_validation(self):
        """Test PaginationInput validation."""
        # Valid input
        input1 = PaginationInput(first=10)
        assert input1.validate() == []
        
        # Invalid: negative first
        input2 = PaginationInput(first=-1)
        errors = input2.validate()
        assert len(errors) == 1
        assert "first must be non-negative" in errors[0]
        
        # Invalid: both first and last
        input3 = PaginationInput(first=10, last=10)
        errors = input3.validate()
        assert len(errors) == 1
        assert "Cannot specify both first and last" in errors[0]
        
        # Invalid: both after and before
        input4 = PaginationInput(after="cursor1", before="cursor2")
        errors = input4.validate()
        assert len(errors) == 1
        assert "Cannot specify both after and before" in errors[0]
    
    def test_date_range_input_validation(self):
        """Test DateRangeInput validation."""
        now = datetime.now()
        past = datetime(2020, 1, 1)
        future = datetime(2025, 1, 1)
        
        # Valid input
        input1 = DateRangeInput(start_date=past, end_date=future)
        assert input1.validate() == []
        
        # Invalid: start after end
        input2 = DateRangeInput(start_date=future, end_date=past)
        errors = input2.validate()
        assert len(errors) == 1
        assert "start_date must be before or equal to end_date" in errors[0]
    
    def test_sort_input(self):
        """Test SortInput."""
        sort = SortInput(field="created_at", direction=SortDirection.DESC)
        assert sort.field == "created_at"
        assert sort.direction == SortDirection.DESC


class TestErrorHandling:
    """Test error handling types."""
    
    def test_field_error_creation(self):
        """Test FieldError creation."""
        error = FieldError(
            field="email",
            message="Invalid email format",
            code="INVALID_EMAIL"
        )
        
        assert error.field == "email"
        assert error.message == "Invalid email format"
        assert error.code == "INVALID_EMAIL"
    
    def test_field_error_from_validation(self):
        """Test creating FieldError from validation."""
        error = FieldError.from_validation_error(
            field="username",
            message="Username already exists"
        )
        
        assert error.field == "username"
        assert error.message == "Username already exists"
        assert error.code == "VALIDATION_ERROR"
    
    def test_operation_result(self):
        """Test OperationResult."""
        # Success case
        result1 = OperationResult(success=True, message="Operation completed")
        assert result1.success is True
        assert result1.message == "Operation completed"
        assert result1.has_errors is False
        
        # Error case
        errors = [
            FieldError(field="email", message="Invalid", code="INVALID")
        ]
        result2 = OperationResult(success=False, errors=errors)
        assert result2.success is False
        assert result2.has_errors is True
        assert len(result2.errors) == 1
    
    def test_mutation_payload(self):
        """Test MutationPayload."""
        # Success case
        payload1 = MutationPayload.success(
            data={"id": "123", "name": "Test"},
            message="Created successfully"
        )
        assert payload1.success is True
        assert payload1.data == {"id": "123", "name": "Test"}
        assert payload1.message == "Created successfully"
        assert payload1.errors is None
        
        # Error case
        errors = [
            FieldError(field="name", message="Required", code="REQUIRED")
        ]
        payload2 = MutationPayload.error(errors=errors)
        assert payload2.success is False
        assert payload2.data is None
        assert payload2.errors == errors
        assert payload2.message == "Operation failed"


class TestCursorUtilities:
    """Test cursor encoding/decoding utilities."""
    
    def test_encode_decode_cursor(self):
        """Test cursor encoding and decoding."""
        # Test with string
        original1 = "test_cursor"
        encoded1 = encode_cursor(original1)
        decoded1 = decode_cursor(encoded1)
        assert decoded1 == original1
        
        # Test with dict
        original2 = {"id": 123, "timestamp": "2023-01-01"}
        encoded2 = encode_cursor(original2)
        decoded2 = decode_cursor(encoded2)
        assert decoded2 == original2
        
        # Test with list
        original3 = [1, 2, 3, "test"]
        encoded3 = encode_cursor(original3)
        decoded3 = decode_cursor(encoded3)
        assert decoded3 == original3
    
    def test_invalid_cursor_decode(self):
        """Test decoding invalid cursor."""
        with pytest.raises(ValueError, match="Invalid cursor"):
            decode_cursor("invalid_base64_@#$%")


class TestMetadata:
    """Test Metadata type."""
    
    def test_metadata_creation(self):
        """Test Metadata creation."""
        now = datetime.now()
        metadata = Metadata(
            created_at=now,
            updated_at=now,
            created_by="user123",
            updated_by="user456",
            version=2
        )
        
        assert metadata.created_at == now
        assert metadata.updated_at == now
        assert metadata.created_by == "user123"
        assert metadata.updated_by == "user456"
        assert metadata.version == 2


class TestErrorCodes:
    """Test ErrorCode enum."""
    
    def test_error_codes_exist(self):
        """Test that all expected error codes exist."""
        # Authentication & Authorization
        assert ErrorCode.UNAUTHENTICATED.value == "UNAUTHENTICATED"
        assert ErrorCode.FORBIDDEN.value == "FORBIDDEN"
        assert ErrorCode.INVALID_TOKEN.value == "INVALID_TOKEN"
        assert ErrorCode.TOKEN_EXPIRED.value == "TOKEN_EXPIRED"
        
        # Validation
        assert ErrorCode.VALIDATION_ERROR.value == "VALIDATION_ERROR"
        assert ErrorCode.INVALID_INPUT.value == "INVALID_INPUT"
        assert ErrorCode.MISSING_FIELD.value == "MISSING_FIELD"
        
        # Resource errors
        assert ErrorCode.NOT_FOUND.value == "NOT_FOUND"
        assert ErrorCode.ALREADY_EXISTS.value == "ALREADY_EXISTS"
        assert ErrorCode.CONFLICT.value == "CONFLICT"
        
        # Rate limiting
        assert ErrorCode.RATE_LIMITED.value == "RATE_LIMITED"
        assert ErrorCode.QUOTA_EXCEEDED.value == "QUOTA_EXCEEDED"
        
        # System errors
        assert ErrorCode.INTERNAL_ERROR.value == "INTERNAL_ERROR"
        assert ErrorCode.SERVICE_UNAVAILABLE.value == "SERVICE_UNAVAILABLE"
        assert ErrorCode.TIMEOUT.value == "TIMEOUT"