"""
Common GraphQL Type Definitions for Identity Module

This module contains common GraphQL types used across the identity module,
including pagination, filtering, sorting, error handling, and utility types.
"""


import graphene

from .enums import SortDirection


class PaginationType(graphene.ObjectType):
    """Pagination information for paginated results."""
    
    class Meta:
        description = "Information about pagination for a set of results"
    
    page = graphene.Int(
        required=True,
        description="Current page number (1-based)"
    )
    
    page_size = graphene.Int(
        required=True,
        description="Number of items per page"
    )
    
    total_items = graphene.Int(
        required=True,
        description="Total number of items available"
    )
    
    total_pages = graphene.Int(
        required=True,
        description="Total number of pages available"
    )
    
    has_previous = graphene.Boolean(
        required=True,
        description="Whether there is a previous page"
    )
    
    has_next = graphene.Boolean(
        required=True,
        description="Whether there is a next page"
    )
    
    start_cursor = graphene.String(
        description="Cursor for the first item on this page"
    )
    
    end_cursor = graphene.String(
        description="Cursor for the last item on this page"
    )


class PageInfoType(graphene.ObjectType):
    """Relay-compliant page information."""
    
    class Meta:
        description = "Relay-compliant pagination information"
    
    has_next_page = graphene.Boolean(
        required=True,
        description="Whether there are more items after this page"
    )
    
    has_previous_page = graphene.Boolean(
        required=True,
        description="Whether there are items before this page"
    )
    
    start_cursor = graphene.String(
        description="Cursor for the first item"
    )
    
    end_cursor = graphene.String(
        description="Cursor for the last item"
    )


class PaginationInput(graphene.InputObjectType):
    """Input type for pagination parameters."""
    
    class Meta:
        description = "Parameters for paginating results"
    
    page = graphene.Int(
        default_value=1,
        description="Page number (1-based, defaults to 1)"
    )
    
    page_size = graphene.Int(
        default_value=20,
        description="Number of items per page (defaults to 20, max 100)"
    )
    
    # Relay-style pagination
    first = graphene.Int(
        description="Number of items to fetch from the beginning"
    )
    
    after = graphene.String(
        description="Cursor to fetch items after"
    )
    
    last = graphene.Int(
        description="Number of items to fetch from the end"
    )
    
    before = graphene.String(
        description="Cursor to fetch items before"
    )


class SortFieldInput(graphene.InputObjectType):
    """Input type for sorting a field."""
    
    class Meta:
        description = "Field sorting specification"
    
    field = graphene.String(
        required=True,
        description="Field name to sort by"
    )
    
    direction = graphene.Field(
        SortDirection,
        default_value=SortDirection.ASC,
        description="Sort direction (defaults to ascending)"
    )


class SortInput(graphene.InputObjectType):
    """Input type for sorting parameters."""
    
    class Meta:
        description = "Parameters for sorting results"
    
    fields = graphene.List(
        SortFieldInput,
        description="List of fields to sort by (applied in order)"
    )


class DateRangeInput(graphene.InputObjectType):
    """Input type for date range filtering."""
    
    class Meta:
        description = "Date range for filtering"
    
    from_date = graphene.DateTime(
        description="Start date (inclusive)"
    )
    
    to_date = graphene.DateTime(
        description="End date (inclusive)"
    )


class FilterInput(graphene.InputObjectType):
    """Base input type for filtering."""
    
    class Meta:
        description = "Base filtering parameters"
    
    search = graphene.String(
        description="Text search across searchable fields"
    )
    
    created_at = graphene.Field(
        DateRangeInput,
        description="Filter by creation date range"
    )
    
    updated_at = graphene.Field(
        DateRangeInput,
        description="Filter by last update date range"
    )


class ErrorType(graphene.ObjectType):
    """Error information type."""
    
    class Meta:
        description = "Error information with details"
    
    code = graphene.String(
        required=True,
        description="Error code identifier"
    )
    
    message = graphene.String(
        required=True,
        description="Human-readable error message"
    )
    
    field = graphene.String(
        description="Field name if error is field-specific"
    )
    
    details = graphene.JSONString(
        description="Additional error details as JSON"
    )


class SuccessType(graphene.ObjectType):
    """Success response type."""
    
    class Meta:
        description = "Success response with optional message"
    
    success = graphene.Boolean(
        required=True,
        default_value=True,
        description="Whether the operation was successful"
    )
    
    message = graphene.String(
        description="Optional success message"
    )


class ValidationErrorType(graphene.ObjectType):
    """Validation error type."""
    
    class Meta:
        description = "Validation error with field information"
    
    field = graphene.String(
        required=True,
        description="Field that failed validation"
    )
    
    message = graphene.String(
        required=True,
        description="Validation error message"
    )
    
    code = graphene.String(
        description="Validation error code"
    )


class OperationResultType(graphene.ObjectType):
    """Generic operation result type."""
    
    class Meta:
        description = "Result of an operation with success/error information"
    
    success = graphene.Boolean(
        required=True,
        description="Whether the operation was successful"
    )
    
    message = graphene.String(
        description="Operation message"
    )
    
    errors = graphene.List(
        ErrorType,
        description="List of errors if operation failed"
    )
    
    validation_errors = graphene.List(
        ValidationErrorType,
        description="List of validation errors"
    )


# Generic edge type for Relay connections
class EdgeType(graphene.Interface):
    """Relay-compliant edge interface."""
    
    class Meta:
        description = "Relay-compliant edge with cursor and node"
    
    cursor = graphene.String(
        required=True,
        description="Cursor for this edge"
    )


# Generic connection type for Relay connections
class ConnectionType(graphene.Interface):
    """Relay-compliant connection interface."""
    
    class Meta:
        description = "Relay-compliant connection with edges and page info"
    
    page_info = graphene.Field(
        PageInfoType,
        required=True,
        description="Pagination information"
    )


class MetadataType(graphene.ObjectType):
    """Metadata information type."""
    
    class Meta:
        description = "Metadata information for entities"
    
    created_at = graphene.DateTime(
        required=True,
        description="When the entity was created"
    )
    
    updated_at = graphene.DateTime(
        required=True,
        description="When the entity was last updated"
    )
    
    created_by = graphene.String(
        description="User ID who created the entity"
    )
    
    updated_by = graphene.String(
        description="User ID who last updated the entity"
    )
    
    version = graphene.Int(
        description="Entity version for optimistic locking"
    )


class AuditMetadataType(graphene.ObjectType):
    """Extended metadata with audit information."""
    
    class Meta:
        description = "Audit metadata for tracked entities"
    
    created_at = graphene.DateTime(
        required=True,
        description="When the entity was created"
    )
    
    updated_at = graphene.DateTime(
        required=True,
        description="When the entity was last updated"
    )
    
    created_by = graphene.String(
        description="User ID who created the entity"
    )
    
    updated_by = graphene.String(
        description="User ID who last updated the entity"
    )
    
    version = graphene.Int(
        description="Entity version for optimistic locking"
    )
    
    deleted_at = graphene.DateTime(
        description="When the entity was soft deleted (if applicable)"
    )
    
    deleted_by = graphene.String(
        description="User ID who deleted the entity"
    )
    
    is_deleted = graphene.Boolean(
        default_value=False,
        description="Whether the entity is soft deleted"
    )


class AddressType(graphene.ObjectType):
    """Address information type."""
    
    class Meta:
        description = "Physical address information"
    
    street = graphene.String(
        description="Street address"
    )
    
    city = graphene.String(
        description="City name"
    )
    
    state_province = graphene.String(
        description="State or province"
    )
    
    postal_code = graphene.String(
        description="Postal or ZIP code"
    )
    
    country = graphene.String(
        description="Country name or code"
    )
    
    is_primary = graphene.Boolean(
        default_value=False,
        description="Whether this is the primary address"
    )


class AddressInput(graphene.InputObjectType):
    """Address input type."""
    
    class Meta:
        description = "Input for address information"
    
    street = graphene.String(
        description="Street address"
    )
    
    city = graphene.String(
        description="City name"
    )
    
    state_province = graphene.String(
        description="State or province"
    )
    
    postal_code = graphene.String(
        description="Postal or ZIP code"
    )
    
    country = graphene.String(
        description="Country name or code"
    )
    
    is_primary = graphene.Boolean(
        default_value=False,
        description="Whether this is the primary address"
    )


class ContactInfoType(graphene.ObjectType):
    """Contact information type."""
    
    class Meta:
        description = "Contact information"
    
    phone = graphene.String(
        description="Phone number"
    )
    
    mobile = graphene.String(
        description="Mobile phone number"
    )
    
    email = graphene.String(
        description="Email address"
    )
    
    fax = graphene.String(
        description="Fax number"
    )
    
    website = graphene.String(
        description="Website URL"
    )


class ContactInfoInput(graphene.InputObjectType):
    """Contact information input type."""
    
    class Meta:
        description = "Input for contact information"
    
    phone = graphene.String(
        description="Phone number"
    )
    
    mobile = graphene.String(
        description="Mobile phone number"
    )
    
    email = graphene.String(
        description="Email address"
    )
    
    fax = graphene.String(
        description="Fax number"
    )
    
    website = graphene.String(
        description="Website URL"
    )


class GeolocationInput(graphene.InputObjectType):
    """Geolocation input type."""
    
    class Meta:
        description = "Geographic location coordinates"
    
    latitude = graphene.Float(
        required=True,
        description="Latitude coordinate"
    )
    
    longitude = graphene.Float(
        required=True,
        description="Longitude coordinate"
    )
    
    accuracy = graphene.Float(
        description="Location accuracy in meters"
    )


class GeolocationResponse(graphene.ObjectType):
    """Geolocation response type."""
    
    class Meta:
        description = "Geographic location information"
    
    latitude = graphene.Float(
        required=True,
        description="Latitude coordinate"
    )
    
    longitude = graphene.Float(
        required=True,
        description="Longitude coordinate"
    )
    
    accuracy = graphene.Float(
        description="Location accuracy in meters"
    )
    
    city = graphene.String(
        description="City name from coordinates"
    )
    
    country = graphene.String(
        description="Country name from coordinates"
    )
    
    timezone = graphene.String(
        description="Timezone at this location"
    )


# Export all types
__all__ = [
    "AddressInput",
    "AddressType",
    "AuditMetadataType",
    "ConnectionType",
    "ContactInfoInput",
    "ContactInfoType",
    "DateRangeInput",
    "EdgeType",
    "ErrorType",
    "FilterInput",
    "GeolocationInput",
    "GeolocationResponse",
    "MetadataType",
    "OperationResultType",
    "PageInfoType",
    "PaginationInput",
    "PaginationType",
    "SortFieldInput",
    "SortInput",
    "SuccessType",
    "ValidationErrorType",
]