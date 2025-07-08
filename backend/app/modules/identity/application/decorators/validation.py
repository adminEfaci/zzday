"""
Validation decorators for command and query handlers.

Provides input/output validation capabilities.
"""

import re
from collections.abc import Callable
from datetime import datetime
from functools import wraps
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field, ValidationError, validator

from app.core.cqrs import Command, Query
from app.modules.identity.domain.errors import ValidationError as DomainValidationError
from app.modules.identity.domain.value_objects.email import Email
from app.modules.identity.domain.value_objects.phone_number import PhoneNumber
from app.modules.identity.domain.value_objects.username import Username


def validate_input(
    schema: type[BaseModel] | None = None,
    validators: dict[str, Callable] | None = None
) -> Callable:
    """
    Decorator to validate command/query input.
    
    Args:
        schema: Pydantic schema for validation
        validators: Dictionary of field validators
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(self, request: Command | Query, *args, **kwargs):
            # Validate using schema if provided
            if schema:
                try:
                    # Convert request to dict for validation
                    request_dict = {}
                    for field in schema.__fields__:
                        if hasattr(request, field):
                            request_dict[field] = getattr(request, field)
                    
                    # Validate against schema
                    validated = schema(**request_dict)
                    
                    # Update request with validated values
                    for field, value in validated.dict().items():
                        if hasattr(request, field):
                            setattr(request, field, value)
                            
                except ValidationError as e:
                    raise DomainValidationError(
                        "Input validation failed",
                        errors=e.errors()
                    ) from e
            
            # Apply custom validators
            if validators:
                for field_name, validator_func in validators.items():
                    if hasattr(request, field_name):
                        value = getattr(request, field_name)
                        try:
                            validated_value = validator_func(value)
                            setattr(request, field_name, validated_value)
                        except Exception as e:
                            raise DomainValidationError(
                                f"Validation failed for field {field_name}: {e!s}"
                            ) from e
            
            # Execute function
            return await func(self, request, *args, **kwargs)
        
        return wrapper
    return decorator


def validate_output(
    schema: type[BaseModel] | None = None,
    validators: dict[str, Callable] | None = None
) -> Callable:
    """
    Decorator to validate handler output.
    
    Args:
        schema: Pydantic schema for validation
        validators: Dictionary of field validators
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(self, request: Command | Query, *args, **kwargs):
            # Execute function
            result = await func(self, request, *args, **kwargs)
            
            # Validate output using schema
            if schema and result:
                try:
                    if hasattr(result, 'data') and result.data:
                        # Validate data field
                        validated = schema(**result.data)
                        result.data = validated.dict()
                    else:
                        # Validate entire result
                        validated = schema(**result)
                except ValidationError as e:
                    raise DomainValidationError(
                        "Output validation failed",
                        errors=e.errors()
                    ) from e
            
            # Apply custom validators
            if validators and result:
                data = result.data if hasattr(result, 'data') else result
                for field_name, validator_func in validators.items():
                    if isinstance(data, dict) and field_name in data:
                        try:
                            data[field_name] = validator_func(data[field_name])
                        except Exception as e:
                            raise DomainValidationError(
                                f"Output validation failed for field "
                                f"{field_name}: {e!s}"
                            ) from e
            
            return result
        
        return wrapper
    return decorator


# Common validators
def validate_email(value: str) -> str:
    """Validate email address."""
    try:
        email = Email(value)
        return email.value
    except ValueError as e:
        raise DomainValidationError(f"Invalid email: {e!s}") from e


def validate_username(value: str) -> str:
    """Validate username."""
    try:
        username = Username(value)
        return username.value
    except ValueError as e:
        raise DomainValidationError(f"Invalid username: {e!s}") from e


def validate_phone_number(value: str) -> str:
    """Validate phone number."""
    try:
        phone = PhoneNumber(value)
        return phone.e164
    except ValueError as e:
        raise DomainValidationError(f"Invalid phone number: {e!s}") from e


def validate_password_strength(min_score: float = 0.7) -> Callable:
    """Create password strength validator."""
    def validator(value: str) -> str:
        # Basic strength check (in production, use password service)
        if len(value) < 8:
            raise DomainValidationError("Password must be at least 8 characters")
        
        has_upper = any(c.isupper() for c in value)
        has_lower = any(c.islower() for c in value)
        has_digit = any(c.isdigit() for c in value)
        has_special = any(c in "!@#$%^&*" for c in value)
        
        score = sum([has_upper, has_lower, has_digit, has_special]) / 4.0
        
        if score < min_score:
            raise DomainValidationError(
                "Password is too weak. Include uppercase, lowercase, "
                "numbers, and special characters."
            )
        
        return value
    
    return validator


def validate_uuid(value: Any) -> UUID:
    """Validate UUID."""
    if isinstance(value, UUID):
        return value
    
    try:
        return UUID(str(value))
    except ValueError as e:
        raise DomainValidationError(f"Invalid UUID: {value}") from e


def validate_enum(enum_class: type) -> Callable:
    """Create enum validator."""
    def validator(value: Any) -> Any:
        if isinstance(value, enum_class):
            return value
        
        try:
            return enum_class(value)
        except ValueError as e:
            valid_values = [e.value for e in enum_class]
            raise DomainValidationError(
                f"Invalid value: {value}. Must be one of: {', '.join(valid_values)}"
            ) from e
    
    return validator


def validate_date_range(
    start_field: str = 'start_date',
    end_field: str = 'end_date',
    max_range_days: int | None = None
) -> Callable:
    """Decorator to validate date ranges."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(self, request: Command | Query, *args, **kwargs):
            # Get dates
            start_date = getattr(request, start_field, None)
            end_date = getattr(request, end_field, None)
            
            if start_date and end_date:
                # Ensure start is before end
                if start_date > end_date:
                    raise DomainValidationError(
                        f"{start_field} must be before {end_field}"
                    )
                
                # Check max range
                if max_range_days:
                    delta = (end_date - start_date).days
                    if delta > max_range_days:
                        raise DomainValidationError(
                            f"Date range cannot exceed {max_range_days} days"
                        )
            
            return await func(self, request, *args, **kwargs)
        
        return wrapper
    return decorator


def validate_pagination(
    max_page_size: int = 100,
    default_page_size: int = 20
) -> Callable:
    """Decorator to validate pagination parameters."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(self, request: Command | Query, *args, **kwargs):
            # Validate page number
            if hasattr(request, 'page') and request.page < 1:
                request.page = 1
            
            # Validate page size
            if hasattr(request, 'page_size'):
                if request.page_size < 1:
                    request.page_size = default_page_size
                elif request.page_size > max_page_size:
                    request.page_size = max_page_size
            
            return await func(self, request, *args, **kwargs)
        
        return wrapper
    return decorator


def sanitize_input(
    fields: list[str] | None = None,
    strip_html: bool = True,
    max_length: dict[str, int] | None = None
) -> Callable:
    """
    Decorator to sanitize input fields.
    
    Args:
        fields: Fields to sanitize (all string fields if None)
        strip_html: Whether to strip HTML tags
        max_length: Maximum length for fields
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(self, request: Command | Query, *args, **kwargs):
            # Get fields to sanitize
            fields_to_sanitize = fields
            if not fields_to_sanitize:
                # Sanitize all string fields
                fields_to_sanitize = [
                    attr for attr in dir(request)
                    if not attr.startswith('_') and 
                    isinstance(getattr(request, attr, None), str)
                ]
            
            # Sanitize each field
            for field in fields_to_sanitize:
                if hasattr(request, field):
                    value = getattr(request, field)
                    if isinstance(value, str):
                        # Strip whitespace
                        value = value.strip()
                        
                        # Strip HTML if requested
                        if strip_html:
                            # Simple HTML stripping (use proper library in production)
                            value = re.sub(r'<[^>]+>', '', value)
                        
                        # Apply max length
                        if max_length and field in max_length:
                            value = value[:max_length[field]]
                        
                        setattr(request, field, value)
            
            return await func(self, request, *args, **kwargs)
        
        return wrapper
    return decorator


# Pydantic schemas for common validations
class EmailValidationSchema(BaseModel):
    """Email validation schema."""
    email: str = Field(..., regex=r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')


class PasswordChangeSchema(BaseModel):
    """Password change validation schema."""
    current_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=8)
    
    @validator('new_password')
    def validate_password_strength(self, v):
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain digit')
        return v


class PaginationSchema(BaseModel):
    """Pagination validation schema."""
    page: int = Field(1, ge=1)
    page_size: int = Field(20, ge=1, le=100)


class DateRangeSchema(BaseModel):
    """Date range validation schema."""
    start_date: datetime
    end_date: datetime
    
    @validator('end_date')
    def validate_date_range(self, v, values):
        if 'start_date' in values and v < values['start_date']:
            raise ValueError('End date must be after start date')
        return v