"""Application layer base classes following pure Python principles.

This module provides the foundational application layer components following
clean architecture principles with pure Python classes, completely independent
of any framework (FastAPI, Pydantic, etc.).

The application layer coordinates between the domain layer and infrastructure,
orchestrating use cases and managing the flow of data. This implementation
provides framework-agnostic DTO classes, use cases, and application services.

Design Principles:
- Pure Python classes with explicit __init__ validation
- Framework-agnostic design for maximum portability
- Clean separation between DTOs, use cases, and services
- Rich functionality with comprehensive error handling
- Performance monitoring and metrics collection
- Context management for request/response handling
- Comprehensive logging and debugging support

Architecture:
- DTO: Data Transfer Objects for moving data between layers
- Request/Response: Specialized DTOs for use case inputs/outputs
- UseCase: Encapsulates business use cases and workflows
- ApplicationService: Coordinates multiple use cases and external services
- Context: Request context for tracking and auditing
"""

import time
from abc import ABC, abstractmethod
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, Generic, TypeVar
from uuid import UUID, uuid4

from app.core.errors import ValidationError

try:
    from app.core.logging import get_logger
except ImportError:
    # Fallback logger
    import logging
    def get_logger(name: str):
        return logging.getLogger(name)

try:
    from app.utils.validation import EmailValidator, UUIDValidator
except ImportError:
    # Fallback validation
    class EmailValidator:
        @staticmethod
        def validate_format(email: str) -> bool:
            return "@" in email and "." in email.split("@")[1]
    
    class UUIDValidator:
        @staticmethod
        def validate_format(uuid_str: str) -> bool:
            try:
                from uuid import UUID
                UUID(uuid_str)
                return True
            except ValueError:
                return False

logger = get_logger(__name__)

# Type variables for application layer components
TRequest = TypeVar("TRequest", bound="Request")
TResponse = TypeVar("TResponse", bound="Response")
TDTO = TypeVar("TDTO", bound="DTO")


# =====================================================================================
# DATA TRANSFER OBJECTS (DTOs)
# =====================================================================================


class DTO(ABC):
    """
    Base Data Transfer Object following pure Python principles.

    DTOs are simple data containers used to transfer data between application
    layers without exposing domain objects. They provide validation, serialization,
    and transformation capabilities.

    Design Features:
    - Pure Python implementation with __init__ validation
    - Framework-agnostic serialization/deserialization
    - Rich validation capabilities
    - Immutable by design (optional)
    - Type conversion and normalization
    - Performance optimizations

    Usage Example:
        class UserDTO(DTO):
            def __init__(self, user_id: UUID, email: str, name: str, is_active: bool = True):
                super().__init__()
                self.user_id = self._validate_uuid(user_id)
                self.email = self._validate_email(email)
                self.name = self._validate_name(name)
                self.is_active = bool(is_active)
                self._freeze()

            def _validate_email(self, email: str) -> str:
                if not email or "@" not in email:
                    raise ValidationError("Invalid email format")
                return email.lower().strip()
    """

    def __init__(self):
        """
        Initialize DTO with validation support.

        Sets up DTO state management and validation tracking.
        """
        self._frozen = False
        self._validated = False
        self._validation_errors: list[str] = []

        # Validation will be called by subclasses after setting attributes

    def _validate_dto(self) -> None:
        """
        Validate DTO state. Override in subclasses for specific validation.

        Raises:
            ValidationError: If DTO is in invalid state
        """
        # Base validation - subclasses should override
        if self._validation_errors:
            error_context = {
                "dto_class": self.__class__.__name__,
                "validation_errors": self._validation_errors,
                "field_count": len([k for k in self.__dict__ if not k.startswith('_')])
            }
            raise ValidationError(
                f"DTO validation failed: {'; '.join(self._validation_errors)}",
                details=error_context
            )

        self._validated = True

    def _freeze(self) -> None:
        """Mark the DTO as frozen (immutable)."""
        self._validated = True
        self._frozen = True

    def __setattr__(self, name: str, value: Any) -> None:
        """Prevent modification after DTO is frozen."""
        if hasattr(self, "_frozen") and self._frozen and not name.startswith("_"):
            raise AttributeError(
                f"Cannot modify immutable DTO {self.__class__.__name__}"
            )
        super().__setattr__(name, value)

    def to_dict(self) -> dict[str, Any]:
        """
        Convert DTO to dictionary for serialization.

        Returns:
            dict[str, Any]: Dictionary representation
        """
        result = {}
        for key, value in self.__dict__.items():
            if not key.startswith("_"):
                if hasattr(value, "to_dict"):
                    result[key] = value.to_dict()
                elif isinstance(value, UUID):
                    result[key] = str(value)
                elif isinstance(value, datetime):
                    result[key] = value.isoformat()
                elif isinstance(value, list | tuple):
                    result[key] = [
                        item.to_dict() if hasattr(item, "to_dict") else item
                        for item in value
                    ]
                else:
                    result[key] = value
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DTO":
        """
        Create DTO instance from dictionary.

        Args:
            data: Dictionary data

        Returns:
            DTO: New DTO instance

        Raises:
            ValidationError: If data is invalid
        """
        # This is a basic implementation - subclasses should override for specific logic
        return cls(**data)

    def _add_validation_error(self, message: str) -> None:
        """Add validation error message."""
        self._validation_errors.append(message)

    def _validate_required(self, value: Any, field_name: str) -> None:
        """Validate that a required field is not empty."""
        if value is None or (isinstance(value, str) and not value.strip()):
            self._add_validation_error(f"{field_name} is required")

    def _validate_type(self, value: Any, expected_type: type, field_name: str) -> None:
        """Validate value type."""
        if not isinstance(value, expected_type):
            self._add_validation_error(
                f"{field_name} must be of type {expected_type.__name__}, got {type(value).__name__}"
            )

    def _validate_uuid(self, value: Any) -> UUID:
        """Enhanced UUID validation using utils."""
        try:
            return UUIDValidator.validate(value)
        except ValueError as e:
            self._add_validation_error(str(e))
            return value if isinstance(value, UUID) else UUID('00000000-0000-0000-0000-000000000000')

    def _validate_email(self, email: str) -> str:
        """Enhanced email validation using utils."""
        try:
            return EmailValidator.validate(email)
        except ValueError as e:
            self._add_validation_error(str(e))

        return email

    def __eq__(self, other: Any) -> bool:
        """Check equality based on all attributes."""
        if not isinstance(other, self.__class__):
            return False

        self_attrs = {k: v for k, v in self.__dict__.items() if not k.startswith("_")}
        other_attrs = {k: v for k, v in other.__dict__.items() if not k.startswith("_")}

        return self_attrs == other_attrs

    def __hash__(self) -> int:
        """Return hash based on all attributes."""
        values = []
        for key in sorted(self.__dict__.keys()):
            if not key.startswith("_"):
                value = self.__dict__[key]
                if isinstance(value, list | dict):
                    # Convert unhashable types
                    if isinstance(value, dict):
                        value = tuple(sorted(value.items()))
                    elif isinstance(value, list):
                        value = tuple(value)
                values.append((key, value))

        return hash((self.__class__.__name__, tuple(values)))

    def __repr__(self) -> str:
        """Detailed string representation for debugging."""
        attrs = []
        for key, value in self.__dict__.items():
            if not key.startswith("_"):
                attrs.append(f"{key}={value!r}")

        attrs_str = ", ".join(attrs)
        return f"{self.__class__.__name__}({attrs_str})"

    def __str__(self) -> str:
        """String representation for display."""
        return f"{self.__class__.__name__}({len([k for k in self.__dict__ if not k.startswith('_')])} fields)"


class Request(DTO):
    """
    Base request DTO for use case inputs.

    Requests represent input data for use cases and include metadata
    for tracking, validation, and auditing.

    Design Features:
    - Rich metadata for request tracking
    - User context and permissions
    - Validation and sanitization
    - Performance tracking
    - Correlation ID support

    Usage Example:
        class CreateUserRequest(Request):
            def __init__(self, email: str, name: str, user_id: UUID = None):
                super().__init__()
                self.email = self._validate_email(email)
                self.name = self._validate_name(name)
                self.user_id = user_id or uuid4()
                self._validate_dto()
                self._freeze()

            def _validate_name(self, name: str) -> str:
                if not name or len(name.strip()) < 2:
                    self._add_validation_error("Name must be at least 2 characters")
                return name.strip()
    """

    def __init__(self):
        """Initialize request with metadata."""
        super().__init__()

        # Request metadata
        self.request_id = uuid4()
        self.created_at = datetime.utcnow()
        self.correlation_id: UUID | None = None
        self.user_id: UUID | None = None
        self.user_context: dict[str, Any] | None = None

        # Request source information
        self.source: str | None = None
        self.ip_address: str | None = None
        self.user_agent: str | None = None

        # Processing metadata
        self.processing_start: datetime | None = None
        self.processing_end: datetime | None = None

    def set_metadata(
        self,
        correlation_id: UUID | None = None,
        user_id: UUID | None = None,
        user_context: dict[str, Any] | None = None,
        source: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> None:
        """
        Set request metadata for tracking and auditing.

        Args:
            correlation_id: Optional correlation ID for request tracking
            user_id: Optional user ID who initiated the request
            user_context: Optional user context and permissions
            source: Optional source system/component name
            ip_address: Optional client IP address
            user_agent: Optional client user agent
        """
        if hasattr(self, "_frozen") and self._frozen:
            raise AttributeError("Cannot modify frozen request")

        if correlation_id is not None:
            self.correlation_id = correlation_id
        if user_id is not None:
            self.user_id = user_id
        if user_context is not None:
            self.user_context = user_context
        if source is not None:
            self.source = source
        if ip_address is not None:
            self.ip_address = ip_address
        if user_agent is not None:
            self.user_agent = user_agent

    def start_processing(self) -> None:
        """Mark request processing as started."""
        self.processing_start = datetime.utcnow()

    def end_processing(self) -> None:
        """Mark request processing as completed."""
        self.processing_end = datetime.utcnow()

    @property
    def processing_time_seconds(self) -> float | None:
        """Get request processing time in seconds."""
        if self.processing_start and self.processing_end:
            return (self.processing_end - self.processing_start).total_seconds()
        return None

    def __repr__(self) -> str:
        """Detailed string representation for debugging."""
        return (
            f"{self.__class__.__name__}(id={self.request_id}, user_id={self.user_id})"
        )


class Response(DTO):
    """
    Base response DTO for use case outputs.

    Responses represent output data from use cases and include metadata
    for performance tracking, error handling, and result validation.

    Design Features:
    - Result status and metadata
    - Error handling support
    - Performance metrics
    - Pagination support
    - Comprehensive validation

    Usage Example:
        class CreateUserResponse(Response):
            def __init__(self, user_id: UUID, email: str, created_at: datetime):
                super().__init__(success=True)
                self.user_id = user_id
                self.email = email
                self.created_at = created_at
                self._validate_dto()
                self._freeze()
    """

    def __init__(self, success: bool = True, message: str | None = None):
        """
        Initialize response with status and metadata.

        Args:
            success: Whether the operation was successful
            message: Optional message describing the result
        """
        super().__init__()

        # Response metadata
        self.response_id = uuid4()
        self.created_at = datetime.utcnow()
        self.success = success
        self.message = message

        # Performance metadata
        self.execution_time: float | None = None
        self.request_id: UUID | None = None

        # Pagination metadata (for list responses)
        self.page: int | None = None
        self.page_size: int | None = None
        self.total_count: int | None = None
        self.has_more: bool | None = None

        # Error metadata
        self.error_code: str | None = None
        self.error_details: dict[str, Any] | None = None

    def set_request_metadata(self, request: Request) -> None:
        """
        Set metadata from the originating request.

        Args:
            request: Request that generated this response
        """
        self.request_id = request.request_id

        if request.processing_time_seconds:
            self.execution_time = request.processing_time_seconds

    def set_pagination(
        self, page: int, page_size: int, total_count: int, has_more: bool | None = None
    ) -> None:
        """
        Set pagination metadata for list responses.

        Args:
            page: Current page number
            page_size: Number of items per page
            total_count: Total number of items
            has_more: Whether there are more pages available
        """
        if hasattr(self, "_frozen") and self._frozen:
            raise AttributeError("Cannot modify frozen response")

        self.page = page
        self.page_size = page_size
        self.total_count = total_count
        self.has_more = (
            has_more if has_more is not None else (page * page_size < total_count)
        )

    def set_error(
        self, error_code: str, message: str, details: dict[str, Any] | None = None
    ) -> None:
        """
        Set error information for failed responses.

        Args:
            error_code: Error code
            message: Error message
            details: Optional error details
        """
        if hasattr(self, "_frozen") and self._frozen:
            raise AttributeError("Cannot modify frozen response")

        self.success = False
        self.error_code = error_code
        self.message = message
        self.error_details = details or {}

    def __repr__(self) -> str:
        """Detailed string representation for debugging."""
        return (
            f"{self.__class__.__name__}(id={self.response_id}, success={self.success})"
        )


# =====================================================================================
# USE CASE CLASSES
# =====================================================================================


class UseCase(ABC, Generic[TRequest, TResponse]):
    """
    Base use case class for application business logic.

    Use cases encapsulate specific business workflows and coordinate between
    domain objects and infrastructure services. They represent the application's
    entry points for business operations.

    Design Features:
    - Framework-agnostic implementation
    - Rich error handling and logging
    - Performance monitoring
    - Transaction support integration points
    - Context management
    - Comprehensive validation

    Usage Example:
        class CreateUserUseCase(UseCase[CreateUserRequest, CreateUserResponse]):
            def __init__(self, user_repository: UserRepository, email_service: EmailService):
                super().__init__()
                self.user_repository = user_repository
                self.email_service = email_service

            async def execute(self, request: CreateUserRequest) -> CreateUserResponse:
                # Validate business rules
                existing_user = await self.user_repository.find_by_email(request.email)
                if existing_user:
                    raise ConflictError("User already exists with this email")

                # Create domain object
                user = User(request.email, request.name, request.user_id)

                # Save to repository
                await self.user_repository.save(user)

                # Send welcome email
                await self.email_service.send_welcome_email(user.email, user.name)

                return CreateUserResponse(user.id, user.email, user.created_at)
    """

    def __init__(self):
        """Initialize use case with performance tracking."""
        self._execution_count = 0
        self._total_execution_time = 0.0
        self._error_count = 0
        self._last_executed = None

    @abstractmethod
    async def execute(self, request: TRequest) -> TResponse:
        """
        Execute the use case business logic.

        Args:
            request: Use case input data

        Returns:
            TResponse: Use case result

        Raises:
            ApplicationError: If use case execution fails
        """

    async def __call__(self, request: TRequest) -> TResponse:
        """
        Make use case callable with comprehensive error handling and logging.

        Args:
            request: Use case input data

        Returns:
            TResponse: Use case result
        """
        start_time = time.time()
        request.start_processing()

        try:
            logger.info(
                "Executing use case",
                use_case=self.__class__.__name__,
                request_id=request.request_id,
                user_id=request.user_id,
                correlation_id=request.correlation_id,
            )

            # Execute the use case
            response = await self.execute(request)

            # Update timing
            request.end_processing()
            execution_time = time.time() - start_time

            # Set response metadata
            response.set_request_metadata(request)

            # Update performance metrics
            self._execution_count += 1
            self._total_execution_time += execution_time
            self._last_executed = datetime.utcnow()

            logger.info(
                "Use case executed successfully",
                use_case=self.__class__.__name__,
                request_id=request.request_id,
                execution_time=execution_time,
                success=response.success,
            )

            return response

        except Exception as e:
            # Update timing and error metrics
            request.end_processing()
            execution_time = time.time() - start_time
            self._error_count += 1
            self._total_execution_time += execution_time

            logger.exception(
                "Use case execution failed",
                use_case=self.__class__.__name__,
                request_id=request.request_id,
                error=str(e),
                execution_time=execution_time,
                error_type=type(e).__name__,
            )
            raise

    def get_performance_stats(self) -> dict[str, Any]:
        """Get performance statistics for this use case."""
        avg_time = self._total_execution_time / max(self._execution_count, 1)
        error_rate = self._error_count / max(self._execution_count, 1)

        return {
            "use_case_class": self.__class__.__name__,
            "execution_count": self._execution_count,
            "error_count": self._error_count,
            "total_execution_time": self._total_execution_time,
            "average_execution_time": avg_time,
            "error_rate": error_rate,
            "last_executed": self._last_executed.isoformat()
            if self._last_executed
            else None,
        }


# =====================================================================================
# APPLICATION SERVICE CLASSES
# =====================================================================================


class ApplicationService(ABC):
    """
    Base application service for coordinating multiple use cases and external services.

    Application services orchestrate complex business workflows that span multiple
    use cases, handle cross-cutting concerns, and integrate with external systems.

    Design Features:
    - Framework-agnostic implementation
    - Multi-use case coordination
    - External service integration
    - Transaction management
    - Error handling and rollback
    - Performance monitoring

    Usage Example:
        class UserManagementService(ApplicationService):
            def __init__(
                self,
                create_user_use_case: CreateUserUseCase,
                send_notification_use_case: SendNotificationUseCase,
                user_repository: UserRepository
            ):
                super().__init__()
                self.create_user_use_case = create_user_use_case
                self.send_notification_use_case = send_notification_use_case
                self.user_repository = user_repository

            async def register_new_user(
                self,
                email: str,
                name: str,
                send_welcome: bool = True
            ) -> UserRegistrationResult:
                # Coordinate multiple use cases
                create_request = CreateUserRequest(email, name)
                user_response = await self.create_user_use_case(create_request)

                if send_welcome and user_response.success:
                    notification_request = SendNotificationRequest(
                        user_id=user_response.user_id,
                        type="welcome",
                        template="user_welcome"
                    )
                    await self.send_notification_use_case(notification_request)

                return UserRegistrationResult(user_response)
    """

    def __init__(self, *args, **kwargs):
        """
        Initialize application service with dependencies.

        Args:
            *args: Positional dependencies
            **kwargs: Keyword dependencies
        """
        self._service_id = uuid4()
        self._created_at = datetime.utcnow()
        self._operation_count = 0
        self._total_operation_time = 0.0
        self._error_count = 0

    @asynccontextmanager
    async def operation_context(self, operation_name: str):
        """
        Context manager for tracking service operations.

        Args:
            operation_name: Name of the operation being performed
        """
        start_time = time.time()
        operation_id = uuid4()

        logger.info(
            "Starting service operation",
            service=self.__class__.__name__,
            operation=operation_name,
            operation_id=operation_id,
        )

        try:
            yield operation_id

            execution_time = time.time() - start_time
            self._operation_count += 1
            self._total_operation_time += execution_time

            logger.info(
                "Service operation completed successfully",
                service=self.__class__.__name__,
                operation=operation_name,
                operation_id=operation_id,
                execution_time=execution_time,
            )

        except Exception as e:
            execution_time = time.time() - start_time
            self._error_count += 1
            self._total_operation_time += execution_time

            logger.exception(
                "Service operation failed",
                service=self.__class__.__name__,
                operation=operation_name,
                operation_id=operation_id,
                error=str(e),
                execution_time=execution_time,
                error_type=type(e).__name__,
            )
            raise

    def get_performance_stats(self) -> dict[str, Any]:
        """Get performance statistics for this service."""
        avg_time = self._total_operation_time / max(self._operation_count, 1)
        error_rate = self._error_count / max(self._operation_count, 1)

        return {
            "service_class": self.__class__.__name__,
            "service_id": str(self._service_id),
            "created_at": self._created_at.isoformat(),
            "operation_count": self._operation_count,
            "error_count": self._error_count,
            "total_operation_time": self._total_operation_time,
            "average_operation_time": avg_time,
            "error_rate": error_rate,
        }


# =====================================================================================
# CONTEXT MANAGEMENT
# =====================================================================================


class ApplicationContext:
    """
    Application context for tracking request/response flow and state.

    Provides centralized context management for tracking requests across
    the application, managing user sessions, and coordinating cross-cutting
    concerns like logging and metrics.
    """

    def __init__(self):
        """Initialize application context."""
        self.context_id = uuid4()
        self.created_at = datetime.utcnow()
        self.correlation_id: UUID | None = None
        self.user_id: UUID | None = None
        self.session_id: UUID | None = None
        self.request_data: dict[str, Any] = {}
        self.response_data: dict[str, Any] = {}
        self.metrics: dict[str, Any] = {}
        self.errors: list[str] = []

    def set_correlation_id(self, correlation_id: UUID) -> None:
        """Set correlation ID for request tracking."""
        self.correlation_id = correlation_id

    def set_user_context(self, user_id: UUID, session_id: UUID | None = None) -> None:
        """Set user context information."""
        self.user_id = user_id
        self.session_id = session_id

    def add_metric(self, key: str, value: Any) -> None:
        """Add metric to context."""
        self.metrics[key] = value

    def add_error(self, error: str) -> None:
        """Add error to context."""
        self.errors.append(error)

    def to_dict(self) -> dict[str, Any]:
        """Convert context to dictionary."""
        return {
            "context_id": str(self.context_id),
            "created_at": self.created_at.isoformat(),
            "correlation_id": str(self.correlation_id) if self.correlation_id else None,
            "user_id": str(self.user_id) if self.user_id else None,
            "session_id": str(self.session_id) if self.session_id else None,
            "request_data": self.request_data,
            "response_data": self.response_data,
            "metrics": self.metrics,
            "errors": self.errors,
        }


# =====================================================================================
# EXPORTS
# =====================================================================================

__all__ = [
    # Base classes
    "DTO",
    "TDTO",
    # Context management
    "ApplicationContext",
    "ApplicationService",
    "Request",
    "Response",
    # Type variables
    "TRequest",
    "TResponse",
    "UseCase",
]
