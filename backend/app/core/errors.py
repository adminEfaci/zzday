"""Enhanced error classes and error handling (production-ready)."""

import logging
import time
import uuid
from collections.abc import Callable
from contextlib import contextmanager
from enum import Enum
from typing import Any


class ErrorSeverity(Enum):
    """Error severity levels for monitoring and alerting."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EzzDayError(Exception):
    """
    Base exception for all EzzDay errors.

    Enhanced with error IDs, severity levels, correlation tracking,
    retry hints, and comprehensive monitoring support.
    """

    default_code: str = "ERROR"
    status_code: int = 500
    severity: ErrorSeverity = ErrorSeverity.MEDIUM
    retryable: bool = False

    def __init__(self, message: str, **kwargs: Any) -> None:
        super().__init__(message)
        self.message = message
        self.code = kwargs.get("code") or self.default_code
        self.details = kwargs.get("details") or {}
        self.correlation_id = kwargs.get("correlation_id") or str(uuid.uuid4())
        self.error_id = str(uuid.uuid4())
        self.timestamp = time.time()
        self.user_message = kwargs.get("user_message") or message
        self.recovery_hint = kwargs.get("recovery_hint")
        self.context = kwargs.get("context") or {}
        self.__cause__ = kwargs.get("cause")

        # Log the error automatically
        self._log_error()

    def _log_error(self) -> None:
        """Log error with structured data."""
        logger = logging.getLogger(f"ezzday.errors.{self.__class__.__name__}")
        log_data = {
            "error_id": self.error_id,
            "correlation_id": self.correlation_id,
            "code": self.code,
            "error_message": self.message,
            "severity": self.severity.value,
            "retryable": self.retryable,
            "status_code": self.status_code,
            "details": self._sanitize_details(self.details),
            "context": self._sanitize_context(self.context),
            "error_class": self.__class__.__name__,
            "error_module": self.__class__.__module__,
        }

        if self.severity == ErrorSeverity.CRITICAL:
            logger.critical("Critical error occurred", extra=log_data)
        elif self.severity == ErrorSeverity.HIGH:
            logger.error("High severity error", extra=log_data)
        elif self.severity == ErrorSeverity.MEDIUM:
            logger.warning("Medium severity error", extra=log_data)
        else:
            logger.info("Low severity error", extra=log_data)
    
    def _sanitize_details(self, details: dict) -> dict:
        """Sanitize error details to remove sensitive information."""
        if not details:
            return {}
        
        sensitive_keys = {'password', 'token', 'secret', 'key', 'credential', 'authorization'}
        sanitized = {}
        
        for key, value in details.items():
            if any(sensitive in key.lower() for sensitive in sensitive_keys):
                sanitized[key] = "***REDACTED***"
            elif isinstance(value, dict):
                sanitized[key] = self._sanitize_details(value)
            else:
                sanitized[key] = value
        
        return sanitized
    
    def _sanitize_context(self, context: dict) -> dict:
        """Sanitize context to remove sensitive information."""
        return self._sanitize_details(context)

    def to_dict(
        self, include_details: bool = True, include_internal: bool = False
    ) -> dict[str, Any]:
        """
        Serialize error for API/logging with granular control over what's included.

        Args:
            include_details: Include error details
            include_internal: Include internal debugging info (correlation_id, error_id, etc.)
        """
        data = {
            "error": self.code,
            "message": self.user_message,
            "timestamp": self.timestamp,
        }

        if include_details and self.details:
            # Filter out sensitive data
            safe_details = {
                k: v
                for k, v in self.details.items()
                if not k.startswith("_") and "password" not in k.lower()
            }
            data["details"] = safe_details

        if self.recovery_hint:
            data["recovery_hint"] = self.recovery_hint

        if self.retryable:
            data["retryable"] = True

        if include_internal:
            data.update(
                {
                    "error_id": self.error_id,
                    "correlation_id": self.correlation_id,
                    "severity": self.severity.value,
                    "internal_message": self.message,
                    "context": self.context,
                }
            )

        return data

    def with_context(self, **context: Any) -> "EzzDayError":
        """Add context to error and return self for chaining."""
        self.context.update(context)
        return self

    def __str__(self) -> str:
        return f"[{self.error_id}] {self.code}: {self.message}"


class DomainError(EzzDayError):
    """Base class for domain errors."""

    default_code = "DOMAIN_ERROR"
    status_code = 400
    severity = ErrorSeverity.MEDIUM


class ApplicationError(EzzDayError):
    """Base class for application layer errors."""

    default_code = "APPLICATION_ERROR"
    status_code = 400
    severity = ErrorSeverity.MEDIUM


class InfrastructureError(EzzDayError):
    """Base class for infrastructure errors."""

    default_code = "INFRASTRUCTURE_ERROR"
    status_code = 500
    severity = ErrorSeverity.HIGH
    retryable = True


class ValidationError(ApplicationError):
    """Enhanced validation error with support for multiple field errors."""

    default_code = "VALIDATION_ERROR"
    status_code = 422
    severity = ErrorSeverity.LOW

    def __init__(
        self,
        message: str,
        field: str | None = None,
        field_errors: dict[str, list[str]] | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, **kwargs)
        if field:
            self.details["field"] = field
        if field_errors:
            self.details["field_errors"] = field_errors
        self.code = self.default_code

    @classmethod
    def from_fields(
        cls, field_errors: dict[str, list[str]], **kwargs: Any
    ) -> "ValidationError":
        """Create validation error from field errors dictionary."""
        total_errors = sum(len(errors) for errors in field_errors.values())
        message = f"Validation failed for {len(field_errors)} field(s) with {total_errors} error(s)"
        return cls(message, field_errors=field_errors, **kwargs)


class NotFoundError(ApplicationError):
    """Resource not found error."""

    default_code = "NOT_FOUND"
    status_code = 404
    severity = ErrorSeverity.LOW

    def __init__(self, resource: str, identifier: Any, **kwargs: Any) -> None:
        message = f"{resource} not found: {identifier}"
        user_message = f"The requested {resource.lower()} was not found"
        super().__init__(message, user_message=user_message, **kwargs)
        self.details.update({"resource": resource, "identifier": str(identifier)})
        self.code = self.default_code


class ConflictError(ApplicationError):
    """Resource conflict error."""

    default_code = "CONFLICT"
    status_code = 409
    severity = ErrorSeverity.MEDIUM

    def __init__(
        self, message: str, resource: str | None = None, **kwargs: Any
    ) -> None:
        super().__init__(message, **kwargs)
        if resource:
            self.details["resource"] = resource
        self.code = self.default_code


class UnauthorizedError(ApplicationError):
    """Unauthorized access error."""

    default_code = "UNAUTHORIZED"
    status_code = 401
    severity = ErrorSeverity.MEDIUM

    def __init__(self, message: str = "Authentication required", **kwargs: Any) -> None:
        user_message = "Please log in to access this resource"
        super().__init__(message, user_message=user_message, **kwargs)
        self.code = self.default_code


class ForbiddenError(ApplicationError):
    """Forbidden access error."""

    default_code = "FORBIDDEN"
    status_code = 403
    severity = ErrorSeverity.MEDIUM

    def __init__(self, message: str = "Access denied", **kwargs: Any) -> None:
        user_message = "You don't have permission to access this resource"
        super().__init__(message, user_message=user_message, **kwargs)
        self.code = self.default_code


class RateLimitError(ApplicationError):
    """Rate limit exceeded error."""

    default_code = "RATE_LIMIT_EXCEEDED"
    status_code = 429
    severity = ErrorSeverity.LOW
    retryable = True

    def __init__(
        self, limit: str, window: str, retry_after: int | None = None, **kwargs: Any
    ) -> None:
        message = f"Rate limit exceeded: {limit} per {window}"
        user_message = "Too many requests. Please try again later."
        recovery_hint = f"Wait {retry_after or 60} seconds before retrying"
        super().__init__(
            message, user_message=user_message, recovery_hint=recovery_hint, **kwargs
        )
        self.details.update(
            {"limit": limit, "window": window, "retry_after": retry_after or 60}
        )
        self.code = self.default_code


class OperationTimeoutError(InfrastructureError):
    """Operation timeout error."""

    default_code = "TIMEOUT"
    status_code = 504
    severity = ErrorSeverity.HIGH
    retryable = True

    def __init__(self, operation: str, timeout_seconds: float, **kwargs: Any) -> None:
        message = f"{operation} timed out after {timeout_seconds}s"
        user_message = "The operation took too long to complete"
        recovery_hint = "Please try again. If the problem persists, contact support."
        super().__init__(
            message, user_message=user_message, recovery_hint=recovery_hint, **kwargs
        )
        self.details.update(
            {"operation": operation, "timeout_seconds": timeout_seconds}
        )
        self.code = self.default_code


class ConfigurationError(InfrastructureError):
    """Configuration error."""

    default_code = "CONFIGURATION_ERROR"
    status_code = 500
    severity = ErrorSeverity.CRITICAL

    def __init__(
        self, message: str, config_key: str | None = None, **kwargs: Any
    ) -> None:
        user_message = "Service configuration issue"
        super().__init__(message, user_message=user_message, **kwargs)
        if config_key:
            self.details["config_key"] = config_key
        self.code = self.default_code


class ExternalServiceError(InfrastructureError):
    """External service error."""

    default_code = "EXTERNAL_SERVICE_ERROR"
    status_code = 502
    severity = ErrorSeverity.HIGH
    retryable = True

    def __init__(
        self,
        service: str,
        message: str,
        service_status_code: int | None = None,
        **kwargs: Any,
    ) -> None:
        full_message = f"{service} error: {message}"
        user_message = "External service temporarily unavailable"
        recovery_hint = "Please try again in a few moments"
        super().__init__(
            full_message,
            user_message=user_message,
            recovery_hint=recovery_hint,
            **kwargs,
        )
        self.details.update(
            {"service": service, "service_status_code": service_status_code}
        )
        self.code = self.default_code


class BusinessRuleError(DomainError):
    """Business rule violation error."""

    default_code = "BUSINESS_RULE_VIOLATION"
    status_code = 422
    severity = ErrorSeverity.MEDIUM

    def __init__(self, rule: str, message: str, **kwargs: Any) -> None:
        super().__init__(message, **kwargs)
        self.details["rule"] = rule
        self.code = self.default_code


class ResourceExhaustedError(InfrastructureError):
    """Resource exhausted error (disk space, memory, etc.)."""

    default_code = "RESOURCE_EXHAUSTED"
    status_code = 507
    severity = ErrorSeverity.CRITICAL

    def __init__(self, resource: str, **kwargs: Any) -> None:
        message = f"{resource} exhausted"
        user_message = "Service temporarily unavailable due to resource constraints"
        super().__init__(message, user_message=user_message, **kwargs)
        self.details["resource"] = resource
        self.code = self.default_code


# Error handling utilities


class ErrorContext:
    """Context manager for error correlation and additional context."""

    def __init__(self, correlation_id: str | None = None, **context: Any) -> None:
        self.correlation_id = correlation_id or str(uuid.uuid4())
        self.context = context
        self._original_factory = None

    def __enter__(self) -> "ErrorContext":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if exc_val and isinstance(exc_val, EzzDayError):
            if not exc_val.correlation_id:
                exc_val.correlation_id = self.correlation_id
            exc_val.context.update(self.context)

    def create_error(
        self, error_class: type[EzzDayError], *args: Any, **kwargs: Any
    ) -> EzzDayError:
        """Create an error with this context applied."""
        kwargs.setdefault("correlation_id", self.correlation_id)
        if "context" in kwargs:
            kwargs["context"].update(self.context)
        else:
            kwargs["context"] = self.context.copy()
        return error_class(*args, **kwargs)


@contextmanager
def error_context(correlation_id: str | None = None, **context: Any) -> Any:
    """Context manager for error correlation."""
    ctx = ErrorContext(correlation_id, **context)
    try:
        yield ctx
    except EzzDayError as e:
        if not e.correlation_id:
            e.correlation_id = ctx.correlation_id
        e.context.update(ctx.context)
        raise


def handle_external_errors(
    service_name: str,
    error_mapping: dict[type[Exception], type[EzzDayError]] | None = None,
    retry_on: list[type[Exception]] | None = None,
    max_retries: int = 3,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Enhanced decorator to handle external service errors with retry logic."""

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            last_exception = None
            retry_exceptions = retry_on or []
            
            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except EzzDayError:
                    raise  # Re-raise our own errors
                except Exception as e:
                    last_exception = e
                    
                    # Check if we should retry
                    should_retry = (
                        attempt < max_retries and 
                        any(isinstance(e, exc_type) for exc_type in retry_exceptions)
                    )
                    
                    if not should_retry:
                        # Map external errors to our error types
                        if error_mapping and type(e) in error_mapping:
                            mapped_error = error_mapping[type(e)]
                            raise mapped_error(
                                str(e), 
                                cause=e,
                                context={"service": service_name, "attempts": attempt + 1}
                            ) from e
                        raise ExternalServiceError(
                            service_name, 
                            str(e), 
                            cause=e,
                            context={"attempts": attempt + 1}
                        ) from e
                    
                    # Wait before retry (exponential backoff)
                    import time
                    time.sleep(2 ** attempt)
            
            # This shouldn't be reached, but just in case
            if last_exception:
                raise ExternalServiceError(service_name, str(last_exception)) from last_exception
            
            # Explicit return for type checker
            return None

        return wrapper

    return decorator


class CircuitBreakerError(InfrastructureError):
    """Circuit breaker is open error."""
    
    default_code = "CIRCUIT_BREAKER_OPEN"
    status_code = 503
    severity = ErrorSeverity.HIGH
    retryable = True


class ServiceDegradedError(InfrastructureError):
    """Service is degraded but still functional."""
    
    default_code = "SERVICE_DEGRADED"
    status_code = 200  # Still successful but degraded
    severity = ErrorSeverity.MEDIUM
    retryable = False


class PermissionDeniedError(ApplicationError):
    """Permission denied error for authorization failures."""
    
    default_code = "PERMISSION_DENIED"
    status_code = 403
    severity = ErrorSeverity.MEDIUM

    def __init__(self, message: str = "Permission denied", resource: str | None = None, action: str | None = None, **kwargs: Any) -> None:
        user_message = "You don't have permission to perform this action"
        super().__init__(message, user_message=user_message, **kwargs)
        if resource:
            self.details["resource"] = resource
        if action:
            self.details["action"] = action
        self.code = self.default_code


class TimeoutError(InfrastructureError):
    """Operation timeout error."""
    
    default_code = "TIMEOUT_ERROR"
    status_code = 408
    severity = ErrorSeverity.HIGH
    retryable = True

    def __init__(self, operation: str, timeout_seconds: float | None = None, **kwargs: Any) -> None:
        message = f"Operation '{operation}' timed out"
        if timeout_seconds:
            message += f" after {timeout_seconds}s"
        user_message = "The operation took too long to complete"
        recovery_hint = "Please try again. If the problem persists, contact support."
        super().__init__(
            message, user_message=user_message, recovery_hint=recovery_hint, **kwargs
        )
        self.details.update({
            "operation": operation,
            "timeout_seconds": timeout_seconds
        })
        self.code = self.default_code


class DataIntegrityError(InfrastructureError):
    """Data integrity constraint violation error."""
    
    default_code = "DATA_INTEGRITY_ERROR"
    status_code = 422
    severity = ErrorSeverity.MEDIUM
    retryable = False

    def __init__(self, message: str, constraint: str | None = None, **kwargs: Any) -> None:
        user_message = "Data integrity constraint violated"
        super().__init__(message, user_message=user_message, **kwargs)
        if constraint:
            self.details["constraint"] = constraint
        self.code = self.default_code


def create_error_from_exception(
    exc: Exception,
    error_class: type[EzzDayError] | None = None,
    **kwargs
) -> EzzDayError:
    """Create an EzzDayError from a standard exception."""
    if isinstance(exc, EzzDayError):
        return exc
    
    error_class = error_class or InfrastructureError
    
    return error_class(
        str(exc),
        cause=exc,
        context={"original_type": type(exc).__name__},
        **kwargs
    )


def safe_import(module_name: str, fallback_factory: callable = None):
    """
    Safely import a module with optional fallback.
    
    Args:
        module_name: Name of the module to import
        fallback_factory: Optional callable that returns fallback object
        
    Returns:
        Imported module or fallback object
        
    Raises:
        ConfigurationError: If module cannot be imported and no fallback provided
    """
    try:
        from importlib import import_module
        return import_module(module_name)
    except ImportError as e:
        if fallback_factory:
            return fallback_factory()
        raise ConfigurationError(
            f"Required module '{module_name}' could not be imported and no fallback provided",
            context={"import_error": str(e)}
        ) from e


def require_import(module_name: str, items: list[str] | None = None):
    """
    Import required module items with detailed error messages.
    
    Args:
        module_name: Name of the module to import from
        items: List of items to import from the module
        
    Returns:
        Module or tuple of imported items
        
    Raises:
        ConfigurationError: If required imports fail
    """
    try:
        from importlib import import_module
        module = import_module(module_name)
        
        if items:
            imported_items = []
            for item in items:
                if hasattr(module, item):
                    imported_items.append(getattr(module, item))
                else:
                    raise ConfigurationError(
                        f"Required item '{item}' not found in module '{module_name}'",
                        context={"module": module_name, "missing_item": item}
                    )
            return tuple(imported_items) if len(imported_items) > 1 else imported_items[0]
        
        return module
        
    except ImportError as e:
        raise ConfigurationError(
            f"Required module '{module_name}' could not be imported",
            context={"import_error": str(e), "required_items": items}
        ) from e
