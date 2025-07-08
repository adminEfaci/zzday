# ruff: noqa: A005
"""Structured logging configuration following pure Python principles.

This module provides comprehensive logging infrastructure for the EzzDay backend,
implementing clean architecture principles with pure Python classes that are
framework-agnostic and independent of any specific logging framework beyond structlog.

The logging system provides structured logging with context management, performance
tracking, security-focused log sanitization, and comprehensive error handling.

Design Principles:
- Pure Python classes with explicit configuration
- Framework-agnostic design for maximum portability
- Structured logging with rich context management
- Security-focused log sanitization and filtering
- Performance monitoring and metrics integration
- Environment-specific logging configuration
- Comprehensive error handling and recovery

Architecture:
- LogLevel: Logging level enumeration with priority mapping
- LogConfig: Configuration management with validation
- LogFilter: Security filters for sensitive data sanitization
- ContextManager: Request/user context management
- PerformanceTracker: Performance monitoring and metrics
- LoggerFactory: Logger creation and configuration
- StructuredLogger: Enhanced logger with rich functionality

Note: This module name intentionally shadows the standard library 'logging' module
to provide a drop-in replacement with enhanced structured logging capabilities.
"""

import logging
import logging.config
import re
import sys
import time
from abc import ABC, abstractmethod
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

import structlog
from structlog.contextvars import merge_contextvars

from app.core.enums import Environment, LogLevel
from app.core.errors import ConfigurationError

# Handle missing LogFormat enum
try:
    from app.core.enums import LogFormat
except ImportError:
    from enum import Enum
    
    class LogFormat(Enum):
        """Log output format options."""
        JSON = "json"
        CONSOLE = "console"
        PLAIN = "plain"
        
        def __str__(self) -> str:
            """String representation."""
            return self.value

# Handle optional monitoring dependency
try:
    from app.core.monitoring import metrics
except ImportError:
    # Fallback metrics implementation
    class MockMetrics:
        """Mock metrics for when monitoring is not available."""
        
        def __init__(self) -> None:
            """Initialize mock metrics."""
            self.auth_attempts = MockCounter()
            self.log_events = MockCounter()
            self.log_errors = MockCounter()
    
    class MockCounter:
        """Mock counter for metrics."""
        
        def labels(self, **kwargs) -> "MockCounter":
            """Mock labels method."""
            return self
        
        def observe(self, value: float) -> None:
            """Mock observe method."""
        
        def inc(self, count: int = 1) -> None:
            """Mock increment method."""
    
    metrics = MockMetrics()

# =====================================================================================
# CONFIGURATION CLASSES
# =====================================================================================


@dataclass
class LogConfig:
    """
    Logging configuration with comprehensive validation and environment defaults.

    Design Features:
    - Pure Python dataclass with explicit validation
    - Environment-specific configuration defaults
    - Security-focused filtering options
    - Performance monitoring settings
    - Framework-agnostic implementation

    Usage Example:
        config = LogConfig(
            level=LogLevel.INFO,
            format=LogFormat.JSON,
            environment=Environment.PRODUCTION,
            enable_context_tracking=True
        )

        # Validate configuration
        config.validate()

        # Apply environment-specific settings
        config.apply_environment_defaults()
    """

    # Core logging settings
    level: LogLevel = field(default=LogLevel.INFO)
    format: LogFormat = field(default=LogFormat.JSON)
    environment: Environment = field(default=Environment.DEVELOPMENT)

    # Output settings
    enable_console_output: bool = field(default=True)
    enable_file_output: bool = field(default=False)
    log_file_path: str | None = field(default=None)
    max_log_file_size: int = field(default=10_000_000)  # 10 MB
    log_file_backup_count: int = field(default=5)

    # Structured logging features
    enable_timestamps: bool = field(default=True)
    enable_caller_info: bool = field(default=False)
    enable_process_info: bool = field(default=True)
    enable_thread_info: bool = field(default=False)
    enable_exception_info: bool = field(default=True)

    # Context management
    enable_context_tracking: bool = field(default=True)
    enable_correlation_ids: bool = field(default=True)
    enable_user_tracking: bool = field(default=True)
    enable_performance_tracking: bool = field(default=True)

    # Security and filtering
    enable_sensitive_data_filtering: bool = field(default=True)
    mask_sensitive_fields: bool = field(default=True)
    truncate_long_messages: bool = field(default=True)
    max_message_length: int = field(default=10000)

    # Performance settings
    async_logging: bool = field(default=False)
    buffer_size: int = field(default=1000)
    flush_interval: float = field(default=1.0)

    # External integrations
    enable_sentry_integration: bool = field(default=False)
    sentry_dsn: str | None = field(default=None)
    enable_prometheus_metrics: bool = field(default=False)

    def __post_init__(self):
        """Post-initialization validation and setup."""
        self.validate()
        self.apply_environment_defaults()

    def validate(self) -> None:
        """
        Validate logging configuration parameters.

        Raises:
            ConfigurationError: If configuration is invalid
        """
        # Validate file output settings
        if self.enable_file_output and not self.log_file_path:
            raise ConfigurationError(
                "Log file path is required when file output is enabled"
            )

        if self.max_log_file_size < 1_000_000:  # 1 MB minimum
            raise ConfigurationError("Maximum log file size must be at least 1 MB")

        if self.log_file_backup_count < 1:
            raise ConfigurationError("Log file backup count must be at least 1")

        # Validate performance settings
        if self.buffer_size < 1:
            raise ConfigurationError("Buffer size must be at least 1")

        if self.flush_interval <= 0:
            raise ConfigurationError("Flush interval must be positive")

        if self.max_message_length < 1000:
            raise ConfigurationError(
                "Maximum message length must be at least 1000 characters"
            )

        # Validate Sentry integration
        if self.enable_sentry_integration and not self.sentry_dsn:
            raise ConfigurationError(
                "Sentry DSN is required when Sentry integration is enabled"
            )

    def apply_environment_defaults(self) -> None:
        """Apply environment-specific defaults and optimizations."""
        if self.environment == Environment.DEVELOPMENT:
            # Development: Verbose logging, console output
            self.format = LogFormat.CONSOLE
            self.enable_caller_info = True
            self.enable_thread_info = True
            self.enable_console_output = True
            self.enable_file_output = False
            self.async_logging = False

        elif self.environment == Environment.TESTING:
            # Testing: Minimal logging, no external integrations
            self.level = LogLevel.WARNING
            self.format = LogFormat.PLAIN
            self.enable_context_tracking = False
            self.enable_performance_tracking = False
            self.enable_sentry_integration = False
            self.enable_prometheus_metrics = False
            self.async_logging = False

        elif self.environment == Environment.STAGING:
            # Staging: Production-like but with more verbosity
            self.format = LogFormat.JSON
            self.enable_file_output = True
            self.enable_performance_tracking = True
            self.async_logging = True

        elif self.environment == Environment.PRODUCTION:
            # Production: Optimized, secure, structured
            self.level = LogLevel.INFO
            self.format = LogFormat.JSON
            self.enable_caller_info = False
            self.enable_thread_info = False
            self.enable_file_output = True
            self.enable_sensitive_data_filtering = True
            self.mask_sensitive_fields = True
            self.async_logging = True
            self.enable_sentry_integration = True
            self.enable_prometheus_metrics = True

    def to_dict(self) -> dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            "level": self.level.level_name,
            "format": self.format.value,
            "environment": self.environment.value,
            "enable_console_output": self.enable_console_output,
            "enable_file_output": self.enable_file_output,
            "log_file_path": self.log_file_path,
            "max_log_file_size": self.max_log_file_size,
            "log_file_backup_count": self.log_file_backup_count,
            "enable_timestamps": self.enable_timestamps,
            "enable_caller_info": self.enable_caller_info,
            "enable_context_tracking": self.enable_context_tracking,
            "enable_performance_tracking": self.enable_performance_tracking,
            "enable_sensitive_data_filtering": self.enable_sensitive_data_filtering,
            "async_logging": self.async_logging,
            "buffer_size": self.buffer_size,
            "flush_interval": self.flush_interval,
        }


# =====================================================================================
# SECURITY FILTERS
# =====================================================================================


class LogFilter(ABC):
    """
    Abstract base class for log filtering and sanitization.

    Provides framework for implementing security-focused log filters
    that sanitize sensitive data and ensure log safety.
    """

    @abstractmethod
    def filter(self, record: dict[str, Any]) -> dict[str, Any]:
        """
        Filter and sanitize log record.

        Args:
            record: Log record to filter

        Returns:
            dict[str, Any]: Filtered log record
        """

    @abstractmethod
    def should_skip(self, record: dict[str, Any]) -> bool:
        """
        Determine if record should be skipped entirely.

        Args:
            record: Log record to evaluate

        Returns:
            bool: True if record should be skipped
        """


class SensitiveDataFilter(LogFilter):
    """
    Filter for sanitizing sensitive data in log records.

    Identifies and masks sensitive information like passwords, tokens,
    credit card numbers, and personally identifiable information.

    Design Features:
    - Configurable sensitive field patterns
    - Multiple masking strategies
    - Performance-optimized regex patterns
    - Comprehensive data type coverage
    """

    def __init__(self, mask_char: str = "*", preserve_length: bool = False):
        """
        Initialize sensitive data filter.

        Args:
            mask_char: Character to use for masking
            preserve_length: Whether to preserve original length when masking
        """
        self.mask_char = mask_char
        self.preserve_length = preserve_length

        # Sensitive field patterns (case-insensitive)
        self.sensitive_patterns = [
            re.compile(r"password", re.IGNORECASE),
            re.compile(r"token", re.IGNORECASE),
            re.compile(r"secret", re.IGNORECASE),
            re.compile(r"key", re.IGNORECASE),
            re.compile(r"credential", re.IGNORECASE),
            re.compile(r"auth", re.IGNORECASE),
            re.compile(r"ssn", re.IGNORECASE),
            re.compile(r"social.security", re.IGNORECASE),
            re.compile(r"credit.card", re.IGNORECASE),
            re.compile(r"card.number", re.IGNORECASE),
            re.compile(r"cvv", re.IGNORECASE),
            re.compile(r"pin", re.IGNORECASE),
        ]

        # Value patterns for sensitive data
        self.value_patterns = [
            # Credit card numbers (basic pattern)
            re.compile(r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b"),
            # SSN pattern
            re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
            # Email addresses in certain contexts
            re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
        ]

    def filter(self, record: dict[str, Any]) -> dict[str, Any]:
        """Filter and sanitize log record."""
        filtered_record = {}

        for key, value in record.items():
            if self._is_sensitive_field(key):
                filtered_record[key] = self._mask_value(value)
            elif isinstance(value, str):
                filtered_record[key] = self._sanitize_string_value(value)
            elif isinstance(value, dict):
                filtered_record[key] = self.filter(value)
            elif isinstance(value, list):
                filtered_record[key] = [
                    self.filter(item)
                    if isinstance(item, dict)
                    else self._sanitize_string_value(item)
                    if isinstance(item, str)
                    else item
                    for item in value
                ]
            else:
                filtered_record[key] = value

        return filtered_record

    def should_skip(self, record: dict[str, Any]) -> bool:
        """Determine if record should be skipped."""
        # Skip records that are entirely sensitive data
        message = record.get("message", "")
        if isinstance(message, str):
            # Skip if message contains only sensitive patterns
            sensitive_count = sum(
                1 for pattern in self.value_patterns if pattern.search(message)
            )
            if sensitive_count > 0 and len(message.strip()) < 50:
                return True

        return False

    def _is_sensitive_field(self, field_name: str) -> bool:
        """Check if field name indicates sensitive data."""
        return any(pattern.search(field_name) for pattern in self.sensitive_patterns)

    def _mask_value(self, value: Any) -> str:
        """Mask sensitive value."""
        if value is None:
            return None

        value_str = str(value)

        if self.preserve_length:
            return self.mask_char * len(value_str)
        return f"{self.mask_char * 3}[MASKED]"

    def _sanitize_string_value(self, value: str) -> str:
        """Sanitize string value by masking sensitive patterns."""
        if not isinstance(value, str):
            return value

        sanitized = value
        for pattern in self.value_patterns:
            sanitized = pattern.sub(lambda m: self._mask_value(m.group()), sanitized)

        return sanitized


class MessageLengthFilter(LogFilter):
    """Filter for truncating overly long log messages."""

    def __init__(
        self, max_length: int = 10000, truncation_suffix: str = "... [TRUNCATED]"
    ):
        """
        Initialize message length filter.

        Args:
            max_length: Maximum allowed message length
            truncation_suffix: Suffix to add to truncated messages
        """
        self.max_length = max_length
        self.truncation_suffix = truncation_suffix

    def filter(self, record: dict[str, Any]) -> dict[str, Any]:
        """Filter and truncate long messages."""
        filtered_record = record.copy()

        message = record.get("message", "")
        if isinstance(message, str) and len(message) > self.max_length:
            truncated_length = self.max_length - len(self.truncation_suffix)
            filtered_record["message"] = (
                message[:truncated_length] + self.truncation_suffix
            )
            filtered_record["original_message_length"] = len(message)
            filtered_record["message_truncated"] = True

        return filtered_record

    def should_skip(self, record: dict[str, Any]) -> bool:
        """Never skip records, just truncate."""
        return False


# =====================================================================================
# CONTEXT MANAGEMENT
# =====================================================================================


class LoggingContext:
    """
    Logging context manager for request and user tracking.

    Provides comprehensive context management for structured logging
    with request correlation, user tracking, and performance monitoring.

    Design Features:
    - Pure Python implementation
    - Request/response correlation
    - User session tracking
    - Performance monitoring
    - Thread-safe context management
    - Rich metadata collection
    """

    def __init__(self):
        """Initialize logging context manager."""
        self._context_stack: list[dict[str, Any]] = []
        self._global_context: dict[str, Any] = {}
        self._request_contexts: dict[UUID, dict[str, Any]] = {}

        # Performance tracking
        self._request_timings: dict[UUID, float] = {}
        self._operation_timings: dict[str, list[float]] = {}

    def set_global_context(self, **kwargs: Any) -> None:
        """Set global context variables."""
        self._global_context.update(kwargs)
        structlog.contextvars.bind_contextvars(**kwargs)

    def clear_global_context(self) -> None:
        """Clear all global context variables."""
        self._global_context.clear()
        structlog.contextvars.clear_contextvars()

    @contextmanager
    def request_context(
        self,
        request_id: UUID | None = None,
        correlation_id: UUID | None = None,
        user_id: UUID | None = None,
        session_id: UUID | None = None,
        **kwargs: Any,
    ):
        """
        Context manager for request-scoped logging context.

        Args:
            request_id: Unique request identifier
            correlation_id: Cross-service correlation identifier
            user_id: User identifier
            session_id: Session identifier
            **kwargs: Additional context variables
        """
        request_id = request_id or uuid4()
        start_time = time.time()

        context = {
            "request_id": str(request_id),
            "correlation_id": str(correlation_id) if correlation_id else None,
            "user_id": str(user_id) if user_id else None,
            "session_id": str(session_id) if session_id else None,
            "request_start_time": datetime.utcnow().isoformat(),
            **kwargs,
        }

        # Store request context
        self._request_contexts[request_id] = context
        self._request_timings[request_id] = start_time

        # Push context
        self._context_stack.append(context)
        structlog.contextvars.bind_contextvars(**context)

        try:
            yield request_id
        finally:
            # Calculate request duration
            duration = time.time() - start_time
            context["request_duration"] = duration

            # Pop context
            if self._context_stack:
                self._context_stack.pop()

            # Clean up request tracking
            self._request_contexts.pop(request_id, None)
            self._request_timings.pop(request_id, None)

            # Clear request-specific context
            structlog.contextvars.unbind_contextvars(
                "request_id",
                "correlation_id",
                "user_id",
                "session_id",
                "request_start_time",
                "request_duration",
            )

    @contextmanager
    def operation_context(self, operation_name: str, **kwargs: Any):
        """
        Context manager for operation-scoped logging context.

        Args:
            operation_name: Name of the operation
            **kwargs: Additional context variables
        """
        operation_id = uuid4()
        start_time = time.time()

        context = {
            "operation_name": operation_name,
            "operation_id": str(operation_id),
            "operation_start_time": datetime.utcnow().isoformat(),
            **kwargs,
        }

        # Push context
        self._context_stack.append(context)
        structlog.contextvars.bind_contextvars(**context)

        try:
            yield operation_id
        finally:
            # Calculate operation duration
            duration = time.time() - start_time
            context["operation_duration"] = duration

            # Track operation performance
            if operation_name not in self._operation_timings:
                self._operation_timings[operation_name] = []
            self._operation_timings[operation_name].append(duration)

            # Keep only last 100 timings per operation
            if len(self._operation_timings[operation_name]) > 100:
                self._operation_timings[operation_name] = self._operation_timings[
                    operation_name
                ][-100:]

            # Pop context
            if self._context_stack:
                self._context_stack.pop()

            # Clear operation-specific context
            structlog.contextvars.unbind_contextvars(
                "operation_name",
                "operation_id",
                "operation_start_time",
                "operation_duration",
            )

    def get_current_context(self) -> dict[str, Any]:
        """Get current logging context."""
        context = self._global_context.copy()
        for ctx in self._context_stack:
            context.update(ctx)
        return context

    def get_operation_stats(self, operation_name: str) -> dict[str, Any]:
        """Get performance statistics for an operation."""
        timings = self._operation_timings.get(operation_name, [])
        if not timings:
            return {"operation_name": operation_name, "call_count": 0}

        return {
            "operation_name": operation_name,
            "call_count": len(timings),
            "avg_duration": sum(timings) / len(timings),
            "min_duration": min(timings),
            "max_duration": max(timings),
            "total_duration": sum(timings),
        }

    def get_all_operation_stats(self) -> dict[str, dict[str, Any]]:
        """Get performance statistics for all operations."""
        return {
            operation: self.get_operation_stats(operation)
            for operation in self._operation_timings
        }


# =====================================================================================
# STRUCTURED LOGGER
# =====================================================================================


class StructuredLogger:
    """
    Enhanced structured logger with rich functionality.

    Provides comprehensive logging capabilities with context management,
    performance tracking, and security features.

    Design Features:
    - Pure Python implementation
    - Rich context management
    - Performance monitoring
    - Security filtering
    - Multiple output formats
    - Error handling and recovery
    """

    def __init__(self, name: str, config: LogConfig):
        """
        Initialize structured logger.

        Args:
            name: Logger name
            config: Logging configuration
        """
        self.name = name
        self.config = config
        self.context = LoggingContext()

        # Initialize filters
        self.filters: list[LogFilter] = []
        if config.enable_sensitive_data_filtering:
            self.filters.append(SensitiveDataFilter(preserve_length=True))
        if config.truncate_long_messages:
            self.filters.append(MessageLengthFilter(config.max_message_length))

        # Get structlog logger
        self._logger = structlog.get_logger(name)

        # Performance tracking
        self._log_count = 0
        self._error_count = 0
        self._last_log_time: datetime | None = None

    def debug(self, message: str, **kwargs: Any) -> None:
        """Log debug message."""
        self._log(LogLevel.DEBUG, message, **kwargs)

    def info(self, message: str, **kwargs: Any) -> None:
        """Log info message."""
        self._log(LogLevel.INFO, message, **kwargs)

    def warning(self, message: str, **kwargs: Any) -> None:
        """Log warning message."""
        self._log(LogLevel.WARNING, message, **kwargs)

    def error(self, message: str, **kwargs: Any) -> None:
        """Log error message."""
        self._log(LogLevel.ERROR, message, **kwargs)
        self._error_count += 1

    def critical(self, message: str, **kwargs: Any) -> None:
        """Log critical message."""
        self._log(LogLevel.CRITICAL, message, **kwargs)
        self._error_count += 1

    def exception(self, message: str, **kwargs: Any) -> None:
        """Log exception with traceback."""
        kwargs["exc_info"] = True
        self.error(message, **kwargs)

    def _log(self, level: LogLevel, message: str, **kwargs: Any) -> None:
        """Internal logging method with filtering and context."""
        if level.priority < self.config.level.priority:
            return

        # Prepare log record
        record = {
            "message": message,
            "level": level.level_name,
            "logger": self.name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **kwargs,
        }

        # Add context
        if self.config.enable_context_tracking:
            try:
                record.update(self.context.get_current_context())
            except Exception as e:
                # Don't fail logging due to context issues
                record["context_error"] = str(e)

        # Apply filters
        for filter_instance in self.filters:
            try:
                if filter_instance.should_skip(record):
                    return
                record = filter_instance.filter(record)
            except Exception as e:
                # Don't fail logging due to filter issues
                record["filter_error"] = str(e)
                break

        # Log the record
        try:
            getattr(self._logger, level.level_name.lower())(
                message, **{k: v for k, v in record.items() if k != "message"}
            )
            self._log_count += 1
            self._last_log_time = datetime.now(timezone.utc)
            
            # Track metrics
            try:
                metrics.log_events.labels(level=level.level_name.lower()).inc()
            except Exception:
                pass  # Don't fail logging for metrics
                
        except Exception as e:
            # Fallback to basic logging if structured logging fails
            with suppress(Exception):
                metrics.log_errors.inc()
            
            fallback_logger = logging.getLogger(self.name)
            fallback_logger.exception("Structured logging failed: %s", str(e))
            fallback_logger.log(level.to_logging_level(), message)

    def get_stats(self) -> dict[str, Any]:
        """Get logger performance statistics."""
        return {
            "logger_name": self.name,
            "log_count": self._log_count,
            "error_count": self._error_count,
            "error_rate": self._error_count / max(self._log_count, 1),
            "last_log_time": self._last_log_time.isoformat()
            if self._last_log_time
            else None,
            "operation_stats": self.context.get_all_operation_stats(),
        }


# =====================================================================================
# LOGGER FACTORY
# =====================================================================================


class LoggerFactory:
    """
    Factory for creating and managing structured loggers.

    Provides centralized logger creation and configuration management
    with caching and performance optimization.
    """

    def __init__(self, config: LogConfig):
        """Initialize logger factory."""
        self.config = config
        self._loggers: dict[str, StructuredLogger] = {}
        self._configured = False

    def configure_logging(self) -> None:
        """Configure global logging settings."""
        if self._configured:
            return

        # Configure structlog
        processors = [
            merge_contextvars,
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
        ]

        if self.config.enable_timestamps:
            processors.append(structlog.processors.TimeStamper(fmt="iso"))

        if self.config.enable_caller_info:
            processors.append(
                structlog.processors.CallsiteParameterAdder(
                    parameters=[
                        structlog.processors.CallsiteParameter.FILENAME,
                        structlog.processors.CallsiteParameter.LINENO,
                        structlog.processors.CallsiteParameter.FUNC_NAME,
                    ]
                )
            )

        if self.config.enable_exception_info:
            processors.extend(
                [
                    structlog.processors.StackInfoRenderer(),
                    structlog.processors.format_exc_info,
                ]
            )

        processors.extend(
            [
                structlog.processors.UnicodeDecoder(),
                structlog.processors.dict_tracebacks,
            ]
        )

        # Add final renderer based on format
        if self.config.format == LogFormat.JSON:
            processors.append(structlog.processors.JSONRenderer())
        elif self.config.format == LogFormat.CONSOLE:
            processors.append(structlog.dev.ConsoleRenderer(colors=True))
        else:
            processors.append(structlog.processors.KeyValueRenderer())

        structlog.configure(
            processors=processors,
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )

        # Configure standard logging
        logging.basicConfig(
            format="%(message)s",
            stream=sys.stdout,
            level=self.config.level.to_logging_level(),
        )

        # Suppress noisy loggers based on environment
        if self.config.environment == Environment.PRODUCTION:
            logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
            logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
            logging.getLogger("httpx").setLevel(logging.WARNING)

        self._configured = True

    def get_logger(self, name: str) -> StructuredLogger:
        """Get or create structured logger."""
        if not self._configured:
            self.configure_logging()

        if name not in self._loggers:
            self._loggers[name] = StructuredLogger(name, self.config)

        return self._loggers[name]

    def get_all_logger_stats(self) -> dict[str, dict[str, Any]]:
        """Get statistics for all loggers."""
        return {name: logger.get_stats() for name, logger in self._loggers.items()}


# =====================================================================================
# GLOBAL CONFIGURATION AND FACTORY
# =====================================================================================

# Global logger factory (initialized by application)
_logger_factory: LoggerFactory | None = None


def configure_logging(config: LogConfig | None = None) -> None:
    """
    Configure global logging system.

    Args:
        config: Logging configuration (uses defaults if not provided)
    """
    global _logger_factory  # noqa: PLW0603 - Required to initialize global factory

    if config is None:
        # Try to get configuration from settings
        try:
            from app.core.config import settings

            config = LogConfig(
                level=LogLevel.from_string(settings.log_level.value),
                environment=Environment(settings.environment.value),
                enable_file_output=settings.environment == Environment.PRODUCTION,
            )
        except (ImportError, AttributeError):
            # Fallback to default configuration
            config = LogConfig()

    _logger_factory = LoggerFactory(config)
    _logger_factory.configure_logging()


def get_logger(name: str) -> StructuredLogger:
    """
    Get structured logger instance.

    Args:
        name: Logger name (usually __name__)

    Returns:
        StructuredLogger: Configured logger instance
    """
    if _logger_factory is None:
        configure_logging()

    return _logger_factory.get_logger(name)


def get_logging_stats() -> dict[str, Any]:
    """
    Get comprehensive logging statistics.

    Returns:
        dict[str, Any]: Logging system statistics
    """
    if _logger_factory is None:
        return {"error": "Logging not configured"}

    return {
        "configuration": _logger_factory.config.to_dict(),
        "logger_stats": _logger_factory.get_all_logger_stats(),
        "system_stats": {
            "configured": _logger_factory._configured,
            "total_loggers": len(_logger_factory._loggers),
        },
    }


# =====================================================================================
# CONVENIENCE FUNCTIONS
# =====================================================================================


def log_context(**kwargs: Any) -> None:
    """Add context variables to all subsequent logs in this context."""
    structlog.contextvars.bind_contextvars(**kwargs)


def clear_context() -> None:
    """Clear all context variables."""
    structlog.contextvars.clear_contextvars()


def log_performance(operation_name: str):
    """Decorator for logging operation performance."""

    def decorator(func):
        logger = get_logger(func.__module__)

        def wrapper(*args, **kwargs):
            with logger.context.operation_context(operation_name):
                return func(*args, **kwargs)

        return wrapper

    return decorator


# =====================================================================================
# EXPORTS
# =====================================================================================

__all__ = [
    "Environment",
    # Configuration
    "LogConfig",
    # Filters
    "LogFilter",
    "LogFormat",
    "LogLevel",
    "LoggerFactory",
    "LoggingContext",
    "MessageLengthFilter",
    "SensitiveDataFilter",
    # Core classes
    "StructuredLogger",
    "clear_context",
    # Factory functions
    "configure_logging",
    "get_logger",
    "get_logging_stats",
    # Convenience functions
    "log_context",
    "log_performance",
]
