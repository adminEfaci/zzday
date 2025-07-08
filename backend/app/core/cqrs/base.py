"""CQRS base classes following pure Python principles.

This module provides a comprehensive Command Query Responsibility Segregation (CQRS)
implementation that follows clean architecture principles with pure Python classes,
completely independent of any framework.

CQRS separates read and write operations to optimize performance, scalability,
and maintainability. This implementation provides framework-agnostic command
and query handling with rich functionality.

Design Principles:
- Pure Python classes with explicit __init__ validation
- Framework-agnostic design for maximum portability
- Clean separation of commands (writes) and queries (reads)
- Rich functionality with comprehensive error handling
- Performance monitoring and metrics collection
- Clean bus implementation without framework magic
- Comprehensive logging and debugging support

Architecture:
- Command: Represents an intent to change system state
- Query: Represents a request for information
- CommandHandler: Processes commands and returns results
- QueryHandler: Processes queries and returns data
- CommandBus/QueryBus: Route messages to appropriate handlers
- Result types: Standardized response handling
"""

import time
from abc import ABC, abstractmethod
from collections.abc import Callable
from datetime import datetime
from typing import Any, Generic, TypeVar
from uuid import UUID, uuid4

from app.core.errors import ConfigurationError, ValidationError
from app.core.logging import get_logger

logger = get_logger(__name__)

# Type variables for CQRS components
TCommand = TypeVar("TCommand", bound="Command")
TQuery = TypeVar("TQuery", bound="Query")
TResult = TypeVar("TResult")
THandler = TypeVar("THandler")


# =====================================================================================
# RESULT TYPES
# =====================================================================================


class CommandResult(Generic[TResult]):
    """
    Standardized command result wrapper.
    
    Provides consistent result handling for command operations with
    success/failure status, data, and error information.
    """
    
    def __init__(
        self,
        success: bool,
        data: TResult | None = None,
        error: str | None = None,
        error_code: str | None = None,
        metadata: dict[str, Any] | None = None
    ):
        self.success = success
        self.data = data
        self.error = error
        self.error_code = error_code
        self.metadata = metadata or {}
        self.timestamp = datetime.utcnow()
    
    @classmethod
    def success_result(cls, data: TResult, metadata: dict[str, Any] | None = None) -> "CommandResult[TResult]":
        """Create successful command result."""
        return cls(success=True, data=data, metadata=metadata)
    
    @classmethod
    def failure_result(
        cls, 
        error: str, 
        error_code: str | None = None,
        metadata: dict[str, Any] | None = None
    ) -> "CommandResult[TResult]":
        """Create failed command result."""
        return cls(success=False, error=error, error_code=error_code, metadata=metadata)
    
    def is_success(self) -> bool:
        """Check if command was successful."""
        return self.success
    
    def is_failure(self) -> bool:
        """Check if command failed."""
        return not self.success
    
    def get_data(self) -> TResult:
        """Get result data, raises exception if failed."""
        if not self.success:
            raise RuntimeError(f"Command failed: {self.error}")
        return self.data
    
    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary."""
        return {
            "success": self.success,
            "data": self.data,
            "error": self.error,
            "error_code": self.error_code,
            "metadata": self.metadata,
            "timestamp": self.timestamp.isoformat()
        }


class QueryResult(Generic[TResult]):
    """
    Standardized query result wrapper with pagination support.
    
    Provides consistent result handling for query operations with
    data, pagination information, and metadata.
    """
    
    def __init__(
        self,
        data: TResult,
        total_count: int | None = None,
        page: int | None = None,
        page_size: int | None = None,
        has_next: bool = False,
        has_previous: bool = False,
        metadata: dict[str, Any] | None = None
    ):
        self.data = data
        self.total_count = total_count
        self.page = page
        self.page_size = page_size
        self.has_next = has_next
        self.has_previous = has_previous
        self.metadata = metadata or {}
        self.timestamp = datetime.utcnow()
    
    @classmethod
    def single_result(cls, data: TResult, metadata: dict[str, Any] | None = None) -> "QueryResult[TResult]":
        """Create result for single item query."""
        return cls(data=data, metadata=metadata)
    
    @classmethod
    def paginated_result(
        cls,
        data: TResult,
        total_count: int,
        page: int,
        page_size: int,
        metadata: dict[str, Any] | None = None
    ) -> "QueryResult[TResult]":
        """Create result for paginated query."""
        has_next = (page * page_size) < total_count
        has_previous = page > 1
        
        return cls(
            data=data,
            total_count=total_count,
            page=page,
            page_size=page_size,
            has_next=has_next,
            has_previous=has_previous,
            metadata=metadata
        )
    
    def get_pagination_info(self) -> dict[str, Any]:
        """Get pagination information."""
        return {
            "total_count": self.total_count,
            "page": self.page,
            "page_size": self.page_size,
            "has_next": self.has_next,
            "has_previous": self.has_previous,
            "total_pages": (self.total_count + self.page_size - 1) // self.page_size if self.total_count and self.page_size else None
        }
    
    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary."""
        result = {
            "data": self.data,
            "metadata": self.metadata,
            "timestamp": self.timestamp.isoformat()
        }
        
        if self.total_count is not None:
            result["pagination"] = self.get_pagination_info()
        
        return result


# =====================================================================================
# COMMAND CLASSES
# =====================================================================================


class Command(ABC):
    """
    Base command class representing an intent to change system state.

    Commands are immutable objects that represent a request to modify the system.
    They capture all necessary information to perform the operation and include
    metadata for tracking and auditing.

    Design Features:
    - Immutable by design (no modification after creation)
    - Rich metadata for tracking and auditing
    - Framework-agnostic validation in __init__
    - Comprehensive error handling
    - Performance tracking capabilities
    - Serialization support for distributed systems

    Usage Example:
        class CreateUserCommand(Command):
            def __init__(self, email: str, name: str, user_id: UUID = None):
                super().__init__()
                self.email = self._validate_email(email)
                self.name = self._validate_name(name)
                self.user_id = user_id or uuid4()
                self._freeze()

            def _validate_email(self, email: str) -> str:
                if not email or "@" not in email:
                    raise ValidationError("Invalid email format")
                return email.lower().strip()
    """

    def __init__(self):
        """
        Initialize command with metadata and validation.

        Sets up command metadata including ID, timestamp, and correlation info
        for tracking and auditing purposes.
        """
        # Command metadata
        self.command_id = uuid4()
        self.created_at = datetime.utcnow()
        self.correlation_id: UUID | None = None
        self.user_id: UUID | None = None
        self.source: str | None = None

        # State management
        self._frozen = False
        self._validated = False

        # Validate command after initialization
        self._validate_command()
        self._validated = True

    def _validate_command(self) -> None:
        """
        Validate command state. Override in subclasses for specific validation.

        Raises:
            ValidationError: If command is in invalid state
        """
        # Base validation - subclasses should override

    def _freeze(self) -> None:
        """Mark the command as frozen (immutable)."""
        self._frozen = True

    def __setattr__(self, name: str, value: Any) -> None:
        """Prevent modification after command is frozen."""
        if (
            hasattr(self, "_frozen")
            and self._frozen
            and name not in ["correlation_id", "user_id", "source"]
        ):
            raise AttributeError(
                f"Cannot modify immutable command {self.__class__.__name__}"
            )
        super().__setattr__(name, value)

    def set_metadata(
        self,
        correlation_id: UUID | None = None,
        user_id: UUID | None = None,
        source: str | None = None,
    ) -> None:
        """
        Set command metadata for tracking and auditing.

        Args:
            correlation_id: Optional correlation ID for request tracking
            user_id: Optional user ID who initiated the command
            source: Optional source system/component name
        """
        if correlation_id is not None:
            self.correlation_id = correlation_id
        if user_id is not None:
            self.user_id = user_id
        if source is not None:
            self.source = source

    def to_dict(self) -> dict[str, Any]:
        """
        Convert command to dictionary for serialization.

        Returns:
            dict[str, Any]: Dictionary representation of the command
        """
        result = {}
        for key, value in self.__dict__.items():
            if not key.startswith("_"):
                if isinstance(value, UUID):
                    result[key] = str(value)
                elif isinstance(value, datetime):
                    result[key] = value.isoformat()
                else:
                    result[key] = value

        result["command_type"] = self.__class__.__name__
        return result

    def __eq__(self, other: Any) -> bool:
        """Check equality based on command ID."""
        if not isinstance(other, Command):
            return False
        return self.command_id == other.command_id

    def __hash__(self) -> int:
        """Return hash based on command ID."""
        return hash(self.command_id)

    def __repr__(self) -> str:
        """Detailed string representation for debugging."""
        return f"{self.__class__.__name__}(id={self.command_id}, created_at={self.created_at})"

    def __str__(self) -> str:
        """String representation for display."""
        return f"{self.__class__.__name__}({self.command_id})"


class Query(ABC):
    """
    Base query class representing a request for information.

    Queries are immutable objects that represent a request to read data from
    the system. They should not modify system state and include criteria
    for filtering and pagination.

    Design Features:
    - Immutable by design
    - Rich criteria and pagination support
    - Framework-agnostic validation
    - Performance tracking
    - Caching support metadata
    - Result formatting options

    Usage Example:
        class GetUserQuery(Query):
            def __init__(self, user_id: UUID, include_profile: bool = False):
                super().__init__()
                self.user_id = self._validate_user_id(user_id)
                self.include_profile = include_profile
                self._freeze()

            def _validate_user_id(self, user_id: UUID) -> UUID:
                if not isinstance(user_id, UUID):
                    raise ValidationError("User ID must be a valid UUID")
                return user_id
    """

    def __init__(self):
        """
        Initialize query with metadata and pagination defaults.
        """
        # Query metadata
        self.query_id = uuid4()
        self.created_at = datetime.utcnow()
        self.correlation_id: UUID | None = None
        self.user_id: UUID | None = None

        # Pagination defaults
        self.page: int = 1
        self.page_size: int = 20
        self.sort_by: str | None = None
        self.sort_direction: str = "asc"

        # Caching metadata
        self.cache_key: str | None = None
        self.cache_ttl: int | None = None

        # State management
        self._frozen = False
        self._validated = False

        # Validate query after initialization
        self._validate_query()
        self._validated = True

    def _validate_query(self) -> None:
        """
        Validate query state. Override in subclasses for specific validation.

        Raises:
            ValidationError: If query is in invalid state
        """
        # Validate pagination
        if self.page < 1:
            raise ValidationError("Page must be positive integer")

        if self.page_size < 1 or self.page_size > 1000:
            raise ValidationError("Page size must be between 1 and 1000")

        if self.sort_direction not in ["asc", "desc"]:
            raise ValidationError("Sort direction must be 'asc' or 'desc'")

    def _freeze(self) -> None:
        """Mark the query as frozen (immutable)."""
        self._frozen = True

    def __setattr__(self, name: str, value: Any) -> None:
        """Prevent modification after query is frozen."""
        if (
            hasattr(self, "_frozen")
            and self._frozen
            and name not in ["correlation_id", "user_id"]
        ):
            raise AttributeError(
                f"Cannot modify immutable query {self.__class__.__name__}"
            )
        super().__setattr__(name, value)

    def set_pagination(
        self,
        page: int = 1,
        page_size: int = 20,
        sort_by: str | None = None,
        sort_direction: str = "asc",
    ) -> None:
        """
        Set pagination parameters before freezing.

        Args:
            page: Page number (1-based)
            page_size: Number of items per page
            sort_by: Field to sort by
            sort_direction: Sort direction ("asc" or "desc")
        """
        if hasattr(self, "_frozen") and self._frozen:
            raise AttributeError("Cannot modify frozen query")

        self.page = page
        self.page_size = page_size
        self.sort_by = sort_by
        self.sort_direction = sort_direction

        # Re-validate after changes
        self._validate_query()

    def set_caching(
        self, cache_key: str | None = None, cache_ttl: int | None = None
    ) -> None:
        """
        Set caching parameters.

        Args:
            cache_key: Custom cache key (auto-generated if not provided)
            cache_ttl: Cache time-to-live in seconds
        """
        if hasattr(self, "_frozen") and self._frozen:
            raise AttributeError("Cannot modify frozen query")

        self.cache_key = cache_key
        self.cache_ttl = cache_ttl

    def to_dict(self) -> dict[str, Any]:
        """Convert query to dictionary for serialization."""
        result = {}
        for key, value in self.__dict__.items():
            if not key.startswith("_"):
                if isinstance(value, UUID):
                    result[key] = str(value)
                elif isinstance(value, datetime):
                    result[key] = value.isoformat()
                else:
                    result[key] = value

        result["query_type"] = self.__class__.__name__
        return result

    def __eq__(self, other: Any) -> bool:
        """Check equality based on query ID."""
        if not isinstance(other, Query):
            return False
        return self.query_id == other.query_id

    def __hash__(self) -> int:
        """Return hash based on query ID."""
        return hash(self.query_id)

    def __repr__(self) -> str:
        """Detailed string representation for debugging."""
        return f"{self.__class__.__name__}(id={self.query_id}, page={self.page}, size={self.page_size})"

    def __str__(self) -> str:
        """String representation for display."""
        return f"{self.__class__.__name__}({self.query_id})"


# =====================================================================================
# HANDLER CLASSES
# =====================================================================================


class CommandHandler(ABC, Generic[TCommand, TResult]):
    """
    Base command handler for processing commands.

    Command handlers contain the business logic for processing commands and
    changing system state. They should be stateless and focused on a single
    command type.

    Design Features:
    - Framework-agnostic implementation
    - Rich error handling and logging
    - Performance monitoring
    - Transaction support integration points
    - Comprehensive validation
    - Result standardization

    Usage Example:
        class CreateUserCommandHandler(CommandHandler[CreateUserCommand, User]):
            def __init__(self, user_repository: UserRepository):
                super().__init__()
                self.user_repository = user_repository

            async def handle(self, command: CreateUserCommand) -> User:
                # Check if user already exists
                existing = await self.user_repository.find_by_email(command.email)
                if existing:
                    raise ConflictError("User already exists")

                # Create new user
                user = User(command.email, command.name, command.user_id)
                await self.user_repository.save(user)
                return user

            @property
            def command_type(self) -> Type[CreateUserCommand]:
                return CreateUserCommand
    """

    def __init__(self):
        """Initialize command handler with performance tracking."""
        self._execution_count = 0
        self._total_execution_time = 0.0
        self._error_count = 0
        self._last_executed = None

    @abstractmethod
    async def handle(self, command: TCommand) -> TResult:
        """
        Handle the command and return result.

        Args:
            command: Command to process

        Returns:
            TResult: Result of command processing

        Raises:
            ApplicationError: If command processing fails
        """

    @property
    @abstractmethod
    def command_type(self) -> type[TCommand]:
        """
        Get the command type this handler processes.

        Returns:
            Type[TCommand]: Command type
        """

    async def execute_with_tracking(self, command: TCommand) -> TResult:
        """
        Execute command with performance tracking and error handling.

        Args:
            command: Command to execute

        Returns:
            TResult: Result of command execution
        """
        start_time = time.time()
        try:
            logger.debug(
                "Executing command",
                command_type=command.__class__.__name__,
                command_id=command.command_id,
                handler=self.__class__.__name__,
            )

            result = await self.handle(command)

            execution_time = time.time() - start_time
            self._execution_count += 1
            self._total_execution_time += execution_time
            self._last_executed = datetime.utcnow()

            logger.info(
                "Command executed successfully",
                command_type=command.__class__.__name__,
                command_id=command.command_id,
                execution_time=execution_time,
            )

            return result

        except Exception as e:
            execution_time = time.time() - start_time
            self._error_count += 1
            self._total_execution_time += execution_time

            logger.exception(
                "Command execution failed",
                command_type=command.__class__.__name__,
                command_id=command.command_id,
                error=str(e),
                execution_time=execution_time,
            )
            raise

    def get_performance_stats(self) -> dict[str, Any]:
        """Get performance statistics for this handler."""
        avg_time = self._total_execution_time / max(self._execution_count, 1)
        return {
            "handler_class": self.__class__.__name__,
            "command_type": self.command_type.__name__,
            "execution_count": self._execution_count,
            "error_count": self._error_count,
            "total_execution_time": self._total_execution_time,
            "average_execution_time": avg_time,
            "last_executed": self._last_executed.isoformat()
            if self._last_executed
            else None,
            "error_rate": self._error_count / max(self._execution_count, 1),
        }


class QueryHandler(ABC, Generic[TQuery, TResult]):
    """
    Base query handler for processing queries.

    Query handlers contain the logic for retrieving and formatting data.
    They should not modify system state and may include caching logic.

    Design Features:
    - Framework-agnostic implementation
    - Caching support integration
    - Performance monitoring
    - Result formatting and pagination
    - Comprehensive error handling
    - Read-only validation

    Usage Example:
        class GetUserQueryHandler(QueryHandler[GetUserQuery, User]):
            def __init__(self, user_repository: UserRepository):
                super().__init__()
                self.user_repository = user_repository

            async def handle(self, query: GetUserQuery) -> User:
                user = await self.user_repository.find_by_id(query.user_id)
                if not user:
                    raise NotFoundError("User not found")
                return user

            @property
            def query_type(self) -> Type[GetUserQuery]:
                return GetUserQuery
    """

    def __init__(self):
        """Initialize query handler with performance tracking."""
        self._execution_count = 0
        self._total_execution_time = 0.0
        self._cache_hits = 0
        self._cache_misses = 0
        self._last_executed = None

    @abstractmethod
    async def handle(self, query: TQuery) -> TResult:
        """
        Handle the query and return result.

        Args:
            query: Query to process

        Returns:
            TResult: Query result

        Raises:
            ApplicationError: If query processing fails
        """

    @property
    @abstractmethod
    def query_type(self) -> type[TQuery]:
        """
        Get the query type this handler processes.

        Returns:
            Type[TQuery]: Query type
        """

    async def execute_with_tracking(self, query: TQuery) -> TResult:
        """
        Execute query with performance tracking and caching support.

        Args:
            query: Query to execute

        Returns:
            TResult: Query result
        """
        start_time = time.time()
        try:
            logger.debug(
                "Executing query",
                query_type=query.__class__.__name__,
                query_id=query.query_id,
                handler=self.__class__.__name__,
            )

            result = await self.handle(query)

            execution_time = time.time() - start_time
            self._execution_count += 1
            self._total_execution_time += execution_time
            self._last_executed = datetime.utcnow()

            logger.debug(
                "Query executed successfully",
                query_type=query.__class__.__name__,
                query_id=query.query_id,
                execution_time=execution_time,
            )

            return result

        except Exception as e:
            execution_time = time.time() - start_time
            self._total_execution_time += execution_time

            logger.exception(
                "Query execution failed",
                query_type=query.__class__.__name__,
                query_id=query.query_id,
                error=str(e),
                execution_time=execution_time,
            )
            raise

    def record_cache_hit(self) -> None:
        """Record a cache hit for performance tracking."""
        self._cache_hits += 1

    def record_cache_miss(self) -> None:
        """Record a cache miss for performance tracking."""
        self._cache_misses += 1

    def get_performance_stats(self) -> dict[str, Any]:
        """Get performance statistics for this handler."""
        avg_time = self._total_execution_time / max(self._execution_count, 1)
        cache_hit_rate = self._cache_hits / max(
            self._cache_hits + self._cache_misses, 1
        )

        return {
            "handler_class": self.__class__.__name__,
            "query_type": self.query_type.__name__,
            "execution_count": self._execution_count,
            "total_execution_time": self._total_execution_time,
            "average_execution_time": avg_time,
            "cache_hits": self._cache_hits,
            "cache_misses": self._cache_misses,
            "cache_hit_rate": cache_hit_rate,
            "last_executed": self._last_executed.isoformat()
            if self._last_executed
            else None,
        }


# =====================================================================================
# BUS CLASSES
# =====================================================================================


class CommandBus:
    """
    Command bus for routing commands to appropriate handlers.

    Provides centralized command routing with comprehensive error handling,
    middleware support, and performance monitoring.

    Design Features:
    - Framework-agnostic handler registration
    - Middleware pipeline support
    - Performance monitoring and metrics
    - Comprehensive error handling
    - Transaction integration points
    - Dead letter queue support
    """

    def __init__(self):
        """Initialize command bus with empty handler registry."""
        self._handlers: dict[type[Command], CommandHandler] = {}
        self._middleware: list[Callable] = []
        self._metrics = {
            "total_commands": 0,
            "successful_commands": 0,
            "failed_commands": 0,
            "total_execution_time": 0.0,
        }

    def register(self, handler: CommandHandler) -> None:
        """
        Register a command handler.

        Args:
            handler: Command handler to register

        Raises:
            ConfigurationError: If handler is already registered for command type
        """
        command_type = handler.command_type

        if command_type in self._handlers:
            raise ConfigurationError(
                f"Handler already registered for command type {command_type.__name__}"
            )

        self._handlers[command_type] = handler

        logger.debug(
            "Command handler registered",
            command_type=command_type.__name__,
            handler=handler.__class__.__name__,
        )

    def unregister(self, command_type: type[Command]) -> None:
        """
        Unregister a command handler.

        Args:
            command_type: Command type to unregister
        """
        if command_type in self._handlers:
            del self._handlers[command_type]
            logger.debug(
                "Command handler unregistered", command_type=command_type.__name__
            )

    async def execute(self, command: Command) -> Any:
        """
        Execute a command by routing to appropriate handler.

        Args:
            command: Command to execute

        Returns:
            Any: Result from command handler

        Raises:
            ConfigurationError: If no handler registered for command type
            ApplicationError: If command execution fails
        """
        start_time = time.time()
        handler = self._handlers.get(type(command))

        if not handler:
            raise ConfigurationError(
                f"No handler registered for command type {type(command).__name__}"
            )

        self._metrics["total_commands"] += 1

        try:
            logger.info(
                "Executing command",
                command_type=type(command).__name__,
                command_id=command.command_id,
                handler=handler.__class__.__name__,
            )

            # Execute through middleware pipeline if any
            result = await self._execute_with_middleware(handler, command)

            execution_time = time.time() - start_time
            self._metrics["successful_commands"] += 1
            self._metrics["total_execution_time"] += execution_time

            logger.info(
                "Command executed successfully",
                command_type=type(command).__name__,
                command_id=command.command_id,
                execution_time=execution_time,
            )

            return result

        except Exception as e:
            execution_time = time.time() - start_time
            self._metrics["failed_commands"] += 1
            self._metrics["total_execution_time"] += execution_time

            logger.exception(
                "Command execution failed",
                command_type=type(command).__name__,
                command_id=command.command_id,
                error=str(e),
                execution_time=execution_time,
            )
            raise

    async def _execute_with_middleware(
        self, handler: CommandHandler, command: Command
    ) -> Any:
        """Execute command through middleware pipeline."""
        if not self._middleware:
            return await handler.execute_with_tracking(command)

        # Build middleware pipeline
        async def pipeline():
            return await handler.execute_with_tracking(command)

        # Apply middleware in reverse order
        for middleware in reversed(self._middleware):
            current_pipeline = pipeline

            def pipeline():
                return middleware(command, current_pipeline)

        return await pipeline()

    def add_middleware(self, middleware: Callable) -> None:
        """
        Add middleware to the command processing pipeline.

        Args:
            middleware: Middleware function
        """
        self._middleware.append(middleware)

    def get_metrics(self) -> dict[str, Any]:
        """Get command bus performance metrics."""
        return {
            "registered_handlers": len(self._handlers),
            "handler_types": [h.command_type.__name__ for h in self._handlers.values()],
            "middleware_count": len(self._middleware),
            **self._metrics,
            "average_execution_time": (
                self._metrics["total_execution_time"]
                / max(self._metrics["total_commands"], 1)
            ),
            "success_rate": (
                self._metrics["successful_commands"]
                / max(self._metrics["total_commands"], 1)
            ),
        }

    def get_handler_stats(self) -> dict[str, Any]:
        """Get performance statistics for all registered handlers."""
        return {
            command_type.__name__: handler.get_performance_stats()
            for command_type, handler in self._handlers.items()
        }


class QueryBus:
    """
    Query bus for routing queries to appropriate handlers.

    Provides centralized query routing with caching support, performance
    monitoring, and comprehensive error handling.

    Design Features:
    - Framework-agnostic handler registration
    - Built-in caching support
    - Performance monitoring
    - Read-only validation
    - Comprehensive error handling
    - Result formatting support
    """

    def __init__(self):
        """Initialize query bus with empty handler registry."""
        self._handlers: dict[type[Query], QueryHandler] = {}
        self._cache: Any | None = None  # Cache implementation can be injected
        self._metrics = {
            "total_queries": 0,
            "successful_queries": 0,
            "failed_queries": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "total_execution_time": 0.0,
        }

    def register(self, handler: QueryHandler) -> None:
        """
        Register a query handler.

        Args:
            handler: Query handler to register

        Raises:
            ConfigurationError: If handler is already registered for query type
        """
        query_type = handler.query_type

        if query_type in self._handlers:
            raise ConfigurationError(
                f"Handler already registered for query type {query_type.__name__}"
            )

        self._handlers[query_type] = handler

        logger.debug(
            "Query handler registered",
            query_type=query_type.__name__,
            handler=handler.__class__.__name__,
        )

    def set_cache(self, cache: Any) -> None:
        """
        Set cache implementation for query results.

        Args:
            cache: Cache implementation (must support get/set methods)
        """
        self._cache = cache

    async def execute(self, query: Query) -> Any:
        """
        Execute a query by routing to appropriate handler.

        Args:
            query: Query to execute

        Returns:
            Any: Query result

        Raises:
            ConfigurationError: If no handler registered for query type
            ApplicationError: If query execution fails
        """
        start_time = time.time()
        handler = self._handlers.get(type(query))

        if not handler:
            raise ConfigurationError(
                f"No handler registered for query type {type(query).__name__}"
            )

        self._metrics["total_queries"] += 1

        # Check cache first if available
        if self._cache and query.cache_key:
            cached_result = await self._get_from_cache(query.cache_key)
            if cached_result is not None:
                self._metrics["cache_hits"] += 1
                handler.record_cache_hit()
                logger.debug(
                    "Query result returned from cache",
                    query_type=type(query).__name__,
                    cache_key=query.cache_key,
                )
                return cached_result
            self._metrics["cache_misses"] += 1
            handler.record_cache_miss()

        try:
            logger.debug(
                "Executing query",
                query_type=type(query).__name__,
                query_id=query.query_id,
                handler=handler.__class__.__name__,
            )

            result = await handler.execute_with_tracking(query)

            # Cache result if caching is configured
            if self._cache and query.cache_key:
                await self._set_cache(query.cache_key, result, query.cache_ttl)

            execution_time = time.time() - start_time
            self._metrics["successful_queries"] += 1
            self._metrics["total_execution_time"] += execution_time

            return result

        except Exception as e:
            execution_time = time.time() - start_time
            self._metrics["failed_queries"] += 1
            self._metrics["total_execution_time"] += execution_time

            logger.exception(
                "Query execution failed",
                query_type=type(query).__name__,
                query_id=query.query_id,
                error=str(e),
                execution_time=execution_time,
            )
            raise

    async def _get_from_cache(self, cache_key: str) -> Any:
        """Get result from cache."""
        if hasattr(self._cache, "get"):
            return await self._cache.get(cache_key)
        return None

    async def _set_cache(
        self, cache_key: str, result: Any, ttl: int | None = None
    ) -> None:
        """Set result in cache."""
        if hasattr(self._cache, "set"):
            if ttl:
                await self._cache.set(cache_key, result, ttl)
            else:
                await self._cache.set(cache_key, result)

    def get_metrics(self) -> dict[str, Any]:
        """Get query bus performance metrics."""
        cache_hit_rate = self._metrics["cache_hits"] / max(
            self._metrics["cache_hits"] + self._metrics["cache_misses"], 1
        )

        return {
            "registered_handlers": len(self._handlers),
            "handler_types": [h.query_type.__name__ for h in self._handlers.values()],
            "cache_enabled": self._cache is not None,
            "cache_hit_rate": cache_hit_rate,
            **self._metrics,
            "average_execution_time": (
                self._metrics["total_execution_time"]
                / max(self._metrics["total_queries"], 1)
            ),
            "success_rate": (
                self._metrics["successful_queries"]
                / max(self._metrics["total_queries"], 1)
            ),
        }

    def get_handler_stats(self) -> dict[str, Any]:
        """Get performance statistics for all registered handlers."""
        return {
            query_type.__name__: handler.get_performance_stats()
            for query_type, handler in self._handlers.items()
        }


# =====================================================================================
# EXPORTS
# =====================================================================================

__all__ = [
    # Base classes
    "Command",
    # Bus classes
    "CommandBus",
    # Handler classes
    "CommandHandler",
    # Result classes
    "CommandResult",
    "Query",
    "QueryBus",
    "QueryHandler",
    "QueryResult",
    # Type variables
    "TCommand",
    "THandler",
    "TQuery",
    "TResult",
]
