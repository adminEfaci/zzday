"""
Task Infrastructure Base Classes for EzzDay Core

This module provides a comprehensive task execution framework supporting
asynchronous task processing, sophisticated retry mechanisms, lifecycle
management, and comprehensive monitoring. Designed for high-performance
background job processing with reliability guarantees.

Key Features:
- Pure Python task definitions (no framework coupling)
- Sophisticated retry policies with exponential backoff
- Comprehensive task lifecycle management and monitoring
- Resource allocation and cleanup mechanisms
- Task dependency and prerequisite management
- Performance metrics and execution tracking
- Context propagation for distributed tracing

Design Principles:
- Pure Python domain logic (no framework coupling)
- Explicit validation and error handling
- Comprehensive lifecycle management
- Performance-oriented with monitoring integration
- Extensible architecture for custom task types

Usage Examples:
    # Basic task implementation
    class EmailNotificationTask(AsyncTask):
        name = "send_email_notification"
        description = "Send email notification to users"
        max_retries = 3
        
        async def execute(self, user_id: str, message: str) -> dict[str, Any]:
            # Task implementation
            email_service = self.get_dependency("email_service")
            result = await email_service.send(user_id, message)
            return {"email_id": result.id, "status": "sent"}
    
    # Task execution with context
    context = TaskContext(
        task_id=uuid4(),
        user_id=user_id,
        correlation_id="req-123"
    )
    
    task = EmailNotificationTask(context)
    result = await task.run(
        user_id="user-456",
        message="Welcome to EzzDay!"
    )
    
    # Advanced task with dependencies
    class DataProcessingTask(AsyncTask):
        name = "process_user_data"
        dependencies = ["database", "redis_cache", "file_storage"]
        resource_requirements = ResourceRequirements(
            memory_mb=512,
            cpu_cores=2,
            max_execution_time=300
        )
        
        async def execute(self, data_file: str) -> ProcessingResult:
            # Complex data processing logic
            pass

Error Handling:
    - TaskError: Base exception for task-related errors
    - TaskValidationError: Invalid task configuration or input
    - TaskExecutionError: Task execution failures
    - TaskTimeoutError: Task execution timeout
    - TaskDependencyError: Missing or failed dependencies

Performance Features:
    - Efficient task state management
    - Resource usage monitoring and limits
    - Execution time tracking and optimization
    - Memory-efficient result storage
    - Concurrent task execution support
"""

import asyncio
import time
import traceback
from abc import ABC, abstractmethod
from collections.abc import Callable
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from app.core.errors import ValidationError
from app.core.logging import get_logger
from app.core.monitoring import metrics

logger = get_logger(__name__)


class TaskError(Exception):
    """Base exception for task-related errors."""


class TaskValidationError(ValidationError):
    """Raised when task configuration or input is invalid."""


class TaskExecutionError(TaskError):
    """Raised when task execution fails."""


class TaskTimeoutError(TaskError):
    """Raised when task execution exceeds timeout."""


class TaskDependencyError(TaskError):
    """Raised when task dependencies are missing or failed."""


class TaskStatus(str, Enum):
    """
    Task execution status with comprehensive lifecycle states.

    State transitions:
    PENDING -> RUNNING -> {COMPLETED, FAILED, CANCELLED}
    FAILED -> RETRYING -> RUNNING -> {COMPLETED, FAILED}
    Any state -> CANCELLED (with proper cleanup)
    """

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    RETRYING = "retrying"
    TIMEOUT = "timeout"


class TaskPriority(str, Enum):
    """Task execution priority levels."""

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


class RetryPolicy:
    """
    Sophisticated retry policy configuration for task execution.

    Supports multiple retry strategies including exponential backoff,
    linear backoff, and custom retry functions. Provides fine-grained
    control over retry behavior based on error types and conditions.

    Features:
    - Multiple backoff strategies (exponential, linear, constant)
    - Error-specific retry policies
    - Maximum retry limits and time bounds
    - Custom retry condition functions
    - Jitter support for distributed systems

    Usage Examples:
        # Exponential backoff with jitter
        policy = RetryPolicy(
            max_retries=5,
            initial_delay=1.0,
            backoff_strategy="exponential",
            backoff_multiplier=2.0,
            max_delay=60.0,
            jitter=True
        )

        # Error-specific retry policy
        policy = RetryPolicy(
            max_retries=3,
            retry_on_errors=[ConnectionError, TimeoutError],
            no_retry_on_errors=[ValidationError]
        )
    """

    def __init__(
        self,
        max_retries: int = 3,
        initial_delay: float = 1.0,
        backoff_strategy: str = "exponential",
        backoff_multiplier: float = 2.0,
        max_delay: float = 300.0,
        jitter: bool = False,
        retry_on_errors: list[type] | None = None,
        no_retry_on_errors: list[type] | None = None,
    ):
        """
        Initialize retry policy with comprehensive configuration.

        Args:
            max_retries: Maximum number of retry attempts
            initial_delay: Initial delay between retries in seconds
            backoff_strategy: Strategy for delay calculation (exponential, linear, constant)
            backoff_multiplier: Multiplier for exponential/linear backoff
            max_delay: Maximum delay between retries
            jitter: Add random jitter to prevent thundering herd
            retry_on_errors: Specific error types that should trigger retries
            no_retry_on_errors: Error types that should never be retried

        Raises:
            TaskValidationError: If configuration is invalid
        """
        self._validate_policy_configuration(
            max_retries, initial_delay, backoff_strategy, backoff_multiplier, max_delay
        )

        self.max_retries = max_retries
        self.initial_delay = initial_delay
        self.backoff_strategy = backoff_strategy
        self.backoff_multiplier = backoff_multiplier
        self.max_delay = max_delay
        self.jitter = jitter
        self.retry_on_errors = set(retry_on_errors or [])
        self.no_retry_on_errors = set(no_retry_on_errors or [])

    def _validate_policy_configuration(
        self,
        max_retries: int,
        initial_delay: float,
        backoff_strategy: str,
        backoff_multiplier: float,
        max_delay: float,
    ) -> None:
        """Validate retry policy configuration."""
        if max_retries < 0:
            raise TaskValidationError("max_retries must be non-negative")

        if initial_delay < 0:
            raise TaskValidationError("initial_delay must be non-negative")

        if backoff_strategy not in ["exponential", "linear", "constant"]:
            raise TaskValidationError(
                f"Invalid backoff_strategy: {backoff_strategy}. "
                f"Must be one of: exponential, linear, constant"
            )

        if backoff_multiplier <= 0:
            raise TaskValidationError("backoff_multiplier must be positive")

        if max_delay < initial_delay:
            raise TaskValidationError("max_delay must be >= initial_delay")

    def should_retry(self, error: Exception, retry_count: int) -> bool:
        """
        Determine if task should be retried based on error and attempt count.

        Args:
            error: The exception that caused the failure
            retry_count: Current number of retry attempts

        Returns:
            True if task should be retried, False otherwise
        """
        # Check retry count limit
        if retry_count >= self.max_retries:
            return False

        # Check no-retry error list
        if self.no_retry_on_errors:
            for error_type in self.no_retry_on_errors:
                if isinstance(error, error_type):
                    return False

        # Check retry-on error list
        if self.retry_on_errors:
            for error_type in self.retry_on_errors:
                if isinstance(error, error_type):
                    return True
            return False  # Only retry on specified errors

        # Default: retry on most errors except validation errors
        return not isinstance(error, TaskValidationError | TaskDependencyError)

    def calculate_delay(self, retry_count: int) -> float:
        """
        Calculate delay for next retry attempt.

        Args:
            retry_count: Current retry attempt number (0-based)

        Returns:
            Delay in seconds before next retry
        """
        if self.backoff_strategy == "constant":
            delay = self.initial_delay
        elif self.backoff_strategy == "linear":
            delay = self.initial_delay * (1 + retry_count * self.backoff_multiplier)
        else:  # exponential
            delay = self.initial_delay * (self.backoff_multiplier**retry_count)

        # Apply max delay limit
        delay = min(delay, self.max_delay)

        # Add jitter if enabled
        if self.jitter:
            import random

            jitter_amount = delay * 0.1  # 10% jitter
            delay += random.uniform(-jitter_amount, jitter_amount)
            delay = max(0, delay)  # Ensure non-negative

        return delay


class ResourceRequirements:
    """
    Resource requirements specification for task execution.

    Defines computational and memory resources needed for task execution.
    Used by task schedulers for resource allocation and admission control.

    Features:
    - Memory and CPU requirements specification
    - Execution time limits and deadlines
    - Custom resource type support
    - Resource validation and constraint checking

    Usage Examples:
        # Basic resource requirements
        requirements = ResourceRequirements(
            memory_mb=256,
            cpu_cores=1,
            max_execution_time=120
        )

        # Advanced requirements with custom resources
        requirements = ResourceRequirements(
            memory_mb=1024,
            cpu_cores=4,
            max_execution_time=600,
            custom_resources={"gpu_memory_mb": 2048, "disk_space_mb": 5000}
        )
    """

    def __init__(
        self,
        memory_mb: int = 128,
        cpu_cores: float = 0.5,
        max_execution_time: int = 300,
        network_bandwidth_mbps: float | None = None,
        custom_resources: dict[str, Any] | None = None,
    ):
        """
        Initialize resource requirements.

        Args:
            memory_mb: Required memory in megabytes
            cpu_cores: Required CPU cores (can be fractional)
            max_execution_time: Maximum execution time in seconds
            network_bandwidth_mbps: Required network bandwidth
            custom_resources: Additional custom resource requirements

        Raises:
            TaskValidationError: If resource requirements are invalid
        """
        self._validate_requirements(memory_mb, cpu_cores, max_execution_time)

        self.memory_mb = memory_mb
        self.cpu_cores = cpu_cores
        self.max_execution_time = max_execution_time
        self.network_bandwidth_mbps = network_bandwidth_mbps
        self.custom_resources = custom_resources or {}

    def _validate_requirements(
        self, memory_mb: int, cpu_cores: float, max_execution_time: int
    ) -> None:
        """Validate resource requirements."""
        if memory_mb <= 0:
            raise TaskValidationError("memory_mb must be positive")

        if cpu_cores <= 0:
            raise TaskValidationError("cpu_cores must be positive")

        if max_execution_time <= 0:
            raise TaskValidationError("max_execution_time must be positive")

    def to_dict(self) -> dict[str, Any]:
        """Convert requirements to dictionary representation."""
        return {
            "memory_mb": self.memory_mb,
            "cpu_cores": self.cpu_cores,
            "max_execution_time": self.max_execution_time,
            "network_bandwidth_mbps": self.network_bandwidth_mbps,
            "custom_resources": self.custom_resources.copy(),
        }


class TaskResult:
    """
    Comprehensive task execution result with detailed metadata.

    Contains complete information about task execution including timing,
    resource usage, errors, and custom metadata. Designed for monitoring,
    debugging, and performance analysis.

    Features:
    - Complete execution lifecycle tracking
    - Resource usage metrics
    - Detailed error information with stack traces
    - Custom metadata support
    - Serialization for persistence and transmission

    Usage Examples:
        # Successful task result
        result = TaskResult(
            task_id=task_id,
            name="data_processing",
            status=TaskStatus.COMPLETED,
            result={"processed_records": 1000}
        )

        # Failed task result with error details
        result = TaskResult(
            task_id=task_id,
            name="email_sending",
            status=TaskStatus.FAILED,
            error="SMTP connection failed",
            error_details={"smtp_error_code": 421}
        )
    """

    def __init__(
        self,
        task_id: UUID,
        name: str,
        status: TaskStatus,
        result: Any | None = None,
        error: str | None = None,
        error_details: dict[str, Any] | None = None,
        started_at: datetime | None = None,
        completed_at: datetime | None = None,
        retry_count: int = 0,
        metadata: dict[str, Any] | None = None,
    ):
        """
        Initialize task result with execution details.

        Args:
            task_id: Unique task identifier
            name: Task name for identification
            status: Current task execution status
            result: Task execution result data
            error: Error message if task failed
            error_details: Additional error context and details
            started_at: Task execution start time
            completed_at: Task execution completion time
            retry_count: Number of retry attempts made
            metadata: Additional custom metadata
        """
        self._validate_result_data(task_id, name, status)

        self.task_id = task_id
        self.name = name
        self.status = status
        self.result = result
        self.error = error
        self.error_details = error_details or {}
        self.started_at = started_at
        self.completed_at = completed_at
        self.retry_count = retry_count
        self.metadata = metadata or {}

        # Derived properties
        self._duration_seconds: float | None = None
        self._resource_usage: dict[str, Any] = {}

    def _validate_result_data(
        self, task_id: UUID, name: str, status: TaskStatus
    ) -> None:
        """Validate task result data."""
        if not isinstance(task_id, UUID):
            raise TaskValidationError("task_id must be UUID instance")

        if not name or not isinstance(name, str):
            raise TaskValidationError("name must be non-empty string")

        if not isinstance(status, TaskStatus):
            raise TaskValidationError("status must be TaskStatus enum value")

    @property
    def duration_seconds(self) -> float | None:
        """Calculate task execution duration in seconds."""
        if self._duration_seconds is not None:
            return self._duration_seconds

        if self.started_at and self.completed_at:
            self._duration_seconds = (
                self.completed_at - self.started_at
            ).total_seconds()
            return self._duration_seconds

        return None

    @property
    def is_successful(self) -> bool:
        """Check if task completed successfully."""
        return self.status == TaskStatus.COMPLETED

    @property
    def is_failed(self) -> bool:
        """Check if task failed."""
        return self.status in (TaskStatus.FAILED, TaskStatus.TIMEOUT)

    @property
    def is_terminal(self) -> bool:
        """Check if task is in terminal state."""
        return self.status in (
            TaskStatus.COMPLETED,
            TaskStatus.FAILED,
            TaskStatus.CANCELLED,
            TaskStatus.TIMEOUT,
        )

    def set_resource_usage(self, **usage_metrics) -> None:
        """Set resource usage metrics for the task execution."""
        self._resource_usage.update(usage_metrics)

    def get_resource_usage(self) -> dict[str, Any]:
        """Get resource usage metrics."""
        return self._resource_usage.copy()

    def to_dict(self) -> dict[str, Any]:
        """Convert result to dictionary representation."""
        return {
            "task_id": str(self.task_id),
            "name": self.name,
            "status": self.status.value,
            "result": self.result,
            "error": self.error,
            "error_details": self.error_details.copy(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat()
            if self.completed_at
            else None,
            "duration_seconds": self.duration_seconds,
            "retry_count": self.retry_count,
            "metadata": self.metadata.copy(),
            "resource_usage": self.get_resource_usage(),
        }


class TaskContext:
    """
    Task execution context with comprehensive environment information.

    Provides execution environment, user context, dependency injection,
    and configuration for task execution. Supports context propagation
    for distributed tracing and correlation across services.

    Features:
    - User and tenant context propagation
    - Dependency injection container
    - Configuration and environment variables
    - Distributed tracing correlation
    - Resource allocation tracking

    Usage Examples:
        # Basic context
        context = TaskContext(
            task_id=uuid4(),
            user_id=user_id,
            correlation_id="req-123"
        )

        # Context with dependencies
        context = TaskContext(
            task_id=uuid4(),
            dependencies={
                "database": db_session,
                "email_service": email_client,
                "cache": redis_client
            }
        )

        # Context with custom configuration
        context = TaskContext(
            task_id=uuid4(),
            config={
                "batch_size": 100,
                "timeout": 300,
                "retry_policy": custom_policy
            }
        )
    """

    def __init__(
        self,
        task_id: UUID | None = None,
        user_id: UUID | None = None,
        tenant_id: UUID | None = None,
        correlation_id: str | None = None,
        dependencies: dict[str, Any] | None = None,
        config: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ):
        """
        Initialize task execution context.

        Args:
            task_id: Unique task identifier (generated if not provided)
            user_id: User context for the task
            tenant_id: Tenant context for multi-tenancy
            correlation_id: Correlation ID for distributed tracing
            dependencies: Dependency injection container
            config: Task-specific configuration
            metadata: Additional context metadata
        """
        self.task_id = task_id or uuid4()
        self.user_id = user_id
        self.tenant_id = tenant_id
        self.correlation_id = correlation_id
        self.dependencies = dependencies or {}
        self.config = config or {}
        self.metadata = metadata or {}

        # Internal state
        self._created_at = datetime.now(datetime.UTC)
        self._resource_allocations: dict[str, Any] = {}

    def get_dependency(self, name: str, default: Any = None) -> Any:
        """
        Get dependency from injection container.

        Args:
            name: Dependency name
            default: Default value if dependency not found

        Returns:
            Dependency instance or default value

        Raises:
            TaskDependencyError: If dependency not found and no default
        """
        if name in self.dependencies:
            return self.dependencies[name]

        if default is not None:
            return default

        raise TaskDependencyError(f"Dependency '{name}' not found in task context")

    def has_dependency(self, name: str) -> bool:
        """Check if dependency exists in context."""
        return name in self.dependencies

    def get_config(self, key: str, default: Any = None) -> Any:
        """Get configuration value with optional default."""
        return self.config.get(key, default)

    def set_resource_allocation(self, resource_type: str, allocation: Any) -> None:
        """Track resource allocation for the task."""
        self._resource_allocations[resource_type] = allocation

    def get_resource_allocation(self, resource_type: str) -> Any:
        """Get resource allocation for specified type."""
        return self._resource_allocations.get(resource_type)

    def to_dict(self) -> dict[str, Any]:
        """Convert context to dictionary representation."""
        return {
            "task_id": str(self.task_id),
            "user_id": str(self.user_id) if self.user_id else None,
            "tenant_id": str(self.tenant_id) if self.tenant_id else None,
            "correlation_id": self.correlation_id,
            "config": self.config.copy(),
            "metadata": self.metadata.copy(),
            "created_at": self._created_at.isoformat(),
            "resource_allocations": self._resource_allocations.copy(),
        }


class AsyncTask(ABC):
    """
    Base class for asynchronous task implementations.

    Provides comprehensive task execution framework with lifecycle management,
    error handling, retry mechanisms, and resource management. Designed for
    high-performance background processing with reliability guarantees.

    Key Features:
    - Abstract base for custom task implementations
    - Sophisticated retry and error handling
    - Resource requirement specification
    - Dependency injection support
    - Comprehensive lifecycle hooks
    - Performance monitoring integration
    - Cancellation and timeout support

    Design Characteristics:
    - Pure Python implementation (no framework coupling)
    - Explicit validation and error handling
    - Extensible architecture with hooks
    - Performance-oriented with monitoring
    - Resource-aware execution management

    Lifecycle Hooks:
        before_execute() - Called before task execution
        execute() - Main task logic (abstract)
        after_execute() - Called after successful execution
        on_failure() - Called when task fails
        on_retry() - Called before retry attempts
        cleanup() - Called for resource cleanup

    Usage Examples:
        class DataProcessingTask(AsyncTask):
            name = "process_user_data"
            description = "Process user data files"
            max_retries = 3
            dependencies = ["database", "file_storage"]

            async def execute(self, file_path: str) -> dict[str, Any]:
                # Main task logic
                db = self.context.get_dependency("database")
                storage = self.context.get_dependency("file_storage")

                # Process data
                data = await storage.read_file(file_path)
                result = await self.process_data(data)
                await db.save_results(result)

                return {"processed_records": len(result)}

            async def before_execute(self) -> None:
                # Setup and validation
                self.logger.info("Starting data processing")

            async def cleanup(self) -> None:
                # Resource cleanup
                await self.close_connections()

    Error Handling:
        Tasks can define custom error handling through the on_failure hook.
        Retry behavior is controlled by the retry_policy attribute.
        Resource cleanup is guaranteed through the cleanup hook.
    """

    # Class-level configuration (override in subclasses)
    name: str = "AsyncTask"
    description: str = "Base asynchronous task"
    version: str = "1.0.0"

    # Execution configuration
    max_retries: int = 3
    retry_policy: RetryPolicy | None = None
    priority: TaskPriority = TaskPriority.NORMAL

    # Resource and dependency configuration
    resource_requirements: ResourceRequirements | None = None
    dependencies: list[str] = []

    # Timeout configuration
    execution_timeout: int | None = None  # seconds

    def __init__(self, context: TaskContext | None = None):
        """
        Initialize async task with execution context.

        Args:
            context: Task execution context (created if not provided)

        Raises:
            TaskValidationError: If task configuration is invalid
        """
        self.context = context or TaskContext()
        self.logger = logger.bind(
            task_id=str(self.context.task_id), task_name=self.name
        )

        # Initialize retry policy
        if not self.retry_policy:
            self.retry_policy = RetryPolicy(max_retries=self.max_retries)

        # Initialize resource requirements
        if not self.resource_requirements:
            self.resource_requirements = ResourceRequirements()

        # Validate task configuration
        self._validate_task_configuration()

        # Internal state
        self._start_time: float | None = None
        self._execution_cancelled = False
        self._resource_monitor = ResourceMonitor()

        self.logger.debug(
            "Task initialized",
            name=self.name,
            version=self.version,
            max_retries=self.max_retries,
            dependencies=self.dependencies,
        )

    def _validate_task_configuration(self) -> None:
        """Validate task configuration and dependencies."""
        if not self.name or not isinstance(self.name, str):
            raise TaskValidationError("Task name must be non-empty string")

        # Validate dependencies are available
        for dep_name in self.dependencies:
            if not self.context.has_dependency(dep_name):
                raise TaskDependencyError(
                    f"Required dependency '{dep_name}' not available in context"
                )

        # Validate timeout configuration
        if self.execution_timeout is not None and self.execution_timeout <= 0:
            raise TaskValidationError("execution_timeout must be positive if specified")

    @abstractmethod
    async def execute(self, **kwargs) -> Any:
        """
        Execute the main task logic.

        This is the core method that subclasses must implement. Contains
        the actual business logic for the task. Should be idempotent
        where possible for retry safety.

        Args:
            **kwargs: Task-specific input parameters

        Returns:
            Task execution result (can be any serializable type)

        Raises:
            Any exception that should trigger retry or failure handling
        """

    async def run(self, **kwargs) -> TaskResult:
        """
        Execute task with comprehensive lifecycle management.

        Orchestrates the complete task execution lifecycle including
        validation, execution, error handling, retries, and cleanup.
        Provides comprehensive monitoring and error tracking.

        Args:
            **kwargs: Task input parameters

        Returns:
            TaskResult with execution details and outcome

        Raises:
            TaskValidationError: If input validation fails
            TaskTimeoutError: If execution exceeds timeout
            TaskExecutionError: If task fails after all retries
        """
        # Create result tracking object
        result = TaskResult(
            task_id=self.context.task_id,
            name=self.name,
            status=TaskStatus.PENDING,
            started_at=datetime.now(datetime.UTC),
            metadata={
                "version": self.version,
                "priority": self.priority.value,
                "resource_requirements": self.resource_requirements.to_dict(),
            },
        )

        retry_count = 0
        last_error = None

        try:
            # Validate input parameters
            await self._validate_input_parameters(**kwargs)

            # Execute with retry logic
            while True:
                try:
                    # Update status and start execution
                    result.status = (
                        TaskStatus.RETRYING if retry_count > 0 else TaskStatus.RUNNING
                    )
                    result.retry_count = retry_count

                    # Execute task with monitoring
                    execution_result = await self._execute_with_monitoring(**kwargs)

                    # Success path
                    result.status = TaskStatus.COMPLETED
                    result.result = execution_result
                    result.completed_at = datetime.now(datetime.UTC)

                    # Track success metrics
                    self._track_success_metrics(result)

                    self.logger.info(
                        "Task completed successfully",
                        duration_seconds=result.duration_seconds,
                        retry_count=retry_count,
                    )

                    return result

                except asyncio.CancelledError:
                    # Handle cancellation
                    result.status = TaskStatus.CANCELLED
                    result.error = "Task execution was cancelled"
                    self.logger.info("Task execution cancelled")
                    raise

                except Exception as e:
                    last_error = e

                    # Check if should retry
                    if self.retry_policy.should_retry(e, retry_count):
                        retry_count += 1
                        delay = self.retry_policy.calculate_delay(retry_count - 1)

                        self.logger.warning(
                            "Task failed, retrying",
                            error=str(e),
                            retry_count=retry_count,
                            max_retries=self.retry_policy.max_retries,
                            retry_delay=delay,
                        )

                        # Call retry hook
                        await self._safe_hook_call(self.on_retry, retry_count, e)

                        # Wait before retry
                        await asyncio.sleep(delay)
                        continue
                    # No more retries - task failed
                    break

            # Task failed after all retries
            result.status = TaskStatus.FAILED
            result.error = str(last_error) if last_error else "Unknown error"
            result.error_details = self._extract_error_details(last_error)
            result.completed_at = datetime.now(datetime.UTC)

            # Call failure hook
            await self._safe_hook_call(self.on_failure, last_error, result)

            # Track failure metrics
            self._track_failure_metrics(result, last_error)

            self.logger.error(
                "Task failed after all retries",
                error=result.error,
                retry_count=retry_count,
                duration_seconds=result.duration_seconds,
            )

            return result

        except Exception as e:
            # Unexpected error in run orchestration
            result.status = TaskStatus.FAILED
            result.error = f"Task orchestration error: {e}"
            result.completed_at = datetime.now(datetime.UTC)

            self.logger.exception(
                "Unexpected error in task orchestration",
                error=str(e),
                error_type=type(e).__name__,
            )

            return result

        finally:
            # Ensure cleanup is always called
            await self._safe_hook_call(self.cleanup)

            # Set resource usage in result
            result.set_resource_usage(**self._resource_monitor.get_usage())

    async def _validate_input_parameters(self, **kwargs) -> None:
        """Validate task input parameters."""
        # Subclasses can override for custom validation

    async def _execute_with_monitoring(self, **kwargs) -> Any:
        """Execute task with comprehensive monitoring and timeout handling."""
        self._start_time = time.time()
        self._resource_monitor.start_monitoring()

        try:
            # Execute lifecycle hooks and main logic
            await self._safe_hook_call(self.before_execute)

            if self.execution_timeout:
                # Execute with timeout
                execution_result = await asyncio.wait_for(
                    self.execute(**kwargs), timeout=self.execution_timeout
                )
            else:
                # Execute without timeout
                execution_result = await self.execute(**kwargs)

            await self._safe_hook_call(self.after_execute, execution_result)

            return execution_result

        except TimeoutError:
            self.logger.exception(
                "Task execution timeout", timeout_seconds=self.execution_timeout
            )
            raise TaskTimeoutError(
                f"Task execution exceeded timeout of {self.execution_timeout} seconds"
            )
        finally:
            self._resource_monitor.stop_monitoring()

    async def _safe_hook_call(self, hook_method: Callable, *args, **kwargs) -> None:
        """Safely call lifecycle hook with error handling."""
        try:
            if callable(hook_method):
                result = hook_method(*args, **kwargs)
                if asyncio.iscoroutine(result):
                    await result
        except Exception as e:
            self.logger.warning(
                "Task lifecycle hook failed", hook=hook_method.__name__, error=str(e)
            )

    def _extract_error_details(self, error: Exception) -> dict[str, Any]:
        """Extract detailed error information for debugging."""
        error_details = {
            "error_type": type(error).__name__,
            "error_message": str(error),
            "error_module": getattr(error, "__module__", None),
        }

        # Add stack trace if available
        if hasattr(error, "__traceback__"):
            error_details["stack_trace"] = traceback.format_exception(
                type(error), error, error.__traceback__
            )

        return error_details

    def _track_success_metrics(self, result: TaskResult) -> None:
        """Track success metrics for monitoring."""
        metrics.task_executions.labels(
            task_name=self.name, status="success", priority=self.priority.value
        ).inc()

        if result.duration_seconds:
            metrics.task_duration.labels(task_name=self.name, status="success").observe(
                result.duration_seconds
            )

    def _track_failure_metrics(self, result: TaskResult, error: Exception) -> None:
        """Track failure metrics for monitoring."""
        metrics.task_executions.labels(
            task_name=self.name, status="failed", priority=self.priority.value
        ).inc()

        metrics.task_failures.labels(
            task_name=self.name, error_type=type(error).__name__
        ).inc()

    # Lifecycle hooks (can be overridden by subclasses)

    async def before_execute(self) -> None:
        """
        Hook called before task execution.

        Use for setup, validation, and resource allocation.
        Exceptions here will prevent task execution.
        """

    async def after_execute(self, result: Any) -> None:
        """
        Hook called after successful task execution.

        Args:
            result: The result returned by execute()

        Use for post-processing, notifications, and cleanup.
        """

    async def on_failure(self, error: Exception, result: TaskResult) -> None:
        """
        Hook called when task fails (after all retries).

        Args:
            error: The final error that caused failure
            result: TaskResult with failure details

        Use for error reporting, compensation, and failure handling.
        """

    async def on_retry(self, retry_count: int, error: Exception) -> None:
        """
        Hook called before each retry attempt.

        Args:
            retry_count: Current retry attempt number (1-based)
            error: The error that triggered the retry

        Use for retry-specific setup and logging.
        """

    async def cleanup(self) -> None:
        """
        Hook called for resource cleanup.

        Always called regardless of task success or failure.
        Should not raise exceptions. Use for resource cleanup,
        connection closing, and state cleanup.
        """

    # Utility methods

    def cancel(self) -> None:
        """Request task cancellation."""
        self._execution_cancelled = True
        self.logger.info("Task cancellation requested")

    def is_cancelled(self) -> bool:
        """Check if task cancellation was requested."""
        return self._execution_cancelled

    def get_execution_time(self) -> float | None:
        """Get current execution time in seconds."""
        if self._start_time:
            return time.time() - self._start_time
        return None

    def get_statistics(self) -> dict[str, Any]:
        """Get task execution statistics."""
        return {
            "task_id": str(self.context.task_id),
            "name": self.name,
            "version": self.version,
            "priority": self.priority.value,
            "max_retries": self.max_retries,
            "dependencies": self.dependencies.copy(),
            "execution_timeout": self.execution_timeout,
            "resource_requirements": self.resource_requirements.to_dict(),
            "execution_time": self.get_execution_time(),
            "cancelled": self.is_cancelled(),
        }


class ResourceMonitor:
    """
    Resource usage monitoring for task execution.

    Tracks memory, CPU, and other resource usage during task execution.
    Provides metrics for performance analysis and resource optimization.
    """

    def __init__(self):
        self._start_time: float | None = None
        self._start_memory: float | None = None
        self._peak_memory: float = 0
        self._monitoring = False

    def start_monitoring(self) -> None:
        """Start resource monitoring."""
        self._start_time = time.time()
        self._start_memory = self._get_memory_usage()
        self._peak_memory = self._start_memory or 0
        self._monitoring = True

    def stop_monitoring(self) -> None:
        """Stop resource monitoring."""
        self._monitoring = False

    def _get_memory_usage(self) -> float | None:
        """Get current memory usage in MB."""
        try:
            import psutil

            process = psutil.Process()
            return process.memory_info().rss / 1024 / 1024  # Convert to MB
        except ImportError:
            return None

    def get_usage(self) -> dict[str, Any]:
        """Get resource usage statistics."""
        current_memory = self._get_memory_usage()

        usage = {
            "execution_time": time.time() - self._start_time
            if self._start_time
            else None,
            "peak_memory_mb": self._peak_memory,
            "current_memory_mb": current_memory,
        }

        if self._start_memory and current_memory:
            usage["memory_delta_mb"] = current_memory - self._start_memory

        return {k: v for k, v in usage.items() if v is not None}
