"""
Event Handler Executor

Provides execution engine for event handlers with comprehensive error handling,
isolation, retry logic, timeout protection, and performance monitoring.
"""

import asyncio
import time
from typing import Any
from uuid import uuid4

from app.core.errors import ValidationError
from app.core.events.types import DomainEvent
from app.core.logging import get_logger

from .base import (
    EventHandlerBase,
    HandlerExecutionContext,
    HandlerResult,
)
from .registry import EventHandlerRegistry

logger = get_logger(__name__)


class HandlerExecutionError(Exception):
    """Exception raised when handler execution fails."""
    
    def __init__(self, message: str, handler_id: str, original_error: Exception | None = None):
        super().__init__(message)
        self.handler_id = handler_id
        self.original_error = original_error


class EventHandlerExecutor:
    """
    Event handler execution engine with comprehensive error handling and monitoring.
    
    Provides isolated execution of event handlers with features like:
    - Handler isolation (failures don't affect other handlers)
    - Configurable retry logic with backoff strategies
    - Timeout protection per handler
    - Performance monitoring and metrics
    - Transaction support detection
    - Batch processing capabilities
    - Comprehensive logging and error tracking
    
    Design Features:
    - Async-first architecture for scalability
    - Handler isolation with individual error handling
    - Configurable retry policies per handler
    - Timeout protection to prevent hanging
    - Comprehensive metrics and monitoring
    - Transaction support for data consistency
    - Batch processing for performance
    
    Usage Example:
        executor = EventHandlerExecutor(registry)
        
        # Execute handlers for single event
        results = await executor.execute_handlers(user_created_event)
        
        # Execute with custom context
        context = HandlerExecutionContext(event=event, correlation_id="req-123")
        results = await executor.execute_handlers_with_context(context)
        
        # Execute specific handler
        result = await executor.execute_handler(handler, event, context)
    """
    
    def __init__(
        self,
        registry: EventHandlerRegistry,
        default_timeout_seconds: float = 30.0,
        max_concurrent_handlers: int = 10,
        enable_handler_isolation: bool = True,
        enable_performance_monitoring: bool = True
    ):
        """
        Initialize the event handler executor.
        
        Args:
            registry: Handler registry for discovering handlers
            default_timeout_seconds: Default timeout for handlers
            max_concurrent_handlers: Maximum concurrent handler executions
            enable_handler_isolation: Whether to isolate handler failures
            enable_performance_monitoring: Whether to collect performance metrics
        """
        self.registry = registry
        self.default_timeout_seconds = default_timeout_seconds
        self.max_concurrent_handlers = max_concurrent_handlers
        self.enable_handler_isolation = enable_handler_isolation
        self.enable_performance_monitoring = enable_performance_monitoring
        
        # Execution state
        self._active_executions: dict[str, HandlerExecutionContext] = {}
        self._execution_semaphore = asyncio.Semaphore(max_concurrent_handlers)
        
        # Performance metrics
        self._execution_metrics: dict[str, dict[str, Any]] = {}
        self._total_executions = 0
        self._total_successes = 0
        self._total_failures = 0
        
        logger.info(
            "Event handler executor initialized",
            default_timeout=default_timeout_seconds,
            max_concurrent=max_concurrent_handlers,
            isolation_enabled=enable_handler_isolation,
            monitoring_enabled=enable_performance_monitoring
        )
    
    async def execute_handlers(
        self,
        event: DomainEvent,
        correlation_id: str | None = None,
        parallel_execution: bool = True
    ) -> list[HandlerResult]:
        """
        Execute all handlers for a domain event.
        
        Args:
            event: Domain event to process
            correlation_id: Optional correlation ID for tracing
            parallel_execution: Whether to execute handlers in parallel
            
        Returns:
            List[HandlerResult]: Results from all handler executions
            
        Raises:
            ValidationError: If event is invalid
        """
        # Validate event
        if not isinstance(event, DomainEvent):
            raise ValidationError("Event must be a DomainEvent instance")
        
        event.validate()
        
        # Create execution context
        context = HandlerExecutionContext(
            event=event,
            event_id=event.event_id,
            correlation_id=correlation_id or event.correlation_id,
            user_id=getattr(event.metadata, 'user_id', None),
            tenant_id=getattr(event.metadata, 'tenant_id', None),
            trace_id=getattr(event.metadata, 'trace_id', None)
        )
        
        return await self.execute_handlers_with_context(context, parallel_execution)
    
    async def execute_handlers_with_context(
        self,
        context: HandlerExecutionContext,
        parallel_execution: bool = True
    ) -> list[HandlerResult]:
        """
        Execute handlers with a specific execution context.
        
        Args:
            context: Execution context with event and metadata
            parallel_execution: Whether to execute handlers in parallel
            
        Returns:
            List[HandlerResult]: Results from all handler executions
        """
        event_type = context.event.__class__.__name__
        
        # Get handlers for event type
        handlers = self.registry.get_handlers_for_event(event_type)
        
        if not handlers:
            logger.debug(f"No handlers found for event type {event_type}")
            return []
        
        logger.info(
            f"Executing {len(handlers)} handlers for event {event_type}",
            event_id=str(context.event_id),
            correlation_id=context.correlation_id,
            handler_count=len(handlers),
            parallel=parallel_execution
        )
        
        # Execute handlers
        if parallel_execution:
            results = await self._execute_handlers_parallel(handlers, context)
        else:
            results = await self._execute_handlers_sequential(handlers, context)
        
        # Log summary
        successful_count = sum(1 for result in results if result.success)
        failed_count = len(results) - successful_count
        
        logger.info(
            f"Handler execution completed for event {event_type}",
            event_id=str(context.event_id),
            total_handlers=len(results),
            successful=successful_count,
            failed=failed_count
        )
        
        return results
    
    async def execute_handler(
        self,
        handler: EventHandlerBase,
        event: DomainEvent,
        context: HandlerExecutionContext
    ) -> HandlerResult:
        """
        Execute a single event handler with comprehensive error handling.
        
        Args:
            handler: Handler to execute
            event: Domain event to process
            context: Execution context
            
        Returns:
            HandlerResult: Execution result
        """
        handler_id = handler.metadata.handler_id
        execution_id = uuid4()
        
        # Update context with handler information
        context.execution_id = execution_id
        context.handler_id = handler_id
        context.handler_name = handler.metadata.handler_name
        context.transaction_required = handler.metadata.requires_transaction
        
        # Acquire execution semaphore
        async with self._execution_semaphore:
            # Track active execution
            self._active_executions[str(execution_id)] = context
            
            try:
                # Execute with retries
                result = await self._execute_with_retries(handler, event, context)
                
                # Update metrics
                if self.enable_performance_monitoring:
                    self._update_metrics(handler_id, result)
                
                return result
                
            finally:
                # Clean up active execution tracking
                self._active_executions.pop(str(execution_id), None)
    
    async def _execute_handlers_parallel(
        self,
        handlers: list[EventHandlerBase],
        context: HandlerExecutionContext
    ) -> list[HandlerResult]:
        """Execute handlers in parallel."""
        tasks = []
        
        for handler in handlers:
            # Create a copy of context for each handler
            handler_context = HandlerExecutionContext(
                event=context.event,
                event_id=context.event_id,
                correlation_id=context.correlation_id,
                user_id=context.user_id,
                tenant_id=context.tenant_id,
                trace_id=context.trace_id,
                attempt_number=context.attempt_number,
                is_retry=context.is_retry,
                batch_processing=context.batch_processing
            )
            
            task = asyncio.create_task(
                self.execute_handler(handler, context.event, handler_context)
            )
            tasks.append(task)
        
        # Wait for all handlers to complete
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Convert exceptions to error results
        final_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                handler = handlers[i]
                error_result = HandlerResult(
                    success=False,
                    handler_id=handler.metadata.handler_id,
                    execution_id=uuid4(),
                    started_at=context.started_at,
                    error=result,
                    error_message=str(result),
                    error_type=type(result).__name__
                )
                final_results.append(error_result)
            else:
                final_results.append(result)
        
        return final_results
    
    async def _execute_handlers_sequential(
        self,
        handlers: list[EventHandlerBase],
        context: HandlerExecutionContext
    ) -> list[HandlerResult]:
        """Execute handlers sequentially."""
        results = []
        
        for handler in handlers:
            # Create a copy of context for each handler
            handler_context = HandlerExecutionContext(
                event=context.event,
                event_id=context.event_id,
                correlation_id=context.correlation_id,
                user_id=context.user_id,
                tenant_id=context.tenant_id,
                trace_id=context.trace_id,
                attempt_number=context.attempt_number,
                is_retry=context.is_retry,
                batch_processing=context.batch_processing
            )
            
            try:
                result = await self.execute_handler(handler, context.event, handler_context)
                results.append(result)
            except Exception as e:
                # Create error result for sequential execution failures
                error_result = HandlerResult(
                    success=False,
                    handler_id=handler.metadata.handler_id,
                    execution_id=uuid4(),
                    started_at=context.started_at,
                    error=e,
                    error_message=str(e),
                    error_type=type(e).__name__
                )
                results.append(error_result)
                
                # Log the error but continue with other handlers
                logger.exception(
                    f"Handler {handler.metadata.handler_name} failed in sequential execution",
                    handler_id=handler.metadata.handler_id,
                    event_type=context.event.__class__.__name__
                )
        
        return results
    
    async def _execute_with_retries(
        self,
        handler: EventHandlerBase,
        event: DomainEvent,
        context: HandlerExecutionContext
    ) -> HandlerResult:
        """Execute handler with retry logic."""
        metadata = handler.metadata
        last_error = None
        
        for attempt in range(1, metadata.max_retries + 2):  # +1 for initial attempt
            context.attempt_number = attempt
            context.is_retry = attempt > 1
            
            try:
                # Execute the handler
                result = await self._execute_single_attempt(handler, event, context)
                
                # Success - update metadata and return
                metadata.increment_execution()
                return result
                
            except Exception as e:
                last_error = e
                metadata.increment_error()
                
                # Check if we should retry
                if not metadata.should_retry(attempt, e):
                    break
                
                # Log retry attempt
                logger.warning(
                    f"Handler {metadata.handler_name} failed, retrying (attempt {attempt}/{metadata.max_retries + 1})",
                    handler_id=metadata.handler_id,
                    attempt=attempt,
                    max_retries=metadata.max_retries,
                    error=str(e),
                    error_type=type(e).__name__
                )
                
                # Wait before retry
                delay = metadata.get_retry_delay(attempt)
                if delay > 0:
                    await asyncio.sleep(delay)
        
        # All retries exhausted - return failure result
        return HandlerResult(
            success=False,
            handler_id=metadata.handler_id,
            execution_id=context.execution_id,
            started_at=context.started_at,
            error=last_error,
            error_message=str(last_error) if last_error else "Unknown error",
            error_type=type(last_error).__name__ if last_error else "UnknownError"
        )
    
    def _validate_handler_result(self, result: Any) -> None:
        """Validate handler result."""
        if not isinstance(result, HandlerResult):
            raise ValidationError("Handler must return HandlerResult")
    
    async def _execute_single_attempt(
        self,
        handler: EventHandlerBase,
        event: DomainEvent,
        context: HandlerExecutionContext
    ) -> HandlerResult:
        """Execute a single handler attempt with timeout protection."""
        start_time = time.time()
        
        # Determine timeout
        timeout = handler.metadata.timeout_seconds or self.default_timeout_seconds
        
        logger.debug(
            f"Executing handler {handler.metadata.handler_name}",
            handler_id=handler.metadata.handler_id,
            event_type=event.__class__.__name__,
            attempt=context.attempt_number,
            timeout=timeout
        )
        
        try:
            # Execute with timeout
            if asyncio.iscoroutinefunction(handler.handle):
                # Async handler
                result = await asyncio.wait_for(
                    handler.handle(event, context),
                    timeout=timeout
                )
            else:
                # Sync handler - run in thread pool
                loop = asyncio.get_event_loop()
                result = await asyncio.wait_for(
                    loop.run_in_executor(None, handler.handle, event, context),
                    timeout=timeout
                )
            
            # Validate result
            self._validate_handler_result(result)
            
            # Add execution metrics
            execution_time_ms = (time.time() - start_time) * 1000
            result.metrics["execution_time_ms"] = execution_time_ms
            
            logger.debug(
                f"Handler {handler.metadata.handler_name} completed successfully",
                handler_id=handler.metadata.handler_id,
                execution_time_ms=execution_time_ms,
                success=result.success
            )
            
            
            return result
            
        except TimeoutError:
            execution_time_ms = (time.time() - start_time) * 1000
            error_msg = f"Handler {handler.metadata.handler_name} timed out after {timeout}s"
            
            logger.exception(
                error_msg,
                handler_id=handler.metadata.handler_id,
                timeout_seconds=timeout,
                execution_time_ms=execution_time_ms
            )
            
            raise HandlerExecutionError(error_msg, handler.metadata.handler_id) from None
            
        except Exception as e:
            execution_time_ms = (time.time() - start_time) * 1000
            
            logger.exception(
                f"Handler {handler.metadata.handler_name} failed",
                handler_id=handler.metadata.handler_id,
                execution_time_ms=execution_time_ms,
                attempt=context.attempt_number
            )
            
            # Re-raise with additional context if handler isolation is disabled
            if not self.enable_handler_isolation:
                raise HandlerExecutionError(
                    f"Handler {handler.metadata.handler_name} failed: {e}",
                    handler.metadata.handler_id,
                    e
                ) from e
            
            raise
    
    def _update_metrics(self, handler_id: str, result: HandlerResult) -> None:
        """Update performance metrics for a handler."""
        if handler_id not in self._execution_metrics:
            self._execution_metrics[handler_id] = {
                "total_executions": 0,
                "successful_executions": 0,
                "failed_executions": 0,
                "total_execution_time_ms": 0.0,
                "average_execution_time_ms": 0.0,
                "min_execution_time_ms": float('inf'),
                "max_execution_time_ms": 0.0,
                "last_execution": None,
            }
        
        metrics = self._execution_metrics[handler_id]
        execution_time = result.duration_ms
        
        # Update counters
        metrics["total_executions"] += 1
        if result.success:
            metrics["successful_executions"] += 1
            self._total_successes += 1
        else:
            metrics["failed_executions"] += 1
            self._total_failures += 1
        
        self._total_executions += 1
        
        # Update timing metrics
        metrics["total_execution_time_ms"] += execution_time
        metrics["average_execution_time_ms"] = (
            metrics["total_execution_time_ms"] / metrics["total_executions"]
        )
        metrics["min_execution_time_ms"] = min(metrics["min_execution_time_ms"], execution_time)
        metrics["max_execution_time_ms"] = max(metrics["max_execution_time_ms"], execution_time)
        metrics["last_execution"] = result.completed_at.isoformat()
    
    def get_execution_metrics(self) -> dict[str, Any]:
        """
        Get execution metrics for all handlers.
        
        Returns:
            Dict[str, Any]: Comprehensive execution metrics
        """
        return {
            "total_executions": self._total_executions,
            "total_successes": self._total_successes,
            "total_failures": self._total_failures,
            "overall_success_rate": (
                self._total_successes / max(self._total_executions, 1)
            ),
            "active_executions": len(self._active_executions),
            "max_concurrent_handlers": self.max_concurrent_handlers,
            "handler_metrics": dict(self._execution_metrics),
        }
    
    def get_active_executions(self) -> dict[str, dict[str, Any]]:
        """
        Get information about currently active executions.
        
        Returns:
            Dict[str, Dict[str, Any]]: Active execution information
        """
        return {
            execution_id: context.to_dict()
            for execution_id, context in self._active_executions.items()
        }
    
    def clear_metrics(self) -> None:
        """Clear all execution metrics."""
        self._execution_metrics.clear()
        self._total_executions = 0
        self._total_successes = 0
        self._total_failures = 0
        
        logger.info("Execution metrics cleared")


# Export all classes
__all__ = [
    "EventHandlerExecutor",
    "HandlerExecutionError",
]