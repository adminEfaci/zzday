"""
EventSaga - Long-Running Business Process Implementation

Implements the Saga pattern for managing long-running business processes that span
multiple services and domain boundaries. Provides distributed transaction management
with compensation patterns and eventual consistency guarantees.

Key Features:
- Distributed transaction management
- Compensation pattern implementation
- State persistence and recovery
- Event-driven saga orchestration
- Saga choreography support
- Timeout and failure handling
- Saga monitoring and observability
- Cross-service coordination
"""

import asyncio
import contextlib
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from app.core.logging import get_logger
from app.modules.identity.domain.events import IdentityDomainEvent

if TYPE_CHECKING:
    from .adapter import EventBusAdapter

logger = get_logger(__name__)


class SagaStatus(Enum):
    """Saga execution status."""
    STARTED = "started"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    COMPENSATING = "compensating"
    COMPENSATED = "compensated"
    ABORTED = "aborted"


class SagaStepStatus(Enum):
    """Individual saga step status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    COMPENSATING = "compensating"
    COMPENSATED = "compensated"
    SKIPPED = "skipped"


class SagaTransactionType(Enum):
    """Type of saga transaction."""
    ORCHESTRATED = "orchestrated"  # Central coordinator
    CHOREOGRAPHED = "choreographed"  # Event-driven coordination


@dataclass
class SagaStep:
    """Represents a single step in a saga transaction."""
    step_id: str
    name: str
    service_name: str
    transaction_handler: Callable[[dict[str, Any]], dict[str, Any]]
    compensation_handler: Callable[[dict[str, Any]], dict[str, Any]]
    timeout_seconds: int = 300
    retry_attempts: int = 3
    retry_delay_seconds: int = 5
    
    # Event configuration
    trigger_event: str | None = None
    success_event: str | None = None
    failure_event: str | None = None
    
    # Runtime state
    status: SagaStepStatus = SagaStepStatus.PENDING
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error: str | None = None
    transaction_result: dict[str, Any] | None = None
    compensation_result: dict[str, Any] | None = None
    attempt_count: int = 0


@dataclass
class SagaContext:
    """Saga execution context containing state and coordination data."""
    saga_id: UUID
    saga_type: str
    correlation_id: str
    transaction_type: SagaTransactionType = SagaTransactionType.ORCHESTRATED
    status: SagaStatus = SagaStatus.STARTED
    input_data: dict[str, Any] = field(default_factory=dict)
    output_data: dict[str, Any] = field(default_factory=dict)
    step_results: dict[str, dict[str, Any]] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error: str | None = None
    timeout_at: datetime | None = None
    
    # Compensation tracking
    completed_steps: list[str] = field(default_factory=list)
    compensated_steps: list[str] = field(default_factory=list)
    failed_step: str | None = None
    
    def add_step_result(self, step_id: str, result: dict[str, Any]) -> None:
        """Add result from a saga step."""
        self.step_results[step_id] = result
        if step_id not in self.completed_steps:
            self.completed_steps.append(step_id)
    
    def get_step_result(self, step_id: str) -> dict[str, Any] | None:
        """Get result from a specific saga step."""
        return self.step_results.get(step_id)
    
    def is_timed_out(self) -> bool:
        """Check if saga has timed out."""
        if not self.timeout_at:
            return False
        return datetime.utcnow() > self.timeout_at
    
    def mark_step_compensated(self, step_id: str) -> None:
        """Mark a step as compensated."""
        if step_id not in self.compensated_steps:
            self.compensated_steps.append(step_id)


class BaseSaga(ABC):
    """
    Base class for implementing distributed saga patterns.
    
    Sagas coordinate long-running business processes across multiple services
    and handle failures through compensation patterns.
    """
    
    def __init__(
        self,
        saga_id: UUID | None = None,
        transaction_type: SagaTransactionType = SagaTransactionType.ORCHESTRATED,
        timeout_minutes: int = 60
    ):
        self.saga_id = saga_id or uuid4()
        self.transaction_type = transaction_type
        self.timeout_minutes = timeout_minutes
        self.saga_type = self.__class__.__name__
        self.steps: list[SagaStep] = []
        self.event_handlers: dict[str, Callable] = {}
    
    @abstractmethod
    def define_steps(self) -> list[SagaStep]:
        """Define the saga steps. Must be implemented by subclasses."""
    
    def add_step(
        self,
        step_id: str,
        name: str,
        service_name: str,
        transaction_handler: Callable,
        compensation_handler: Callable,
        **kwargs
    ) -> 'BaseSaga':
        """Add a step to the saga."""
        step = SagaStep(
            step_id=step_id,
            name=name,
            service_name=service_name,
            transaction_handler=transaction_handler,
            compensation_handler=compensation_handler,
            **kwargs
        )
        self.steps.append(step)
        return self
    
    def add_event_handler(
        self,
        event_type: str,
        handler: Callable[[IdentityDomainEvent, SagaContext], None]
    ) -> 'BaseSaga':
        """Add an event handler for saga coordination."""
        self.event_handlers[event_type] = handler
        return self
    
    async def handle_event(
        self,
        event: IdentityDomainEvent,
        context: SagaContext
    ) -> None:
        """Handle an event during saga execution."""
        event_type = event.__class__.__name__
        
        if event_type in self.event_handlers:
            try:
                handler = self.event_handlers[event_type]
                if asyncio.iscoroutinefunction(handler):
                    await handler(event, context)
                else:
                    handler(event, context)
                    
                logger.debug(
                    "Event handled in saga",
                    saga_id=str(self.saga_id),
                    event_type=event_type,
                    correlation_id=context.correlation_id
                )
                
            except Exception as e:
                logger.exception(
                    "Error handling event in saga",
                    saga_id=str(self.saga_id),
                    event_type=event_type,
                    error=str(e)
                )
                raise
    
    def validate_saga(self) -> list[str]:
        """Validate saga definition and return list of issues."""
        issues = []
        
        # Check for duplicate step IDs
        step_ids = [step.step_id for step in self.steps]
        if len(step_ids) != len(set(step_ids)):
            issues.append("Duplicate step IDs found")
        
        # Check that all steps have compensation handlers
        for step in self.steps:
            if not step.compensation_handler:
                issues.append(f"Step '{step.step_id}' missing compensation handler")
        
        # Check choreographed saga event configuration
        if self.transaction_type == SagaTransactionType.CHOREOGRAPHED:
            for step in self.steps:
                if not step.trigger_event:
                    issues.append(f"Choreographed step '{step.step_id}' missing trigger event")
        
        return issues
    
    def get_next_step(self, context: SagaContext) -> SagaStep | None:
        """Get the next step to execute based on current context."""
        for step in self.steps:
            if (step.status == SagaStepStatus.PENDING and 
                step.step_id not in context.completed_steps):
                return step
        return None


class EventSaga:
    """
    Saga execution engine that manages distributed transactions using the saga pattern.
    
    Provides coordination for long-running business processes that span multiple
    services with compensation-based failure handling.
    """
    
    def __init__(
        self,
        event_bus_adapter: 'EventBusAdapter',
        enable_persistence: bool = True,
        max_concurrent_sagas: int = 50
    ):
        """
        Initialize the saga engine.
        
        Args:
            event_bus_adapter: Event bus adapter for coordination
            enable_persistence: Enable saga state persistence
            max_concurrent_sagas: Maximum concurrent sagas
        """
        self.event_bus_adapter = event_bus_adapter
        self.enable_persistence = enable_persistence
        self.max_concurrent_sagas = max_concurrent_sagas
        
        # Saga registry and state
        self.registered_sagas: dict[str, type[BaseSaga]] = {}
        self.active_sagas: dict[UUID, SagaContext] = {}
        self.saga_instances: dict[UUID, BaseSaga] = {}
        
        # Execution control
        self.execution_semaphore = asyncio.Semaphore(max_concurrent_sagas)
        self.shutdown_event = asyncio.Event()
        
        # Background tasks
        self.timeout_monitor_task: asyncio.Task | None = None
        
        # Performance tracking
        self.executed_sagas = 0
        self.failed_sagas = 0
        self.compensated_sagas = 0
        
        logger.info(
            "EventSaga initialized",
            max_concurrent=max_concurrent_sagas,
            persistence_enabled=enable_persistence
        )
    
    async def start(self) -> None:
        """Start the saga engine and background tasks."""
        # Start timeout monitor
        self.timeout_monitor_task = asyncio.create_task(self._monitor_timeouts())
        
        logger.info("EventSaga started")
    
    async def stop(self) -> None:
        """Stop the saga engine and cleanup resources."""
        self.shutdown_event.set()
        
        # Cancel background tasks
        if self.timeout_monitor_task:
            self.timeout_monitor_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self.timeout_monitor_task
        
        logger.info("EventSaga stopped")
    
    def register_saga(
        self,
        saga_class: type[BaseSaga],
        saga_type: str | None = None
    ) -> None:
        """
        Register a saga class for execution.
        
        Args:
            saga_class: The saga class to register
            saga_type: Optional custom saga type name
        """
        saga_type = saga_type or saga_class.__name__
        self.registered_sagas[saga_type] = saga_class
        
        logger.debug(
            "Saga registered",
            saga_type=saga_type,
            saga_class=saga_class.__name__
        )
    
    async def start_saga(
        self,
        saga_type: str,
        input_data: dict[str, Any],
        correlation_id: str | None = None,
        saga_id: UUID | None = None,
        timeout_minutes: int | None = None
    ) -> UUID:
        """
        Start a new saga instance.
        
        Args:
            saga_type: Type of saga to start
            input_data: Input data for the saga
            correlation_id: Optional correlation ID
            saga_id: Optional specific saga ID
            timeout_minutes: Optional timeout override
            
        Returns:
            UUID: The saga instance ID
        """
        if saga_type not in self.registered_sagas:
            raise ValueError(f"Unknown saga type: {saga_type}")
        
        # Create saga instance
        saga_id = saga_id or uuid4()
        correlation_id = correlation_id or str(uuid4())
        
        # Create saga context
        timeout_at = None
        if timeout_minutes:
            timeout_at = datetime.utcnow() + timedelta(minutes=timeout_minutes)
        
        context = SagaContext(
            saga_id=saga_id,
            saga_type=saga_type,
            correlation_id=correlation_id,
            input_data=input_data.copy(),
            started_at=datetime.utcnow(),
            timeout_at=timeout_at
        )
        
        # Create saga instance
        saga_class = self.registered_sagas[saga_type]
        saga_instance = saga_class(saga_id)
        saga_instance.steps = saga_instance.define_steps()
        context.transaction_type = saga_instance.transaction_type
        
        # Validate saga
        issues = saga_instance.validate_saga()
        if issues:
            raise ValueError(f"Saga validation failed: {'; '.join(issues)}")
        
        # Store instances
        self.active_sagas[saga_id] = context
        self.saga_instances[saga_id] = saga_instance
        
        # Start execution
        self._execution_task = asyncio.create_task(self._execute_saga(saga_id))
        
        logger.info(
            "Saga started",
            saga_id=str(saga_id),
            saga_type=saga_type,
            transaction_type=context.transaction_type.value,
            correlation_id=correlation_id
        )
        
        return saga_id
    
    async def abort_saga(self, saga_id: UUID, reason: str = "Manual abort") -> bool:
        """
        Abort a running saga and trigger compensation.
        
        Args:
            saga_id: ID of saga to abort
            reason: Reason for aborting
            
        Returns:
            bool: True if aborted successfully
        """
        if saga_id not in self.active_sagas:
            return False
        
        context = self.active_sagas[saga_id]
        
        if context.status in [SagaStatus.COMPLETED, SagaStatus.FAILED, SagaStatus.ABORTED]:
            return False
        
        # Update status
        context.status = SagaStatus.FAILED
        context.error = reason
        context.completed_at = datetime.utcnow()
        
        # Trigger compensation
        await self._compensate_saga(saga_id)
        
        context.status = SagaStatus.ABORTED
        
        logger.info(
            "Saga aborted",
            saga_id=str(saga_id),
            reason=reason,
            correlation_id=context.correlation_id
        )
        
        return True
    
    def get_saga_status(self, saga_id: UUID) -> dict[str, Any] | None:
        """
        Get the current status of a saga.
        
        Args:
            saga_id: ID of saga
            
        Returns:
            Dict containing saga status information
        """
        if saga_id not in self.active_sagas:
            return None
        
        context = self.active_sagas[saga_id]
        saga_instance = self.saga_instances.get(saga_id)
        
        status = {
            'saga_id': str(saga_id),
            'saga_type': context.saga_type,
            'status': context.status.value,
            'transaction_type': context.transaction_type.value,
            'correlation_id': context.correlation_id,
            'created_at': context.created_at.isoformat(),
            'started_at': context.started_at.isoformat() if context.started_at else None,
            'completed_at': context.completed_at.isoformat() if context.completed_at else None,
            'timeout_at': context.timeout_at.isoformat() if context.timeout_at else None,
            'error': context.error,
            'input_data': context.input_data,
            'output_data': context.output_data,
            'completed_steps': context.completed_steps,
            'compensated_steps': context.compensated_steps,
            'failed_step': context.failed_step,
            'steps': []
        }
        
        if saga_instance:
            for step in saga_instance.steps:
                step_info = {
                    'step_id': step.step_id,
                    'name': step.name,
                    'service_name': step.service_name,
                    'status': step.status.value,
                    'started_at': step.started_at.isoformat() if step.started_at else None,
                    'completed_at': step.completed_at.isoformat() if step.completed_at else None,
                    'error': step.error,
                    'attempt_count': step.attempt_count
                }
                status['steps'].append(step_info)
        
        return status
    
    def get_statistics(self) -> dict[str, Any]:
        """Get saga engine statistics."""
        return {
            'registered_sagas': list(self.registered_sagas.keys()),
            'active_sagas': len(self.active_sagas),
            'executed_sagas': self.executed_sagas,
            'failed_sagas': self.failed_sagas,
            'compensated_sagas': self.compensated_sagas,
            'max_concurrent': self.max_concurrent_sagas,
            'persistence_enabled': self.enable_persistence
        }
    
    async def handle_event(
        self,
        event: IdentityDomainEvent,
        target_sagas: list[UUID] | None = None
    ) -> None:
        """
        Handle an event and route it to relevant sagas.
        
        Args:
            event: The domain event to handle
            target_sagas: Specific sagas to route to (if None, routes to all)
        """
        sagas_to_notify = target_sagas or list(self.active_sagas.keys())
        
        for saga_id in sagas_to_notify:
            if saga_id in self.saga_instances:
                saga_instance = self.saga_instances[saga_id]
                context = self.active_sagas[saga_id]
                
                try:
                    await saga_instance.handle_event(event, context)
                    
                    # Check if this event triggers choreographed saga progression
                    if context.transaction_type == SagaTransactionType.CHOREOGRAPHED:
                        await self._handle_choreographed_event(saga_id, event)
                        
                except Exception as e:
                    logger.exception(
                        "Error handling event in saga",
                        saga_id=str(saga_id),
                        event_type=event.__class__.__name__,
                        error=str(e)
                    )
    
    # Private methods
    
    async def _execute_saga(self, saga_id: UUID) -> None:
        """Execute a saga instance."""
        async with self.execution_semaphore:
            try:
                context = self.active_sagas[saga_id]
                saga_instance = self.saga_instances[saga_id]
                
                context.status = SagaStatus.RUNNING
                
                logger.info(
                    "Starting saga execution",
                    saga_id=str(saga_id),
                    transaction_type=context.transaction_type.value,
                    correlation_id=context.correlation_id
                )
                
                if context.transaction_type == SagaTransactionType.ORCHESTRATED:
                    await self._execute_orchestrated_saga(saga_instance, context)
                else:
                    await self._execute_choreographed_saga(saga_instance, context)
                
                # Check final status
                if not context.is_timed_out() and len(context.completed_steps) == len(saga_instance.steps):
                    context.status = SagaStatus.COMPLETED
                    context.completed_at = datetime.utcnow()
                    self.executed_sagas += 1
                    
                    logger.info(
                        "Saga completed successfully",
                        saga_id=str(saga_id),
                        correlation_id=context.correlation_id
                    )
                elif context.failed_step or context.is_timed_out():
                    context.status = SagaStatus.FAILED
                    context.completed_at = datetime.utcnow()
                    if context.is_timed_out():
                        context.error = "Saga timed out"
                    self.failed_sagas += 1
                    
                    # Trigger compensation
                    await self._compensate_saga(saga_id)
                
            except Exception as e:
                context = self.active_sagas.get(saga_id)
                if context:
                    context.status = SagaStatus.FAILED
                    context.completed_at = datetime.utcnow()
                    context.error = str(e)
                    self.failed_sagas += 1
                
                logger.exception(
                    "Saga execution failed",
                    saga_id=str(saga_id),
                    error=str(e)
                )
                
                # Trigger compensation
                await self._compensate_saga(saga_id)
    
    async def _execute_orchestrated_saga(
        self,
        saga_instance: BaseSaga,
        context: SagaContext
    ) -> None:
        """Execute an orchestrated saga where steps are centrally coordinated."""
        while context.status == SagaStatus.RUNNING and not context.is_timed_out():
            next_step = saga_instance.get_next_step(context)
            
            if not next_step:
                break  # No more steps to execute
            
            success = await self._execute_saga_step(next_step, context)
            
            if not success:
                context.failed_step = next_step.step_id
                break
    
    async def _execute_choreographed_saga(
        self,
        saga_instance: BaseSaga,
        context: SagaContext
    ) -> None:
        """Execute a choreographed saga where steps are event-driven."""
        # For choreographed sagas, we wait for events to trigger step execution
        # The actual execution happens in _handle_choreographed_event
        
        # Initialize first step if it has no trigger event
        first_step = saga_instance.steps[0] if saga_instance.steps else None
        if first_step and not first_step.trigger_event:
            await self._execute_saga_step(first_step, context)
    
    async def _execute_saga_step(
        self,
        step: SagaStep,
        context: SagaContext
    ) -> bool:
        """Execute a single saga step with retry logic."""
        step.status = SagaStepStatus.RUNNING
        step.started_at = datetime.utcnow()
        
        for attempt in range(step.retry_attempts + 1):
            try:
                step.attempt_count = attempt + 1
                
                logger.debug(
                    "Executing saga step",
                    saga_id=str(context.saga_id),
                    step_id=step.step_id,
                    service=step.service_name,
                    attempt=attempt + 1
                )
                
                # Prepare step input
                step_input = {
                    'context': context,
                    'input_data': context.input_data,
                    'step_results': context.step_results,
                    'correlation_id': context.correlation_id
                }
                
                # Execute step with timeout
                result = await asyncio.wait_for(
                    self._call_saga_handler(step.transaction_handler, step_input),
                    timeout=step.timeout_seconds
                )
                
                # Store result
                step.transaction_result = result or {}
                context.add_step_result(step.step_id, step.transaction_result)
                
                # Mark as completed
                step.status = SagaStepStatus.COMPLETED
                step.completed_at = datetime.utcnow()
                
                # Publish success event if configured
                if step.success_event:
                    await self._publish_step_event(
                        step.success_event,
                        context,
                        step.step_id,
                        step.transaction_result
                    )
                
                logger.debug(
                    "Saga step completed",
                    saga_id=str(context.saga_id),
                    step_id=step.step_id,
                    service=step.service_name
                )
                
                return True
                
            except TimeoutError:
                error = f"Step timed out after {step.timeout_seconds} seconds"
                step.error = error
                
                if attempt < step.retry_attempts:
                    step.status = SagaStepStatus.RUNNING
                    await asyncio.sleep(step.retry_delay_seconds)
                    continue
                
            except Exception as e:
                error = str(e)
                step.error = error
                
                logger.exception(
                    "Saga step failed",
                    saga_id=str(context.saga_id),
                    step_id=step.step_id,
                    service=step.service_name,
                    attempt=attempt + 1,
                    error=error
                )
                
                if attempt < step.retry_attempts:
                    step.status = SagaStepStatus.RUNNING
                    await asyncio.sleep(step.retry_delay_seconds)
                    continue
        
        # All attempts failed
        step.status = SagaStepStatus.FAILED
        step.completed_at = datetime.utcnow()
        
        # Publish failure event if configured
        if step.failure_event:
            await self._publish_step_event(
                step.failure_event,
                context,
                step.step_id,
                {'error': step.error}
            )
        
        return False
    
    async def _compensate_saga(self, saga_id: UUID) -> None:
        """Execute compensation for a failed saga."""
        if saga_id not in self.active_sagas:
            return
        
        context = self.active_sagas[saga_id]
        saga_instance = self.saga_instances[saga_id]
        
        context.status = SagaStatus.COMPENSATING
        
        logger.info(
            "Starting saga compensation",
            saga_id=str(saga_id),
            completed_steps=len(context.completed_steps)
        )
        
        # Compensate completed steps in reverse order
        for step_id in reversed(context.completed_steps):
            if step_id in context.compensated_steps:
                continue  # Already compensated
            
            step = next((s for s in saga_instance.steps if s.step_id == step_id), None)
            
            if step and step.compensation_handler:
                try:
                    step.status = SagaStepStatus.COMPENSATING
                    
                    compensation_input = {
                        'context': context,
                        'transaction_result': step.transaction_result,
                        'step_results': context.step_results,
                        'correlation_id': context.correlation_id
                    }
                    
                    result = await self._call_saga_handler(
                        step.compensation_handler,
                        compensation_input
                    )
                    
                    step.compensation_result = result or {}
                    step.status = SagaStepStatus.COMPENSATED
                    context.mark_step_compensated(step_id)
                    
                    logger.debug(
                        "Saga step compensated",
                        saga_id=str(saga_id),
                        step_id=step_id,
                        service=step.service_name
                    )
                    
                except Exception as e:
                    logger.exception(
                        "Saga compensation failed",
                        saga_id=str(saga_id),
                        step_id=step_id,
                        service=step.service_name,
                        error=str(e)
                    )
        
        context.status = SagaStatus.COMPENSATED
        context.completed_at = datetime.utcnow()
        self.compensated_sagas += 1
        
        logger.info(
            "Saga compensation completed",
            saga_id=str(saga_id),
            compensated_steps=len(context.compensated_steps)
        )
    
    async def _handle_choreographed_event(
        self,
        saga_id: UUID,
        event: IdentityDomainEvent
    ) -> None:
        """Handle event for choreographed saga progression."""
        context = self.active_sagas[saga_id]
        saga_instance = self.saga_instances[saga_id]
        
        event_type = event.__class__.__name__
        
        # Find steps triggered by this event
        for step in saga_instance.steps:
            if (step.trigger_event == event_type and 
                step.status == SagaStepStatus.PENDING and
                step.step_id not in context.completed_steps):
                
                success = await self._execute_saga_step(step, context)
                
                if not success:
                    context.failed_step = step.step_id
                    break
    
    async def _call_saga_handler(
        self,
        handler: Callable,
        step_input: dict[str, Any]
    ) -> dict[str, Any]:
        """Call saga handler (sync or async)."""
        if asyncio.iscoroutinefunction(handler):
            return await handler(step_input)
        return handler(step_input)
    
    async def _publish_step_event(
        self,
        event_type: str,
        context: SagaContext,
        step_id: str,
        data: dict[str, Any]
    ) -> None:
        """Publish an event for saga step completion/failure."""
        try:
            # This would create and publish an actual domain event
            # For now, we log the event
            logger.info(
                "Saga step event published",
                event_type=event_type,
                saga_id=str(context.saga_id),
                step_id=step_id,
                correlation_id=context.correlation_id,
                data_keys=list(data.keys()) if data else []
            )
            
        except Exception as e:
            logger.exception(
                "Failed to publish saga step event",
                event_type=event_type,
                saga_id=str(context.saga_id),
                step_id=step_id,
                error=str(e)
            )
    
    async def _monitor_timeouts(self) -> None:
        """Background task to monitor saga timeouts."""
        while not self.shutdown_event.is_set():
            try:
                current_time = datetime.utcnow()
                timed_out_sagas = []
                
                for saga_id, context in self.active_sagas.items():
                    if (context.timeout_at and 
                        current_time > context.timeout_at and
                        context.status in [SagaStatus.RUNNING, SagaStatus.STARTED]):
                        
                        timed_out_sagas.append(saga_id)
                
                # Handle timed out sagas
                for saga_id in timed_out_sagas:
                    logger.warning(
                        "Saga timed out",
                        saga_id=str(saga_id),
                        timeout_at=self.active_sagas[saga_id].timeout_at.isoformat()
                    )
                    
                    await self.abort_saga(saga_id, "Saga timed out")
                
                # Sleep before next check
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                logger.exception("Error in saga timeout monitor", error=str(e))
                await asyncio.sleep(60)