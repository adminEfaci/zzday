"""
EventWorkflowEngine - Orchestrates Complex Event-Driven Business Processes

Manages complex event workflows that span multiple domain events and business processes.
Provides choreography-based workflow execution with state management, error handling,
and compensation patterns.

Key Features:
- Event choreography and orchestration
- Workflow state management and persistence
- Compensation and rollback capabilities
- Conditional workflow execution
- Parallel and sequential step execution
- Workflow monitoring and analytics
- Error handling and retry mechanisms
- Workflow versioning and migration
"""

import asyncio
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from app.core.logging import get_logger
from app.modules.identity.domain.events import IdentityDomainEvent

if TYPE_CHECKING:
    from .adapter import EventBusAdapter

logger = get_logger(__name__)


class WorkflowStatus(Enum):
    """Workflow execution status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    COMPENSATING = "compensating"
    COMPENSATED = "compensated"
    CANCELLED = "cancelled"
    SUSPENDED = "suspended"


class StepStatus(Enum):
    """Individual step execution status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    RETRYING = "retrying"


class WorkflowExecutionMode(Enum):
    """Workflow execution mode."""
    SEQUENTIAL = "sequential"
    PARALLEL = "parallel"
    CONDITIONAL = "conditional"
    EVENT_DRIVEN = "event_driven"


@dataclass
class WorkflowStep:
    """Represents a single step in a workflow."""
    step_id: str
    name: str
    handler: Callable[[dict[str, Any]], dict[str, Any]]
    compensation_handler: Callable[[dict[str, Any]], None] | None = None
    timeout_seconds: int = 300
    retry_attempts: int = 3
    retry_delay_seconds: int = 5
    required: bool = True
    condition: Callable[[dict[str, Any]], bool] | None = None
    depends_on: list[str] = field(default_factory=list)
    parallel_group: str | None = None
    
    # Runtime state
    status: StepStatus = StepStatus.PENDING
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error: str | None = None
    result: dict[str, Any] | None = None
    attempt_count: int = 0


@dataclass
class WorkflowContext:
    """Workflow execution context containing state and data."""
    workflow_id: UUID
    workflow_type: str
    correlation_id: str
    status: WorkflowStatus = WorkflowStatus.PENDING
    input_data: dict[str, Any] = field(default_factory=dict)
    output_data: dict[str, Any] = field(default_factory=dict)
    step_data: dict[str, dict[str, Any]] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error: str | None = None
    compensation_steps: list[str] = field(default_factory=list)
    
    def set_step_result(self, step_id: str, result: dict[str, Any]) -> None:
        """Set result data for a workflow step."""
        self.step_data[step_id] = result
    
    def get_step_result(self, step_id: str) -> dict[str, Any] | None:
        """Get result data from a workflow step."""
        return self.step_data.get(step_id)
    
    def merge_output(self, data: dict[str, Any]) -> None:
        """Merge data into output_data."""
        self.output_data.update(data)


class BaseWorkflow(ABC):
    """
    Base class for implementing event-driven workflows.
    
    Workflows define business processes that span multiple domain events
    and require coordination between different components.
    """
    
    def __init__(self, workflow_id: UUID | None = None):
        self.workflow_id = workflow_id or uuid4()
        self.steps: list[WorkflowStep] = []
        self.event_handlers: dict[str, Callable] = {}
        self.workflow_type = self.__class__.__name__
    
    @abstractmethod
    def define_steps(self) -> list[WorkflowStep]:
        """Define the workflow steps. Must be implemented by subclasses."""
    
    def add_step(
        self,
        step_id: str,
        name: str,
        handler: Callable,
        **kwargs
    ) -> 'BaseWorkflow':
        """Add a step to the workflow."""
        step = WorkflowStep(
            step_id=step_id,
            name=name,
            handler=handler,
            **kwargs
        )
        self.steps.append(step)
        return self
    
    def add_event_handler(
        self,
        event_type: str,
        handler: Callable[[IdentityDomainEvent, WorkflowContext], None]
    ) -> 'BaseWorkflow':
        """Add an event handler for workflow events."""
        self.event_handlers[event_type] = handler
        return self
    
    async def handle_event(
        self,
        event: IdentityDomainEvent,
        context: WorkflowContext
    ) -> None:
        """Handle an event during workflow execution."""
        event_type = event.__class__.__name__
        
        if event_type in self.event_handlers:
            try:
                handler = self.event_handlers[event_type]
                if asyncio.iscoroutinefunction(handler):
                    await handler(event, context)
                else:
                    handler(event, context)
                    
                logger.debug(
                    "Event handled in workflow",
                    workflow_id=str(self.workflow_id),
                    event_type=event_type,
                    correlation_id=context.correlation_id
                )
                
            except Exception as e:
                logger.exception(
                    "Error handling event in workflow",
                    workflow_id=str(self.workflow_id),
                    event_type=event_type,
                    error=str(e)
                )
                raise
    
    def validate_workflow(self) -> list[str]:
        """Validate workflow definition and return list of issues."""
        issues = []
        
        # Check for duplicate step IDs
        step_ids = [step.step_id for step in self.steps]
        if len(step_ids) != len(set(step_ids)):
            issues.append("Duplicate step IDs found")
        
        # Check dependencies
        for step in self.steps:
            for dep in step.depends_on:
                if dep not in step_ids:
                    issues.append(f"Step '{step.step_id}' depends on non-existent step '{dep}'")
        
        # Check for circular dependencies
        if self._has_circular_dependencies():
            issues.append("Circular dependencies detected")
        
        return issues
    
    def _has_circular_dependencies(self) -> bool:
        """Check for circular dependencies in workflow steps."""
        # Simple cycle detection using DFS
        visited = set()
        rec_stack = set()
        
        def has_cycle(step_id: str) -> bool:
            if step_id in rec_stack:
                return True
            if step_id in visited:
                return False
            
            visited.add(step_id)
            rec_stack.add(step_id)
            
            # Find step and check dependencies
            step = next((s for s in self.steps if s.step_id == step_id), None)
            if step:
                for dep in step.depends_on:
                    if has_cycle(dep):
                        return True
            
            rec_stack.remove(step_id)
            return False
        
        for step in self.steps:
            if step.step_id not in visited and has_cycle(step.step_id):
                return True
        
        return False


class EventWorkflowEngine:
    """
    Engine for executing event-driven workflows with full lifecycle management.
    
    Provides orchestration capabilities for complex business processes that span
    multiple domain events and require coordination between different components.
    """
    
    def __init__(
        self,
        event_bus_adapter: 'EventBusAdapter',
        enable_persistence: bool = True,
        max_concurrent_workflows: int = 100
    ):
        """
        Initialize the workflow engine.
        
        Args:
            event_bus_adapter: Event bus adapter for publishing/subscribing
            enable_persistence: Enable workflow state persistence
            max_concurrent_workflows: Maximum concurrent workflows
        """
        self.event_bus_adapter = event_bus_adapter
        self.enable_persistence = enable_persistence
        self.max_concurrent_workflows = max_concurrent_workflows
        
        # Workflow registry and state
        self.registered_workflows: dict[str, type[BaseWorkflow]] = {}
        self.active_workflows: dict[UUID, WorkflowContext] = {}
        self.workflow_instances: dict[UUID, BaseWorkflow] = {}
        
        # Execution state
        self.execution_semaphore = asyncio.Semaphore(max_concurrent_workflows)
        self.shutdown_event = asyncio.Event()
        
        # Performance tracking
        self.executed_workflows = 0
        self.failed_workflows = 0
        self.compensated_workflows = 0
        
        logger.info(
            "EventWorkflowEngine initialized",
            max_concurrent=max_concurrent_workflows,
            persistence_enabled=enable_persistence
        )
    
    def register_workflow(
        self,
        workflow_class: type[BaseWorkflow],
        workflow_type: str | None = None
    ) -> None:
        """
        Register a workflow class for execution.
        
        Args:
            workflow_class: The workflow class to register
            workflow_type: Optional custom workflow type name
        """
        workflow_type = workflow_type or workflow_class.__name__
        self.registered_workflows[workflow_type] = workflow_class
        
        logger.debug(
            "Workflow registered",
            workflow_type=workflow_type,
            workflow_class=workflow_class.__name__
        )
    
    async def start_workflow(
        self,
        workflow_type: str,
        input_data: dict[str, Any],
        correlation_id: str | None = None,
        workflow_id: UUID | None = None
    ) -> UUID:
        """
        Start a new workflow instance.
        
        Args:
            workflow_type: Type of workflow to start
            input_data: Input data for the workflow
            correlation_id: Optional correlation ID
            workflow_id: Optional specific workflow ID
            
        Returns:
            UUID: The workflow instance ID
        """
        if workflow_type not in self.registered_workflows:
            raise ValueError(f"Unknown workflow type: {workflow_type}")
        
        # Create workflow instance
        workflow_id = workflow_id or uuid4()
        correlation_id = correlation_id or str(uuid4())
        
        # Create workflow context
        context = WorkflowContext(
            workflow_id=workflow_id,
            workflow_type=workflow_type,
            correlation_id=correlation_id,
            input_data=input_data.copy(),
            started_at=datetime.utcnow()
        )
        
        # Create workflow instance
        workflow_class = self.registered_workflows[workflow_type]
        workflow_instance = workflow_class(workflow_id)
        workflow_instance.steps = workflow_instance.define_steps()
        
        # Validate workflow
        issues = workflow_instance.validate_workflow()
        if issues:
            raise ValueError(f"Workflow validation failed: {'; '.join(issues)}")
        
        # Store instances
        self.active_workflows[workflow_id] = context
        self.workflow_instances[workflow_id] = workflow_instance
        
        # Start execution
        self._execution_task = asyncio.create_task(self._execute_workflow(workflow_id))
        
        logger.info(
            "Workflow started",
            workflow_id=str(workflow_id),
            workflow_type=workflow_type,
            correlation_id=correlation_id,
            input_keys=list(input_data.keys())
        )
        
        return workflow_id
    
    async def cancel_workflow(self, workflow_id: UUID) -> bool:
        """
        Cancel a running workflow.
        
        Args:
            workflow_id: ID of workflow to cancel
            
        Returns:
            bool: True if cancelled successfully
        """
        if workflow_id not in self.active_workflows:
            return False
        
        context = self.active_workflows[workflow_id]
        
        if context.status in [WorkflowStatus.COMPLETED, WorkflowStatus.FAILED, WorkflowStatus.CANCELLED]:
            return False
        
        # Update status
        context.status = WorkflowStatus.CANCELLED
        context.completed_at = datetime.utcnow()
        
        # Trigger compensation if needed
        if context.compensation_steps:
            await self._compensate_workflow(workflow_id)
        
        logger.info(
            "Workflow cancelled",
            workflow_id=str(workflow_id),
            correlation_id=context.correlation_id
        )
        
        return True
    
    async def suspend_workflow(self, workflow_id: UUID) -> bool:
        """
        Suspend a running workflow.
        
        Args:
            workflow_id: ID of workflow to suspend
            
        Returns:
            bool: True if suspended successfully
        """
        if workflow_id not in self.active_workflows:
            return False
        
        context = self.active_workflows[workflow_id]
        
        if context.status != WorkflowStatus.RUNNING:
            return False
        
        context.status = WorkflowStatus.SUSPENDED
        
        logger.info(
            "Workflow suspended",
            workflow_id=str(workflow_id),
            correlation_id=context.correlation_id
        )
        
        return True
    
    async def resume_workflow(self, workflow_id: UUID) -> bool:
        """
        Resume a suspended workflow.
        
        Args:
            workflow_id: ID of workflow to resume
            
        Returns:
            bool: True if resumed successfully
        """
        if workflow_id not in self.active_workflows:
            return False
        
        context = self.active_workflows[workflow_id]
        
        if context.status != WorkflowStatus.SUSPENDED:
            return False
        
        context.status = WorkflowStatus.RUNNING
        
        # Resume execution
        self._resume_task = asyncio.create_task(self._execute_workflow(workflow_id))
        
        logger.info(
            "Workflow resumed",
            workflow_id=str(workflow_id),
            correlation_id=context.correlation_id
        )
        
        return True
    
    def get_workflow_status(self, workflow_id: UUID) -> dict[str, Any] | None:
        """
        Get the current status of a workflow.
        
        Args:
            workflow_id: ID of workflow
            
        Returns:
            Dict containing workflow status information
        """
        if workflow_id not in self.active_workflows:
            return None
        
        context = self.active_workflows[workflow_id]
        workflow_instance = self.workflow_instances.get(workflow_id)
        
        status = {
            'workflow_id': str(workflow_id),
            'workflow_type': context.workflow_type,
            'status': context.status.value,
            'correlation_id': context.correlation_id,
            'created_at': context.created_at.isoformat(),
            'started_at': context.started_at.isoformat() if context.started_at else None,
            'completed_at': context.completed_at.isoformat() if context.completed_at else None,
            'error': context.error,
            'input_data': context.input_data,
            'output_data': context.output_data,
            'steps': []
        }
        
        if workflow_instance:
            for step in workflow_instance.steps:
                step_info = {
                    'step_id': step.step_id,
                    'name': step.name,
                    'status': step.status.value,
                    'started_at': step.started_at.isoformat() if step.started_at else None,
                    'completed_at': step.completed_at.isoformat() if step.completed_at else None,
                    'error': step.error,
                    'attempt_count': step.attempt_count
                }
                status['steps'].append(step_info)
        
        return status
    
    def get_statistics(self) -> dict[str, Any]:
        """Get workflow engine statistics."""
        return {
            'registered_workflows': list(self.registered_workflows.keys()),
            'active_workflows': len(self.active_workflows),
            'executed_workflows': self.executed_workflows,
            'failed_workflows': self.failed_workflows,
            'compensated_workflows': self.compensated_workflows,
            'max_concurrent': self.max_concurrent_workflows,
            'persistence_enabled': self.enable_persistence
        }
    
    async def handle_event(
        self,
        event: IdentityDomainEvent,
        target_workflows: list[UUID] | None = None
    ) -> None:
        """
        Handle an event and route it to relevant workflows.
        
        Args:
            event: The domain event to handle
            target_workflows: Specific workflows to route to (if None, routes to all)
        """
        workflows_to_notify = target_workflows or list(self.active_workflows.keys())
        
        for workflow_id in workflows_to_notify:
            if workflow_id in self.workflow_instances:
                workflow_instance = self.workflow_instances[workflow_id]
                context = self.active_workflows[workflow_id]
                
                try:
                    await workflow_instance.handle_event(event, context)
                except Exception as e:
                    logger.exception(
                        "Error handling event in workflow",
                        workflow_id=str(workflow_id),
                        event_type=event.__class__.__name__,
                        error=str(e)
                    )
    
    # Private methods
    
    async def _execute_workflow(self, workflow_id: UUID) -> None:
        """Execute a workflow instance."""
        async with self.execution_semaphore:
            try:
                context = self.active_workflows[workflow_id]
                workflow_instance = self.workflow_instances[workflow_id]
                
                context.status = WorkflowStatus.RUNNING
                
                logger.info(
                    "Starting workflow execution",
                    workflow_id=str(workflow_id),
                    correlation_id=context.correlation_id
                )
                
                # Execute workflow steps
                await self._execute_steps(workflow_instance, context)
                
                # Mark as completed if all required steps succeeded
                if self._all_required_steps_completed(workflow_instance):
                    context.status = WorkflowStatus.COMPLETED
                    context.completed_at = datetime.utcnow()
                    self.executed_workflows += 1
                    
                    logger.info(
                        "Workflow completed successfully",
                        workflow_id=str(workflow_id),
                        correlation_id=context.correlation_id
                    )
                else:
                    context.status = WorkflowStatus.FAILED
                    context.completed_at = datetime.utcnow()
                    context.error = "Required steps failed"
                    self.failed_workflows += 1
                    
                    # Trigger compensation
                    await self._compensate_workflow(workflow_id)
                
            except Exception as e:
                context = self.active_workflows.get(workflow_id)
                if context:
                    context.status = WorkflowStatus.FAILED
                    context.completed_at = datetime.utcnow()
                    context.error = str(e)
                    self.failed_workflows += 1
                
                logger.exception(
                    "Workflow execution failed",
                    workflow_id=str(workflow_id),
                    error=str(e)
                )
                
                # Trigger compensation
                await self._compensate_workflow(workflow_id)
    
    async def _execute_steps(
        self,
        workflow_instance: BaseWorkflow,
        context: WorkflowContext
    ) -> None:
        """Execute workflow steps according to their dependencies and execution mode."""
        # Build dependency graph
        remaining_steps = workflow_instance.steps.copy()
        completed_steps = set()
        
        while remaining_steps and context.status == WorkflowStatus.RUNNING:
            # Find steps that can be executed (dependencies satisfied)
            executable_steps = [
                step for step in remaining_steps
                if all(dep in completed_steps for dep in step.depends_on)
                and (step.condition is None or step.condition(context.input_data))
            ]
            
            if not executable_steps:
                # Check if we're waiting for something or if we're stuck
                if any(step.status == StepStatus.RUNNING for step in workflow_instance.steps):
                    await asyncio.sleep(1)  # Wait for running steps
                    continue
                break  # No more executable steps
            
            # Group steps by parallel group
            parallel_groups = {}
            sequential_steps = []
            
            for step in executable_steps:
                if step.parallel_group:
                    if step.parallel_group not in parallel_groups:
                        parallel_groups[step.parallel_group] = []
                    parallel_groups[step.parallel_group].append(step)
                else:
                    sequential_steps.append(step)
            
            # Execute parallel groups concurrently
            tasks = []
            for group_steps in parallel_groups.values():
                group_tasks = [
                    self._execute_step(step, context)
                    for step in group_steps
                ]
                tasks.extend(group_tasks)
            
            # Execute sequential steps
            for step in sequential_steps:
                tasks.append(self._execute_step(step, context))
            
            # Wait for all tasks to complete
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            
            # Update completed steps
            for step in executable_steps:
                if step.status == StepStatus.COMPLETED:
                    completed_steps.add(step.step_id)
                    if step.compensation_handler:
                        context.compensation_steps.append(step.step_id)
                
                remaining_steps.remove(step)
    
    async def _execute_step(
        self,
        step: WorkflowStep,
        context: WorkflowContext
    ) -> None:
        """Execute a single workflow step with retry logic."""
        step.status = StepStatus.RUNNING
        step.started_at = datetime.utcnow()
        
        for attempt in range(step.retry_attempts + 1):
            try:
                step.attempt_count = attempt + 1
                
                logger.debug(
                    "Executing workflow step",
                    workflow_id=str(context.workflow_id),
                    step_id=step.step_id,
                    attempt=attempt + 1
                )
                
                # Prepare step input
                step_input = {
                    'context': context,
                    'input_data': context.input_data,
                    'step_data': context.step_data
                }
                
                # Execute step with timeout
                result = await asyncio.wait_for(
                    self._call_step_handler(step.handler, step_input),
                    timeout=step.timeout_seconds
                )
                
                # Store result
                step.result = result or {}
                context.set_step_result(step.step_id, step.result)
                
                # Mark as completed
                step.status = StepStatus.COMPLETED
                step.completed_at = datetime.utcnow()
                
                logger.debug(
                    "Workflow step completed",
                    workflow_id=str(context.workflow_id),
                    step_id=step.step_id,
                    attempt=attempt + 1
                )
                
                return
                
            except TimeoutError:
                error = f"Step timed out after {step.timeout_seconds} seconds"
                step.error = error
                
                if attempt < step.retry_attempts:
                    step.status = StepStatus.RETRYING
                    await asyncio.sleep(step.retry_delay_seconds)
                    continue
                
            except Exception as e:
                error = str(e)
                step.error = error
                
                logger.exception(
                    "Workflow step failed",
                    workflow_id=str(context.workflow_id),
                    step_id=step.step_id,
                    attempt=attempt + 1,
                    error=error
                )
                
                if attempt < step.retry_attempts:
                    step.status = StepStatus.RETRYING
                    await asyncio.sleep(step.retry_delay_seconds)
                    continue
        
        # All attempts failed
        if step.required:
            step.status = StepStatus.FAILED
        else:
            step.status = StepStatus.SKIPPED
        
        step.completed_at = datetime.utcnow()
    
    async def _call_step_handler(
        self,
        handler: Callable,
        step_input: dict[str, Any]
    ) -> dict[str, Any]:
        """Call step handler (sync or async)."""
        if asyncio.iscoroutinefunction(handler):
            return await handler(step_input)
        return handler(step_input)
    
    def _all_required_steps_completed(self, workflow_instance: BaseWorkflow) -> bool:
        """Check if all required steps completed successfully."""
        for step in workflow_instance.steps:
            if step.required and step.status != StepStatus.COMPLETED:
                return False
        return True
    
    async def _compensate_workflow(self, workflow_id: UUID) -> None:
        """Execute compensation steps for a failed workflow."""
        if workflow_id not in self.active_workflows:
            return
        
        context = self.active_workflows[workflow_id]
        workflow_instance = self.workflow_instances[workflow_id]
        
        context.status = WorkflowStatus.COMPENSATING
        
        logger.info(
            "Starting workflow compensation",
            workflow_id=str(workflow_id),
            compensation_steps=len(context.compensation_steps)
        )
        
        # Execute compensation steps in reverse order
        for step_id in reversed(context.compensation_steps):
            step = next((s for s in workflow_instance.steps if s.step_id == step_id), None)
            
            if step and step.compensation_handler:
                try:
                    compensation_input = {
                        'context': context,
                        'step_result': step.result,
                        'step_data': context.step_data
                    }
                    
                    if asyncio.iscoroutinefunction(step.compensation_handler):
                        await step.compensation_handler(compensation_input)
                    else:
                        step.compensation_handler(compensation_input)
                    
                    logger.debug(
                        "Compensation step executed",
                        workflow_id=str(workflow_id),
                        step_id=step_id
                    )
                    
                except Exception as e:
                    logger.exception(
                        "Compensation step failed",
                        workflow_id=str(workflow_id),
                        step_id=step_id,
                        error=str(e)
                    )
        
        context.status = WorkflowStatus.COMPENSATED
        context.completed_at = datetime.utcnow()
        self.compensated_workflows += 1
        
        logger.info(
            "Workflow compensation completed",
            workflow_id=str(workflow_id)
        )