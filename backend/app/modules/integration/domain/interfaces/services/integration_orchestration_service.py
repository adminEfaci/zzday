"""
Integration Orchestration Service Interface

Port for orchestrating complex integration workflows including
multi-step processes, conditional flows, and error handling.
"""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any
from uuid import UUID

if TYPE_CHECKING:
    from app.modules.integration.domain.value_objects import WorkflowDefinition, WorkflowStep


class IIntegrationOrchestrationService(ABC):
    """Port for integration orchestration operations."""
    
    @abstractmethod
    async def create_workflow(
        self,
        name: str,
        description: str,
        steps: list["WorkflowStep"],
        triggers: list[dict[str, Any]] | None = None,
        metadata: dict[str, Any] | None = None
    ) -> UUID:
        """
        Create an integration workflow.
        
        Args:
            name: Workflow name
            description: Workflow description
            steps: List of workflow steps
            triggers: Optional workflow triggers
            metadata: Optional metadata
            
        Returns:
            ID of created workflow
            
        Raises:
            InvalidWorkflowError: If workflow definition is invalid
            CircularDependencyError: If steps have circular dependencies
        """
        ...
    
    @abstractmethod
    async def execute_workflow(
        self,
        workflow_id: UUID,
        input_data: dict[str, Any],
        context: dict[str, Any] | None = None,
        async_execution: bool = False
    ) -> dict[str, Any]:
        """
        Execute an integration workflow.
        
        Args:
            workflow_id: ID of workflow to execute
            input_data: Input data for workflow
            context: Optional execution context
            async_execution: Whether to execute asynchronously
            
        Returns:
            Workflow execution result
            
        Raises:
            WorkflowNotFoundError: If workflow doesn't exist
            WorkflowExecutionError: If execution fails
            WorkflowTimeoutError: If execution times out
        """
        ...
    
    @abstractmethod
    async def pause_workflow_execution(
        self,
        execution_id: UUID,
        reason: str | None = None
    ) -> None:
        """
        Pause a running workflow execution.
        
        Args:
            execution_id: ID of execution to pause
            reason: Optional pause reason
            
        Raises:
            ExecutionNotFoundError: If execution doesn't exist
            ExecutionNotRunningError: If execution not running
        """
        ...
    
    @abstractmethod
    async def resume_workflow_execution(
        self,
        execution_id: UUID,
        override_data: dict[str, Any] | None = None
    ) -> None:
        """
        Resume a paused workflow execution.
        
        Args:
            execution_id: ID of execution to resume
            override_data: Optional data to override
            
        Raises:
            ExecutionNotFoundError: If execution doesn't exist
            ExecutionNotPausedError: If execution not paused
        """
        ...
    
    @abstractmethod
    async def cancel_workflow_execution(
        self,
        execution_id: UUID,
        reason: str
    ) -> None:
        """
        Cancel a workflow execution.
        
        Args:
            execution_id: ID of execution to cancel
            reason: Cancellation reason
            
        Raises:
            ExecutionNotFoundError: If execution doesn't exist
            ExecutionAlreadyCompletedError: If already completed
        """
        ...
    
    @abstractmethod
    async def get_execution_status(
        self,
        execution_id: UUID
    ) -> dict[str, Any]:
        """
        Get workflow execution status.
        
        Args:
            execution_id: ID of execution
            
        Returns:
            Execution status and progress
        """
        ...
    
    @abstractmethod
    async def handle_step_failure(
        self,
        execution_id: UUID,
        step_id: str,
        error: Exception,
        retry_config: dict[str, Any] | None = None
    ) -> str:
        """
        Handle workflow step failure.
        
        Args:
            execution_id: ID of execution
            step_id: ID of failed step
            error: The error that occurred
            retry_config: Optional retry configuration
            
        Returns:
            Action taken (retry, skip, fail, etc)
        """
        ...
    
    @abstractmethod
    async def evaluate_condition(
        self,
        condition: dict[str, Any],
        context: dict[str, Any]
    ) -> bool:
        """
        Evaluate a workflow condition.
        
        Args:
            condition: Condition definition
            context: Evaluation context
            
        Returns:
            True if condition is met
        """
        ...
    
    @abstractmethod
    async def transform_step_data(
        self,
        step: "WorkflowStep",
        input_data: dict[str, Any],
        previous_results: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Transform data between workflow steps.
        
        Args:
            step: Current workflow step
            input_data: Original input data
            previous_results: Results from previous steps
            
        Returns:
            Transformed data for step
        """
        ...
    
    @abstractmethod
    async def schedule_workflow(
        self,
        workflow_id: UUID,
        schedule: dict[str, Any],
        input_data: dict[str, Any] | None = None
    ) -> UUID:
        """
        Schedule workflow execution.
        
        Args:
            workflow_id: ID of workflow
            schedule: Schedule configuration
            input_data: Optional default input data
            
        Returns:
            ID of scheduled job
        """
        ...
    
    @abstractmethod
    async def validate_workflow(
        self,
        workflow_definition: "WorkflowDefinition"
    ) -> tuple[bool, list[str]]:
        """
        Validate workflow definition.
        
        Args:
            workflow_definition: Workflow to validate
            
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        ...
    
    @abstractmethod
    async def get_workflow_metrics(
        self,
        workflow_id: UUID,
        include_step_metrics: bool = True
    ) -> dict[str, Any]:
        """
        Get workflow execution metrics.
        
        Args:
            workflow_id: ID of workflow
            include_step_metrics: Include per-step metrics
            
        Returns:
            Workflow metrics and statistics
        """
        ...