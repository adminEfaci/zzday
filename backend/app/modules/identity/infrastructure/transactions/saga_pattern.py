"""Saga pattern implementation for distributed transactions.

This module provides saga pattern support for managing distributed transactions
across multiple services and ensuring data consistency in microservices architecture.
"""

import asyncio
import uuid
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Type, Union
from dataclasses import dataclass, field

from app.core.logging import get_logger

logger = get_logger(__name__)


class SagaStatus(Enum):
    """Saga execution status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    COMPENSATING = "compensating"
    COMPENSATED = "compensated"


class StepStatus(Enum):
    """Individual step status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    COMPENSATING = "compensating"
    COMPENSATED = "compensated"


@dataclass
class SagaStep:
    """Individual step in a saga."""
    step_id: str
    name: str
    action: callable
    compensation: Optional[callable] = None
    status: StepStatus = StepStatus.PENDING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error: Optional[str] = None
    result: Optional[Any] = None
    compensation_result: Optional[Any] = None
    retry_count: int = 0
    max_retries: int = 3
    timeout: int = 30  # seconds
    
    def __post_init__(self):
        if not self.step_id:
            self.step_id = str(uuid.uuid4())


@dataclass
class SagaExecution:
    """Saga execution state."""
    saga_id: str
    name: str
    steps: List[SagaStep]
    status: SagaStatus = SagaStatus.PENDING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    current_step: int = 0
    context: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    
    def __post_init__(self):
        if not self.saga_id:
            self.saga_id = str(uuid.uuid4())


class SagaTransaction:
    """Saga transaction coordinator."""
    
    def __init__(self, name: str):
        self.name = name
        self.steps: List[SagaStep] = []
        self.timeout = 300  # 5 minutes default
        self.context: Dict[str, Any] = {}
    
    def add_step(
        self,
        name: str,
        action: callable,
        compensation: Optional[callable] = None,
        max_retries: int = 3,
        timeout: int = 30,
    ) -> "SagaTransaction":
        """Add a step to the saga.
        
        Args:
            name: Step name
            action: Function to execute
            compensation: Optional compensation function
            max_retries: Maximum retry attempts
            timeout: Step timeout in seconds
            
        Returns:
            Self for method chaining
        """
        step = SagaStep(
            step_id=str(uuid.uuid4()),
            name=name,
            action=action,
            compensation=compensation,
            max_retries=max_retries,
            timeout=timeout,
        )
        
        self.steps.append(step)
        return self
    
    def set_context(self, key: str, value: Any) -> "SagaTransaction":
        """Set context value.
        
        Args:
            key: Context key
            value: Context value
            
        Returns:
            Self for method chaining
        """
        self.context[key] = value
        return self
    
    def set_timeout(self, timeout: int) -> "SagaTransaction":
        """Set saga timeout.
        
        Args:
            timeout: Timeout in seconds
            
        Returns:
            Self for method chaining
        """
        self.timeout = timeout
        return self
    
    async def execute(self) -> SagaExecution:
        """Execute the saga.
        
        Returns:
            SagaExecution: Execution result
        """
        execution = SagaExecution(
            saga_id=str(uuid.uuid4()),
            name=self.name,
            steps=self.steps.copy(),
            context=self.context.copy(),
        )
        
        coordinator = SagaCoordinator()
        return await coordinator.execute_saga(execution)


class SagaCoordinator:
    """Coordinates saga execution."""
    
    def __init__(self):
        self.running_sagas: Dict[str, SagaExecution] = {}
    
    async def execute_saga(self, execution: SagaExecution) -> SagaExecution:
        """Execute a saga.
        
        Args:
            execution: Saga execution to run
            
        Returns:
            SagaExecution: Completed execution
        """
        execution.status = SagaStatus.RUNNING
        execution.started_at = datetime.utcnow()
        
        self.running_sagas[execution.saga_id] = execution
        
        logger.info(
            "Starting saga execution",
            saga_id=execution.saga_id,
            name=execution.name,
            steps=len(execution.steps),
        )
        
        try:
            # Execute steps sequentially
            for i, step in enumerate(execution.steps):
                execution.current_step = i
                
                success = await self._execute_step(step, execution.context)
                
                if not success:
                    # Step failed, start compensation
                    execution.status = SagaStatus.COMPENSATING
                    execution.error = step.error
                    
                    await self._compensate_saga(execution)
                    
                    execution.status = SagaStatus.COMPENSATED
                    execution.completed_at = datetime.utcnow()
                    
                    logger.error(
                        "Saga failed and compensated",
                        saga_id=execution.saga_id,
                        failed_step=step.name,
                        error=step.error,
                    )
                    
                    return execution
            
            # All steps completed successfully
            execution.status = SagaStatus.COMPLETED
            execution.completed_at = datetime.utcnow()
            
            logger.info(
                "Saga completed successfully",
                saga_id=execution.saga_id,
                name=execution.name,
                duration=(execution.completed_at - execution.started_at).total_seconds(),
            )
            
        except Exception as e:
            execution.status = SagaStatus.FAILED
            execution.error = str(e)
            execution.completed_at = datetime.utcnow()
            
            logger.exception(
                "Saga execution failed",
                saga_id=execution.saga_id,
                error=str(e),
            )
            
            # Attempt compensation
            try:
                await self._compensate_saga(execution)
                execution.status = SagaStatus.COMPENSATED
            except Exception as comp_error:
                logger.exception(
                    "Saga compensation failed",
                    saga_id=execution.saga_id,
                    compensation_error=str(comp_error),
                )
        
        finally:
            if execution.saga_id in self.running_sagas:
                del self.running_sagas[execution.saga_id]
        
        return execution
    
    async def _execute_step(self, step: SagaStep, context: Dict[str, Any]) -> bool:
        """Execute a single step.
        
        Args:
            step: Step to execute
            context: Execution context
            
        Returns:
            bool: True if successful
        """
        step.status = StepStatus.RUNNING
        step.started_at = datetime.utcnow()
        
        logger.debug(
            "Executing saga step",
            step_id=step.step_id,
            name=step.name,
            retry_count=step.retry_count,
        )
        
        for attempt in range(step.max_retries + 1):
            try:
                # Execute step with timeout
                if asyncio.iscoroutinefunction(step.action):
                    step.result = await asyncio.wait_for(
                        step.action(context),
                        timeout=step.timeout
                    )
                else:
                    step.result = step.action(context)
                
                step.status = StepStatus.COMPLETED
                step.completed_at = datetime.utcnow()
                
                logger.debug(
                    "Saga step completed",
                    step_id=step.step_id,
                    name=step.name,
                    attempt=attempt + 1,
                )
                
                return True
                
            except asyncio.TimeoutError:
                step.error = f"Step timeout after {step.timeout} seconds"
                logger.warning(
                    "Saga step timeout",
                    step_id=step.step_id,
                    name=step.name,
                    timeout=step.timeout,
                    attempt=attempt + 1,
                )
                
            except Exception as e:
                step.error = str(e)
                logger.warning(
                    "Saga step failed",
                    step_id=step.step_id,
                    name=step.name,
                    error=str(e),
                    attempt=attempt + 1,
                )
            
            # Retry if not last attempt
            if attempt < step.max_retries:
                step.retry_count += 1
                await asyncio.sleep(2 ** attempt)  # Exponential backoff
        
        step.status = StepStatus.FAILED
        step.completed_at = datetime.utcnow()
        
        logger.error(
            "Saga step failed after all retries",
            step_id=step.step_id,
            name=step.name,
            error=step.error,
            total_attempts=step.max_retries + 1,
        )
        
        return False
    
    async def _compensate_saga(self, execution: SagaExecution) -> None:
        """Compensate completed steps in reverse order.
        
        Args:
            execution: Saga execution to compensate
        """
        logger.info(
            "Starting saga compensation",
            saga_id=execution.saga_id,
            name=execution.name,
        )
        
        # Compensate in reverse order
        for i in range(execution.current_step, -1, -1):
            step = execution.steps[i]
            
            # Only compensate completed steps
            if step.status == StepStatus.COMPLETED and step.compensation:
                await self._compensate_step(step, execution.context)
    
    async def _compensate_step(self, step: SagaStep, context: Dict[str, Any]) -> None:
        """Compensate a single step.
        
        Args:
            step: Step to compensate
            context: Execution context
        """
        step.status = StepStatus.COMPENSATING
        
        logger.debug(
            "Compensating saga step",
            step_id=step.step_id,
            name=step.name,
        )
        
        try:
            if asyncio.iscoroutinefunction(step.compensation):
                step.compensation_result = await asyncio.wait_for(
                    step.compensation(context),
                    timeout=step.timeout
                )
            else:
                step.compensation_result = step.compensation(context)
            
            step.status = StepStatus.COMPENSATED
            
            logger.debug(
                "Saga step compensated",
                step_id=step.step_id,
                name=step.name,
            )
            
        except Exception as e:
            logger.exception(
                "Saga step compensation failed",
                step_id=step.step_id,
                name=step.name,
                error=str(e),
            )
            # Continue with other compensations
    
    def get_saga_status(self, saga_id: str) -> Optional[SagaExecution]:
        """Get saga execution status.
        
        Args:
            saga_id: Saga ID
            
        Returns:
            SagaExecution or None if not found
        """
        return self.running_sagas.get(saga_id)
    
    def get_running_sagas(self) -> Dict[str, SagaExecution]:
        """Get all running sagas.
        
        Returns:
            Dict of running sagas
        """
        return self.running_sagas.copy()


class SagaManager:
    """High-level saga management."""
    
    def __init__(self):
        self.coordinator = SagaCoordinator()
        self.saga_history: Dict[str, SagaExecution] = {}
    
    def create_saga(self, name: str) -> SagaTransaction:
        """Create a new saga transaction.
        
        Args:
            name: Saga name
            
        Returns:
            SagaTransaction: New saga transaction
        """
        return SagaTransaction(name)
    
    async def execute_saga(self, saga: SagaTransaction) -> SagaExecution:
        """Execute a saga.
        
        Args:
            saga: Saga transaction to execute
            
        Returns:
            SagaExecution: Execution result
        """
        execution = await saga.execute()
        
        # Store in history
        self.saga_history[execution.saga_id] = execution
        
        return execution
    
    def get_saga_history(self, limit: int = 100) -> List[SagaExecution]:
        """Get saga execution history.
        
        Args:
            limit: Maximum number of results
            
        Returns:
            List of saga executions
        """
        executions = list(self.saga_history.values())
        executions.sort(key=lambda x: x.started_at or datetime.min, reverse=True)
        return executions[:limit]
    
    def get_saga_stats(self) -> Dict[str, Any]:
        """Get saga statistics.
        
        Returns:
            Dict containing saga statistics
        """
        total_sagas = len(self.saga_history)
        running_sagas = len(self.coordinator.running_sagas)
        
        status_counts = {}
        for execution in self.saga_history.values():
            status = execution.status.value
            status_counts[status] = status_counts.get(status, 0) + 1
        
        return {
            "total_sagas": total_sagas,
            "running_sagas": running_sagas,
            "status_counts": status_counts,
            "success_rate": status_counts.get("completed", 0) / max(total_sagas, 1),
        }


# Global saga manager
_saga_manager = SagaManager()


def get_saga_manager() -> SagaManager:
    """Get the global saga manager.
    
    Returns:
        SagaManager: Global saga manager instance
    """
    return _saga_manager


# Convenience functions
def create_saga(name: str) -> SagaTransaction:
    """Create a new saga transaction.
    
    Args:
        name: Saga name
        
    Returns:
        SagaTransaction: New saga transaction
    """
    return get_saga_manager().create_saga(name)


async def execute_saga(saga: SagaTransaction) -> SagaExecution:
    """Execute a saga.
    
    Args:
        saga: Saga transaction to execute
        
    Returns:
        SagaExecution: Execution result
    """
    return await get_saga_manager().execute_saga(saga)


# Example usage functions
async def example_user_registration_saga():
    """Example saga for user registration across multiple services."""
    
    async def create_user_account(context: Dict[str, Any]) -> Dict[str, Any]:
        """Create user account."""
        # Simulate user account creation
        user_id = str(uuid.uuid4())
        context["user_id"] = user_id
        return {"user_id": user_id}
    
    async def compensate_user_account(context: Dict[str, Any]) -> None:
        """Compensate user account creation."""
        # Simulate user account deletion
        user_id = context.get("user_id")
        logger.info(f"Compensating user account: {user_id}")
    
    async def send_welcome_email(context: Dict[str, Any]) -> Dict[str, Any]:
        """Send welcome email."""
        # Simulate email sending
        user_id = context.get("user_id")
        email_id = str(uuid.uuid4())
        context["email_id"] = email_id
        return {"email_id": email_id}
    
    async def compensate_welcome_email(context: Dict[str, Any]) -> None:
        """Compensate welcome email."""
        # Simulate email cancellation (if possible)
        email_id = context.get("email_id")
        logger.info(f"Compensating welcome email: {email_id}")
    
    async def setup_user_profile(context: Dict[str, Any]) -> Dict[str, Any]:
        """Set up user profile."""
        # Simulate profile setup
        user_id = context.get("user_id")
        profile_id = str(uuid.uuid4())
        context["profile_id"] = profile_id
        return {"profile_id": profile_id}
    
    async def compensate_user_profile(context: Dict[str, Any]) -> None:
        """Compensate user profile setup."""
        # Simulate profile deletion
        profile_id = context.get("profile_id")
        logger.info(f"Compensating user profile: {profile_id}")
    
    # Create and execute saga
    saga = (create_saga("user_registration")
            .add_step("create_account", create_user_account, compensate_user_account)
            .add_step("send_welcome_email", send_welcome_email, compensate_welcome_email)
            .add_step("setup_profile", setup_user_profile, compensate_user_profile)
            .set_context("email", "user@example.com")
            .set_timeout(120))
    
    return await execute_saga(saga)