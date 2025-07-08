"""
Task Queue Port Interface

Port for asynchronous task queue operations.
"""

from abc import ABC, abstractmethod
from typing import Any
from uuid import UUID


class ITaskQueuePort(ABC):
    """Port for task queue operations."""
    
    @abstractmethod
    async def queue_email_verification(
        self,
        user_id: UUID,
        email: str,
        token: str
    ) -> str:
        """
        Queue email verification task.
        
        Args:
            user_id: User identifier
            email: Email to verify
            token: Verification token
            
        Returns:
            Task ID
        """
    
    @abstractmethod
    async def queue_welcome_email(self, user_id: UUID) -> str:
        """
        Queue welcome email task.
        
        Args:
            user_id: User identifier
            
        Returns:
            Task ID
        """
    
    @abstractmethod
    async def queue_password_reset_email(
        self,
        user_id: UUID,
        reset_token: str
    ) -> str:
        """
        Queue password reset email.
        
        Args:
            user_id: User identifier
            reset_token: Reset token
            
        Returns:
            Task ID
        """
    
    @abstractmethod
    async def queue_security_alert(
        self,
        user_id: UUID,
        alert_type: str,
        context: dict[str, Any]
    ) -> str:
        """
        Queue security alert.
        
        Args:
            user_id: User identifier
            alert_type: Type of alert
            context: Alert context
            
        Returns:
            Task ID
        """
    
    @abstractmethod
    async def queue_profile_completion_check(self, user_id: UUID) -> str:
        """
        Queue profile completion check.
        
        Args:
            user_id: User identifier
            
        Returns:
            Task ID
        """
    
    @abstractmethod
    async def queue_avatar_processing(
        self,
        user_id: UUID,
        file_path: str
    ) -> str:
        """
        Queue avatar processing task.
        
        Args:
            user_id: User identifier
            file_path: Path to avatar file
            
        Returns:
            Task ID
        """
    
    @abstractmethod
    async def get_task_status(self, task_id: str) -> dict[str, Any]:
        """
        Get task execution status.
        
        Args:
            task_id: Task identifier
            
        Returns:
            Task status information
        """
