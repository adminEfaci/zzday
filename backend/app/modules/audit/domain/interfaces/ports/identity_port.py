"""Identity port interface for audit domain.

This module defines the contract for integrating with the Identity module,
following the Dependency Inversion Principle.
"""

from abc import ABC, abstractmethod
from typing import Any
from uuid import UUID


class IIdentityPort(ABC):
    """
    Port interface for Identity module integration.
    
    This interface defines the contract for audit domain to interact
    with identity services without direct dependencies.
    """

    @abstractmethod
    async def get_user_info(self, user_id: UUID) -> dict[str, Any] | None:
        """
        Get user information for audit context.
        
        Args:
            user_id: User identifier
            
        Returns:
            User information dict or None if not found
        """

    @abstractmethod
    async def get_session_info(self, session_id: UUID) -> dict[str, Any] | None:
        """
        Get session information for audit context.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Session information dict or None if not found
        """

    @abstractmethod
    async def validate_user_permissions(
        self, user_id: UUID, resource: str, action: str
    ) -> bool:
        """
        Validate user permissions for audit operations.
        
        Args:
            user_id: User identifier
            resource: Resource being accessed
            action: Action being performed
            
        Returns:
            True if user has permission
        """

    @abstractmethod
    async def get_user_roles(self, user_id: UUID) -> list[str]:
        """
        Get user roles for audit metadata.
        
        Args:
            user_id: User identifier
            
        Returns:
            List of user role names
        """

    @abstractmethod
    async def is_user_active(self, user_id: UUID) -> bool:
        """
        Check if user is currently active.
        
        Args:
            user_id: User identifier
            
        Returns:
            True if user is active
        """

    @abstractmethod
    async def get_user_groups(self, user_id: UUID) -> list[str]:
        """
        Get user groups for audit context.
        
        Args:
            user_id: User identifier
            
        Returns:
            List of group names
        """

    @abstractmethod
    async def resolve_user_display_name(self, user_id: UUID) -> str | None:
        """
        Resolve user display name for audit reports.
        
        Args:
            user_id: User identifier
            
        Returns:
            User display name or None if not found
        """
