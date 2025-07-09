"""
Identity Module Public Contract

This module defines the public interface that other modules can use to interact
with the Identity module. This contract ensures loose coupling between modules
and maintains clear boundaries.

Key Principles:
- Only expose necessary operations
- Use DTOs for data transfer
- No domain objects exposed
- Async/await for all operations
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


# DTOs for Identity Module Communication
class UserInfoDTO(BaseModel):
    """Basic user information DTO."""
    
    id: UUID
    email: str
    username: Optional[str] = None
    is_active: bool = True
    created_at: datetime
    
    class Config:
        json_encoders = {
            UUID: str,
            datetime: lambda v: v.isoformat()
        }


class UserAuthenticationDTO(BaseModel):
    """User authentication result DTO."""
    
    user_id: UUID
    is_authenticated: bool
    session_id: Optional[UUID] = None
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    expires_at: Optional[datetime] = None


class UserPermissionCheckDTO(BaseModel):
    """Permission check result DTO."""
    
    user_id: UUID
    permission: str
    resource: Optional[str] = None
    is_allowed: bool
    checked_at: datetime = Field(default_factory=datetime.utcnow)


class UserRoleDTO(BaseModel):
    """User role information DTO."""
    
    id: UUID
    name: str
    permissions: List[str] = []


class SessionInfoDTO(BaseModel):
    """Session information DTO."""
    
    id: UUID
    user_id: UUID
    is_active: bool
    created_at: datetime
    last_activity: datetime
    expires_at: Optional[datetime] = None
    device_info: Optional[Dict[str, Any]] = None


class IIdentityContract(ABC):
    """
    Public contract for Identity module.
    
    This interface defines all operations that other modules can perform
    with the Identity module. All methods are async and return DTOs.
    """
    
    @abstractmethod
    async def get_user_by_id(self, user_id: UUID) -> Optional[UserInfoDTO]:
        """
        Get basic user information by ID.
        
        Args:
            user_id: User identifier
            
        Returns:
            UserInfoDTO if user exists, None otherwise
        """
        pass
    
    @abstractmethod
    async def get_user_by_email(self, email: str) -> Optional[UserInfoDTO]:
        """
        Get basic user information by email.
        
        Args:
            email: User email address
            
        Returns:
            UserInfoDTO if user exists, None otherwise
        """
        pass
    
    @abstractmethod
    async def get_users_by_ids(self, user_ids: List[UUID]) -> List[UserInfoDTO]:
        """
        Get multiple users by their IDs.
        
        Args:
            user_ids: List of user identifiers
            
        Returns:
            List of UserInfoDTO for found users
        """
        pass
    
    @abstractmethod
    async def authenticate_user(
        self, 
        email: str, 
        password: str,
        device_info: Optional[Dict[str, Any]] = None
    ) -> UserAuthenticationDTO:
        """
        Authenticate user with credentials.
        
        Args:
            email: User email
            password: User password
            device_info: Optional device information
            
        Returns:
            UserAuthenticationDTO with authentication result
        """
        pass
    
    @abstractmethod
    async def validate_session(self, session_id: UUID) -> Optional[SessionInfoDTO]:
        """
        Validate if session is active and valid.
        
        Args:
            session_id: Session identifier
            
        Returns:
            SessionInfoDTO if session is valid, None otherwise
        """
        pass
    
    @abstractmethod
    async def check_permission(
        self, 
        user_id: UUID, 
        permission: str,
        resource: Optional[str] = None
    ) -> UserPermissionCheckDTO:
        """
        Check if user has specific permission.
        
        Args:
            user_id: User identifier
            permission: Permission to check
            resource: Optional resource identifier
            
        Returns:
            UserPermissionCheckDTO with check result
        """
        pass
    
    @abstractmethod
    async def get_user_roles(self, user_id: UUID) -> List[UserRoleDTO]:
        """
        Get all roles assigned to user.
        
        Args:
            user_id: User identifier
            
        Returns:
            List of UserRoleDTO
        """
        pass
    
    @abstractmethod
    async def invalidate_session(self, session_id: UUID) -> bool:
        """
        Invalidate user session.
        
        Args:
            session_id: Session identifier
            
        Returns:
            True if session was invalidated, False otherwise
        """
        pass
    
    @abstractmethod
    async def get_active_sessions(self, user_id: UUID) -> List[SessionInfoDTO]:
        """
        Get all active sessions for user.
        
        Args:
            user_id: User identifier
            
        Returns:
            List of active SessionInfoDTO
        """
        pass
    
    @abstractmethod
    async def is_user_active(self, user_id: UUID) -> bool:
        """
        Check if user account is active.
        
        Args:
            user_id: User identifier
            
        Returns:
            True if user is active, False otherwise
        """
        pass