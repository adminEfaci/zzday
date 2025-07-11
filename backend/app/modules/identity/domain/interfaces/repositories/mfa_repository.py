"""MFA Repository Interface

Domain contract for MFA device data access that must be implemented by the infrastructure layer.
"""

from abc import abstractmethod
from typing import TYPE_CHECKING, Protocol
from uuid import UUID

if TYPE_CHECKING:
    from app.modules.identity.domain.entities.admin.mfa_device import MFADevice


class IMFARepository(Protocol):
    """Repository interface for MFA device management."""
    
    @abstractmethod
    async def save(self, device: 'MFADevice') -> None:
        """Save MFA device entity (create or update).
        
        Args:
            device: MFA device entity to save
        """
        ...
    
    @abstractmethod
    async def find_by_id(self, device_id: UUID) -> 'MFADevice' | None:
        """Find MFA device by ID.
        
        Args:
            device_id: Device identifier
            
        Returns:
            MFA device entity if found, None otherwise
        """
        ...
    
    @abstractmethod
    async def find_by_user(self, user_id: UUID) -> list['MFADevice']:
        """Find all MFA devices for user.
        
        Args:
            user_id: User identifier
            
        Returns:
            List of user's MFA device entities
        """
        ...
    
    @abstractmethod
    async def find_verified_by_user(self, user_id: UUID) -> list['MFADevice']:
        """Find verified MFA devices for user.
        
        Args:
            user_id: User identifier
            
        Returns:
            List of verified MFA device entities
        """
        ...
    
    @abstractmethod
    async def delete(self, device_id: UUID) -> bool:
        """Delete MFA device.
        
        Args:
            device_id: Device identifier
            
        Returns:
            True if deleted, False if not found
        """
        ...
    
    @abstractmethod
    async def exists(self, device_id: UUID) -> bool:
        """Check if MFA device exists.
        
        Args:
            device_id: Device identifier
            
        Returns:
            True if device exists
        """
        ...
    
    @abstractmethod
    async def find_primary_device(self, user_id: UUID) -> 'MFADevice' | None:
        """Find primary MFA device for user.
        
        Args:
            user_id: User identifier
            
        Returns:
            Primary MFA device entity if found, None otherwise
        """
        ...
    
    @abstractmethod
    async def count_devices_by_user(self, user_id: UUID) -> int:
        """Count MFA devices for user.
        
        Args:
            user_id: User identifier
            
        Returns:
            Number of MFA devices
        """
        ...
    
    @abstractmethod
    async def find_by_method(self, user_id: UUID, method: str) -> list['MFADevice']:
        """Find MFA devices by method type.
        
        Args:
            user_id: User identifier
            method: MFA method type
            
        Returns:
            List of MFA device entities
        """
        ...