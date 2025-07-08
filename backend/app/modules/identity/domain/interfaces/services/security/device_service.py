"""
Device Management Service Interface

Port for device registration, trust management, and tracking.
"""

from abc import ABC, abstractmethod
from typing import Any
from uuid import UUID


class IDeviceService(ABC):
    """Port for device management operations."""
    
    @abstractmethod
    async def register_device(
        self,
        user_id: UUID,
        device_info: dict[str, Any]
    ) -> UUID:
        """
        Register new device.
        
        Args:
            user_id: User identifier
            device_info: Device details
            
        Returns:
            Device ID
        """
    
    @abstractmethod
    async def trust_device(
        self,
        device_id: UUID,
        trust_duration: int | None = None
    ) -> None:
        """
        Mark device as trusted.
        
        Args:
            device_id: Device identifier
            trust_duration: Trust duration in days (None for permanent)
        """
    
    @abstractmethod
    async def is_device_trusted(self, device_id: UUID) -> bool:
        """
        Check if device is trusted.
        
        Args:
            device_id: Device identifier
            
        Returns:
            True if device is trusted
        """
    
    @abstractmethod
    async def revoke_device_trust(self, device_id: UUID) -> bool:
        """
        Revoke device trust.
        
        Args:
            device_id: Device identifier
            
        Returns:
            True if revoked successfully
        """
    
    @abstractmethod
    async def get_user_devices(self, user_id: UUID) -> list[dict[str, Any]]:
        """
        Get all user devices.
        
        Args:
            user_id: User identifier
            
        Returns:
            List of device information
        """
    
    @abstractmethod
    async def update_device_info(
        self,
        device_id: UUID,
        device_info: dict[str, Any]
    ) -> bool:
        """
        Update device information.
        
        Args:
            device_id: Device identifier
            device_info: Updated device details
            
        Returns:
            True if updated successfully
        """
