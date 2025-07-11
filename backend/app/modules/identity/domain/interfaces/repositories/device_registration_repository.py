"""Device Registration Repository Interface

Domain contract for device registration data access that must be implemented by the infrastructure layer.
"""

from typing import Protocol
from uuid import UUID

from app.modules.identity.domain.enums import DevicePlatform, DeviceType


class IDeviceRegistrationRepository(Protocol):
    """Repository interface for device registration management."""
    
    async def create(
        self, 
        user_id: UUID,
        device_name: str,
        device_type: DeviceType,
        platform: DevicePlatform,
        device_fingerprint: str,
        is_trusted: bool = False,
        metadata: dict | None = None
    ) -> UUID:
        """Register new device.
        
        Args:
            user_id: User identifier
            device_name: User-friendly device name
            device_type: Device type (mobile, desktop, etc.)
            platform: Device platform (iOS, Android, etc.)
            device_fingerprint: Unique device fingerprint
            is_trusted: Whether device is trusted
            metadata: Additional device metadata
            
        Returns:
            Created device registration ID
        """
        ...
    
    async def find_by_id(self, device_id: UUID) -> dict | None:
        """Find device registration by ID.
        
        Args:
            device_id: Device identifier
            
        Returns:
            Device data if found, None otherwise
        """
        ...
    
    async def find_by_user(self, user_id: UUID) -> list[dict]:
        """Find all registered devices for user.
        
        Args:
            user_id: User identifier
            
        Returns:
            List of user's registered devices
        """
        ...
    
    async def find_by_fingerprint(
        self, 
        device_fingerprint: str
    ) -> dict | None:
        """Find device by fingerprint.
        
        Args:
            device_fingerprint: Device fingerprint
            
        Returns:
            Device data if found, None otherwise
        """
        ...
    
    async def trust_device(self, device_id: UUID) -> bool:
        """Mark device as trusted.
        
        Args:
            device_id: Device identifier
            
        Returns:
            True if trusted, False if not found
        """
        ...
    
    async def revoke_trust(self, device_id: UUID) -> bool:
        """Revoke trust from device.
        
        Args:
            device_id: Device identifier
            
        Returns:
            True if trust revoked, False if not found
        """
        ...
    
    async def update_last_seen(
        self, 
        device_id: UUID,
        ip_address: str | None = None,
        location: str | None = None
    ) -> bool:
        """Update device last seen information.
        
        Args:
            device_id: Device identifier
            ip_address: Last seen IP address
            location: Last seen location
            
        Returns:
            True if updated, False if not found
        """
        ...
    
    async def delete_device(self, device_id: UUID) -> bool:
        """Delete device registration.
        
        Args:
            device_id: Device identifier
            
        Returns:
            True if deleted, False if not found
        """
        ...