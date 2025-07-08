"""
MFA Device Repository Implementation

Adapter implementation of the MFA device repository interface 
that wraps the existing MFA repository and provides domain entities.
"""

from typing import Any
from uuid import UUID

from sqlmodel import Session
from app.modules.identity.domain.interfaces.repositories.mfa_device_repository import IMFADeviceRepository
from app.modules.identity.domain.entities.admin.mfa_device import MFADevice, DeviceName, MFASecret
from app.modules.identity.domain.enums import MFAMethod
from app.modules.identity.infrastructure.repositories.mfa_repository import SQLMFARepository
from app.core.errors import InfrastructureError
from app.core.logging import get_logger
from datetime import datetime, UTC


logger = get_logger(__name__)


class SQLMFADeviceRepository(IMFADeviceRepository):
    """SQL implementation of MFA device repository interface."""
    
    def __init__(self, session: Session):
        """Initialize repository with database session.
        
        Args:
            session: SQLModel database session
        """
        self.session = session
        self._mfa_repo = SQLMFARepository(session)
    
    async def add(self, device: MFADevice) -> None:
        """Add MFA device.
        
        Args:
            device: MFA device entity
        """
        try:
            # Use the existing create method with device data
            await self._mfa_repo.create(
                user_id=device.user_id,
                device_name=device.device_name.value,
                device_type=device.method,
                secret=device.secret.value,
                backup_codes=[code.value for code in device.backup_codes] if device.backup_codes else None,
                is_verified=device.verified
            )
            
            logger.info(
                "MFA device added successfully",
                device_id=str(device.id),
                user_id=str(device.user_id),
                method=device.method.value
            )
            
        except Exception as e:
            logger.error(
                "Failed to add MFA device",
                device_id=str(device.id),
                error=str(e)
            )
            raise InfrastructureError(f"Failed to add MFA device: {str(e)}")
    
    async def get_by_id(self, device_id: UUID) -> MFADevice | None:
        """Get MFA device by ID.
        
        Args:
            device_id: Device identifier
            
        Returns:
            MFA device entity if found, None otherwise
        """
        try:
            device_data = await self._mfa_repo.find_by_id(device_id)
            
            if not device_data:
                return None
            
            return self._dict_to_entity(device_data)
            
        except Exception as e:
            logger.error(
                "Failed to get MFA device by ID",
                device_id=str(device_id),
                error=str(e)
            )
            raise InfrastructureError(f"Failed to get MFA device: {str(e)}")
    
    async def get_by_user_id(self, user_id: UUID) -> list[MFADevice]:
        """Get all MFA devices for user.
        
        Args:
            user_id: User identifier
            
        Returns:
            List of MFA device entities
        """
        try:
            devices_data = await self._mfa_repo.find_by_user(user_id)
            
            return [self._dict_to_entity(data) for data in devices_data]
            
        except Exception as e:
            logger.error(
                "Failed to get MFA devices for user",
                user_id=str(user_id),
                error=str(e)
            )
            raise InfrastructureError(f"Failed to get user MFA devices: {str(e)}")
    
    async def get_verified_devices(self, user_id: UUID) -> list[MFADevice]:
        """Get verified MFA devices for user.
        
        Args:
            user_id: User identifier
            
        Returns:
            List of verified MFA device entities
        """
        try:
            devices_data = await self._mfa_repo.find_verified_by_user(user_id)
            
            return [self._dict_to_entity(data) for data in devices_data]
            
        except Exception as e:
            logger.error(
                "Failed to get verified MFA devices",
                user_id=str(user_id),
                error=str(e)
            )
            raise InfrastructureError(f"Failed to get verified devices: {str(e)}")
    
    async def get_by_user_and_method(
        self,
        user_id: UUID,
        method: MFAMethod
    ) -> list[MFADevice]:
        """Get MFA devices by user and method.
        
        Args:
            user_id: User identifier
            method: MFA method type
            
        Returns:
            List of MFA device entities matching criteria
        """
        try:
            # Get all user devices
            devices_data = await self._mfa_repo.find_by_user(user_id)
            
            # Filter by method
            filtered = [
                data for data in devices_data 
                if data.get('method') == method.value
            ]
            
            return [self._dict_to_entity(data) for data in filtered]
            
        except Exception as e:
            logger.error(
                "Failed to get MFA devices by user and method",
                user_id=str(user_id),
                method=method.value,
                error=str(e)
            )
            raise InfrastructureError(f"Failed to get devices by method: {str(e)}")
    
    async def update(self, device: MFADevice) -> None:
        """Update MFA device.
        
        Args:
            device: MFA device entity
        """
        try:
            # Get the model directly from session
            from app.modules.identity.infrastructure.models.mfa_model import MFADeviceModel
            
            model = await self.session.get(MFADeviceModel, device.id)
            if not model:
                raise InfrastructureError(f"MFA device {device.id} not found")
            
            # Update model attributes
            model.device_name = device.device_name.value
            model.verified = device.verified
            model.verified_at = device.verified_at if hasattr(device, 'verified_at') else None
            model.is_primary = device.is_primary
            model.last_used = device.last_used
            model.failed_attempts = device.failed_attempts
            model.locked_until = device.locked_until
            model.updated_at = datetime.now(UTC)
            
            # Update method-specific attributes
            if device.phone_number:
                model.phone_number = device.phone_number
            if device.email:
                model.email = device.email
            if device.credential_id:
                model.credential_id = device.credential_id
            
            # Handle backup codes update
            if hasattr(device, 'backup_codes_used'):
                model.recovery_codes_used = device.backup_codes_used
            
            self.session.add(model)
            await self.session.commit()
            
            logger.info(
                "MFA device updated successfully",
                device_id=str(device.id)
            )
            
        except Exception as e:
            await self.session.rollback()
            logger.error(
                "Failed to update MFA device",
                device_id=str(device.id),
                error=str(e)
            )
            raise InfrastructureError(f"Failed to update MFA device: {str(e)}")
    
    async def delete(self, device_id: UUID) -> None:
        """Delete MFA device.
        
        Args:
            device_id: Device identifier
        """
        try:
            await self._mfa_repo.disable_device(device_id)
            
            logger.info(
                "MFA device deleted successfully",
                device_id=str(device_id)
            )
            
        except Exception as e:
            logger.error(
                "Failed to delete MFA device",
                device_id=str(device_id),
                error=str(e)
            )
            raise InfrastructureError(f"Failed to delete MFA device: {str(e)}")
    
    def _dict_to_entity(self, data: dict[str, Any]) -> MFADevice:
        """Convert dictionary data to MFA device entity.
        
        Args:
            data: Device data dictionary
            
        Returns:
            MFA device entity
        """
        # Create value objects
        device_name = DeviceName(value=data['device_name'])
        secret = MFASecret(value=data.get('secret', ''), algorithm=data.get('algorithm', 'sha1'))
        
        # Create device entity
        device = MFADevice(
            id=data['id'],
            user_id=data['user_id'],
            method=MFAMethod(data['method']),
            device_name=device_name,
            secret=secret,
            backup_codes=[],  # Will be loaded separately if needed
            verified=data.get('verified', False),
            is_primary=data.get('is_primary', False),
            created_at=data.get('created_at', datetime.now(UTC)),
            last_used=data.get('last_used'),
            failed_attempts=data.get('failed_attempts', 0),
            locked_until=data.get('locked_until'),
            phone_number=data.get('phone_number'),
            email=data.get('email'),
            credential_id=data.get('credential_id')
        )
        
        # Set verified_at if device is verified
        if device.verified and data.get('verified_at'):
            device.verified_at = data['verified_at']
        
        # Set backup codes count if available
        if 'active_backup_codes' in data:
            device.backup_codes_count = data['active_backup_codes']
        
        # Set backup codes used count if available
        if 'recovery_codes_used' in data:
            device.backup_codes_used = data['recovery_codes_used']
        
        return device