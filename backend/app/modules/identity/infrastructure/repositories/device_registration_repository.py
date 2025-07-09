"""
Device Registration Repository Implementation

SQLModel-based implementation of the device registration repository interface.
"""

from datetime import UTC, datetime
from uuid import UUID

from sqlmodel import Session, and_, func, select

from app.core.errors import InfrastructureError
from app.core.logging import get_logger
from app.modules.identity.domain.entities.device.device_registration import (
    DeviceRegistration,
)
from app.modules.identity.domain.enums import DevicePlatform, DeviceType
from app.modules.identity.domain.interfaces.repositories.device_registration_repository import (
    IDeviceRegistrationRepository,
)
from app.modules.identity.infrastructure.models.device_model import (
    DeviceRegistrationModel,
)

logger = get_logger(__name__)


class SQLDeviceRegistrationRepository(IDeviceRegistrationRepository):
    """SQLModel implementation of device registration repository."""
    
    def __init__(self, session: Session):
        """Initialize repository with database session.
        
        Args:
            session: SQLModel database session
        """
        self.session = session
        self.model_class = DeviceRegistrationModel
    
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
        try:
            # Create domain entity
            device = DeviceRegistration.create(
                user_id=user_id,
                device_id=device_fingerprint,  # Using fingerprint as device_id
                device_name=device_name,
                device_type=device_type,
                fingerprint=device_fingerprint,
                platform=platform,
                push_token=metadata.get('push_token') if metadata else None,
                app_version=metadata.get('app_version') if metadata else None,
                os_version=metadata.get('os_version') if metadata else None
            )
            
            # Set trust if requested
            if is_trusted:
                device.trust()
            
            # Convert to model and save
            model = DeviceRegistrationModel.from_domain(device)
            self.session.add(model)
            await self.session.commit()
            
            logger.info(
                "Device registered successfully",
                device_id=str(device.id),
                user_id=str(user_id),
                platform=platform.value
            )
            
            return device.id
            
        except Exception as e:
            await self.session.rollback()
            logger.error(
                "Failed to register device",
                user_id=str(user_id),
                error=str(e)
            )
            raise InfrastructureError(f"Failed to register device: {e!s}")
    
    async def find_by_id(self, device_id: UUID) -> dict | None:
        """Find device registration by ID.
        
        Args:
            device_id: Device identifier
            
        Returns:
            Device data if found, None otherwise
        """
        try:
            stmt = select(DeviceRegistrationModel).where(DeviceRegistrationModel.id == device_id)
            result = await self.session.exec(stmt)
            model = result.first()
            
            if model:
                return model.to_dict()
            return None
            
        except Exception as e:
            logger.error(
                "Failed to find device by ID",
                device_id=str(device_id),
                error=str(e)
            )
            raise InfrastructureError(f"Failed to find device: {e!s}")
    
    async def find_by_user(self, user_id: UUID) -> list[dict]:
        """Find all registered devices for user.
        
        Args:
            user_id: User identifier
            
        Returns:
            List of user's registered devices
        """
        try:
            stmt = select(DeviceRegistrationModel).where(
                DeviceRegistrationModel.user_id == user_id
            ).order_by(DeviceRegistrationModel.last_seen.desc())
            
            result = await self.session.exec(stmt)
            models = result.all()
            
            return [model.to_dict() for model in models]
            
        except Exception as e:
            logger.error(
                "Failed to find devices for user",
                user_id=str(user_id),
                error=str(e)
            )
            raise InfrastructureError(f"Failed to find user devices: {e!s}")
    
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
        try:
            stmt = select(DeviceRegistrationModel).where(
                DeviceRegistrationModel.fingerprint == device_fingerprint
            )
            result = await self.session.exec(stmt)
            model = result.first()
            
            if model:
                return model.to_dict()
            return None
            
        except Exception as e:
            logger.error(
                "Failed to find device by fingerprint",
                fingerprint=device_fingerprint,
                error=str(e)
            )
            raise InfrastructureError(f"Failed to find device: {e!s}")
    
    async def trust_device(self, device_id: UUID) -> bool:
        """Mark device as trusted.
        
        Args:
            device_id: Device identifier
            
        Returns:
            True if trusted, False if not found
        """
        try:
            model = await self.session.get(DeviceRegistrationModel, device_id)
            if not model:
                return False
            
            # Convert to domain, trust, and save back
            device = model.to_domain()
            device.trust()
            
            # Update model
            model.trusted = device.trusted
            model.trust_expires_at = device.trust_expires_at
            model.updated_at = datetime.now(UTC)
            
            self.session.add(model)
            await self.session.commit()
            
            logger.info(
                "Device trusted successfully",
                device_id=str(device_id)
            )
            
            return True
            
        except Exception as e:
            await self.session.rollback()
            logger.error(
                "Failed to trust device",
                device_id=str(device_id),
                error=str(e)
            )
            raise InfrastructureError(f"Failed to trust device: {e!s}")
    
    async def revoke_trust(self, device_id: UUID) -> bool:
        """Revoke trust from device.
        
        Args:
            device_id: Device identifier
            
        Returns:
            True if trust revoked, False if not found
        """
        try:
            model = await self.session.get(DeviceRegistrationModel, device_id)
            if not model:
                return False
            
            # Convert to domain, untrust, and save back
            device = model.to_domain()
            device.untrust()
            
            # Update model
            model.trusted = device.trusted
            model.trust_expires_at = device.trust_expires_at
            model.updated_at = datetime.now(UTC)
            
            self.session.add(model)
            await self.session.commit()
            
            logger.info(
                "Device trust revoked successfully",
                device_id=str(device_id)
            )
            
            return True
            
        except Exception as e:
            await self.session.rollback()
            logger.error(
                "Failed to revoke device trust",
                device_id=str(device_id),
                error=str(e)
            )
            raise InfrastructureError(f"Failed to revoke device trust: {e!s}")
    
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
        try:
            model = await self.session.get(DeviceRegistrationModel, device_id)
            if not model:
                return False
            
            # Update last seen
            model.last_seen = datetime.now(UTC)
            model.updated_at = datetime.now(UTC)
            
            # Update metadata if provided
            if ip_address or location:
                if model.metadata is None:
                    model.metadata = {}
                
                if ip_address:
                    model.metadata['last_ip_address'] = ip_address
                if location:
                    model.metadata['last_location'] = location
            
            self.session.add(model)
            await self.session.commit()
            
            return True
            
        except Exception as e:
            await self.session.rollback()
            logger.error(
                "Failed to update device last seen",
                device_id=str(device_id),
                error=str(e)
            )
            raise InfrastructureError(f"Failed to update device: {e!s}")
    
    async def delete_device(self, device_id: UUID) -> bool:
        """Delete device registration.
        
        Args:
            device_id: Device identifier
            
        Returns:
            True if deleted, False if not found
        """
        try:
            model = await self.session.get(DeviceRegistrationModel, device_id)
            if not model:
                return False
            
            await self.session.delete(model)
            await self.session.commit()
            
            logger.info(
                "Device deleted successfully",
                device_id=str(device_id)
            )
            
            return True
            
        except Exception as e:
            await self.session.rollback()
            logger.error(
                "Failed to delete device",
                device_id=str(device_id),
                error=str(e)
            )
            raise InfrastructureError(f"Failed to delete device: {e!s}")
    
    async def cleanup_inactive_devices(self, inactive_days: int = 90) -> int:
        """Clean up inactive devices.
        
        Args:
            inactive_days: Number of days of inactivity before cleanup
            
        Returns:
            Number of devices cleaned up
        """
        try:
            cutoff_date = datetime.now(UTC).replace(day=datetime.now(UTC).day - inactive_days)
            
            stmt = select(DeviceRegistrationModel).where(
                DeviceRegistrationModel.last_seen < cutoff_date
            )
            
            result = await self.session.exec(stmt)
            models = result.all()
            
            count = len(models)
            for model in models:
                await self.session.delete(model)
            
            await self.session.commit()
            
            logger.info(
                "Cleaned up inactive devices",
                count=count,
                inactive_days=inactive_days
            )
            
            return count
            
        except Exception as e:
            await self.session.rollback()
            logger.error(
                "Failed to cleanup inactive devices",
                error=str(e)
            )
            raise InfrastructureError(f"Failed to cleanup devices: {e!s}")
    
    async def count_by_user(self, user_id: UUID) -> int:
        """Count devices for a user.
        
        Args:
            user_id: User identifier
            
        Returns:
            Number of devices registered for the user
        """
        try:
            stmt = select(func.count(DeviceRegistrationModel.id)).where(
                DeviceRegistrationModel.user_id == user_id
            )
            result = await self.session.exec(stmt)
            return result.first() or 0
            
        except Exception as e:
            logger.error(
                "Failed to count user devices",
                user_id=str(user_id),
                error=str(e)
            )
            raise InfrastructureError(f"Failed to count devices: {e!s}")
    
    async def count_trusted_by_user(self, user_id: UUID) -> int:
        """Count trusted devices for a user.
        
        Args:
            user_id: User identifier
            
        Returns:
            Number of trusted devices for the user
        """
        try:
            stmt = select(func.count(DeviceRegistrationModel.id)).where(
                and_(
                    DeviceRegistrationModel.user_id == user_id,
                    DeviceRegistrationModel.trusted == True
                )
            )
            result = await self.session.exec(stmt)
            return result.first() or 0
            
        except Exception as e:
            logger.error(
                "Failed to count trusted devices",
                user_id=str(user_id),
                error=str(e)
            )
            raise InfrastructureError(f"Failed to count trusted devices: {e!s}")
    
    async def find_trusted_by_user(self, user_id: UUID) -> list[dict]:
        """Find all trusted devices for a user.
        
        Args:
            user_id: User identifier
            
        Returns:
            List of trusted devices
        """
        try:
            stmt = select(DeviceRegistrationModel).where(
                and_(
                    DeviceRegistrationModel.user_id == user_id,
                    DeviceRegistrationModel.trusted == True
                )
            ).order_by(DeviceRegistrationModel.last_seen.desc())
            
            result = await self.session.exec(stmt)
            models = result.all()
            
            return [model.to_dict() for model in models]
            
        except Exception as e:
            logger.error(
                "Failed to find trusted devices",
                user_id=str(user_id),
                error=str(e)
            )
            raise InfrastructureError(f"Failed to find trusted devices: {e!s}")
    
    async def update_device_info(
        self,
        device_id: UUID,
        device_name: str | None = None,
        push_token: str | None = None,
        app_version: str | None = None,
        os_version: str | None = None
    ) -> bool:
        """Update device information.
        
        Args:
            device_id: Device identifier
            device_name: New device name
            push_token: New push token
            app_version: New app version
            os_version: New OS version
            
        Returns:
            True if updated, False if not found
        """
        try:
            model = await self.session.get(DeviceRegistrationModel, device_id)
            if not model:
                return False
            
            # Update fields if provided
            if device_name is not None:
                model.device_name = device_name
            if push_token is not None:
                model.push_token = push_token
            if app_version is not None:
                model.app_version = app_version
            if os_version is not None:
                model.os_version = os_version
            
            model.updated_at = datetime.now(UTC)
            
            self.session.add(model)
            await self.session.commit()
            
            return True
            
        except Exception as e:
            await self.session.rollback()
            logger.error(
                "Failed to update device info",
                device_id=str(device_id),
                error=str(e)
            )
            raise InfrastructureError(f"Failed to update device: {e!s}")