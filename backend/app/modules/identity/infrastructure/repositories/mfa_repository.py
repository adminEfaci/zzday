"""
MFA Repository Implementation

SQLModel-based implementation of the MFA repository interface.
"""

from datetime import datetime, UTC, timedelta
from typing import Any
from uuid import UUID
import hashlib

from sqlmodel import Session, select, and_, or_, col, func
from app.modules.identity.domain.entities.admin.mfa_device import MFADevice, BackupCode
from app.modules.identity.domain.enums import MFAMethod as MfaMethod
from app.modules.identity.domain.interfaces.repositories.mfa_repository import IMFARepository
from app.modules.identity.infrastructure.models.mfa_model import MFADeviceModel, BackupCodeModel, RecoveryCodeModel
from app.core.errors import InfrastructureError
from app.core.logging import get_logger


logger = get_logger(__name__)


class SQLMFARepository(IMFARepository):
    """SQLModel implementation of MFA repository."""
    
    def __init__(self, session: Session):
        """Initialize repository with database session.
        
        Args:
            session: SQLModel database session
        """
        self.session = session
        self.device_model_class = MFADeviceModel
        self.backup_code_model_class = BackupCodeModel
        self.recovery_code_model_class = RecoveryCodeModel
    
    async def create(
        self, 
        user_id: UUID,
        device_name: str,
        device_type: MfaMethod,
        secret: str,
        backup_codes: list[str] | None = None,
        is_verified: bool = False
    ) -> UUID:
        """Create new MFA device.
        
        Args:
            user_id: User identifier
            device_name: User-friendly device name
            device_type: MFA method type
            secret: Encrypted secret key
            backup_codes: Optional backup codes
            is_verified: Whether device is verified
            
        Returns:
            Created device ID
        """
        try:
            # Create domain entity
            device = MFADevice.create(
                user_id=user_id,
                method=device_type,
                device_name=device_name,
                generate_backup_codes=False  # We'll handle backup codes separately
            )
            
            # Override the secret with the provided encrypted one
            device.secret.value = secret
            
            if is_verified:
                device.verified = True
                device.verified_at = datetime.now(UTC)
            
            # Convert to model and save
            model = MFADeviceModel.from_domain(device)
            self.session.add(model)
            
            # Handle backup codes if provided
            if backup_codes:
                expires_at = datetime.now(UTC) + timedelta(days=365)
                for code in backup_codes:
                    # Create BackupCode value object for hashing
                    backup_code_obj = BackupCode(value=code)
                    backup_code_model = BackupCodeModel.from_backup_code(
                        device_id=device.id,
                        code=backup_code_obj,
                        expires_at=expires_at
                    )
                    self.session.add(backup_code_model)
                
                model.recovery_codes_generated = True
                model.recovery_codes_count = len(backup_codes)
            
            await self.session.commit()
            
            logger.info(
                "MFA device created successfully",
                device_id=str(device.id),
                user_id=str(user_id),
                method=device_type.value
            )
            
            return device.id
            
        except Exception as e:
            await self.session.rollback()
            logger.error(
                "Failed to create MFA device",
                user_id=str(user_id),
                error=str(e)
            )
            raise InfrastructureError(f"Failed to create MFA device: {str(e)}")
    
    async def find_by_id(self, device_id: UUID) -> dict | None:
        """Find MFA device by ID.
        
        Args:
            device_id: Device identifier
            
        Returns:
            Device data if found, None otherwise
        """
        try:
            stmt = select(MFADeviceModel).where(MFADeviceModel.id == device_id)
            result = await self.session.exec(stmt)
            model = result.first()
            
            if model:
                device_data = model.to_dict()
                
                # Load backup codes count
                backup_stmt = select(func.count(BackupCodeModel.id)).where(
                    and_(
                        BackupCodeModel.device_id == device_id,
                        BackupCodeModel.is_used == False,
                        BackupCodeModel.expires_at > datetime.now(UTC)
                    )
                )
                backup_result = await self.session.exec(backup_stmt)
                device_data['active_backup_codes'] = backup_result.first() or 0
                
                return device_data
            
            return None
            
        except Exception as e:
            logger.error(
                "Failed to find MFA device by ID",
                device_id=str(device_id),
                error=str(e)
            )
            raise InfrastructureError(f"Failed to find MFA device: {str(e)}")
    
    async def find_by_user(self, user_id: UUID) -> list[dict]:
        """Find all MFA devices for user.
        
        Args:
            user_id: User identifier
            
        Returns:
            List of user's MFA devices
        """
        try:
            stmt = select(MFADeviceModel).where(
                and_(
                    MFADeviceModel.user_id == user_id,
                    MFADeviceModel.is_enabled == True
                )
            ).order_by(
                MFADeviceModel.is_primary.desc(),
                MFADeviceModel.created_at.desc()
            )
            
            result = await self.session.exec(stmt)
            models = result.all()
            
            devices = []
            for model in models:
                device_data = model.to_dict()
                
                # Load backup codes count for each device
                backup_stmt = select(func.count(BackupCodeModel.id)).where(
                    and_(
                        BackupCodeModel.device_id == model.id,
                        BackupCodeModel.is_used == False,
                        BackupCodeModel.expires_at > datetime.now(UTC)
                    )
                )
                backup_result = await self.session.exec(backup_stmt)
                device_data['active_backup_codes'] = backup_result.first() or 0
                
                devices.append(device_data)
            
            return devices
            
        except Exception as e:
            logger.error(
                "Failed to find MFA devices for user",
                user_id=str(user_id),
                error=str(e)
            )
            raise InfrastructureError(f"Failed to find user MFA devices: {str(e)}")
    
    async def find_verified_by_user(self, user_id: UUID) -> list[dict]:
        """Find verified MFA devices for user.
        
        Args:
            user_id: User identifier
            
        Returns:
            List of verified MFA devices
        """
        try:
            stmt = select(MFADeviceModel).where(
                and_(
                    MFADeviceModel.user_id == user_id,
                    MFADeviceModel.verified == True,
                    MFADeviceModel.is_enabled == True
                )
            ).order_by(
                MFADeviceModel.is_primary.desc(),
                MFADeviceModel.last_used.desc()
            )
            
            result = await self.session.exec(stmt)
            models = result.all()
            
            return [model.to_dict() for model in models]
            
        except Exception as e:
            logger.error(
                "Failed to find verified MFA devices",
                user_id=str(user_id),
                error=str(e)
            )
            raise InfrastructureError(f"Failed to find verified devices: {str(e)}")
    
    async def verify_device(self, device_id: UUID) -> bool:
        """Mark MFA device as verified.
        
        Args:
            device_id: Device identifier
            
        Returns:
            True if verified, False if not found
        """
        try:
            model = await self.session.get(MFADeviceModel, device_id)
            if not model:
                return False
            
            model.verified = True
            model.verified_at = datetime.now(UTC)
            model.updated_at = datetime.now(UTC)
            
            self.session.add(model)
            await self.session.commit()
            
            logger.info(
                "MFA device verified successfully",
                device_id=str(device_id)
            )
            
            return True
            
        except Exception as e:
            await self.session.rollback()
            logger.error(
                "Failed to verify MFA device",
                device_id=str(device_id),
                error=str(e)
            )
            raise InfrastructureError(f"Failed to verify device: {str(e)}")
    
    async def disable_device(self, device_id: UUID) -> bool:
        """Disable MFA device.
        
        Args:
            device_id: Device identifier
            
        Returns:
            True if disabled, False if not found
        """
        try:
            model = await self.session.get(MFADeviceModel, device_id)
            if not model:
                return False
            
            model.is_enabled = False
            model.is_primary = False
            model.disabled_at = datetime.now(UTC)
            model.updated_at = datetime.now(UTC)
            
            self.session.add(model)
            await self.session.commit()
            
            logger.info(
                "MFA device disabled successfully",
                device_id=str(device_id)
            )
            
            return True
            
        except Exception as e:
            await self.session.rollback()
            logger.error(
                "Failed to disable MFA device",
                device_id=str(device_id),
                error=str(e)
            )
            raise InfrastructureError(f"Failed to disable device: {str(e)}")
    
    async def update_last_used(self, device_id: UUID) -> bool:
        """Update device last used timestamp.
        
        Args:
            device_id: Device identifier
            
        Returns:
            True if updated, False if not found
        """
        try:
            model = await self.session.get(MFADeviceModel, device_id)
            if not model:
                return False
            
            model.last_used = datetime.now(UTC)
            model.verification_count += 1
            model.updated_at = datetime.now(UTC)
            
            # Reset failed attempts on successful use
            model.failed_attempts = 0
            model.locked_until = None
            
            self.session.add(model)
            await self.session.commit()
            
            return True
            
        except Exception as e:
            await self.session.rollback()
            logger.error(
                "Failed to update MFA device last used",
                device_id=str(device_id),
                error=str(e)
            )
            raise InfrastructureError(f"Failed to update device: {str(e)}")
    
    async def get_backup_codes(self, device_id: UUID) -> list[str]:
        """Get backup codes for device.
        
        Args:
            device_id: Device identifier
            
        Returns:
            List of backup codes (returns empty codes, actual codes are not stored)
        """
        try:
            # We only store hashes, so return count information instead
            stmt = select(BackupCodeModel).where(
                and_(
                    BackupCodeModel.device_id == device_id,
                    BackupCodeModel.is_used == False,
                    BackupCodeModel.expires_at > datetime.now(UTC)
                )
            )
            
            result = await self.session.exec(stmt)
            codes = result.all()
            
            # Return placeholder codes with count
            return [f"BACKUP-{i+1}" for i in range(len(codes))]
            
        except Exception as e:
            logger.error(
                "Failed to get backup codes",
                device_id=str(device_id),
                error=str(e)
            )
            raise InfrastructureError(f"Failed to get backup codes: {str(e)}")
    
    async def use_backup_code(self, device_id: UUID, code: str) -> bool:
        """Mark backup code as used.
        
        Args:
            device_id: Device identifier
            code: Backup code that was used
            
        Returns:
            True if code was valid and marked as used
        """
        try:
            # Hash the provided code
            code_hash = hashlib.sha256(code.encode()).hexdigest()
            
            # Find the matching backup code
            stmt = select(BackupCodeModel).where(
                and_(
                    BackupCodeModel.device_id == device_id,
                    BackupCodeModel.code_hash == code_hash,
                    BackupCodeModel.is_used == False,
                    BackupCodeModel.expires_at > datetime.now(UTC)
                )
            )
            
            result = await self.session.exec(stmt)
            backup_code_model = result.first()
            
            if not backup_code_model:
                return False
            
            # Mark as used
            backup_code_model.is_used = True
            backup_code_model.used_at = datetime.now(UTC)
            
            # Update device last used
            device_model = await self.session.get(MFADeviceModel, device_id)
            if device_model:
                device_model.last_used = datetime.now(UTC)
                device_model.verification_count += 1
                device_model.recovery_codes_count = max(0, device_model.recovery_codes_count - 1)
                device_model.updated_at = datetime.now(UTC)
                self.session.add(device_model)
            
            self.session.add(backup_code_model)
            await self.session.commit()
            
            logger.info(
                "Backup code used successfully",
                device_id=str(device_id)
            )
            
            return True
            
        except Exception as e:
            await self.session.rollback()
            logger.error(
                "Failed to use backup code",
                device_id=str(device_id),
                error=str(e)
            )
            raise InfrastructureError(f"Failed to use backup code: {str(e)}")
    
    # Additional methods not in interface but useful for the implementation
    
    async def set_primary_device(self, user_id: UUID, device_id: UUID) -> bool:
        """Set a device as the primary MFA device for the user.
        
        Args:
            user_id: User identifier
            device_id: Device identifier to set as primary
            
        Returns:
            True if set as primary, False if device not found
        """
        try:
            # First, unset any existing primary devices
            stmt = select(MFADeviceModel).where(
                and_(
                    MFADeviceModel.user_id == user_id,
                    MFADeviceModel.is_primary == True
                )
            )
            result = await self.session.exec(stmt)
            existing_primary = result.all()
            
            for model in existing_primary:
                model.is_primary = False
                model.updated_at = datetime.now(UTC)
                self.session.add(model)
            
            # Set the new primary device
            device_model = await self.session.get(MFADeviceModel, device_id)
            if not device_model or device_model.user_id != user_id:
                return False
            
            device_model.is_primary = True
            device_model.updated_at = datetime.now(UTC)
            
            self.session.add(device_model)
            await self.session.commit()
            
            logger.info(
                "MFA device set as primary",
                device_id=str(device_id),
                user_id=str(user_id)
            )
            
            return True
            
        except Exception as e:
            await self.session.rollback()
            logger.error(
                "Failed to set primary MFA device",
                device_id=str(device_id),
                error=str(e)
            )
            raise InfrastructureError(f"Failed to set primary device: {str(e)}")
    
    async def increment_failed_attempts(self, device_id: UUID) -> int:
        """Increment failed verification attempts for a device.
        
        Args:
            device_id: Device identifier
            
        Returns:
            Updated failed attempts count
        """
        try:
            model = await self.session.get(MFADeviceModel, device_id)
            if not model:
                return 0
            
            model.failed_attempts += 1
            model.updated_at = datetime.now(UTC)
            
            # Lock after 5 failed attempts
            if model.failed_attempts >= 5:
                model.locked_until = datetime.now(UTC) + timedelta(minutes=15)
            
            self.session.add(model)
            await self.session.commit()
            
            return model.failed_attempts
            
        except Exception as e:
            await self.session.rollback()
            logger.error(
                "Failed to increment failed attempts",
                device_id=str(device_id),
                error=str(e)
            )
            raise InfrastructureError(f"Failed to update failed attempts: {str(e)}")
    
    async def generate_recovery_codes(self, user_id: UUID, count: int = 8) -> list[str]:
        """Generate recovery codes for a user.
        
        Args:
            user_id: User identifier
            count: Number of recovery codes to generate
            
        Returns:
            List of generated recovery codes (unhashed)
        """
        try:
            import secrets
            
            # Delete any existing unused recovery codes
            stmt = select(RecoveryCodeModel).where(
                and_(
                    RecoveryCodeModel.user_id == user_id,
                    RecoveryCodeModel.is_used == False
                )
            )
            result = await self.session.exec(stmt)
            existing = result.all()
            
            for model in existing:
                await self.session.delete(model)
            
            # Generate new recovery codes
            codes = []
            expires_at = datetime.now(UTC) + timedelta(days=365)
            
            for _ in range(count):
                code = secrets.token_hex(8)
                code_hash = hashlib.sha256(code.encode()).hexdigest()
                
                recovery_model = RecoveryCodeModel.from_code(
                    user_id=user_id,
                    code_hash=code_hash,
                    expires_at=expires_at
                )
                
                self.session.add(recovery_model)
                codes.append(code)
            
            await self.session.commit()
            
            logger.info(
                "Recovery codes generated successfully",
                user_id=str(user_id),
                count=count
            )
            
            return codes
            
        except Exception as e:
            await self.session.rollback()
            logger.error(
                "Failed to generate recovery codes",
                user_id=str(user_id),
                error=str(e)
            )
            raise InfrastructureError(f"Failed to generate recovery codes: {str(e)}")
    
    async def use_recovery_code(self, user_id: UUID, code: str) -> bool:
        """Use a recovery code.
        
        Args:
            user_id: User identifier
            code: Recovery code to use
            
        Returns:
            True if code was valid and used, False otherwise
        """
        try:
            # Hash the provided code
            code_hash = hashlib.sha256(code.encode()).hexdigest()
            
            # Find the matching recovery code
            stmt = select(RecoveryCodeModel).where(
                and_(
                    RecoveryCodeModel.user_id == user_id,
                    RecoveryCodeModel.code_hash == code_hash,
                    RecoveryCodeModel.is_used == False,
                    RecoveryCodeModel.expires_at > datetime.now(UTC)
                )
            )
            
            result = await self.session.exec(stmt)
            recovery_model = result.first()
            
            if not recovery_model:
                return False
            
            # Mark as used
            recovery_model.is_used = True
            recovery_model.used_at = datetime.now(UTC)
            
            self.session.add(recovery_model)
            await self.session.commit()
            
            logger.info(
                "Recovery code used successfully",
                user_id=str(user_id)
            )
            
            return True
            
        except Exception as e:
            await self.session.rollback()
            logger.error(
                "Failed to use recovery code",
                user_id=str(user_id),
                error=str(e)
            )
            raise InfrastructureError(f"Failed to use recovery code: {str(e)}")
    
    async def count_devices_by_method(self, user_id: UUID, method: MfaMethod) -> int:
        """Count MFA devices by method for a user.
        
        Args:
            user_id: User identifier
            method: MFA method to count
            
        Returns:
            Number of devices with the specified method
        """
        try:
            stmt = select(func.count(MFADeviceModel.id)).where(
                and_(
                    MFADeviceModel.user_id == user_id,
                    MFADeviceModel.method == method.value,
                    MFADeviceModel.is_enabled == True
                )
            )
            
            result = await self.session.exec(stmt)
            return result.first() or 0
            
        except Exception as e:
            logger.error(
                "Failed to count devices by method",
                user_id=str(user_id),
                method=method.value,
                error=str(e)
            )
            raise InfrastructureError(f"Failed to count devices: {str(e)}")