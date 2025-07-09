"""
Setup MFA command implementation.

Handles multi-factor authentication device setup.
"""

import base64
import io
from datetime import UTC, datetime
from uuid import UUID

import pyotp
import qrcode

from app.core.cqrs import Command, CommandHandler
from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    require_auth,
    validate_request,
)
from app.modules.identity.application.dtos.internal import EmailContext, SMSContext
from app.modules.identity.application.dtos.request import SetupMFARequest
from app.modules.identity.application.dtos.response import MFASetupResponse
from app.modules.identity.domain.entities import MFADevice, User
from app.modules.identity.domain.enums import AuditAction, MFAMethod
from app.modules.identity.domain.events import MFAEnabled
from app.modules.identity.domain.exceptions import (
    InvalidPhoneNumberError,
    MFAAlreadyEnabledError,
    UserNotFoundError,
)
from app.modules.identity.domain.interfaces.repositories.mfa_device_repository import (
    IMFADeviceRepository,
)
from app.modules.identity.domain.interfaces.repositories.user_repository import (
    IUserRepository,
)
from app.modules.identity.domain.interfaces.services.communication.notification_service import (
    IEmailService,
    ISMSService,
)
from app.modules.identity.domain.interfaces.services.infrastructure.cache_port import (
    ICachePort as ICacheService,
)
from app.modules.identity.domain.services import MFAService, SecurityService
from app.modules.identity.domain.interfaces.services import (
    ICachePort,
)


class SetupMFACommand(Command[MFASetupResponse]):
    """Command to setup MFA for a user."""
    
    def __init__(
        self,
        user_id: UUID,
        method: MFAMethod,
        device_name: str,
        phone_number: str | None = None,
        is_primary: bool = False,
        ip_address: str | None = None
    ):
        self.user_id = user_id
        self.method = method
        self.device_name = device_name
        self.phone_number = phone_number
        self.is_primary = is_primary
        self.ip_address = ip_address


class SetupMFACommandHandler(CommandHandler[SetupMFACommand, MFASetupResponse]):
    """Handler for MFA setup."""
    
    def __init__(
        self,
        user_repository: IUserRepository,
        mfa_device_repository: IMFADeviceRepository,
        mfa_service: MFAService,
        security_service: SecurityService,
        email_service: IEmailService,
        sms_service: ISMSService,
        cache_service: ICacheService,
        event_bus: EventBus,
        unit_of_work: UnitOfWork
    ):
        self._user_repository = user_repository
        self._mfa_device_repository = mfa_device_repository
        self._mfa_service = mfa_service
        self._security_service = security_service
        self._email_service = email_service
        self._sms_service = sms_service
        self._cache_service = cache_service
        self._event_bus = event_bus
        self._unit_of_work = unit_of_work
    
    @audit_action(
        action=AuditAction.MFA_SETUP_INITIATED,
        resource_type="mfa_device",
        include_request=True
    )
    @require_auth
    @validate_request(SetupMFARequest)
    @rate_limit(
        max_requests=5,
        window_seconds=3600,
        strategy='user'
    )
    async def handle(self, command: SetupMFACommand) -> MFASetupResponse:
        """
        Setup MFA device for user.
        
        Process:
        1. Load user and validate
        2. Check existing MFA devices
        3. Validate method-specific requirements
        4. Create MFA device
        5. Generate secrets/codes
        6. Send verification code if needed
        7. Return setup information
        
        Returns:
            MFASetupResponse with setup details
            
        Raises:
            UserNotFoundError: If user not found
            MFAAlreadyEnabledError: If method already setup
            InvalidPhoneNumberError: If phone invalid for SMS
        """
        async with self._unit_of_work:
            # 1. Load user
            user = await self._user_repository.find_by_id(command.user_id)
            
            if not user:
                raise UserNotFoundError(f"User {command.user_id} not found")
            
            # 2. Check existing devices
            existing_devices = await self._mfa_device_repository.get_by_user_id(
                user.id
            )
            
            # Check if method already exists and is verified
            method_devices = [
                d for d in existing_devices 
                if d.method == command.method and d.is_verified
            ]
            
            if method_devices and command.method != MFAMethod.BACKUP_CODES:
                raise MFAAlreadyEnabledError(
                    f"MFA method {command.method.value} is already enabled"
                )
            
            # 3. Validate method-specific requirements
            if command.method == MFAMethod.SMS:
                if not command.phone_number:
                    raise InvalidPhoneNumberError("Phone number required for SMS MFA")
                
                # Validate phone number format
                if not self._is_valid_phone_number(command.phone_number):
                    raise InvalidPhoneNumberError("Invalid phone number format")
            
            # 4. Create MFA device
            device = MFADevice.create(
                user_id=user.id,
                method=command.method,
                name=command.device_name,
                is_primary=command.is_primary or len(existing_devices) == 0
            )
            
            # 5. Generate method-specific data
            secret = None
            qr_code = None
            backup_codes = None
            
            if command.method == MFAMethod.AUTHENTICATOR_APP:
                # Generate TOTP secret
                secret = pyotp.random_base32()
                device.secret = await self._mfa_service.encrypt_secret(secret)
                
                # Generate QR code
                qr_code = await self._generate_totp_qr_code(
                    user=user,
                    secret=secret
                )
                
            elif command.method == MFAMethod.SMS:
                # Store encrypted phone number
                device.phone_number = await self._mfa_service.encrypt_phone(
                    command.phone_number
                )
                
                # Send initial verification code
                verification_code = await self._mfa_service.generate_verification_code()
                await self._send_sms_verification(
                    phone_number=command.phone_number,
                    code=verification_code
                )
                
                # Cache verification code
                await self._cache_verification_code(
                    device_id=device.id,
                    code=verification_code
                )
                
            elif command.method == MFAMethod.EMAIL:
                # Email uses user's primary email
                device.email = user.email
                
                # Send initial verification code
                verification_code = await self._mfa_service.generate_verification_code()
                await self._send_email_verification(
                    email=user.email,
                    username=user.username,
                    code=verification_code
                )
                
                # Cache verification code
                await self._cache_verification_code(
                    device_id=device.id,
                    code=verification_code
                )
                
            elif command.method == MFAMethod.BACKUP_CODES:
                # Generate backup codes
                backup_codes = await self._mfa_service.generate_backup_codes(
                    count=10
                )
                
                # Store hashed codes
                hashed_codes = []
                for code in backup_codes:
                    hashed = await self._mfa_service.hash_backup_code(code)
                    hashed_codes.append(hashed)
                
                device.backup_codes = hashed_codes
                device.backup_codes_generated_at = datetime.now(UTC)
                
                # Mark as verified (backup codes don't need verification)
                device.verify()
            
            # 6. Handle primary device setting
            if command.is_primary and existing_devices:
                # Unset other primary devices
                for existing in existing_devices:
                    if existing.is_primary:
                        existing.is_primary = False
                        await self._mfa_device_repository.update(existing)
            
            # 7. Save device
            await self._mfa_device_repository.add(device)
            
            # 8. Clear MFA cache
            await self._cache_service.delete(f"mfa_devices:{user.id}")
            
            # 9. Log security event
            await self._security_service.log_security_event(
                user_id=user.id,
                event_type="mfa_setup_initiated",
                ip_address=command.ip_address,
                details={
                    "method": command.method.value,
                    "device_name": command.device_name
                }
            )
            
            # 10. Publish event if first MFA device
            if not user.mfa_enabled:
                await self._event_bus.publish(
                    MFAEnabled(
                        aggregate_id=user.id,
                        method=command.method,
                        device_id=device.id,
                        is_first_device=True
                    )
                )
            
            # 11. Commit transaction
            await self._unit_of_work.commit()
            
            # 12. Return setup response
            return MFASetupResponse(
                device_id=device.id,
                secret=secret if command.method == MFAMethod.AUTHENTICATOR_APP else None,
                qr_code=qr_code,
                backup_codes=backup_codes if command.method == MFAMethod.BACKUP_CODES else None,
                verification_required=command.method != MFAMethod.BACKUP_CODES,
                success=True,
                message=self._get_setup_message(command.method)
            )
    
    def _is_valid_phone_number(self, phone_number: str) -> bool:
        """Validate phone number format."""
        # Simple validation - in production use phonenumbers library
        import re
        pattern = r'^\+?1?\d{10,15}$'
        return bool(re.match(pattern, phone_number.replace(" ", "").replace("-", "")))
    
    async def _generate_totp_qr_code(
        self,
        user: User,
        secret: str
    ) -> str:
        """Generate QR code for TOTP setup."""
        # Generate provisioning URI
        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(
            name=user.email,
            issuer_name="YourApp"
        )
        
        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(provisioning_uri)
        qr.make(fit=True)
        
        # Create image
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        buffer.seek(0)
        
        return base64.b64encode(buffer.getvalue()).decode()
    
    async def _send_sms_verification(
        self,
        phone_number: str,
        code: str
    ) -> None:
        """Send SMS verification code."""
        await self._sms_service.send_sms(
            SMSContext(
                recipient=phone_number,
                message=f"Your verification code is: {code}. Valid for 5 minutes.",
                message_type="transactional",
                priority="high"
            )
        )
    
    async def _send_email_verification(
        self,
        email: str,
        username: str,
        code: str
    ) -> None:
        """Send email verification code."""
        await self._email_service.send_email(
            EmailContext(
                recipient=email,
                template="mfa_verification",
                subject="Your MFA verification code",
                variables={
                    "username": username,
                    "code": code,
                    "valid_for": "5 minutes"
                },
                priority="high"
            )
        )
    
    async def _cache_verification_code(
        self,
        device_id: UUID,
        code: str
    ) -> None:
        """Cache verification code for later validation."""
        await self._cache_service.set(
            key=f"mfa_verify:{device_id}",
            value=code,
            ttl=300  # 5 minutes
        )
    
    def _get_setup_message(self, method: MFAMethod) -> str:
        """Get appropriate setup message for method."""
        messages = {
            MFAMethod.AUTHENTICATOR_APP: "Scan the QR code with your authenticator app and enter the verification code.",
            MFAMethod.SMS: "A verification code has been sent to your phone.",
            MFAMethod.EMAIL: "A verification code has been sent to your email.",
            MFAMethod.BACKUP_CODES: "Backup codes generated. Store them securely."
        }
        
        return messages.get(method, "MFA setup initiated.")