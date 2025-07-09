"""
SMS MFA Provider Implementation

SMS-based Multi-Factor Authentication provider.
"""

import logging
import random
import string
from datetime import datetime, UTC, timedelta
from typing import Any

from app.modules.identity.domain.entities.admin.mfa_device import MFADevice
from app.modules.identity.domain.enums import MFAMethod
from app.modules.identity.domain.interfaces.services.communication.notification_service import ISMSService
from app.modules.identity.infrastructure.services.mfa_provider_factory import IMFAProvider

logger = logging.getLogger(__name__)


class SMSMFAProvider(IMFAProvider):
    """SMS-based MFA provider implementation."""
    
    def __init__(
        self,
        sms_service: ISMSService,
        code_length: int = 6,
        code_expiry_minutes: int = 5,
        max_attempts: int = 3,
        rate_limit_minutes: int = 1
    ):
        """Initialize SMS MFA provider.
        
        Args:
            sms_service: SMS sending service
            code_length: Length of verification codes
            code_expiry_minutes: Code expiration time
            max_attempts: Maximum verification attempts
            rate_limit_minutes: Minimum time between code sends
        """
        self.sms_service = sms_service
        self.code_length = code_length
        self.code_expiry_minutes = code_expiry_minutes
        self.max_attempts = max_attempts
        self.rate_limit_minutes = rate_limit_minutes
        
        # In-memory code storage (should use cache in production)
        self._active_codes: dict[str, dict[str, Any]] = {}
    
    @property
    def method(self) -> MFAMethod:
        """Get MFA method type."""
        return MFAMethod.SMS
    
    @property
    def name(self) -> str:
        """Get provider name."""
        return "SMS Authentication"
    
    def generate_code(self) -> str:
        """Generate verification code."""
        # Generate numeric code
        return ''.join(random.choices(string.digits, k=self.code_length))
    
    async def send_code(
        self,
        device: MFADevice,
        user_identifier: str | None = None
    ) -> dict[str, Any]:
        """Send verification code via SMS.
        
        Args:
            device: MFA device
            user_identifier: Optional user identifier for context
            
        Returns:
            Send result information
        """
        if device.method != MFAMethod.SMS:
            raise ValueError("Device must be SMS method")
        
        if not device.phone_number:
            raise ValueError("Device must have phone number")
        
        # Check rate limiting
        device_key = f"sms:{device.id}"
        if device_key in self._active_codes:
            last_sent = self._active_codes[device_key].get('sent_at')
            if last_sent:
                time_passed = (datetime.now(UTC) - last_sent).total_seconds() / 60
                if time_passed < self.rate_limit_minutes:
                    remaining = self.rate_limit_minutes - time_passed
                    raise ValueError(f"Please wait {remaining:.0f} seconds before requesting a new code")
        
        # Generate new code
        code = self.generate_code()
        
        # Format message
        message = self._format_message(code, user_identifier)
        
        # Send SMS
        try:
            result = await self.sms_service.send_sms(
                to=device.phone_number,
                message=message
            )
            
            # Store code information
            self._active_codes[device_key] = {
                'code': code,
                'sent_at': datetime.now(UTC),
                'expires_at': datetime.now(UTC) + timedelta(minutes=self.code_expiry_minutes),
                'attempts': 0,
                'device_id': str(device.id),
                'phone_number': device.phone_number
            }
            
            logger.info(f"SMS code sent to device {device.id}")
            
            return {
                'sent': True,
                'masked_phone': self._mask_phone_number(device.phone_number),
                'expires_in_seconds': self.code_expiry_minutes * 60,
                'message_id': result.get('message_id')
            }
            
        except Exception as e:
            logger.error(f"Failed to send SMS code: {e}")
            raise ValueError("Failed to send verification code")
    
    async def verify_code(
        self,
        device: MFADevice,
        code: str
    ) -> tuple[bool, dict[str, Any]]:
        """Verify SMS code.
        
        Args:
            device: MFA device
            code: Verification code
            
        Returns:
            Tuple of (is_valid, metadata)
        """
        device_key = f"sms:{device.id}"
        
        # Check if code exists
        if device_key not in self._active_codes:
            return False, {'error': 'No active code found'}
        
        code_info = self._active_codes[device_key]
        
        # Check expiration
        if datetime.now(UTC) > code_info['expires_at']:
            del self._active_codes[device_key]
            return False, {'error': 'Code has expired'}
        
        # Check attempts
        code_info['attempts'] += 1
        if code_info['attempts'] > self.max_attempts:
            del self._active_codes[device_key]
            return False, {'error': 'Too many failed attempts'}
        
        # Verify code
        if code != code_info['code']:
            remaining_attempts = self.max_attempts - code_info['attempts']
            return False, {
                'error': 'Invalid code',
                'remaining_attempts': remaining_attempts
            }
        
        # Success - remove code
        del self._active_codes[device_key]
        
        return True, {
            'verified_at': datetime.now(UTC).isoformat(),
            'method': 'sms',
            'device_id': str(device.id)
        }
    
    async def setup_device(
        self,
        device: MFADevice,
        phone_number: str
    ) -> dict[str, Any]:
        """Setup SMS MFA device.
        
        Args:
            device: MFA device
            phone_number: Phone number to register
            
        Returns:
            Setup information
        """
        if device.method != MFAMethod.SMS:
            raise ValueError("Device must be SMS method")
        
        # Validate phone number format
        if not self._validate_phone_number(phone_number):
            raise ValueError("Invalid phone number format")
        
        # Store phone number
        device.phone_number = phone_number
        
        # Send verification code
        result = await self.send_code(device)
        
        return {
            'device_id': str(device.id),
            'phone_number': self._mask_phone_number(phone_number),
            'verification_sent': result['sent'],
            'expires_in_seconds': result['expires_in_seconds']
        }
    
    async def is_available(self) -> bool:
        """Check if provider is available."""
        # Check if SMS service is configured and operational
        try:
            return await self.sms_service.is_available()
        except (AttributeError, ConnectionError, Exception):
            return False
    
    def _format_message(self, code: str, user_identifier: str | None) -> str:
        """Format SMS message.
        
        Args:
            code: Verification code
            user_identifier: Optional user context
            
        Returns:
            Formatted message
        """
        app_name = "EzzDay"
        
        if user_identifier:
            return (
                f"Your {app_name} verification code is: {code}\n"
                f"This code expires in {self.code_expiry_minutes} minutes.\n"
                f"If you didn't request this, please ignore."
            )
        else:
            return (
                f"Your {app_name} verification code is: {code}\n"
                f"Valid for {self.code_expiry_minutes} minutes."
            )
    
    def _mask_phone_number(self, phone: str) -> str:
        """Mask phone number for display.
        
        Args:
            phone: Phone number
            
        Returns:
            Masked phone number
        """
        if len(phone) < 7:
            return "***"
        
        # Show last 4 digits
        return f"***-***-{phone[-4:]}"
    
    def _validate_phone_number(self, phone: str) -> bool:
        """Validate phone number format.
        
        Args:
            phone: Phone number
            
        Returns:
            True if valid
        """
        # Remove common formatting
        cleaned = phone.replace(' ', '').replace('-', '').replace('(', '').replace(')', '')
        
        # Check if it starts with + for international
        if cleaned.startswith('+'):
            cleaned = cleaned[1:]
        
        # Must be digits only and reasonable length
        return cleaned.isdigit() and 7 <= len(cleaned) <= 15
    
    async def cleanup_expired_codes(self) -> int:
        """Clean up expired codes.
        
        Returns:
            Number of codes cleaned up
        """
        now = datetime.now(UTC)
        expired_keys = []
        
        for key, info in self._active_codes.items():
            if now > info['expires_at']:
                expired_keys.append(key)
        
        for key in expired_keys:
            del self._active_codes[key]
        
        return len(expired_keys)