"""
Email MFA Provider Implementation

Email-based Multi-Factor Authentication provider.
"""

import logging
import random
import string
from datetime import UTC, datetime, timedelta
from typing import Any

from app.modules.identity.domain.entities.admin.mfa_device import MFADevice
from app.modules.identity.domain.enums import MFAMethod
from app.modules.identity.domain.interfaces.services.communication.notification_service import (
    IEmailService,
)
from app.modules.identity.domain.value_objects.email import Email
from app.modules.identity.infrastructure.services.mfa_provider_factory import (
    IMFAProvider,
)

logger = logging.getLogger(__name__)


class EmailMFAProvider(IMFAProvider):
    """Email-based MFA provider implementation."""
    
    def __init__(
        self,
        email_service: IEmailService,
        code_length: int = 6,
        code_expiry_minutes: int = 10,
        max_attempts: int = 5,
        rate_limit_minutes: int = 1,
        app_name: str = "EzzDay",
        support_email: str = "support@ezzday.com"
    ):
        """Initialize Email MFA provider.
        
        Args:
            email_service: Email sending service
            code_length: Length of verification codes
            code_expiry_minutes: Code expiration time
            max_attempts: Maximum verification attempts
            rate_limit_minutes: Minimum time between code sends
            app_name: Application name for emails
            support_email: Support email address
        """
        self.email_service = email_service
        self.code_length = code_length
        self.code_expiry_minutes = code_expiry_minutes
        self.max_attempts = max_attempts
        self.rate_limit_minutes = rate_limit_minutes
        self.app_name = app_name
        self.support_email = support_email
        
        # In-memory code storage (should use cache in production)
        self._active_codes: dict[str, dict[str, Any]] = {}
    
    @property
    def method(self) -> MFAMethod:
        """Get MFA method type."""
        return MFAMethod.EMAIL
    
    @property
    def name(self) -> str:
        """Get provider name."""
        return "Email Authentication"
    
    def generate_code(self) -> str:
        """Generate verification code."""
        # Mix of uppercase letters and digits for better readability
        charset = string.ascii_uppercase + string.digits
        # Avoid confusing characters
        charset = charset.replace('O', '').replace('0', '').replace('I', '').replace('1', '')
        
        code = ''.join(random.choices(charset, k=self.code_length))
        
        # Format as XXX-XXX for 6 digits
        if self.code_length == 6:
            return f"{code[:3]}-{code[3:]}"
        return code
    
    async def send_code(
        self,
        device: MFADevice,
        user_identifier: str | None = None
    ) -> dict[str, Any]:
        """Send verification code via email.
        
        Args:
            device: MFA device
            user_identifier: Optional user identifier for context
            
        Returns:
            Send result information
        """
        if device.method != MFAMethod.EMAIL:
            raise ValueError("Device must be EMAIL method")
        
        if not device.email:
            raise ValueError("Device must have email address")
        
        # Check rate limiting
        device_key = f"email:{device.id}"
        if device_key in self._active_codes:
            last_sent = self._active_codes[device_key].get('sent_at')
            if last_sent:
                time_passed = (datetime.now(UTC) - last_sent).total_seconds() / 60
                if time_passed < self.rate_limit_minutes:
                    remaining = self.rate_limit_minutes - time_passed
                    raise ValueError(f"Please wait {remaining:.0f} seconds before requesting a new code")
        
        # Generate new code
        code = self.generate_code()
        
        # Create email content
        subject = f"{self.app_name} - Verification Code"
        html_content = self._create_email_html(code, user_identifier)
        text_content = self._create_email_text(code, user_identifier)
        
        # Send email
        try:
            result = await self.email_service.send_email(
                to=device.email,
                subject=subject,
                html_content=html_content,
                text_content=text_content
            )
            
            # Store code information
            self._active_codes[device_key] = {
                'code': code.replace('-', ''),  # Store without formatting
                'sent_at': datetime.now(UTC),
                'expires_at': datetime.now(UTC) + timedelta(minutes=self.code_expiry_minutes),
                'attempts': 0,
                'device_id': str(device.id),
                'email': device.email
            }
            
            logger.info(f"Email code sent to device {device.id}")
            
            return {
                'sent': True,
                'masked_email': self._mask_email(device.email),
                'expires_in_seconds': self.code_expiry_minutes * 60,
                'message_id': result.get('message_id')
            }
            
        except Exception as e:
            logger.error(f"Failed to send email code: {e}")
            raise ValueError("Failed to send verification code")
    
    async def verify_code(
        self,
        device: MFADevice,
        code: str
    ) -> tuple[bool, dict[str, Any]]:
        """Verify email code.
        
        Args:
            device: MFA device
            code: Verification code
            
        Returns:
            Tuple of (is_valid, metadata)
        """
        device_key = f"email:{device.id}"
        
        # Remove formatting from input code
        clean_code = code.replace('-', '').replace(' ', '').upper()
        
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
        if clean_code != code_info['code']:
            remaining_attempts = self.max_attempts - code_info['attempts']
            return False, {
                'error': 'Invalid code',
                'remaining_attempts': remaining_attempts
            }
        
        # Success - remove code
        del self._active_codes[device_key]
        
        return True, {
            'verified_at': datetime.now(UTC).isoformat(),
            'method': 'email',
            'device_id': str(device.id)
        }
    
    async def setup_device(
        self,
        device: MFADevice,
        email: str
    ) -> dict[str, Any]:
        """Setup email MFA device.
        
        Args:
            device: MFA device
            email: Email address to register
            
        Returns:
            Setup information
        """
        if device.method != MFAMethod.EMAIL:
            raise ValueError("Device must be EMAIL method")
        
        # Validate email
        try:
            validated_email = Email(email)
            device.email = validated_email.value
        except ValueError as e:
            raise ValueError(f"Invalid email format: {e}")
        
        # Send verification code
        result = await self.send_code(device)
        
        return {
            'device_id': str(device.id),
            'email': self._mask_email(device.email),
            'verification_sent': result['sent'],
            'expires_in_seconds': result['expires_in_seconds']
        }
    
    async def is_available(self) -> bool:
        """Check if provider is available."""
        # Check if email service is configured and operational
        try:
            return await self.email_service.is_available()
        except (AttributeError, ConnectionError, Exception):
            return False
    
    def _create_email_html(self, code: str, user_identifier: str | None) -> str:
        """Create HTML email content.
        
        Args:
            code: Verification code
            user_identifier: Optional user context
            
        Returns:
            HTML content
        """
        greeting = f"Hello {user_identifier}," if user_identifier else "Hello,"
        
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; color: #333; }}
                .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                .header {{ background-color: #007bff; color: white; padding: 20px; text-align: center; }}
                .content {{ background-color: #f8f9fa; padding: 30px; }}
                .code-box {{ background-color: white; border: 2px solid #007bff; 
                            padding: 20px; margin: 20px 0; text-align: center; 
                            font-size: 28px; font-weight: bold; letter-spacing: 5px; }}
                .footer {{ text-align: center; color: #666; font-size: 12px; margin-top: 20px; }}
                .warning {{ color: #dc3545; margin-top: 20px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>{self.app_name} Verification</h1>
                </div>
                <div class="content">
                    <p>{greeting}</p>
                    <p>Your verification code is:</p>
                    <div class="code-box">{code}</div>
                    <p>This code will expire in <strong>{self.code_expiry_minutes} minutes</strong>.</p>
                    <p>Enter this code in the application to complete your authentication.</p>
                    <div class="warning">
                        <p><strong>Security Notice:</strong></p>
                        <p>If you didn't request this code, please ignore this email and 
                        consider changing your password.</p>
                    </div>
                </div>
                <div class="footer">
                    <p>This is an automated message from {self.app_name}.</p>
                    <p>Please do not reply to this email.</p>
                    <p>For support, contact: <a href="mailto:{self.support_email}">{self.support_email}</a></p>
                </div>
            </div>
        </body>
        </html>
        """
    
    def _create_email_text(self, code: str, user_identifier: str | None) -> str:
        """Create plain text email content.
        
        Args:
            code: Verification code
            user_identifier: Optional user context
            
        Returns:
            Plain text content
        """
        greeting = f"Hello {user_identifier}," if user_identifier else "Hello,"
        
        return f"""
{greeting}

Your {self.app_name} verification code is:

{code}

This code will expire in {self.code_expiry_minutes} minutes.

Enter this code in the application to complete your authentication.

SECURITY NOTICE:
If you didn't request this code, please ignore this email and consider changing your password.

---
This is an automated message from {self.app_name}.
Please do not reply to this email.
For support, contact: {self.support_email}
"""
    
    def _mask_email(self, email: str) -> str:
        """Mask email address for display.
        
        Args:
            email: Email address
            
        Returns:
            Masked email
        """
        try:
            local, domain = email.split('@')
            
            if len(local) <= 3:
                masked_local = local[0] + '*' * (len(local) - 1)
            else:
                masked_local = local[:2] + '*' * (len(local) - 4) + local[-2:]
            
            return f"{masked_local}@{domain}"
        except (ValueError, IndexError, AttributeError):
            return "***@***"
    
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