"""
Multi-Factor Authentication Service Interface

Protocol for MFA operations including TOTP, SMS, email, and backup codes.
"""

from typing import Any, Protocol
from uuid import UUID


class IMFAService(Protocol):
    """Protocol for multi-factor authentication operations."""
    
    async def generate_totp_secret(self, user_id: UUID) -> dict[str, Any]:
        """
        Generate TOTP secret for user.
        
        Args:
            user_id: User identifier
            
        Returns:
            Dict containing:
                - secret: Base32 encoded secret
                - qr_code: QR code data URL
                - backup_codes: List of backup codes
        """
        ...
    
    async def verify_totp_code(self, user_id: UUID, code: str) -> bool:
        """
        Verify TOTP code.
        
        Args:
            user_id: User identifier
            code: 6-digit TOTP code
            
        Returns:
            True if code is valid
        """
        ...
    
    async def generate_backup_codes(
        self, 
        user_id: UUID, 
        count: int = 10
    ) -> list[str]:
        """
        Generate backup codes.
        
        Args:
            user_id: User identifier
            count: Number of codes to generate
            
        Returns:
            List of backup codes
        """
        ...
    
    async def verify_backup_code(self, user_id: UUID, code: str) -> bool:
        """
        Verify and consume backup code.
        
        Args:
            user_id: User identifier
            code: Backup code to verify
            
        Returns:
            True if code is valid (code is consumed)
        """
        ...
    
    async def send_sms_code(
        self, 
        user_id: UUID, 
        phone: str,
        purpose: str = "login"
    ) -> str:
        """
        Send SMS verification code.
        
        Args:
            user_id: User identifier
            phone: Phone number
            purpose: Purpose of code (login/verification)
            
        Returns:
            Code identifier for verification
            
        Raises:
            SMSDeliveryError: If SMS fails to send
        """
        ...
    
    async def verify_sms_code(self, code_id: str, code: str) -> bool:
        """
        Verify SMS code.
        
        Args:
            code_id: Code identifier from send_sms_code
            code: User provided code
            
        Returns:
            True if code is valid
        """
        ...
    
    async def send_email_code(
        self, 
        user_id: UUID, 
        email: str,
        purpose: str = "login"
    ) -> str:
        """
        Send email verification code.
        
        Args:
            user_id: User identifier
            email: Email address
            purpose: Purpose of code
            
        Returns:
            Code identifier for verification
        """
        ...
    
    async def verify_email_code(self, code_id: str, code: str) -> bool:
        """
        Verify email code.
        
        Args:
            code_id: Code identifier
            code: User provided code
            
        Returns:
            True if code is valid
        """
        ...
    
    async def get_available_methods(self, user_id: UUID) -> list[dict[str, Any]]:
        """
        Get available MFA methods for user.
        
        Args:
            user_id: User identifier
            
        Returns:
            List of available methods with metadata
        """
        ...
