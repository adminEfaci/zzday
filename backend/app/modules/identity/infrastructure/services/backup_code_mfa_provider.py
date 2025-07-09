"""
Backup Code MFA Provider Implementation

Backup recovery codes for Multi-Factor Authentication.
"""

import logging
import secrets
import string
from datetime import UTC, datetime
from typing import Any

from app.modules.identity.domain.entities.admin.mfa_device import MFADevice, MFAMethod
from app.modules.identity.infrastructure.services.mfa_provider_factory import (
    IMFAProvider,
)

logger = logging.getLogger(__name__)


class BackupCodeMFAProvider(IMFAProvider):
    """Backup code MFA provider implementation."""
    
    def __init__(
        self,
        code_length: int = 8,
        code_count: int = 10,
        alphanumeric: bool = True
    ):
        """Initialize backup code MFA provider.
        
        Args:
            code_length: Length of each backup code
            code_count: Number of codes to generate
            alphanumeric: Use alphanumeric codes (vs numeric only)
        """
        self.code_length = code_length
        self.code_count = code_count
        self.alphanumeric = alphanumeric
        
        # Define character set
        if alphanumeric:
            # Exclude ambiguous characters (0, O, I, l)
            self.charset = string.ascii_uppercase.replace('O', '').replace('I', '') + \
                          string.digits.replace('0', '')
        else:
            self.charset = string.digits
    
    @property
    def method(self) -> MFAMethod:
        """Get MFA method type."""
        return MFAMethod.BACKUP_CODE
    
    @property
    def name(self) -> str:
        """Get provider name."""
        return "Backup Recovery Codes"
    
    async def send_code(
        self,
        device: MFADevice,
        user_identifier: str | None = None
    ) -> dict[str, Any]:
        """Backup codes are not sent - they're pre-generated.
        
        Args:
            device: MFA device
            user_identifier: Optional user identifier
            
        Returns:
            Information about backup code usage
        """
        if device.method != MFAMethod.BACKUP_CODE:
            raise ValueError("Device must be BACKUP_CODE method")
        
        remaining_codes = device.get_remaining_backup_codes()
        
        return {
            'sent': False,
            'message': 'Enter one of your backup recovery codes',
            'remaining_codes': remaining_codes,
            'warning': 'Each code can only be used once' if remaining_codes > 0 else 'No backup codes remaining'
        }
    
    async def verify_code(
        self,
        device: MFADevice,
        code: str
    ) -> tuple[bool, dict[str, Any]]:
        """Verify backup code.
        
        Args:
            device: MFA device
            code: Backup code to verify
            
        Returns:
            Tuple of (is_valid, metadata)
        """
        if device.method != MFAMethod.BACKUP_CODE:
            return False, {'error': 'Device must be BACKUP_CODE method'}
        
        # Normalize code (remove spaces, dashes)
        normalized_code = code.upper().replace(' ', '').replace('-', '')
        
        # Use device's backup code verification
        is_valid = device.use_backup_code(normalized_code)
        
        if is_valid:
            remaining = device.get_remaining_backup_codes()
            
            metadata = {
                'verified_at': datetime.now(UTC).isoformat(),
                'method': 'backup_code',
                'device_id': str(device.id),
                'remaining_codes': remaining
            }
            
            if remaining < 3:
                metadata['warning'] = f'Only {remaining} backup codes remaining. Generate new codes soon.'
            
            return True, metadata
        return False, {
            'error': 'Invalid or already used backup code',
            'remaining_codes': device.get_remaining_backup_codes()
        }
    
    async def setup_device(
        self,
        device: MFADevice,
        regenerate: bool = False
    ) -> dict[str, Any]:
        """Setup backup code MFA device.
        
        Args:
            device: MFA device
            regenerate: Whether to regenerate codes
            
        Returns:
            Setup information with generated codes
        """
        if device.method != MFAMethod.BACKUP_CODE:
            raise ValueError("Device must be BACKUP_CODE method")
        
        # Generate new codes if needed
        if not device.backup_codes or regenerate:
            codes = device.generate_backup_codes(count=self.code_count)
        else:
            # Return existing codes (for display)
            codes = [code.value for code in device.backup_codes if not code.is_used]
        
        # Format codes for display
        formatted_codes = [self._format_code(code) for code in codes]
        
        return {
            'device_id': str(device.id),
            'codes': formatted_codes,
            'code_count': len(formatted_codes),
            'instructions': self._get_setup_instructions(),
            'download_filename': f'backup-codes-{datetime.now(UTC).strftime("%Y%m%d")}.txt'
        }
    
    async def is_available(self) -> bool:
        """Check if provider is available."""
        # Backup codes are always available
        return True
    
    def generate_codes(self, count: int | None = None) -> list[str]:
        """Generate backup codes.
        
        Args:
            count: Number of codes to generate
            
        Returns:
            List of generated codes
        """
        count = count or self.code_count
        codes = []
        
        for _ in range(count):
            code = ''.join(secrets.choice(self.charset) for _ in range(self.code_length))
            codes.append(code)
        
        return codes
    
    def _format_code(self, code: str) -> str:
        """Format code for display.
        
        Args:
            code: Raw backup code
            
        Returns:
            Formatted code
        """
        # Add dashes every 4 characters for readability
        if len(code) <= 4:
            return code
        
        parts = [code[i:i+4] for i in range(0, len(code), 4)]
        return '-'.join(parts)
    
    def _get_setup_instructions(self) -> str:
        """Get setup instructions for backup codes.
        
        Returns:
            Instructions text
        """
        return (
            "Save these backup codes in a secure location. "
            "Each code can be used only once to sign in if you lose access to your other authentication methods. "
            "Do not share these codes with anyone."
        )
    
    def validate_code_format(self, code: str) -> bool:
        """Validate backup code format.
        
        Args:
            code: Code to validate
            
        Returns:
            True if format is valid
        """
        # Remove formatting
        normalized = code.upper().replace(' ', '').replace('-', '')
        
        # Check length
        if len(normalized) != self.code_length:
            return False
        
        # Check characters
        return all(c in self.charset for c in normalized)
    
    def export_codes_text(self, codes: list[str], account_info: str | None = None) -> str:
        """Export codes as text for download.
        
        Args:
            codes: List of backup codes
            account_info: Optional account information
            
        Returns:
            Text content for download
        """
        lines = [
            "EzzDay Backup Recovery Codes",
            "=" * 30,
            ""
        ]
        
        if account_info:
            lines.extend([
                f"Account: {account_info}",
                f"Generated: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}",
                ""
            ])
        
        lines.extend([
            "IMPORTANT: Keep these codes secure!",
            "Each code can only be used once.",
            "",
            "Backup Codes:",
            "-" * 20
        ])
        
        for i, code in enumerate(codes, 1):
            lines.append(f"{i:2d}. {self._format_code(code)}")
        
        lines.extend([
            "",
            "-" * 30,
            "Store these codes in a safe place.",
            "Do not share them with anyone."
        ])
        
        return '\n'.join(lines)