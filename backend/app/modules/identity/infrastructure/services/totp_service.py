"""
TOTP Service Implementation

Time-based One-Time Password service using pyotp library.
"""

import base64
import io
import logging
from typing import Any

import pyotp
import qrcode
from qrcode.image.svg import SvgPathImage

from app.modules.identity.domain.entities.admin.mfa_device import MFADevice, MFAMethod
from app.modules.identity.domain.interfaces.services.authentication.mfa_service import (
    ITOTPService,
)

logger = logging.getLogger(__name__)


class TOTPService(ITOTPService):
    """TOTP service implementation using pyotp."""
    
    def __init__(
        self,
        issuer_name: str = "EzzDay",
        digits: int = 6,
        interval: int = 30,
        algorithm: str = "SHA1"
    ):
        """Initialize TOTP service.
        
        Args:
            issuer_name: Name to display in authenticator apps
            digits: Number of digits in the OTP (default: 6)
            interval: Time interval in seconds (default: 30)
            algorithm: Hash algorithm (SHA1, SHA256, SHA512)
        """
        self.issuer_name = issuer_name
        self.digits = digits
        self.interval = interval
        self.algorithm = algorithm
    
    def generate_secret(self) -> str:
        """Generate a new TOTP secret."""
        return pyotp.random_base32()
    
    def generate_uri(
        self,
        secret: str,
        user_identifier: str,
        issuer_name: str | None = None
    ) -> str:
        """Generate provisioning URI for QR code.
        
        Args:
            secret: TOTP secret
            user_identifier: User's email or username
            issuer_name: Optional override for issuer name
            
        Returns:
            Provisioning URI for authenticator apps
        """
        totp = pyotp.TOTP(
            secret,
            digits=self.digits,
            interval=self.interval,
            digest=getattr(pyotp.utils, self.algorithm, pyotp.utils.SHA1)
        )
        
        return totp.provisioning_uri(
            name=user_identifier,
            issuer_name=issuer_name or self.issuer_name
        )
    
    def generate_qr_code(
        self,
        secret: str,
        user_identifier: str,
        format: str = "svg"
    ) -> str:
        """Generate QR code for TOTP setup.
        
        Args:
            secret: TOTP secret
            user_identifier: User's email or username
            format: Output format (svg, png, ascii)
            
        Returns:
            QR code data as string
        """
        uri = self.generate_uri(secret, user_identifier)
        
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(uri)
        qr.make(fit=True)
        
        if format == "svg":
            img = qr.make_image(image_factory=SvgPathImage)
            stream = io.BytesIO()
            img.save(stream)
            return stream.getvalue().decode('utf-8')
        
        if format == "png":
            img = qr.make_image(fill_color="black", back_color="white")
            stream = io.BytesIO()
            img.save(stream, format='PNG')
            return base64.b64encode(stream.getvalue()).decode('utf-8')
        
        if format == "ascii":
            # Generate ASCII representation
            return qr.get_matrix()
        
        raise ValueError(f"Unsupported format: {format}")
    
    def verify_token(
        self,
        secret: str,
        token: str,
        window: int = 1
    ) -> bool:
        """Verify TOTP token.
        
        Args:
            secret: TOTP secret
            token: Token to verify
            window: Number of time windows to check (for clock drift)
            
        Returns:
            True if token is valid
        """
        try:
            totp = pyotp.TOTP(
                secret,
                digits=self.digits,
                interval=self.interval,
                digest=getattr(pyotp.utils, self.algorithm, pyotp.utils.SHA1)
            )
            
            # Verify with time window for clock drift
            return totp.verify(token, valid_window=window)
            
        except Exception as e:
            logger.error(f"TOTP verification error: {e}")
            return False
    
    def generate_current_token(self, secret: str) -> str:
        """Generate current TOTP token (for testing).
        
        Args:
            secret: TOTP secret
            
        Returns:
            Current valid token
        """
        totp = pyotp.TOTP(
            secret,
            digits=self.digits,
            interval=self.interval,
            digest=getattr(pyotp.utils, self.algorithm, pyotp.utils.SHA1)
        )
        
        return totp.now()
    
    def get_remaining_seconds(self) -> int:
        """Get seconds remaining in current time window.
        
        Returns:
            Seconds until next token rotation
        """
        import time
        return self.interval - int(time.time() % self.interval)
    
    def setup_device(
        self,
        device: MFADevice,
        user_identifier: str
    ) -> dict[str, Any]:
        """Setup TOTP device for user.
        
        Args:
            device: MFA device to setup
            user_identifier: User's email or username
            
        Returns:
            Setup information including QR code
        """
        if device.method != MFAMethod.TOTP:
            raise ValueError("Device must be TOTP method")
        
        # Generate new secret if not provided
        if not device.secret:
            device.secret = self.generate_secret()
        
        # Generate provisioning URI and QR code
        uri = self.generate_uri(device.secret, user_identifier)
        qr_svg = self.generate_qr_code(device.secret, user_identifier, "svg")
        qr_png = self.generate_qr_code(device.secret, user_identifier, "png")
        
        return {
            "device_id": str(device.id),
            "secret": device.secret,
            "uri": uri,
            "qr_code_svg": qr_svg,
            "qr_code_png": qr_png,
            "algorithm": self.algorithm,
            "digits": self.digits,
            "interval": self.interval,
            "issuer": self.issuer_name
        }
    
    def validate_setup(
        self,
        device: MFADevice,
        token1: str,
        token2: str | None = None
    ) -> bool:
        """Validate TOTP setup with verification tokens.
        
        Args:
            device: MFA device being setup
            token1: First verification token
            token2: Optional second token for better validation
            
        Returns:
            True if setup is valid
        """
        if not device.secret:
            return False
        
        # Verify first token
        if not self.verify_token(device.secret, token1):
            return False
        
        # If second token provided, verify it's different and valid
        if token2:
            if token1 == token2:
                return False  # Same token, user didn't wait
            
            # Give more time window for second token
            return self.verify_token(device.secret, token2, window=2)
        
        return True
    
    def generate_backup_codes(self, count: int = 8) -> list[str]:
        """Generate backup codes for account recovery.
        
        Args:
            count: Number of codes to generate
            
        Returns:
            List of backup codes
        """
        import secrets
        codes = []
        
        for _ in range(count):
            # Generate 8-digit numeric codes
            code = ''.join(secrets.choice('0123456789') for _ in range(8))
            # Format as XXXX-XXXX for readability
            formatted = f"{code[:4]}-{code[4:]}"
            codes.append(formatted)
        
        return codes
    
    def format_backup_codes(self, codes: list[str]) -> str:
        """Format backup codes for display.
        
        Args:
            codes: List of backup codes
            
        Returns:
            Formatted string for display
        """
        formatted = "=== MFA Backup Codes ===\n\n"
        formatted += "Keep these codes in a safe place.\n"
        formatted += "Each code can only be used once.\n\n"
        
        for i, code in enumerate(codes, 1):
            formatted += f"{i:2d}. {code}\n"
        
        formatted += "\n======================\n"
        return formatted