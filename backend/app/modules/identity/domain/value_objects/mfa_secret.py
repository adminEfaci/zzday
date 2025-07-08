"""
MFA Secret Value Object

Immutable representation of Multi-Factor Authentication secrets.
"""

import base64
import hashlib
import secrets
from dataclasses import dataclass
from enum import Enum

from .base import ValueObject


class MFAAlgorithm(Enum):
    """Supported MFA algorithms."""
    
    SHA1 = "SHA1"
    SHA256 = "SHA256"
    SHA512 = "SHA512"


class MFAType(Enum):
    """Types of MFA secrets."""
    
    TOTP = "TOTP"  # Time-based One-Time Password
    HOTP = "HOTP"  # HMAC-based One-Time Password
    BACKUP = "BACKUP"  # Backup codes
    SMS = "SMS"  # SMS-based (stores phone number hash)
    EMAIL = "EMAIL"  # Email-based (stores email hash)
    PUSH = "PUSH"  # Push notification (stores device token)
    BIOMETRIC = "BIOMETRIC"  # Biometric data reference
    HARDWARE = "HARDWARE"  # Hardware token reference


@dataclass(frozen=True)
class MFASecret(ValueObject):
    """
    Value object representing an MFA secret.
    
    Handles generation, validation, and secure storage of MFA secrets.
    """
    
    secret_value: str  # Base32 encoded for TOTP/HOTP, or encrypted value for others
    mfa_type: MFAType
    algorithm: MFAAlgorithm = MFAAlgorithm.SHA1
    digits: int = 6
    period: int = 30  # For TOTP
    counter: int = 0  # For HOTP
    
    def __post_init__(self):
        """Validate MFA secret."""
        if not self.secret_value:
            raise ValueError("Secret value is required")
        
        # Validate based on type
        if self.mfa_type in [MFAType.TOTP, MFAType.HOTP]:
            # Should be valid base32
            try:
                base64.b32decode(self.secret_value)
            except Exception as e:
                raise ValueError("Invalid base32 secret for TOTP/HOTP") from e
            
            # Check minimum length (80 bits = 16 base32 chars as per RFC 4226)
            if len(self.secret_value) < 16:
                raise ValueError("Secret too short for TOTP/HOTP (minimum 80 bits)")
        
        # Validate digits
        if self.digits not in [6, 7, 8]:
            raise ValueError("Digits must be 6, 7, or 8")
        
        # Validate period for TOTP
        if self.mfa_type == MFAType.TOTP and self.period not in [30, 60]:
            raise ValueError("TOTP period must be 30 or 60 seconds")
        
        # Validate counter for HOTP
        if self.mfa_type == MFAType.HOTP and self.counter < 0:
            raise ValueError("HOTP counter must be non-negative")
    
    @classmethod
    def generate_totp_secret(
        cls,
        length: int = 32,  # 160 bits in base32
        algorithm: MFAAlgorithm = MFAAlgorithm.SHA1,
        digits: int = 6,
        period: int = 30
    ) -> 'MFASecret':
        """Generate a new TOTP secret."""
        # Generate random bytes (20 bytes = 160 bits for compatibility)
        if length == 32:
            random_bytes = secrets.token_bytes(20)
        else:
            # Calculate bytes needed for desired base32 length
            byte_length = (length * 5) // 8
            random_bytes = secrets.token_bytes(byte_length)
        
        # Convert to base32
        secret = base64.b32encode(random_bytes).decode('ascii').rstrip('=')
        
        return cls(
            secret_value=secret,
            mfa_type=MFAType.TOTP,
            algorithm=algorithm,
            digits=digits,
            period=period
        )
    
    @classmethod
    def generate_hotp_secret(
        cls,
        length: int = 32,
        algorithm: MFAAlgorithm = MFAAlgorithm.SHA1,
        digits: int = 6,
        initial_counter: int = 0
    ) -> 'MFASecret':
        """Generate a new HOTP secret."""
        # Similar to TOTP but with counter
        if length == 32:
            random_bytes = secrets.token_bytes(20)
        else:
            byte_length = (length * 5) // 8
            random_bytes = secrets.token_bytes(byte_length)
        
        secret = base64.b32encode(random_bytes).decode('ascii').rstrip('=')
        
        return cls(
            secret_value=secret,
            mfa_type=MFAType.HOTP,
            algorithm=algorithm,
            digits=digits,
            counter=initial_counter
        )
    
    @classmethod
    def generate_backup_codes(cls, count: int = 10, length: int = 8) -> list['MFASecret']:
        """Generate backup codes."""
        codes = []
        
        for _ in range(count):
            # Generate alphanumeric code
            code = ''.join(secrets.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(length))
            
            # Store as hash for security
            code_hash = hashlib.sha256(code.encode()).hexdigest()
            
            codes.append(cls(
                secret_value=code_hash,
                mfa_type=MFAType.BACKUP,
                algorithm=MFAAlgorithm.SHA256
            ))
        
        return codes
    
    @classmethod
    def from_existing_secret(
        cls,
        secret: str,
        mfa_type: MFAType,
        algorithm: MFAAlgorithm = MFAAlgorithm.SHA1
    ) -> 'MFASecret':
        """Create from an existing secret value."""
        return cls(
            secret_value=secret,
            mfa_type=mfa_type,
            algorithm=algorithm
        )
    
    @property
    def is_time_based(self) -> bool:
        """Check if this is a time-based secret."""
        return self.mfa_type == MFAType.TOTP
    
    @property
    def is_counter_based(self) -> bool:
        """Check if this is a counter-based secret."""
        return self.mfa_type == MFAType.HOTP
    
    @property
    def requires_network(self) -> bool:
        """Check if this MFA method requires network connectivity."""
        return self.mfa_type in [MFAType.SMS, MFAType.EMAIL, MFAType.PUSH]
    
    @property
    def is_backup_code(self) -> bool:
        """Check if this is a backup code."""
        return self.mfa_type == MFAType.BACKUP
    
    def get_provisioning_uri(
        self,
        account_name: str,
        issuer: str,
        icon_url: str | None = None
    ) -> str:
        """
        Generate provisioning URI for QR code generation.
        
        Format: otpauth://TYPE/LABEL?PARAMETERS
        """
        if self.mfa_type not in [MFAType.TOTP, MFAType.HOTP]:
            raise ValueError("Provisioning URI only available for TOTP/HOTP")
        
        # Build label
        label = f"{issuer}:{account_name}"
        
        # Build parameters
        params = [
            f"secret={self.secret_value}",
            f"issuer={issuer}",
            f"algorithm={self.algorithm.value}",
            f"digits={self.digits}"
        ]
        
        if self.mfa_type == MFAType.TOTP:
            params.append(f"period={self.period}")
        elif self.mfa_type == MFAType.HOTP:
            params.append(f"counter={self.counter}")
        
        if icon_url:
            params.append(f"image={icon_url}")
        
        # Build URI
        type_name = self.mfa_type.value.lower()
        return f"otpauth://{type_name}/{label}?{'&'.join(params)}"
    
    def increment_counter(self) -> 'MFASecret':
        """
        Increment HOTP counter.
        
        Returns a new instance with incremented counter.
        """
        if self.mfa_type != MFAType.HOTP:
            raise ValueError("Counter increment only valid for HOTP")
        
        return MFASecret(
            secret_value=self.secret_value,
            mfa_type=self.mfa_type,
            algorithm=self.algorithm,
            digits=self.digits,
            counter=self.counter + 1
        )
    
    def mask_secret(self) -> str:
        """Get masked version of secret for display."""
        if len(self.secret_value) <= 8:
            return '*' * len(self.secret_value)
        
        # Show first 4 and last 4 characters
        return f"{self.secret_value[:4]}...{self.secret_value[-4:]}"
    
    def get_fingerprint(self) -> str:
        """Get fingerprint of secret for tracking."""
        # Never expose actual secret
        return hashlib.sha256(self.secret_value.encode()).hexdigest()[:16]
    
    def to_storage_format(self) -> dict:
        """Convert to format suitable for secure storage."""
        return {
            'type': self.mfa_type.value,
            'algorithm': self.algorithm.value,
            'digits': self.digits,
            'period': self.period if self.mfa_type == MFAType.TOTP else None,
            'counter': self.counter if self.mfa_type == MFAType.HOTP else None,
            'fingerprint': self.get_fingerprint()
            # Note: secret_value would be encrypted by infrastructure
        }
    
    def __str__(self) -> str:
        """String representation (safe for logging)."""
        return f"MFASecret(type={self.mfa_type.value}, fingerprint={self.get_fingerprint()[:8]}...)"
    
    def __repr__(self) -> str:
        """Debug representation."""
        extra = ""
        if self.mfa_type == MFAType.TOTP:
            extra = f", period={self.period}s"
        elif self.mfa_type == MFAType.HOTP:
            extra = f", counter={self.counter}"
        
        return f"MFASecret(type={self.mfa_type.value}, alg={self.algorithm.value}, digits={self.digits}{extra})"