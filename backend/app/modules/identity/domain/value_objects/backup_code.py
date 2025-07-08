"""
Backup Code Value Object

Immutable representation of MFA backup/recovery codes.
"""

import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum

from .base import ValueObject


class BackupCodeStatus(Enum):
    """Status of a backup code."""
    
    ACTIVE = "active"
    USED = "used"
    EXPIRED = "expired"
    REVOKED = "revoked"


class BackupCodeFormat(Enum):
    """Format of backup codes."""
    
    NUMERIC = "numeric"  # 8-10 digit numbers
    ALPHANUMERIC = "alphanumeric"  # Mix of letters and numbers
    WORDS = "words"  # Memorable word combinations
    GROUPED = "grouped"  # Grouped format (e.g., XXXX-XXXX-XXXX)


@dataclass(frozen=True)
class BackupCode(ValueObject):
    """
    Value object representing a single backup code.
    
    Stores the hashed value for security, never the plain text code.
    """
    
    code_hash: str
    generated_at: datetime
    status: BackupCodeStatus = BackupCodeStatus.ACTIVE
    used_at: datetime | None = None
    format_type: BackupCodeFormat = BackupCodeFormat.ALPHANUMERIC
    
    def __post_init__(self):
        """Validate backup code."""
        if not self.code_hash:
            raise ValueError("Code hash is required")
        
        # Validate hash format (should be hex)
        if not all(c in '0123456789abcdef' for c in self.code_hash.lower()):
            raise ValueError("Invalid code hash format")
        
        # Ensure timestamps are timezone-aware
        if self.generated_at.tzinfo is None:
            object.__setattr__(self, 'generated_at', self.generated_at.replace(tzinfo=UTC))
        
        if self.used_at and self.used_at.tzinfo is None:
            object.__setattr__(self, 'used_at', self.used_at.replace(tzinfo=UTC))
        
        # Validate status transitions
        if self.status == BackupCodeStatus.USED and not self.used_at:
            raise ValueError("Used codes must have used_at timestamp")
        
        if self.used_at and self.status != BackupCodeStatus.USED:
            raise ValueError("Only used codes should have used_at timestamp")
    
    @classmethod
    def generate_set(
        cls,
        count: int = 10,
        format_type: BackupCodeFormat = BackupCodeFormat.ALPHANUMERIC,
        length: int = 8
    ) -> tuple[list['BackupCode'], list[str]]:
        """
        Generate a set of backup codes.
        
        Returns tuple of (BackupCode objects, plain text codes).
        Plain text codes should be shown to user once and never stored.
        """
        codes = []
        plain_codes = []
        
        for _ in range(count):
            # Generate code based on format
            if format_type == BackupCodeFormat.NUMERIC:
                plain_code = cls._generate_numeric(length)
            elif format_type == BackupCodeFormat.ALPHANUMERIC:
                plain_code = cls._generate_alphanumeric(length)
            elif format_type == BackupCodeFormat.WORDS:
                plain_code = cls._generate_word_based()
            elif format_type == BackupCodeFormat.GROUPED:
                plain_code = cls._generate_grouped()
            else:
                plain_code = cls._generate_alphanumeric(length)
            
            # Hash the code
            code_hash = hashlib.sha256(plain_code.encode()).hexdigest()
            
            # Create BackupCode object
            backup_code = cls(
                code_hash=code_hash,
                generated_at=datetime.now(UTC),
                format_type=format_type
            )
            
            codes.append(backup_code)
            plain_codes.append(plain_code)
        
        return codes, plain_codes
    
    @staticmethod
    def _generate_numeric(length: int = 8) -> str:
        """Generate numeric backup code."""
        return ''.join(secrets.choice('0123456789') for _ in range(length))
    
    @staticmethod
    def _generate_alphanumeric(length: int = 8) -> str:
        """Generate alphanumeric backup code."""
        # Exclude ambiguous characters (0, O, I, l)
        chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
        return ''.join(secrets.choice(chars) for _ in range(length))
    
    @staticmethod
    def _generate_word_based() -> str:
        """Generate word-based backup code (simplified version)."""
        # In production, would use a proper word list
        adjectives = ['swift', 'bright', 'cosmic', 'lunar', 'solar', 'mystic']
        nouns = ['falcon', 'phoenix', 'dragon', 'tiger', 'eagle', 'wolf']
        numbers = [''.join(secrets.choice('0123456789') for _ in range(3))]
        
        adjective = secrets.choice(adjectives)
        noun = secrets.choice(nouns)
        number = numbers[0]
        
        return f"{adjective}-{noun}-{number}"
    
    @staticmethod
    def _generate_grouped() -> str:
        """Generate grouped format backup code.
        
        Format: XXXX-XXXX-XXXX
        """
        chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
        groups = []
        
        for _ in range(3):
            group = ''.join(secrets.choice(chars) for _ in range(4))
            groups.append(group)
        
        return '-'.join(groups)
    
    @classmethod
    def from_plain_code(
        cls, 
        plain_code: str, 
        format_type: BackupCodeFormat = BackupCodeFormat.ALPHANUMERIC
    ) -> 'BackupCode':
        """Create BackupCode from plain text (for verification)."""
        # Normalize code
        normalized = plain_code.strip().upper()
        
        # Remove formatting characters for grouped codes
        if format_type == BackupCodeFormat.GROUPED:
            normalized = normalized.replace('-', '')
        
        # Hash the normalized code
        code_hash = hashlib.sha256(normalized.encode()).hexdigest()
        
        return cls(
            code_hash=code_hash,
            generated_at=datetime.now(UTC),
            format_type=format_type
        )
    
    def verify_code(self, plain_code: str) -> bool:
        """Verify a plain text code against this backup code."""
        # Normalize input
        normalized = plain_code.strip().upper()
        
        # Remove formatting for grouped codes
        if self.format_type == BackupCodeFormat.GROUPED:
            normalized = normalized.replace('-', '')
        
        # Hash and compare
        input_hash = hashlib.sha256(normalized.encode()).hexdigest()
        return secrets.compare_digest(self.code_hash, input_hash)
    
    def mark_used(self) -> 'BackupCode':
        """Mark code as used and return new instance."""
        if self.status != BackupCodeStatus.ACTIVE:
            raise ValueError(f"Cannot use {self.status.value} code")
        
        return BackupCode(
            code_hash=self.code_hash,
            generated_at=self.generated_at,
            status=BackupCodeStatus.USED,
            used_at=datetime.now(UTC),
            format_type=self.format_type
        )
    
    def revoke(self) -> 'BackupCode':
        """Revoke code and return new instance."""
        if self.status == BackupCodeStatus.USED:
            raise ValueError("Cannot revoke used code")
        
        return BackupCode(
            code_hash=self.code_hash,
            generated_at=self.generated_at,
            status=BackupCodeStatus.REVOKED,
            used_at=None,
            format_type=self.format_type
        )
    
    @property
    def is_active(self) -> bool:
        """Check if code is active and usable."""
        return self.status == BackupCodeStatus.ACTIVE
    
    @property
    def is_used(self) -> bool:
        """Check if code has been used."""
        return self.status == BackupCodeStatus.USED
    
    @property
    def age_days(self) -> int:
        """Get age of code in days."""
        age = datetime.now(UTC) - self.generated_at
        return age.days
    
    def get_fingerprint(self) -> str:
        """Get fingerprint for tracking (first 8 chars of hash)."""
        return self.code_hash[:8]
    
    def format_for_display(self, plain_code: str) -> str:
        """
        Format plain code for display based on format type.
        
        Note: Only use with actual plain code during generation.
        """
        if self.format_type == BackupCodeFormat.GROUPED:
            # Already in grouped format
            return plain_code
        if self.format_type == BackupCodeFormat.NUMERIC:
            # Group numeric codes: XXXX XXXX
            if len(plain_code) == 8:
                return f"{plain_code[:4]} {plain_code[4:]}"
            return plain_code
        if self.format_type == BackupCodeFormat.ALPHANUMERIC:
            # Group alphanumeric: XXXX-XXXX
            if len(plain_code) == 8:
                return f"{plain_code[:4]}-{plain_code[4:]}"
            return plain_code
        return plain_code
    
    def to_audit_entry(self) -> dict:
        """Create audit log entry."""
        entry = {
            'fingerprint': self.get_fingerprint(),
            'status': self.status.value,
            'format': self.format_type.value,
            'generated_at': self.generated_at.isoformat(),
            'age_days': self.age_days
        }
        
        if self.used_at:
            entry['used_at'] = self.used_at.isoformat()
        
        return entry
    
    def __str__(self) -> str:
        """String representation (safe for logging)."""
        return f"BackupCode(fingerprint={self.get_fingerprint()}, status={self.status.value})"
    
    def __repr__(self) -> str:
        """Debug representation."""
        return f"BackupCode(format={self.format_type.value}, status={self.status.value}, age={self.age_days}d)"