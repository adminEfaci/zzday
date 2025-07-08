"""
Email Value Object

Represents a validated email address.
"""

import re
from dataclasses import dataclass
from typing import Any, ClassVar

from .base import ValueObject


@dataclass(frozen=True)
class Email(ValueObject):
    """Email value object with validation."""
    
    # RFC 5322 compliant email regex (simplified version)
    EMAIL_REGEX: ClassVar[re.Pattern] = re.compile(
        r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    )
    
    # Common temporary email domains to block
    DISPOSABLE_DOMAINS: ClassVar[frozenset[str]] = frozenset({
        '10minutemail.com', 'guerrillamail.com', 'mailinator.com',
        'temp-mail.org', 'throwaway.email', 'yopmail.com',
        'tempmail.com', 'trashmail.com', 'maildrop.cc'
    })
    
    value: str
    is_verified: bool = False
    is_primary: bool = False
    
    def __post_init__(self):
        """Validate email address."""
        # Convert to lowercase
        object.__setattr__(self, 'value', self.value.lower().strip())
        
        # Basic validation
        if not self.value:
            raise ValueError("Email address cannot be empty")
        
        if len(self.value) > 254:  # RFC 5321
            raise ValueError("Email address is too long")
        
        # Format validation
        if not self.EMAIL_REGEX.match(self.value):
            raise ValueError(f"Invalid email format: {self.value}")
        
        # Check local part length
        local_part = self.value.split('@')[0]
        if len(local_part) > 64:  # RFC 5321
            raise ValueError("Email local part is too long")
        
        # Check for consecutive dots
        if '..' in self.value:
            raise ValueError("Email cannot contain consecutive dots")
        
        # Check for leading/trailing dots
        if self.value.startswith('.') or self.value.endswith('.'):
            raise ValueError("Email cannot start or end with a dot")
        
        if local_part.startswith('.') or local_part.endswith('.'):
            raise ValueError("Email local part cannot start or end with a dot")
    
    @property
    def domain(self) -> str:
        """Get email domain."""
        return self.value.split('@')[1]
    
    @property
    def local_part(self) -> str:
        """Get local part of email."""
        return self.value.split('@')[0]
    
    @property
    def is_disposable(self) -> bool:
        """Check if email is from a disposable email service."""
        return self.domain in self.DISPOSABLE_DOMAINS
    
    @property
    def is_corporate(self) -> bool:
        """Check if email appears to be corporate (not free email)."""
        free_domains = {
            'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
            'aol.com', 'icloud.com', 'mail.com', 'protonmail.com',
            'yandex.com', 'qq.com', '163.com', '126.com'
        }
        return self.domain not in free_domains and not self.is_disposable
    
    def mask(self) -> str:
        """Return masked version for display."""
        local = self.local_part
        domain = self.domain
        
        if len(local) <= 3:
            # Too short to mask effectively
            masked_local = local[0] + '*' * (len(local) - 1)
        else:
            # Show first 2 and last character
            masked_local = local[:2] + '*' * (len(local) - 3) + local[-1]
        
        # Mask domain partially
        domain_parts = domain.split('.')
        if len(domain_parts[0]) > 3:
            domain_parts[0] = domain_parts[0][:2] + '*' * (len(domain_parts[0]) - 2)
        
        return f"{masked_local}@{'.'.join(domain_parts)}"
    
    def get_gravatar_url(self, size: int = 200, default: str = 'mp') -> str:
        """Get Gravatar URL for this email."""
        import hashlib
        email_hash = hashlib.md5(self.value.encode('utf-8')).hexdigest()
        return f"https://www.gravatar.com/avatar/{email_hash}?s={size}&d={default}"
    
    def normalize(self) -> str:
        """Get normalized email (for some providers like Gmail)."""
        local = self.local_part
        domain = self.domain
        
        # Gmail ignores dots and everything after +
        if domain in ['gmail.com', 'googlemail.com']:
            # Remove dots
            local = local.replace('.', '')
            # Remove everything after +
            if '+' in local:
                local = local.split('+')[0]
        
        return f"{local}@{domain}"
    
    @classmethod
    def parse(cls, value: str, is_verified: bool = False) -> 'Email':
        """Parse and create email value object."""
        return cls(value=value, is_verified=is_verified)
    
    def __str__(self) -> str:
        """String representation."""
        return self.value
    
    def __eq__(self, other: Any) -> bool:
        """Email equality based on normalized value."""
        if not isinstance(other, Email):
            return False
        return self.normalize() == other.normalize()
    
    def __hash__(self) -> int:
        """Hash based on normalized email."""
        return hash(self.normalize())
    
    def __lt__(self, other: 'Email') -> bool:
        """Less than comparison for sorting."""
        if not isinstance(other, Email):
            return NotImplemented
        return self.value < other.value
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "value": self.value,
            "domain": self.domain,
            "local_part": self.local_part,
            "is_verified": self.is_verified,
            "is_primary": self.is_primary,
            "is_disposable": self.is_disposable,
            "is_corporate": self.is_corporate,
            "masked": self.mask(),
            "normalized": self.normalize()
        }