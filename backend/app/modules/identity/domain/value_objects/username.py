"""
Username Value Object

Represents a validated username.
"""

import re
from dataclasses import dataclass
from typing import Any, ClassVar

from app.core.domain.base import ValueObject


@dataclass(frozen=True)
class Username(ValueObject):
    """Username value object with validation."""

    # Username validation regex: alphanumeric, underscore, hyphen, dot
    # Must start with letter or number, 3-30 characters
    USERNAME_REGEX: ClassVar[re.Pattern] = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._-]{2,29}$')

    # Reserved usernames that cannot be used
    RESERVED_USERNAMES: ClassVar[frozenset[str]] = frozenset({
        'admin', 'administrator', 'root', 'system', 'user', 'test',
        'guest', 'demo', 'api', 'app', 'www', 'ftp', 'mail', 'email',
        'blog', 'help', 'support', 'contact', 'about', 'legal', 'privacy',
        'terms', 'service', 'services', 'login', 'logout', 'register',
        'signup', 'signin', 'dashboard', 'account', 'profile', 'settings',
        'config', 'configuration', 'public', 'private', 'secure', 'security',
        'anonymous', 'null', 'undefined', 'none', 'true', 'false',
        'home', 'index', 'main', 'default', 'error', '404', '500',
        'abuse', 'postmaster', 'webmaster', 'hostmaster', 'info',
        'sales', 'marketing', 'billing', 'payments', 'invoice',
        'noreply', 'no-reply', 'donotreply', 'do-not-reply',
        'ezzday', 'ezz-day', 'ezzday-admin', 'ezzday-support'
    })

    # Offensive words to block (simplified list)
    BLOCKED_PATTERNS: ClassVar[tuple[str, ...]] = (
        'admin', 'root', 'hack', 'crack', 'exploit'
    )
    
    value: str
    display_name: str = None
    
    def __post_init__(self):
        """Validate username."""
        # Normalize username
        normalized = self.value.lower().strip()
        object.__setattr__(self, 'value', normalized)
        
        # Set display name if not provided
        if not self.display_name:
            object.__setattr__(self, 'display_name', self.value)
        
        # Length validation
        if len(self.value) < 3:
            raise ValueError("Username must be at least 3 characters long")
        
        if len(self.value) > 30:
            raise ValueError("Username cannot exceed 30 characters")
        
        # Format validation
        if not self.USERNAME_REGEX.match(self.value):
            raise ValueError(
                "Username must start with a letter or number and can only "
                "contain letters, numbers, dots, hyphens, and underscores"
            )
        
        # Check consecutive special characters
        if '..' in self.value or '--' in self.value or '__' in self.value:
            raise ValueError("Username cannot contain consecutive special characters")
        
        # Check for reserved usernames
        if self.value in self.RESERVED_USERNAMES:
            raise ValueError(f"Username '{self.value}' is reserved")
        
        # Check for blocked patterns
        for pattern in self.BLOCKED_PATTERNS:
            if pattern in self.value:
                raise ValueError(f"Username contains blocked pattern: {pattern}")
        
        # Username shouldn't look like an email
        if '@' in self.value:
            raise ValueError("Username cannot contain @ symbol")
        
        # Shouldn't start or end with special characters
        if self.value[0] in '.-_' or self.value[-1] in '.-_':
            raise ValueError("Username cannot start or end with special characters")
    
    @property
    def is_valid_mention(self) -> bool:
        """Check if username can be used for @mentions."""
        # For mentions, we might have stricter rules
        return not any(char in self.value for char in '.-')
    
    def get_mention(self) -> str:
        """Get username formatted for mention."""
        return f"@{self.value}"
    
    def get_profile_url(self, base_url: str = "") -> str:
        """Get profile URL for this username."""
        return f"{base_url}/u/{self.value}"
    
    def mask(self) -> str:
        """Return masked version for privacy."""
        if len(self.value) <= 4:
            return self.value[0] + '*' * (len(self.value) - 1)
        
        # Show first 2 and last 2 characters
        return self.value[:2] + '*' * (len(self.value) - 4) + self.value[-2:]
    
    def to_search_terms(self) -> list[str]:
        """Generate search terms for this username."""
        terms = [self.value]
        
        # Add variations without special characters
        clean = re.sub(r'[._-]', '', self.value)
        if clean != self.value:
            terms.append(clean)
        
        # Add parts split by special characters
        parts = re.split(r'[._-]', self.value)
        terms.extend(p for p in parts if len(p) >= 3)
        
        return list(set(terms))
    
    @classmethod
    def generate_from_email(cls, email: str) -> 'Username':
        """Generate username suggestion from email."""
        local_part = email.split('@')[0]
        
        # Remove special characters except dots, hyphens, underscores
        cleaned = re.sub(r'[^a-zA-Z0-9._-]', '', local_part)
        
        # Ensure it starts with alphanumeric
        if cleaned and not cleaned[0].isalnum():
            cleaned = cleaned.lstrip('.-_')
        
        # Truncate if too long
        if len(cleaned) > 27:  # Leave room for numbers
            cleaned = cleaned[:27]
        
        # If too short or empty, generate a default
        if len(cleaned) < 3:
            cleaned = f"user{cleaned}"
        
        # If it's reserved or invalid, append numbers
        base = cleaned
        counter = 1
        while True:
            try:
                username = base if counter == 1 else f"{base}{counter}"
                return cls(value=username)
            except ValueError as e:
                counter += 1
                if counter > 9999:
                    raise ValueError("Could not generate valid username") from e
    
    @classmethod
    def parse(cls, value: str, display_name: str | None = None) -> 'Username':
        """Parse and create username value object."""
        return cls(value=value, display_name=display_name)
    
    def __str__(self) -> str:
        """String representation."""
        return self.value
    
    def __eq__(self, other: Any) -> bool:
        """Username equality is case-insensitive."""
        if not isinstance(other, Username):
            return False
        return self.value.lower() == other.value.lower()
    
    def __hash__(self) -> int:
        """Hash based on lowercase username."""
        return hash(self.value.lower())
    
    def __lt__(self, other: 'Username') -> bool:
        """Less than comparison for sorting."""
        if not isinstance(other, Username):
            return NotImplemented
        return self.value.lower() < other.value.lower()
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "value": self.value,
            "display_name": self.display_name or self.value,
            "mention": self.get_mention(),
            "is_valid_mention": self.is_valid_mention,
            "masked": self.mask(),
            "search_terms": self.to_search_terms()
        }
