"""
Group Name Value Object

Encapsulates and validates group names.
"""

import re
from dataclasses import dataclass

from .base import ValueObject


class GroupLimits:
    """Group name limits and constraints."""
    MIN_NAME_LENGTH = 3
    MAX_NAME_LENGTH = 50


class GroupNamePatterns:
    """Group name patterns and restrictions."""
    FORBIDDEN_CHARS = ['<', '>', '"', "'", '&', '\n', '\r', '\t']
    
    RESERVED_NAMES = {
        'admin', 'administrator', 'root', 'system', 'api', 'www', 'ftp',
        'mail', 'email', 'support', 'help', 'contact', 'about', 'legal',
        'privacy', 'terms', 'service', 'public', 'private', 'anonymous',
        'guest', 'user', 'users', 'group', 'groups', 'default', 'null',
        'undefined', 'none', 'true', 'false', 'test', 'demo'
    }
    
    RESERVED_PREFIXES = ['system:', 'admin:', 'api:', 'internal:']


@dataclass(frozen=True)
class GroupName(ValueObject[str]):
    """Value object for group names."""
    
    value: str
    
    def __post_init__(self):
        """Validate group name."""
        self._validate()
    
    def _validate(self) -> None:
        """Validate the group name."""
        if not self.value:
            raise ValueError("Group name cannot be empty")
        
        # Check length constraints
        if len(self.value) < GroupLimits.MIN_NAME_LENGTH:
            raise ValueError(f"Group name must be at least {GroupLimits.MIN_NAME_LENGTH} characters")
        
        if len(self.value) > GroupLimits.MAX_NAME_LENGTH:
            raise ValueError(f"Group name cannot exceed {GroupLimits.MAX_NAME_LENGTH} characters")
        
        # Check for forbidden characters
        for char in GroupNamePatterns.FORBIDDEN_CHARS:
            if char in self.value:
                raise ValueError(f"Group name cannot contain '{char}'")
        
        # Check for reserved names
        lower_name = self.value.lower()
        if lower_name in GroupNamePatterns.RESERVED_NAMES:
            raise ValueError(f"'{self.value}' is a reserved group name")
        
        # Check for reserved prefixes
        for prefix in GroupNamePatterns.RESERVED_PREFIXES:
            if lower_name.startswith(prefix.lower()):
                raise ValueError(f"Group name cannot start with '{prefix}'")
        
        # Additional validation rules
        if self.value.strip() != self.value:
            raise ValueError("Group name cannot have leading or trailing whitespace")
        
        if "  " in self.value:
            raise ValueError("Group name cannot contain consecutive spaces")
    
    @property
    def display_name(self) -> str:
        """Get formatted display name."""
        return self.value.strip()
    
    @property
    def url_slug(self) -> str:
        """Get URL-safe slug version of the name."""
        # Convert to lowercase and replace spaces with hyphens
        slug = self.value.lower().replace(" ", "-")
        
        # Remove any non-alphanumeric characters except hyphens
        slug = re.sub(r'[^a-z0-9-]', '', slug)
        
        # Remove multiple consecutive hyphens
        slug = re.sub(r'-+', '-', slug)
        
        # Remove leading/trailing hyphens
        return slug.strip('-')
    
    def is_system_group(self) -> bool:
        """Check if this is a system group name."""
        return self.value.lower().startswith("system:")
    
    def matches_pattern(self, pattern: str) -> bool:
        """Check if name matches a pattern (with wildcards)."""
        import fnmatch
        return fnmatch.fnmatch(self.value.lower(), pattern.lower())
    
    def __str__(self) -> str:
        """String representation."""
        return self.value
    
    def __repr__(self) -> str:
        """Developer representation."""
        return f"GroupName('{self.value}')"