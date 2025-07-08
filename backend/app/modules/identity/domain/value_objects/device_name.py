"""
Device Name Value Object

Immutable representation of a device name with validation and normalization.
"""

import re
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum

from .base import ValueObject


class DeviceNamePattern(Enum):
    """Common device naming patterns."""
    
    PERSONAL = "personal"  # "John's iPhone"
    MODEL_BASED = "model"  # "iPhone 15 Pro"
    LOCATION_BASED = "location"  # "Office Desktop"
    CUSTOM = "custom"  # User-defined
    GENERATED = "generated"  # System-generated


@dataclass(frozen=True)
class DeviceName(ValueObject):
    """
    Value object representing a device name.
    
    Handles validation, normalization, and sanitization of device names
    for consistent storage and display.
    """
    
    value: str
    pattern: DeviceNamePattern = DeviceNamePattern.CUSTOM
    
    def __post_init__(self):
        """Validate and normalize device name."""
        if not self.value or not self.value.strip():
            raise ValueError("Device name cannot be empty")
        
        # Normalize and validate
        normalized = self._normalize(self.value)
        
        # Check length after normalization
        if len(normalized) < 1:
            raise ValueError("Device name too short after normalization")
        
        if len(normalized) > 100:
            raise ValueError("Device name too long (max 100 characters)")
        
        # Check for invalid patterns
        if not self._is_valid_pattern(normalized):
            raise ValueError("Device name contains invalid characters or patterns")
        
        # Store normalized value
        object.__setattr__(self, 'value', normalized)
        
        # Detect pattern if not specified
        if self.pattern == DeviceNamePattern.CUSTOM:
            detected_pattern = self._detect_pattern(normalized)
            object.__setattr__(self, 'pattern', detected_pattern)
    
    def _normalize(self, name: str) -> str:
        """Normalize device name."""
        # Remove leading/trailing whitespace
        name = name.strip()
        
        # Normalize Unicode characters
        name = unicodedata.normalize('NFKC', name)
        
        # Replace multiple spaces with single space
        name = re.sub(r'\s+', ' ', name)
        
        # Remove control characters
        name = ''.join(char for char in name if not unicodedata.category(char).startswith('C'))
        
        # Limit special characters
        # Allow letters, numbers, spaces, and common punctuation
        allowed_pattern = r'[^a-zA-Z0-9\s\-_\'\.,()&]'
        return re.sub(allowed_pattern, '', name)
    
    def _is_valid_pattern(self, name: str) -> bool:
        """Check if name matches valid patterns."""
        # Must contain at least one alphanumeric character
        if not re.search(r'[a-zA-Z0-9]', name):
            return False
        
        # Check for SQL injection patterns
        sql_patterns = [
            r'(?i)(union|select|insert|update|delete|drop|create|alter|exec|script)',
            r'[;\'"].*[;\'"]',  # Quotes with content
            r'--',  # SQL comments
            r'/\*.*\*/'  # Multi-line comments
        ]
        
        for pattern in sql_patterns:
            if re.search(pattern, name):
                return False
        
        # Check for XSS patterns
        xss_patterns = [
            r'<[^>]+>',  # HTML tags
            r'javascript:',
            r'on\w+\s*=',  # Event handlers
        ]
        
        for pattern in xss_patterns:
            if re.search(pattern, name, re.IGNORECASE):
                return False
        
        return True
    
    def _detect_pattern(self, name: str) -> DeviceNamePattern:
        """Detect the naming pattern used."""
        # Check for possessive pattern (e.g., "John's iPhone")
        if re.search(r"'s\s+\w+", name):
            return DeviceNamePattern.PERSONAL
        
        # Check for model-based patterns
        model_keywords = [
            'iPhone', 'iPad', 'MacBook', 'iMac', 'Android', 'Galaxy',
            'Pixel', 'Surface', 'ThinkPad', 'Dell', 'HP', 'Lenovo'
        ]
        
        if any(keyword in name for keyword in model_keywords):
            return DeviceNamePattern.MODEL_BASED
        
        # Check for location-based patterns
        location_keywords = [
            'Office', 'Home', 'Work', 'Desktop', 'Laptop', 'Mobile',
            'Kitchen', 'Living Room', 'Bedroom', 'Study'
        ]
        
        if any(keyword in name for keyword in location_keywords):
            return DeviceNamePattern.LOCATION_BASED
        
        # Check for generated pattern (UUIDs, random strings)
        if re.match(r'^[a-f0-9]{8}-?[a-f0-9]{4}-?[a-f0-9]{4}-?[a-f0-9]{4}-?[a-f0-9]{12}$', name.lower()):
            return DeviceNamePattern.GENERATED
        
        return DeviceNamePattern.CUSTOM
    
    @classmethod
    def generate_default(cls, device_type: str, user_name: str | None = None) -> 'DeviceName':
        """Generate a default device name."""
        if user_name:
            # Personal pattern
            name = f"{user_name}'s {device_type}"
            pattern = DeviceNamePattern.PERSONAL
        else:
            # Generic pattern
            timestamp = datetime.now(UTC).strftime('%Y%m%d')
            name = f"{device_type} {timestamp}"
            pattern = DeviceNamePattern.GENERATED
        
        return cls(value=name, pattern=pattern)
    
    @property
    def is_personal(self) -> bool:
        """Check if this is a personal device name."""
        return self.pattern == DeviceNamePattern.PERSONAL
    
    @property
    def is_generic(self) -> bool:
        """Check if this is a generic/generated name."""
        return self.pattern in [DeviceNamePattern.GENERATED, DeviceNamePattern.MODEL_BASED]
    
    @property
    def contains_pii(self) -> bool:
        """
        Check if device name might contain personally identifiable information.
        
        This is a heuristic check for names that might reveal user identity.
        """
        # Check for possessive pattern
        if self.is_personal:
            return True
        
        # Check for common name patterns
        # This is a simplified check - in production would use more sophisticated NER
        name_pattern = r'\b[A-Z][a-z]+\b'  # Capitalized words
        potential_names = re.findall(name_pattern, self.value)
        
        # If multiple capitalized words, might be a full name
        if len(potential_names) >= 2:
            return True
        
        # Check for email-like patterns
        return bool(re.search(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+", self.value))
    
    def anonymize(self) -> 'DeviceName':
        """Create anonymized version of device name."""
        if not self.contains_pii:
            return self  # Already anonymous
        
        # Extract device type if possible
        device_types = [
            'iPhone', 'iPad', 'Android', 'Phone', 'Tablet', 'Desktop',
            'Laptop', 'Computer', 'Mobile', 'Device'
        ]
        
        device_type = None
        for dt in device_types:
            if dt.lower() in self.value.lower():
                device_type = dt
                break
        
        if device_type:
            return DeviceName(
                value=f"Anonymous {device_type}",
                pattern=DeviceNamePattern.GENERATED
            )
        return DeviceName(
            value="Anonymous Device",
            pattern=DeviceNamePattern.GENERATED
        )
    
    def format_display(self, max_length: int = 30) -> str:
        """Format device name for display."""
        if len(self.value) <= max_length:
            return self.value
        
        # Truncate with ellipsis
        return f"{self.value[:max_length-3]}..."
    
    def format_safe(self) -> str:
        """Format device name for safe display (HTML escaped)."""
        # Basic HTML escaping
        safe_value = self.value
        safe_value = safe_value.replace('&', '&amp;')
        safe_value = safe_value.replace('<', '&lt;')
        safe_value = safe_value.replace('>', '&gt;')
        safe_value = safe_value.replace('"', '&quot;')
        return safe_value.replace("'", '&#39;')
    
    def similarity_score(self, other: 'DeviceName') -> float:
        """
        Calculate similarity score with another device name.
        
        Returns score between 0.0 and 1.0.
        """
        if self.value == other.value:
            return 1.0
        
        # Convert to lowercase for comparison
        name1 = self.value.lower()
        name2 = other.value.lower()
        
        # Levenshtein distance normalized by max length
        distance = self._levenshtein_distance(name1, name2)
        max_length = max(len(name1), len(name2))
        
        if max_length == 0:
            return 1.0
        
        return 1.0 - (distance / max_length)
    
    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein distance between two strings."""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    def __str__(self) -> str:
        """String representation."""
        return self.value
    
    def __repr__(self) -> str:
        """Debug representation."""
        return f"DeviceName(value='{self.format_display()}', pattern={self.pattern.value})"