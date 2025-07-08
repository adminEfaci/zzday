"""
Person Name Value Object

Immutable representation of a person's name with cultural awareness.
"""

import re
import unicodedata
from dataclasses import dataclass
from typing import Any

from app.core.domain.base import ValueObject


@dataclass(frozen=True)
class PersonName(ValueObject):
    """Value object representing a person's name."""
    
    first_name: str
    last_name: str
    middle_name: str | None = None
    prefix: str | None = None  # Mr., Dr., Prof., etc.
    suffix: str | None = None  # Jr., III, PhD, etc.
    preferred_name: str | None = None  # Nickname or preferred first name
    
    def __post_init__(self):
        """Validate name components."""
        # Validate required fields
        if not self.first_name or not self.first_name.strip():
            raise ValueError("First name is required")
        
        if not self.last_name or not self.last_name.strip():
            raise ValueError("Last name is required")
        
        # Normalize and validate names
        object.__setattr__(self, 'first_name', self._normalize_name(self.first_name))
        object.__setattr__(self, 'last_name', self._normalize_name(self.last_name))
        
        if self.middle_name:
            object.__setattr__(self, 'middle_name', self._normalize_name(self.middle_name))
        
        if self.prefix:
            object.__setattr__(self, 'prefix', self._normalize_title(self.prefix))
        
        if self.suffix:
            object.__setattr__(self, 'suffix', self._normalize_suffix(self.suffix))
        
        if self.preferred_name:
            object.__setattr__(self, 'preferred_name', self._normalize_name(self.preferred_name))
        
        # Additional validation
        self._validate_name_parts()
    
    def _normalize_name(self, name: str) -> str:
        """Normalize a name component."""
        # Remove extra whitespace
        normalized = ' '.join(name.split())
        
        # Normalize unicode (NFD then NFC for proper handling of accents)
        normalized = unicodedata.normalize('NFC', normalized)
        
        # Handle special cases (e.g., McDonald, O'Brien)
        normalized = self._handle_special_cases(normalized)
        
        return normalized.strip()
    
    def _normalize_title(self, title: str) -> str:
        """Normalize a title/prefix."""
        title = title.strip()
        
        # Common title mappings
        title_map = {
            'mister': 'Mr.',
            'mr': 'Mr.',
            'missus': 'Mrs.',
            'mrs': 'Mrs.',
            'miss': 'Ms.',
            'ms': 'Ms.',
            'doctor': 'Dr.',
            'dr': 'Dr.',
            'professor': 'Prof.',
            'prof': 'Prof.',
            'reverend': 'Rev.',
            'rev': 'Rev.'
        }
        
        lower_title = title.lower().rstrip('.')
        return title_map.get(lower_title, title)
    
    def _normalize_suffix(self, suffix: str) -> str:
        """Normalize a suffix."""
        suffix = suffix.strip()
        
        # Common suffix mappings
        suffix_map = {
            'junior': 'Jr.',
            'jr': 'Jr.',
            'senior': 'Sr.',
            'sr': 'Sr.',
            'phd': 'PhD',
            'ph.d': 'PhD',
            'md': 'MD',
            'm.d': 'MD',
            'esq': 'Esq.',
            'esquire': 'Esq.'
        }
        
        lower_suffix = suffix.lower().rstrip('.')
        return suffix_map.get(lower_suffix, suffix)
    
    def _handle_special_cases(self, name: str) -> str:
        """Handle special name cases like McDonald, O'Brien, etc."""
        # Handle Mc names (McDonald, McCabe)
        name = re.sub(r'\bMc(\w)', lambda m: f"Mc{m.group(1).upper()}", name, flags=re.IGNORECASE)
        
        # Handle Mac names (MacArthur, MacBeth)
        name = re.sub(r'\bMac(\w)', lambda m: f"Mac{m.group(1).upper()}", name, flags=re.IGNORECASE)
        
        # Handle O' names (O'Brien, O'Connor)
        name = re.sub(r"\bO'(\w)", lambda m: f"O'{m.group(1).upper()}", name, flags=re.IGNORECASE)
        
        # Handle hyphenated names
        parts = name.split('-')
        if len(parts) > 1:
            name = '-'.join(self._capitalize_word(part) for part in parts)
        else:
            name = self._capitalize_word(name)
        
        return name
    
    def _capitalize_word(self, word: str) -> str:
        """Properly capitalize a word, preserving internal capitals."""
        if not word:
            return word
        
        # Check if word has internal capitals (like McDONALD -> McDonald)
        if any(c.isupper() for c in word[1:]):
            # If it's all caps, title case it
            if word.isupper():
                return word.title()
            # Otherwise preserve existing capitalization
            return word
        
        # Normal capitalization
        return word.capitalize()
    
    def _validate_name_parts(self):
        """Validate all name parts."""
        # Check for invalid characters (numbers, most special chars)
        invalid_pattern = r'[0-9@#$%^&*()_+=\[\]{};:"\\|<>?/~`]'
        
        for field, value in [
            ('first_name', self.first_name),
            ('last_name', self.last_name),
            ('middle_name', self.middle_name),
            ('preferred_name', self.preferred_name)
        ]:
            if value and re.search(invalid_pattern, value):
                raise ValueError(f"Invalid characters in {field}")
        
        # Validate length constraints
        max_length = 50
        for field, value in [
            ('first_name', self.first_name),
            ('last_name', self.last_name),
            ('middle_name', self.middle_name)
        ]:
            if value and len(value) > max_length:
                raise ValueError(f"{field} cannot exceed {max_length} characters")
    
    @classmethod
    def create_simple(cls, first_name: str, last_name: str) -> 'PersonName':
        """Create a simple name with just first and last."""
        return cls(
            first_name=first_name,
            last_name=last_name
        )
    
    @classmethod
    def parse(cls, full_name: str) -> 'PersonName':
        """
        Parse a full name string into components.
        This is a best-effort parser and may not handle all edge cases.
        """
        if not full_name or not full_name.strip():
            raise ValueError("Full name cannot be empty")
        
        # Common prefixes to extract
        prefixes = ['Mr.', 'Mrs.', 'Ms.', 'Dr.', 'Prof.', 'Rev.']
        # Common suffixes to extract
        suffixes = ['Jr.', 'Sr.', 'II', 'III', 'IV', 'PhD', 'MD', 'Esq.']
        
        parts = full_name.strip().split()
        
        prefix = None
        suffix = None
        
        # Check for prefix
        if parts and any(parts[0].lower().startswith(p.lower()) for p in prefixes):
            prefix = parts[0]
            parts = parts[1:]
        
        # Check for suffix
        if parts and any(parts[-1].lower().rstrip('.') == s.lower().rstrip('.') for s in suffixes):
            suffix = parts[-1]
            parts = parts[:-1]
        
        # Parse remaining parts
        if not parts:
            raise ValueError("No name parts found after parsing")
        
        if len(parts) == 1:
            # Only one name part - assume it's last name
            return cls(first_name="", last_name=parts[0], prefix=prefix, suffix=suffix)
        if len(parts) == 2:
            # First and last name
            return cls(
                first_name=parts[0],
                last_name=parts[1],
                prefix=prefix,
                suffix=suffix
            )
        # First, middle, and last name
        return cls(
            first_name=parts[0],
            middle_name=' '.join(parts[1:-1]),
            last_name=parts[-1],
            prefix=prefix,
            suffix=suffix
        )
    
    @property
    def full_name(self) -> str:
        """Get full name with all components."""
        parts = []
        
        if self.prefix:
            parts.append(self.prefix)
        
        parts.append(self.first_name)
        
        if self.middle_name:
            parts.append(self.middle_name)
        
        parts.append(self.last_name)
        
        if self.suffix:
            parts.append(self.suffix)
        
        return ' '.join(parts)
    
    @property
    def display_name(self) -> str:
        """Get display name (preferred name or first name)."""
        return self.preferred_name or self.first_name
    
    @property
    def formal_name(self) -> str:
        """Get formal name (prefix + last name)."""
        if self.prefix:
            return f"{self.prefix} {self.last_name}"
        return self.last_name
    
    @property
    def informal_name(self) -> str:
        """Get informal name (first name only)."""
        return self.display_name
    
    @property
    def initials(self) -> str:
        """Get initials."""
        parts = []
        parts.append(self.first_name[0].upper())
        
        if self.middle_name:
            parts.append(self.middle_name[0].upper())
        
        parts.append(self.last_name[0].upper())
        
        return ''.join(parts)
    
    @property
    def monogram(self) -> str:
        """Get monogram (traditional: first, last, middle)."""
        if self.middle_name:
            return f"{self.first_name[0]}{self.last_name[0]}{self.middle_name[0]}".upper()
        return f"{self.first_name[0]}{self.last_name[0]}".upper()
    
    def format_last_first(self) -> str:
        """Format as 'Last, First Middle'."""
        parts = [self.last_name]
        
        name_parts = [self.first_name]
        if self.middle_name:
            name_parts.append(self.middle_name)
        
        parts.append(' '.join(name_parts))
        
        return ', '.join(parts)
    
    def format_citation(self) -> str:
        """Format for citations (Last, F. M.)."""
        parts = [self.last_name]
        
        initials = [f"{self.first_name[0]}."]
        if self.middle_name:
            initials.append(f"{self.middle_name[0]}.")
        
        parts.append(' '.join(initials))
        
        return ', '.join(parts)
    
    def get_sort_key(self) -> str:
        """Get sort key for ordering names."""
        # Remove accents for sorting
        sort_last = unicodedata.normalize('NFD', self.last_name)
        sort_last = ''.join(c for c in sort_last if not unicodedata.combining(c))
        
        sort_first = unicodedata.normalize('NFD', self.first_name)
        sort_first = ''.join(c for c in sort_first if not unicodedata.combining(c))
        
        return f"{sort_last.lower()}, {sort_first.lower()}"
    
    def anonymize(self) -> 'PersonName':
        """Create anonymized version (initials only)."""
        return PersonName(
            first_name=f"{self.first_name[0]}***",
            last_name=f"{self.last_name[0]}***",
            middle_name=f"{self.middle_name[0]}***" if self.middle_name else None,
            prefix=self.prefix,
            suffix=self.suffix,
            preferred_name=None
        )
    
    def matches_search(self, query: str) -> bool:
        """Check if name matches search query."""
        query_lower = query.lower()
        
        # Check each name component
        if query_lower in self.first_name.lower():
            return True
        if query_lower in self.last_name.lower():
            return True
        if self.middle_name and query_lower in self.middle_name.lower():
            return True
        if self.preferred_name and query_lower in self.preferred_name.lower():
            return True
        
        # Check full name
        if query_lower in self.full_name.lower():
            return True
        
        # Check initials
        return query_lower == self.initials.lower()
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "first_name": self.first_name,
            "last_name": self.last_name,
            "middle_name": self.middle_name,
            "prefix": self.prefix,
            "suffix": self.suffix,
            "preferred_name": self.preferred_name,
            "full_name": self.full_name,
            "display_name": self.display_name,
            "initials": self.initials
        }
    
    def __str__(self) -> str:
        """String representation."""
        return self.full_name
    
    def __repr__(self) -> str:
        """Debug representation."""
        return f"PersonName('{self.display_name} {self.last_name}')"