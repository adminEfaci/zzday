"""
Social Insurance Number (SIN) Value Object

Immutable representation of a Canadian Social Insurance Number with validation.
"""

import re
from dataclasses import dataclass

from app.core.domain.base import ValueObject


@dataclass(frozen=True)
class SIN(ValueObject):
    """
    Value object representing a Canadian Social Insurance Number.
    
    A SIN is a 9-digit number used in Canada for various government programs.
    It follows the Luhn algorithm for validation.
    """
    
    value: str
    
    def __post_init__(self):
        """Validate and normalize SIN."""
        if not self.value:
            raise ValueError("SIN is required")
        
        # Remove all non-digit characters
        digits_only = re.sub(r'\D', '', self.value)
        
        if len(digits_only) != 9:
            raise ValueError("SIN must be exactly 9 digits")
        
        # Store normalized value
        object.__setattr__(self, 'value', digits_only)
        
        # Validate using Luhn algorithm
        if not self._is_valid_luhn():
            raise ValueError("Invalid SIN checksum")
        
        # Validate against known invalid patterns
        if not self._is_valid_pattern():
            raise ValueError("Invalid SIN pattern")
    
    def _is_valid_luhn(self) -> bool:
        """
        Validate SIN using the Luhn algorithm.
        
        The Luhn algorithm:
        1. Double every second digit from right to left
        2. If doubled digit > 9, subtract 9
        3. Sum all digits
        4. Valid if sum is divisible by 10
        """
        digits = [int(d) for d in self.value]
        
        # Double every second digit from right to left
        for i in range(len(digits) - 2, -1, -2):
            digits[i] *= 2
            if digits[i] > 9:
                digits[i] -= 9
        
        # Sum all digits
        total = sum(digits)
        
        # Valid if divisible by 10
        return total % 10 == 0
    
    def _is_valid_pattern(self) -> bool:
        """
        Check for known invalid SIN patterns.
        
        Invalid patterns include:
        - All same digits (e.g., 111111111)
        - Known test SINs
        - SINs starting with 0 or 8 (not issued)
        """
        # Check if all digits are the same
        if len(set(self.value)) == 1:
            return False
        
        # Check first digit (0 and 8 are not issued)
        first_digit = self.value[0]
        if first_digit in ('0', '8'):
            return False
        
        # Known invalid/test SINs
        invalid_sins = {
            '000000000',
            '999999999',
            '123456789'
        }
        
        return self.value not in invalid_sins
    
    @property
    def first_digit(self) -> str:
        """Get the first digit of the SIN."""
        return self.value[0]
    
    @property
    def province_of_registration(self) -> str | None:
        """
        Get the province of registration based on first digit.
        
        Note: This only indicates where the SIN was registered,
        not current residence.
        """
        province_map = {
            '1': 'Atlantic Provinces',  # NS, NB, PE, NL
            '2': 'Quebec',
            '3': 'Quebec',
            '4': 'Ontario',
            '5': 'Ontario',
            '6': 'Prairie Provinces',   # MB, SK, AB, NT, NU
            '7': 'Pacific Region',      # BC, YT
            '9': 'Temporary Resident'   # Temporary workers, students
        }
        
        return province_map.get(self.first_digit)
    
    @property
    def is_temporary_resident(self) -> bool:
        """Check if this is a temporary resident SIN."""
        return self.first_digit == '9'
    
    @property
    def is_permanent_resident(self) -> bool:
        """Check if this is a permanent resident/citizen SIN."""
        return self.first_digit != '9'
    
    def format_display(self) -> str:
        """Format SIN for display (XXX-XXX-XXX)."""
        return f"{self.value[:3]}-{self.value[3:6]}-{self.value[6:]}"
    
    def format_masked(self) -> str:
        """Format SIN with masking for security (XXX-XX*-***)."""
        return f"{self.value[:3]}-{self.value[3:5]}*-***"
    
    def format_partial(self) -> str:
        """Format partial SIN showing only last 4 digits (***-**X-XXX)."""
        return f"***-**{self.value[5]}-{self.value[6:]}"
    
    def matches_partial(self, partial: str) -> bool:
        """
        Check if SIN matches a partial SIN.
        
        Partial can be last 4 digits or formatted partial.
        """
        # Remove non-digits from partial
        partial_digits = re.sub(r'\D', '', partial)
        
        if len(partial_digits) == 4:
            # Check last 4 digits
            return self.value.endswith(partial_digits)
        if len(partial_digits) == 9:
            # Full SIN comparison
            return self.value == partial_digits
        return False
    
    @classmethod
    def generate_test_sin(cls) -> 'SIN':
        """
        Generate a valid test SIN for development/testing.
        
        Uses prefix 9 (temporary resident) to avoid conflicts.
        """
        # Start with 90000000
        base = '90000000'
        
        # Calculate check digit using Luhn
        digits = [int(d) for d in base]
        
        # Double every second digit from right
        for i in range(len(digits) - 2, -1, -2):
            digits[i] *= 2
            if digits[i] > 9:
                digits[i] -= 9
        
        # Calculate check digit
        total = sum(digits)
        check_digit = (10 - (total % 10)) % 10
        
        test_sin = base + str(check_digit)
        return cls(test_sin)
    
    def to_storage_format(self) -> str:
        """Get format suitable for secure storage (just digits)."""
        return self.value
    
    def __eq__(self, other) -> bool:
        """Compare SINs for equality."""
        if not isinstance(other, SIN):
            return False
        return self.value == other.value
    
    def __hash__(self) -> int:
        """Hash for use in sets/dicts."""
        return hash(self.value)
    
    def __str__(self) -> str:
        """String representation (masked for security)."""
        return self.format_masked()
    
    def __repr__(self) -> str:
        """Debug representation (masked for security)."""
        return f"SIN(masked={self.format_masked()})"