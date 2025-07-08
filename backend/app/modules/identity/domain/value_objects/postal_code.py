"""
Postal Code Value Object

Immutable representation of postal/zip codes with country-specific validation.
"""

import re
from dataclasses import dataclass

from app.core.domain.base import ValueObject


@dataclass(frozen=True)
class PostalCode(ValueObject):
    """Value object representing a postal or zip code."""
    
    value: str
    country_code: str
    
    def __post_init__(self):
        """Validate postal code format based on country."""
        if not self.value or not self.value.strip():
            raise ValueError("Postal code is required")
        
        if not self.country_code or len(self.country_code) != 2:
            raise ValueError("Valid 2-letter country code is required")
        
        # Normalize
        normalized_value = self.value.strip().upper()
        object.__setattr__(self, 'value', normalized_value)
        object.__setattr__(self, 'country_code', self.country_code.upper())
        
        # Validate format based on country
        self._validate_format()
    
    def _validate_format(self):
        """Validate postal code format for specific countries."""
        validators = {
            'US': self._validate_us_zip,
            'CA': self._validate_canadian_postal,
            'GB': self._validate_uk_postcode,
            'AU': self._validate_australian_postcode,
            'DE': self._validate_german_postcode,
            'FR': self._validate_french_postcode,
            'JP': self._validate_japanese_postcode,
            'BR': self._validate_brazilian_cep,
            'MX': self._validate_mexican_cp,
            'IN': self._validate_indian_pincode,
            'CN': self._validate_chinese_postcode,
            'NG': self._validate_nigerian_postcode
        }
        
        validator = validators.get(self.country_code)
        if validator and not validator():
            raise ValueError(f"Invalid postal code format for {self.country_code}")
    
    def _validate_us_zip(self) -> bool:
        """Validate US ZIP code (5 digits or 5+4 format)."""
        # Basic 5-digit ZIP
        if re.match(r'^\d{5}$', self.value):
            return True
        # ZIP+4 format
        return bool(re.match(r"^\d{5}-\d{4}$", self.value))
    
    def _validate_canadian_postal(self) -> bool:
        """Validate Canadian postal code (A1A 1A1 format)."""
        # With or without space
        pattern = r'^[A-Z]\d[A-Z]\s?\d[A-Z]\d$'
        return bool(re.match(pattern, self.value))
    
    def _validate_uk_postcode(self) -> bool:
        """Validate UK postcode."""
        # UK postcodes have various formats
        patterns = [
            r'^[A-Z]{1,2}\d{1,2}\s?\d[A-Z]{2}$',  # SW1A 1AA
            r'^[A-Z]{1,2}\d[A-Z]\s?\d[A-Z]{2}$',   # W1A 1AA
            r'^[A-Z]\d{2}\s?\d[A-Z]{2}$',          # M1 1AA
            r'^[A-Z]{2}\d{2}\s?\d[A-Z]{2}$',       # CR2 6XH
            r'^[A-Z]\d\s?\d[A-Z]{2}$',             # L1 8JQ
            r'^[A-Z]{2}\d\s?\d[A-Z]{2}$'           # CR0 2YR
        ]
        return any(re.match(pattern, self.value) for pattern in patterns)
    
    def _validate_australian_postcode(self) -> bool:
        """Validate Australian postcode (4 digits)."""
        return bool(re.match(r'^\d{4}$', self.value))
    
    def _validate_german_postcode(self) -> bool:
        """Validate German postcode (5 digits)."""
        return bool(re.match(r'^\d{5}$', self.value))
    
    def _validate_french_postcode(self) -> bool:
        """Validate French postcode (5 digits)."""
        return bool(re.match(r'^\d{5}$', self.value))
    
    def _validate_japanese_postcode(self) -> bool:
        """Validate Japanese postcode (7 digits, often formatted as 123-4567)."""
        # With or without hyphen
        return bool(re.match(r'^\d{3}-?\d{4}$', self.value))
    
    def _validate_brazilian_cep(self) -> bool:
        """Validate Brazilian CEP (8 digits, often formatted as 12345-678)."""
        # With or without hyphen
        return bool(re.match(r'^\d{5}-?\d{3}$', self.value))
    
    def _validate_mexican_cp(self) -> bool:
        """Validate Mexican CP (5 digits)."""
        return bool(re.match(r'^\d{5}$', self.value))
    
    def _validate_indian_pincode(self) -> bool:
        """Validate Indian PIN code (6 digits)."""
        return bool(re.match(r'^\d{6}$', self.value))
    
    def _validate_chinese_postcode(self) -> bool:
        """Validate Chinese postcode (6 digits)."""
        return bool(re.match(r'^\d{6}$', self.value))
    
    def _validate_nigerian_postcode(self) -> bool:
        """Validate Nigerian postcode (6 digits)."""
        return bool(re.match(r'^\d{6}$', self.value))
    
    @property
    def is_extended_format(self) -> bool:
        """Check if postal code uses extended format (e.g., ZIP+4)."""
        return bool(self.country_code == "US" and "-" in self.value)
    
    @property
    def base_code(self) -> str:
        """Get base postal code without extensions."""
        if self.country_code == 'US' and '-' in self.value:
            return self.value.split('-')[0]
        if self.country_code == 'CA':
            # Return first 3 characters (forward sortation area)
            return self.value.replace(' ', '')[:3]
        return self.value
    
    def format_for_display(self) -> str:
        """Format postal code for display."""
        if self.country_code == 'CA':
            # Ensure Canadian postal codes have space
            clean = self.value.replace(' ', '')
            if len(clean) == 6:
                return f"{clean[:3]} {clean[3:]}"
        
        if self.country_code == 'JP':
            # Format Japanese postal codes with hyphen
            clean = self.value.replace('-', '')
            if len(clean) == 7:
                return f"{clean[:3]}-{clean[3:]}"
        
        if self.country_code == 'BR':
            # Format Brazilian CEP with hyphen
            clean = self.value.replace('-', '')
            if len(clean) == 8:
                return f"{clean[:5]}-{clean[5:]}"
        
        return self.value
    
    def format_for_mailing(self) -> str:
        """Format postal code for mailing labels."""
        # Most countries use uppercase for mailing
        if self.country_code in ['US', 'CA', 'GB', 'AU']:
            return self.value.upper()
        
        # Some countries prefer formatted display
        return self.format_for_display()
    
    def get_region_info(self) -> str | None:
        """Get region information from postal code if possible."""
        if self.country_code == 'US':
            # First digit indicates region
            regions = {
                '0': 'Northeast',
                '1': 'Northeast', 
                '2': 'Mid-Atlantic',
                '3': 'Southeast',
                '4': 'Midwest',
                '5': 'Midwest',
                '6': 'Southwest',
                '7': 'Southwest',
                '8': 'West',
                '9': 'West'
            }
            return regions.get(self.value[0])
        
        if self.country_code == 'CA':
            # First letter indicates province/region
            province_codes = {
                'A': 'Newfoundland and Labrador',
                'B': 'Nova Scotia',
                'C': 'Prince Edward Island',
                'E': 'New Brunswick',
                'G': 'Quebec East',
                'H': 'Montreal',
                'J': 'Quebec West',
                'K': 'Eastern Ontario',
                'L': 'Central Ontario',
                'M': 'Toronto',
                'N': 'Southwestern Ontario',
                'P': 'Northern Ontario',
                'R': 'Manitoba',
                'S': 'Saskatchewan',
                'T': 'Alberta',
                'V': 'British Columbia',
                'X': 'Northwest Territories/Nunavut',
                'Y': 'Yukon'
            }
            return province_codes.get(self.value[0])
        
        return None
    
    def is_po_box_postal_code(self) -> bool:
        """Check if this might be a PO Box postal code."""
        # Some postal codes are specifically for PO Boxes
        if self.country_code == 'US':
            # Certain ZIP codes are known PO Box ranges
            # This is a simplified check
            return False
        return False
    
    def __str__(self) -> str:
        """String representation."""
        return self.format_for_display()
    
    def __repr__(self) -> str:
        """Debug representation."""
        return f"PostalCode(value='{self.value}', country='{self.country_code}')"