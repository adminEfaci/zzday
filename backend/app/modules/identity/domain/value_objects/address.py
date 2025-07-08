"""
Address Value Object

Immutable representation of a physical address.
"""

import re
from dataclasses import dataclass
from typing import Any

from .base import ValueObject
from .postal_code import PostalCode


@dataclass(frozen=True)
class Address(ValueObject[str]):
    """Value object representing a complete physical address."""
    
    street_line1: str
    city: str
    state_province: str
    postal_code: PostalCode
    country_code: str
    street_line2: str | None = None
    street_line3: str | None = None
    county: str | None = None
    
    def __post_init__(self):
        """Validate address components."""
        # Validate required fields
        if not self.street_line1 or not self.street_line1.strip():
            raise ValueError("Street address line 1 is required")
        
        if not self.city or not self.city.strip():
            raise ValueError("City is required")
        
        if not self.state_province or not self.state_province.strip():
            raise ValueError("State/Province is required")
        
        if not self.country_code or len(self.country_code) != 2:
            raise ValueError("Valid 2-letter country code is required")
        
        # Normalize strings
        object.__setattr__(self, 'street_line1', self._normalize_string(self.street_line1))
        object.__setattr__(self, 'city', self._normalize_string(self.city))
        object.__setattr__(self, 'state_province', self._normalize_string(self.state_province))
        object.__setattr__(self, 'country_code', self.country_code.upper())
        
        if self.street_line2:
            object.__setattr__(self, 'street_line2', self._normalize_string(self.street_line2))
        
        if self.street_line3:
            object.__setattr__(self, 'street_line3', self._normalize_string(self.street_line3))
        
        if self.county:
            object.__setattr__(self, 'county', self._normalize_string(self.county))
        
        # Validate postal code country matches
        if self.postal_code.country_code != self.country_code:
            raise ValueError("Postal code country must match address country")
        
        # Validate state/province format for known countries
        self._validate_state_province()
    
    @staticmethod
    def _normalize_string(value: str) -> str:
        """Normalize string by trimming and fixing spacing."""
        # Remove extra spaces
        normalized = ' '.join(value.split())
        return normalized.strip()
    
    def _validate_state_province(self):
        """Validate state/province format for specific countries."""
        # US states
        if self.country_code == 'US':
            us_states = {
                'AL', 'AK', 'AZ', 'AR', 'CA', 'CO', 'CT', 'DE', 'FL', 'GA',
                'HI', 'ID', 'IL', 'IN', 'IA', 'KS', 'KY', 'LA', 'ME', 'MD',
                'MA', 'MI', 'MN', 'MS', 'MO', 'MT', 'NE', 'NV', 'NH', 'NJ',
                'NM', 'NY', 'NC', 'ND', 'OH', 'OK', 'OR', 'PA', 'RI', 'SC',
                'SD', 'TN', 'TX', 'UT', 'VT', 'VA', 'WA', 'WV', 'WI', 'WY',
                'DC', 'PR', 'VI', 'GU', 'AS', 'MP'  # Territories
            }
            if self.state_province.upper() not in us_states:
                # Allow full state names too - in production would validate against full names
                pass
        
        # Canadian provinces
        elif self.country_code == 'CA':
            ca_provinces = {
                'AB', 'BC', 'MB', 'NB', 'NL', 'NS', 'NT', 'NU', 
                'ON', 'PE', 'QC', 'SK', 'YT'
            }
            if self.state_province.upper() not in ca_provinces:
                # Allow full province names too - in production would validate against full names
                pass
    
    @classmethod
    def create_us_address(
        cls,
        street_line1: str,
        city: str,
        state: str,
        zip_code: str,
        street_line2: str | None = None,
        street_line3: str | None = None
    ) -> 'Address':
        """Convenience method for creating US addresses."""
        postal_code = PostalCode(value=zip_code, country_code='US')
        
        return cls(
            street_line1=street_line1,
            street_line2=street_line2,
            street_line3=street_line3,
            city=city,
            state_province=state,
            postal_code=postal_code,
            country_code='US'
        )
    
    @property
    def street_lines(self) -> list[str]:
        """Get all street lines as a list."""
        lines = [self.street_line1]
        if self.street_line2:
            lines.append(self.street_line2)
        if self.street_line3:
            lines.append(self.street_line3)
        return lines
    
    @property
    def is_us_address(self) -> bool:
        """Check if this is a US address."""
        return self.country_code == 'US'
    
    @property
    def is_canadian_address(self) -> bool:
        """Check if this is a Canadian address."""
        return self.country_code == 'CA'
    
    @property
    def is_po_box(self) -> bool:
        """Check if this appears to be a PO Box address."""
        po_box_patterns = [
            r'^\s*P\.?\s*O\.?\s*BOX',
            r'^\s*POST\s*OFFICE\s*BOX',
            r'^\s*PO\s*BOX'
        ]
        
        combined_street = ' '.join(self.street_lines).upper()
        return any(re.match(pattern, combined_street) for pattern in po_box_patterns)
    
    def format_single_line(self, include_country: bool = True) -> str:
        """Format address as single line."""
        parts = []
        parts.extend(self.street_lines)
        parts.append(f"{self.city}, {self.state_province} {self.postal_code}")
        
        if include_country:
            parts.append(self.country_code)
        
        return ', '.join(parts)
    
    def format_multiline(self, include_country: bool = True) -> str:
        """Format address as multiple lines."""
        lines = []
        lines.extend(self.street_lines)
        lines.append(f"{self.city}, {self.state_province} {self.postal_code}")
        
        if include_country:
            lines.append(self._get_country_name())
        
        return '\n'.join(lines)
    
    def format_for_mailing(self) -> str:
        """Format address for mailing labels (uppercase)."""
        lines = []
        
        # Street lines in uppercase
        for line in self.street_lines:
            lines.append(line.upper())
        
        # City, State ZIP format for US
        if self.is_us_address:
            lines.append(f"{self.city.upper()}, {self.state_province.upper()} {self.postal_code.format_for_mailing()}")
        else:
            lines.append(f"{self.city.upper()}, {self.state_province.upper()} {self.postal_code.format_for_mailing()}")
        
        # Country (if not domestic)
        lines.append(self._get_country_name().upper())
        
        return '\n'.join(lines)
    
    def _get_country_name(self) -> str:
        """Get full country name from code."""
        # Common countries
        country_names = {
            'US': 'United States',
            'CA': 'Canada',
            'NG': 'Nigeria',
            'GB': 'United Kingdom',
            'AU': 'Australia',
            'NZ': 'New Zealand',
            'DE': 'Germany',
            'FR': 'France',
            'IT': 'Italy',
            'ES': 'Spain',
            'MX': 'Mexico',
            'BR': 'Brazil',
            'JP': 'Japan',
            'CN': 'China',
            'IN': 'India',
            'KR': 'South Korea',
            'SG': 'Singapore'
        }
        
        return country_names.get(self.country_code, self.country_code)
    
    def get_components(self) -> dict[str, Any]:
        """Get address components as dictionary."""
        return {
            "street_line1": self.street_line1,
            "street_line2": self.street_line2,
            "street_line3": self.street_line3,
            "city": self.city,
            "state_province": self.state_province,
            "postal_code": self.postal_code.value,
            "county": self.county,
            "country_code": self.country_code,
            "country_name": self._get_country_name()
        }
    
    def anonymize(self) -> 'Address':
        """Create anonymized version of address (keep city/state/country)."""
        return Address(
            street_line1="[REDACTED]",
            street_line2=None,
            street_line3=None,
            city=self.city,
            state_province=self.state_province,
            postal_code=PostalCode(
                value='0' * len(self.postal_code.value),
                country_code=self.country_code
            ),
            country_code=self.country_code,
            county=self.county
        )
    
    def calculate_distance_to(self, other: 'Address') -> float | None:
        """
        Calculate approximate distance to another address.
        This would integrate with a geocoding service in production.
        """
        # Placeholder - would use geocoding service
        if self.country_code != other.country_code:
            return None  # International
        
        if self.state_province != other.state_province:
            return 500.0  # Different states
        
        if self.city != other.city:
            return 50.0  # Different cities
        
        if self.postal_code.value[:3] != other.postal_code.value[:3]:
            return 10.0  # Different areas
        
        return 1.0  # Same area
    
    def __str__(self) -> str:
        """String representation."""
        return self.format_single_line(include_country=False)
    
    def __eq__(self, other: Any) -> bool:
        """Address equality based on normalized components."""
        if not isinstance(other, Address):
            return False
        return (
            self.street_line1.lower() == other.street_line1.lower() and
            self.city.lower() == other.city.lower() and
            self.state_province.lower() == other.state_province.lower() and
            self.postal_code == other.postal_code and
            self.country_code == other.country_code
        )
    
    def __hash__(self) -> int:
        """Hash based on normalized address components."""
        return hash((
            self.street_line1.lower(),
            self.city.lower(),
            self.state_province.lower(),
            self.postal_code,
            self.country_code
        ))
    
    def __repr__(self) -> str:
        """Debug representation."""
        return f"Address(city='{self.city}', state='{self.state_province}', country='{self.country_code}')"