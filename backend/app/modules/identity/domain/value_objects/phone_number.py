"""
Phone Number Value Object

Represents a validated phone number with international format support.
"""

import re
from dataclasses import dataclass
from typing import Any

from app.core.domain.base import ValueObject


@dataclass(frozen=True)
class PhoneNumber(ValueObject):
    """Phone number value object with E.164 validation."""
    
    # E.164 format: +[country code][number] (up to 15 digits total)
    PHONE_REGEX = re.compile(r'^\+[1-9]\d{1,14}$')
    
    # Common country codes for validation
    COMMON_COUNTRY_CODES = {
        '1': 'US/CA',  # North America
        '44': 'GB',     # UK
        '33': 'FR',     # France
        '49': 'DE',     # Germany
        '34': 'ES',     # Spain
        '39': 'IT',     # Italy
        '81': 'JP',     # Japan
        '86': 'CN',     # China
        '91': 'IN',     # India
        '7': 'RU',      # Russia
        '55': 'BR',     # Brazil
        '61': 'AU',     # Australia
        '64': 'NZ',     # New Zealand
        '27': 'ZA',     # South Africa
        '966': 'SA',    # Saudi Arabia
        '971': 'AE',    # UAE
        '20': 'EG',     # Egypt
        '234': 'NG',    # Nigeria
        '254': 'KE',    # Kenya
    }
    
    value: str
    country_code: str | None = None
    national_number: str | None = None
    is_mobile: bool = True
    is_verified: bool = False
    
    def __post_init__(self):
        """Validate and parse phone number."""
        # Remove any formatting characters
        cleaned = re.sub(r'[\s\-\(\)\.]+', '', self.value)
        
        # Ensure it starts with +
        if not cleaned.startswith('+'):
            # Try to infer country code or default to US
            if cleaned.startswith('00'):
                cleaned = '+' + cleaned[2:]
            elif len(cleaned) == 10 and cleaned[0] in '23456789':
                # Likely US number without country code
                cleaned = '+1' + cleaned
            elif len(cleaned) == 11 and cleaned[0] == '1':
                # US number with country code
                cleaned = '+' + cleaned
            else:
                raise ValueError(f"Invalid phone number format: {self.value}")
        
        # Validate E.164 format
        if not self.PHONE_REGEX.match(cleaned):
            raise ValueError(f"Phone number must be in E.164 format: {self.value}")
        
        # Parse country code and national number
        object.__setattr__(self, 'value', cleaned)
        self._parse_components()
    
    def _parse_components(self) -> None:
        """Parse country code and national number."""
        # Try to match country codes (longest match first)
        for length in [4, 3, 2, 1]:
            potential_code = self.value[1:1+length]
            if potential_code in self.COMMON_COUNTRY_CODES:
                object.__setattr__(self, 'country_code', potential_code)
                object.__setattr__(self, 'national_number', self.value[1+length:])
                break
        
        # If no match found, assume first 1-3 digits are country code
        if not self.country_code:
            # Simple heuristic: if total length > 10, first 1-3 digits are country code
            if len(self.value) > 11:  # Including +
                object.__setattr__(self, 'country_code', self.value[1:3])
                object.__setattr__(self, 'national_number', self.value[3:])
            else:
                object.__setattr__(self, 'country_code', self.value[1:2])
                object.__setattr__(self, 'national_number', self.value[2:])
    
    def format_international(self) -> str:
        """Format as international number."""
        if self.country_code and self.national_number:
            # Format as +XX XXX XXX XXXX (varies by country)
            if self.country_code == '1':  # North America
                # Format as +1 (XXX) XXX-XXXX
                if len(self.national_number) == 10:
                    area = self.national_number[:3]
                    exchange = self.national_number[3:6]
                    number = self.national_number[6:]
                    return f"+{self.country_code} ({area}) {exchange}-{number}"
            elif self.country_code == '44':  # UK
                # Format as +44 XXXX XXXXXX
                if len(self.national_number) >= 10:
                    return f"+{self.country_code} {self.national_number[:4]} {self.national_number[4:]}"
            
            # Default formatting
            return f"+{self.country_code} {self.national_number}"
        
        return self.value
    
    def format_national(self) -> str:
        """Format as national number (without country code)."""
        if self.national_number:
            if self.country_code == '1' and len(self.national_number) == 10:
                # Format as (XXX) XXX-XXXX for North America
                area = self.national_number[:3]
                exchange = self.national_number[3:6]
                number = self.national_number[6:]
                return f"({area}) {exchange}-{number}"
            
            return self.national_number
        
        # Fallback to removing country code
        return self.value[1 + len(self.country_code):] if self.country_code else self.value[1:]
    
    def get_country(self) -> str | None:
        """Get country name from country code."""
        if self.country_code:
            return self.COMMON_COUNTRY_CODES.get(self.country_code, 'Unknown')
        return None
    
    def mask(self) -> str:
        """Return masked version for display."""
        if len(self.value) < 8:
            return self.value  # Too short to mask effectively
        
        # Show country code and last 4 digits
        visible_start = self.value[:len(self.country_code) + 3] if self.country_code else self.value[:4]
        visible_end = self.value[-4:]
        masked_middle = '*' * (len(self.value) - len(visible_start) - len(visible_end))
        
        return f"{visible_start}{masked_middle}{visible_end}"
    
    def to_sms_format(self) -> str:
        """Format for SMS sending (E.164)."""
        return self.value
    
    def to_tel_uri(self) -> str:
        """Convert to tel: URI format."""
        return f"tel:{self.value}"
    
    def to_whatsapp_uri(self) -> str:
        """Convert to WhatsApp URI format."""
        # WhatsApp uses number without + sign
        return f"https://wa.me/{self.value[1:]}"
    
    @classmethod
    def parse(cls, value: str, default_country_code: str = '1') -> 'PhoneNumber':
        """Parse phone number with default country code."""
        cleaned = re.sub(r'[\s\-\(\)\.]+', '', value)
        
        # If no country code provided, add default
        if not cleaned.startswith('+') and not cleaned.startswith('00'):
            if len(cleaned) == 10 and default_country_code:
                cleaned = f"+{default_country_code}{cleaned}"
        
        return cls(value=cleaned)
    
    def __str__(self) -> str:
        """String representation."""
        return self.format_international()
    
    def __eq__(self, other: Any) -> bool:
        """Phone number equality based on E.164 format."""
        if not isinstance(other, PhoneNumber):
            return False
        return self.value == other.value
    
    def __hash__(self) -> int:
        """Hash based on E.164 format."""
        return hash(self.value)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "value": self.value,
            "country_code": self.country_code,
            "national_number": self.national_number,
            "formatted": self.format_international(),
            "national_formatted": self.format_national(),
            "masked": self.mask(),
            "country": self.get_country(),
            "is_mobile": self.is_mobile,
            "is_verified": self.is_verified,
            "tel_uri": self.to_tel_uri()
        }
