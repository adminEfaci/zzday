"""
Contact Information Value Object

Represents contact information with multiple communication methods.
"""

from dataclasses import dataclass
from typing import Any

from app.core.domain.base import ValueObject
from app.shared.value_objects.address import Address
from app.shared.value_objects.email import EmailAddress
from app.shared.value_objects.phone import PhoneNumber


@dataclass(frozen=True)
class ContactInfo(ValueObject):
    """
    Value object representing contact information.
    
    Encapsulates phone, email, and address information
    with methods for determining available contact methods.
    """
    
    phone: PhoneNumber | None = None
    email: EmailAddress | None = None
    address: Address | None = None
    
    def __post_init__(self) -> None:
        """Validate contact information."""
        if not self.phone and not self.email and not self.address:
            raise ValueError("At least one contact method is required")
    
    def get_available_methods(self) -> list[str]:
        """Get available contact methods."""
        methods = []
        
        if self.phone:
            methods.append("phone")
            methods.append("sms")
        
        if self.email:
            methods.append("email")
        
        if self.address:
            methods.append("mail")
        
        return methods
    
    def can_be_contacted(self) -> bool:
        """Check if contact can be reached electronically."""
        return self.phone is not None or self.email is not None
    
    def get_primary_method(self) -> str | None:
        """Get the primary contact method."""
        if self.phone:
            return "phone"
        if self.email:
            return "email"
        if self.address:
            return "mail"
        return None
    
    def mask_sensitive_data(self) -> dict[str, str | None]:
        """Get masked contact information for display."""
        return {
            "phone": self.phone.mask() if self.phone else None,
            "email": self.email.mask() if self.email else None,
            "address": self.address.get_display_string() if self.address else None
        }
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "phone": self.phone.to_dict() if self.phone else None,
            "email": self.email.to_dict() if self.email else None,
            "address": self.address.to_dict() if self.address else None,
            "available_methods": self.get_available_methods(),
            "primary_method": self.get_primary_method()
        }