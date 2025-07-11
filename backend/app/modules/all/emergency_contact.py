"""
Emergency Contact Entity

Represents an emergency contact for a user.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from app.core.domain.base import Entity
from app.shared.value_objects.address import Address
from app.shared.value_objects.email import EmailAddress
from app.shared.value_objects.phone import PhoneNumber
from app.modules.identity.domain.value_objects import ContactInfo

from .user_enums import Relationship as ContactRelationship


@dataclass
class EmergencyContact(Entity):
    """Emergency contact entity for user safety."""
    
    id: UUID
    user_id: UUID
    contact_name: str
    relationship: ContactRelationship
    contact_info: ContactInfo
    is_primary: bool = False
    verified: bool = False
    verification_date: datetime | None = None
    notes: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    
    def __post_init__(self):
        """Initialize emergency contact entity."""
        super().__post_init__()
        
        # Validate contact data - NO EVENTS
        if not self.contact_name or not self.contact_name.strip():
            raise ValueError("Contact name is required")
        
        if len(self.contact_name.strip()) < 2:
            raise ValueError("Contact name must be at least 2 characters")
        
        if self.notes and len(self.notes) > 500:
            raise ValueError("Notes cannot exceed 500 characters")
    
    @classmethod
    def create(
        cls,
        user_id: UUID,
        contact_name: str,
        relationship: str,
        phone: str,
        email: str | None = None,
        address: dict[str, Any] | None = None,
        notes: str | None = None,
        is_primary: bool = False
    ) -> 'EmergencyContact':
        """Create a new emergency contact."""
        # Validate relationship enum value
        try:
            relationship_obj = ContactRelationship(relationship)
        except ValueError:
            valid_values = [r.value for r in ContactRelationship]
            raise ValueError(f"Invalid relationship. Must be one of: {', '.join(valid_values)}")
        
        # Convert string values to value objects
        phone_obj = PhoneNumber(phone)
        email_obj = EmailAddress(email) if email else None
        address_obj = Address(**address) if address else None
        
        # Create ContactInfo value object
        contact_info = ContactInfo(
            phone=phone_obj,
            email=email_obj,
            address=address_obj
        )
        
        return cls(
            id=uuid4(),
            user_id=user_id,
            contact_name=contact_name,
            relationship=relationship_obj,
            contact_info=contact_info,
            notes=notes,
            is_primary=is_primary,
            verified=False,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC)
        )
    
    def set_as_primary(self) -> None:
        """Set this contact as primary."""
        self.is_primary = True
        self.updated_at = datetime.now(UTC)
    
    def unset_as_primary(self) -> None:
        """Unset this contact as primary."""
        self.is_primary = False
        self.updated_at = datetime.now(UTC)
    
    def update_contact_info(
        self,
        contact_name: str | None = None,
        phone: PhoneNumber | None = None,
        email: EmailAddress | None = None,
        address: Address | None = None,
        notes: str | None = None
    ) -> None:
        """Update contact information."""
        if contact_name is not None:
            if not contact_name.strip():
                raise ValueError("Contact name cannot be empty")
            if len(contact_name.strip()) < 2:
                raise ValueError("Contact name must be at least 2 characters")
            self.contact_name = contact_name
        
        # Update ContactInfo if any contact details changed
        if phone is not None or email is not None or address is not None:
            # Create new ContactInfo with updated values
            new_phone = phone if phone is not None else self.contact_info.phone
            new_email = email if email is not None else self.contact_info.email
            new_address = address if address is not None else self.contact_info.address
            
            self.contact_info = ContactInfo(
                phone=new_phone,
                email=new_email,
                address=new_address
            )
            
            # Reset verification if phone changed
            if phone is not None and self.verified:
                self.verified = False
                self.verification_date = None
        
        if notes is not None:
            if len(notes) > 500:
                raise ValueError("Notes cannot exceed 500 characters")
            self.notes = notes
        
        self.updated_at = datetime.now(UTC)
    
    def get_display_info(self) -> dict[str, Any]:
        """Get contact information for display."""
        masked_info = self.contact_info.mask_sensitive_data()
        
        return {
            "name": self.contact_name,
            "relationship": self.relationship.get_display_name(),
            "phone": masked_info["phone"],
            "email": masked_info["email"],
            "is_primary": self.is_primary,
            "verified": self.verified,
            "contact_methods": self.contact_info.get_available_methods()
        }
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": str(self.id),
            "user_id": str(self.user_id),
            "contact_name": self.contact_name,
            "relationship": self.relationship.value,
            "contact_info": self.contact_info.to_dict(),
            "is_primary": self.is_primary,
            "verified": self.verified,
            "verification_date": self.verification_date.isoformat() if self.verification_date else None,
            "notes": self.notes,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat()
        }