"""
Emergency Contact Model

SQLModel definition for emergency contact persistence.
"""

from datetime import datetime, UTC
from typing import Any
from uuid import UUID

from sqlmodel import Field, SQLModel, Column, JSON
from app.modules.identity.domain.entities.admin.emergency_contact import EmergencyContact
from app.modules.identity.domain.enums import ContactRelationship
from app.shared.value_objects.email import EmailAddress
from app.shared.value_objects.phone import PhoneNumber
from app.shared.value_objects.address import Address


class EmergencyContactModel(SQLModel, table=True):
    """Emergency contact persistence model."""
    
    __tablename__ = "emergency_contacts"
    
    # Identity
    id: UUID = Field(primary_key=True)
    user_id: UUID = Field(index=True)
    
    # Contact information
    contact_name: str = Field(index=True)
    relationship: str = Field()
    phone: str = Field(index=True)
    email: str | None = Field(default=None, index=True)
    
    # Address stored as JSON
    address: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON))
    
    # Status
    is_primary: bool = Field(default=False, index=True)
    verified: bool = Field(default=False, index=True)
    verification_date: datetime | None = Field(default=None)
    
    # Additional info
    notes: str | None = Field(default=None)
    
    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC), index=True)
    
    @classmethod
    def from_domain(cls, contact: EmergencyContact) -> "EmergencyContactModel":
        """Create model from domain entity."""
        return cls(
            id=contact.id,
            user_id=contact.user_id,
            contact_name=contact.contact_name,
            relationship=contact.relationship.value if isinstance(contact.relationship, ContactRelationship) else contact.relationship,
            phone=contact.phone.value if hasattr(contact.phone, 'value') else str(contact.phone),
            email=contact.email.value if contact.email and hasattr(contact.email, 'value') else str(contact.email) if contact.email else None,
            address=contact.address.to_dict() if contact.address and hasattr(contact.address, 'to_dict') else contact.address,
            is_primary=contact.is_primary,
            verified=contact.verified,
            verification_date=contact.verification_date,
            notes=contact.notes,
            created_at=contact.created_at,
            updated_at=contact.updated_at
        )
    
    def to_domain(self) -> EmergencyContact:
        """Convert to domain entity."""
        # Reconstruct value objects
        phone = PhoneNumber(self.phone) if self.phone else None
        email = EmailAddress(self.email) if self.email else None
        address = Address(**self.address) if self.address else None
        relationship = ContactRelationship(self.relationship) if self.relationship else ContactRelationship.OTHER
        
        # Create contact instance
        contact = EmergencyContact(
            id=self.id,
            user_id=self.user_id,
            contact_name=self.contact_name,
            relationship=relationship,
            phone=phone,
            email=email,
            address=address,
            is_primary=self.is_primary,
            verified=self.verified,
            verification_date=self.verification_date,
            notes=self.notes,
            created_at=self.created_at,
            updated_at=self.updated_at
        )
        
        return contact
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            "id": str(self.id),
            "user_id": str(self.user_id),
            "contact_name": self.contact_name,
            "relationship": self.relationship,
            "phone": self.phone,
            "email": self.email,
            "address": self.address,
            "is_primary": self.is_primary,
            "verified": self.verified,
            "verification_date": self.verification_date.isoformat() if self.verification_date else None,
            "notes": self.notes,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat()
        }