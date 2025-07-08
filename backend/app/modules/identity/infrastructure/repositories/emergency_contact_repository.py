"""
Emergency Contact Repository Implementation

SQLModel-based implementation of the emergency contact repository interface.
"""

from datetime import datetime, UTC
from typing import Any
from uuid import UUID, uuid4

from sqlmodel import Session, select, and_, or_, col, func
from app.core.infrastructure.repository import SQLRepository
from app.modules.identity.domain.entities.admin.emergency_contact import EmergencyContact
from app.modules.identity.domain.enums import ContactRelationship
from app.modules.identity.domain.interfaces.repositories.emergency_contact_repository import IEmergencyContactRepository
from app.modules.identity.infrastructure.models.emergency_contact_model import EmergencyContactModel
from app.shared.value_objects.email import EmailAddress
from app.shared.value_objects.phone import PhoneNumber
from app.shared.value_objects.address import Address


class SQLEmergencyContactRepository(SQLRepository[EmergencyContact, EmergencyContactModel], IEmergencyContactRepository):
    """SQLModel implementation of emergency contact repository."""
    
    def __init__(self, session: Session):
        super().__init__(session, EmergencyContactModel)
    
    async def create(
        self, 
        user_id: UUID,
        name: str,
        email: str | None = None,
        phone_number: str | None = None,
        relationship: str | None = None,
        is_primary: bool = False,
        is_verified: bool = False
    ) -> UUID:
        """Create emergency contact."""
        # Validate at least one contact method
        if not email and not phone_number:
            raise ValueError("At least one contact method (email or phone) is required")
        
        # Create contact entity
        contact = EmergencyContact(
            id=uuid4(),
            user_id=user_id,
            contact_name=name,
            relationship=ContactRelationship(relationship) if relationship else ContactRelationship.OTHER,
            phone=PhoneNumber(phone_number) if phone_number else None,
            email=EmailAddress(email) if email else None,
            is_primary=is_primary,
            verified=is_verified,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC)
        )
        
        # If this is the primary contact, unset other primary contacts
        if is_primary:
            await self._unset_other_primary_contacts(user_id, contact.id)
        
        # Save to database
        model = EmergencyContactModel.from_domain(contact)
        self.session.add(model)
        await self.session.commit()
        
        return contact.id
    
    async def find_by_id(self, contact_id: UUID) -> dict | None:
        """Find emergency contact by ID."""
        model = await self.session.get(EmergencyContactModel, contact_id)
        
        if not model:
            return None
        
        return model.to_dict()
    
    async def find_by_user(self, user_id: UUID) -> list[dict]:
        """Find all emergency contacts for user."""
        stmt = select(EmergencyContactModel).where(
            EmergencyContactModel.user_id == user_id
        ).order_by(
            EmergencyContactModel.is_primary.desc(),
            EmergencyContactModel.created_at.asc()
        )
        
        result = await self.session.exec(stmt)
        models = result.all()
        
        return [model.to_dict() for model in models]
    
    async def find_primary_contact(self, user_id: UUID) -> dict | None:
        """Find primary emergency contact for user."""
        stmt = select(EmergencyContactModel).where(
            and_(
                EmergencyContactModel.user_id == user_id,
                EmergencyContactModel.is_primary == True
            )
        )
        
        result = await self.session.exec(stmt)
        model = result.first()
        
        return model.to_dict() if model else None
    
    async def update(
        self, 
        contact_id: UUID,
        name: str | None = None,
        email: str | None = None,
        phone_number: str | None = None,
        relationship: str | None = None,
        is_primary: bool | None = None
    ) -> bool:
        """Update emergency contact."""
        model = await self.session.get(EmergencyContactModel, contact_id)
        
        if not model:
            return False
        
        # Update fields if provided
        if name is not None:
            model.contact_name = name
        
        if email is not None:
            model.email = email
            # Reset verification if contact method changed
            if model.verified and model.email != email:
                model.verified = False
                model.verification_date = None
        
        if phone_number is not None:
            model.phone = phone_number
            # Reset verification if contact method changed
            if model.verified and model.phone != phone_number:
                model.verified = False
                model.verification_date = None
        
        if relationship is not None:
            model.relationship = relationship
        
        if is_primary is not None:
            model.is_primary = is_primary
            # If setting as primary, unset other primary contacts
            if is_primary:
                await self._unset_other_primary_contacts(model.user_id, contact_id)
        
        model.updated_at = datetime.now(UTC)
        self.session.add(model)
        await self.session.commit()
        
        return True
    
    async def verify_contact(self, contact_id: UUID) -> bool:
        """Mark emergency contact as verified."""
        model = await self.session.get(EmergencyContactModel, contact_id)
        
        if not model:
            return False
        
        model.verified = True
        model.verification_date = datetime.now(UTC)
        model.updated_at = datetime.now(UTC)
        
        self.session.add(model)
        await self.session.commit()
        
        return True
    
    async def set_primary(self, contact_id: UUID) -> bool:
        """Set contact as primary (unsets other primary contacts)."""
        model = await self.session.get(EmergencyContactModel, contact_id)
        
        if not model:
            return False
        
        # Unset other primary contacts
        await self._unset_other_primary_contacts(model.user_id, contact_id)
        
        # Set this contact as primary
        model.is_primary = True
        model.updated_at = datetime.now(UTC)
        
        self.session.add(model)
        await self.session.commit()
        
        return True
    
    async def delete(self, contact_id: UUID) -> bool:
        """Delete emergency contact."""
        model = await self.session.get(EmergencyContactModel, contact_id)
        
        if not model:
            return False
        
        await self.session.delete(model)
        await self.session.commit()
        
        return True
    
    async def find_domain_by_id(self, contact_id: UUID) -> EmergencyContact | None:
        """Find emergency contact domain entity by ID."""
        model = await self.session.get(EmergencyContactModel, contact_id)
        return model.to_domain() if model else None
    
    async def find_domain_by_user(self, user_id: UUID) -> list[EmergencyContact]:
        """Find all emergency contact domain entities for user."""
        stmt = select(EmergencyContactModel).where(
            EmergencyContactModel.user_id == user_id
        ).order_by(
            EmergencyContactModel.is_primary.desc(),
            EmergencyContactModel.created_at.asc()
        )
        
        result = await self.session.exec(stmt)
        models = result.all()
        
        return [model.to_domain() for model in models]
    
    async def save(self, contact: EmergencyContact) -> None:
        """Save emergency contact domain entity."""
        model = EmergencyContactModel.from_domain(contact)
        
        # Check if contact exists
        existing = await self.session.get(EmergencyContactModel, contact.id)
        if existing:
            # Update existing model
            for key, value in model.dict(exclude={'id'}).items():
                setattr(existing, key, value)
            self.session.add(existing)
        else:
            # Add new model
            self.session.add(model)
        
        await self.session.commit()
    
    async def count_by_user(self, user_id: UUID) -> int:
        """Count emergency contacts for user."""
        stmt = select(func.count(EmergencyContactModel.id)).where(
            EmergencyContactModel.user_id == user_id
        )
        result = await self.session.exec(stmt)
        return result.first() or 0
    
    async def find_verified_by_user(self, user_id: UUID) -> list[EmergencyContact]:
        """Find all verified emergency contacts for user."""
        stmt = select(EmergencyContactModel).where(
            and_(
                EmergencyContactModel.user_id == user_id,
                EmergencyContactModel.verified == True
            )
        ).order_by(
            EmergencyContactModel.is_primary.desc(),
            EmergencyContactModel.created_at.asc()
        )
        
        result = await self.session.exec(stmt)
        models = result.all()
        
        return [model.to_domain() for model in models]
    
    async def _unset_other_primary_contacts(self, user_id: UUID, exclude_id: UUID) -> None:
        """Unset primary flag for other contacts of the same user."""
        stmt = select(EmergencyContactModel).where(
            and_(
                EmergencyContactModel.user_id == user_id,
                EmergencyContactModel.id != exclude_id,
                EmergencyContactModel.is_primary == True
            )
        )
        
        result = await self.session.exec(stmt)
        models = result.all()
        
        for model in models:
            model.is_primary = False
            model.updated_at = datetime.now(UTC)
            self.session.add(model)