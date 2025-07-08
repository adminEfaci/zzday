"""Emergency Contact Repository Interface

Domain contract for emergency contact data access that must be implemented by the infrastructure layer.
"""

from abc import abstractmethod
from typing import Protocol
from uuid import UUID


class IEmergencyContactRepository(Protocol):
    """Repository interface for emergency contact management."""
    
    @abstractmethod
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
        """Create emergency contact.
        
        Args:
            user_id: User identifier
            name: Contact name
            email: Contact email
            phone_number: Contact phone number
            relationship: Relationship to user
            is_primary: Whether this is primary contact
            is_verified: Whether contact is verified
            
        Returns:
            Created contact ID
        """
        ...
    
    @abstractmethod
    async def find_by_id(self, contact_id: UUID) -> dict | None:
        """Find emergency contact by ID.
        
        Args:
            contact_id: Contact identifier
            
        Returns:
            Contact data if found, None otherwise
        """
        ...
    
    @abstractmethod
    async def find_by_user(self, user_id: UUID) -> list[dict]:
        """Find all emergency contacts for user.
        
        Args:
            user_id: User identifier
            
        Returns:
            List of user's emergency contacts
        """
        ...
    
    @abstractmethod
    async def find_primary_contact(self, user_id: UUID) -> dict | None:
        """Find primary emergency contact for user.
        
        Args:
            user_id: User identifier
            
        Returns:
            Primary contact data if found, None otherwise
        """
        ...
    
    @abstractmethod
    async def update(
        self, 
        contact_id: UUID,
        name: str | None = None,
        email: str | None = None,
        phone_number: str | None = None,
        relationship: str | None = None,
        is_primary: bool | None = None
    ) -> bool:
        """Update emergency contact.
        
        Args:
            contact_id: Contact identifier
            name: New contact name
            email: New contact email
            phone_number: New contact phone
            relationship: New relationship
            is_primary: New primary status
            
        Returns:
            True if updated, False if not found
        """
        ...
    
    @abstractmethod
    async def verify_contact(self, contact_id: UUID) -> bool:
        """Mark emergency contact as verified.
        
        Args:
            contact_id: Contact identifier
            
        Returns:
            True if verified, False if not found
        """
        ...
    
    @abstractmethod
    async def set_primary(self, contact_id: UUID) -> bool:
        """Set contact as primary (unsets other primary contacts).
        
        Args:
            contact_id: Contact identifier
            
        Returns:
            True if set as primary, False if not found
        """
        ...
    
    @abstractmethod
    async def delete(self, contact_id: UUID) -> bool:
        """Delete emergency contact.
        
        Args:
            contact_id: Contact identifier
            
        Returns:
            True if deleted, False if not found
        """
        ...