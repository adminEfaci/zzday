"""
Emergency Contact Domain Service

Handles emergency contact verification and management logic.
"""

from datetime import UTC, datetime
from typing import Any

from app.modules.identity.domain.entities.user.emergency_contact import EmergencyContact
from app.modules.identity.domain.value_objects import ContactInfo


class EmergencyContactService:
    """Domain service for emergency contact operations."""
    
    def verify_contact(
        self,
        contact: EmergencyContact,
        verification_method: str = "phone_call"
    ) -> dict[str, Any]:
        """Verify an emergency contact."""
        if contact.verified:
            return {
                "success": True,
                "message": "Contact already verified",
                "already_verified": True
            }
        
        # Validate verification method
        available_methods = self._get_available_verification_methods(contact)
        if verification_method not in available_methods:
            return {
                "success": False,
                "message": f"Verification method '{verification_method}' not available",
                "available_methods": available_methods
            }
        
        # Perform verification logic (would integrate with external services)
        verification_result = self._perform_verification(contact, verification_method)
        
        if verification_result["success"]:
            # Update contact verification status
            contact.verified = True
            contact.verification_date = datetime.now(UTC)
            contact.updated_at = datetime.now(UTC)
            
            # Emit verification event
            from ..user_events import EmergencyContactVerified
            contact.add_domain_event(EmergencyContactVerified(
                user_id=contact.user_id,
                contact_id=contact.id,
                verification_method=verification_method,
                verified_at=contact.verification_date
            ))
        
        return verification_result
    
    def can_contact_be_reached(self, contact: EmergencyContact) -> bool:
        """Check if contact can be reached for emergencies."""
        return (
            contact.verified and 
            (contact.phone is not None or contact.email is not None)
        )
    
    def get_contact_methods(self, contact: EmergencyContact) -> list[str]:
        """Get available contact methods for emergency contact."""
        methods = []
        
        if contact.phone:
            methods.append("phone")
            methods.append("sms")
        
        if contact.email:
            methods.append("email")
        
        return methods
    
    def set_as_primary_contact(self, contact: EmergencyContact) -> None:
        """Set contact as primary with business logic."""
        if not contact.verified:
            raise ValueError("Cannot set unverified contact as primary")
        
        if not self.can_contact_be_reached(contact):
            raise ValueError("Primary contact must be reachable")
        
        contact.set_as_primary()
    
    def create_contact_info(self, contact: EmergencyContact) -> ContactInfo:
        """Create ContactInfo value object from emergency contact."""
        return ContactInfo(
            phone=contact.phone,
            email=contact.email,
            address=contact.address
        )
    
    def _get_available_verification_methods(self, contact: EmergencyContact) -> list[str]:
        """Get available verification methods for contact."""
        methods = []
        
        if contact.phone:
            methods.extend(["phone_call", "sms"])
        
        if contact.email:
            methods.append("email")
        
        return methods
    
    def _perform_verification(self, contact: EmergencyContact, method: str) -> dict[str, Any]:
        """Perform the actual verification (mock implementation)."""
        # In real implementation, this would:
        # - Send SMS/make call/send email
        # - Generate verification code
        # - Store verification attempt
        # - Return verification token/code
        
        if method == "phone_call":
            return {
                "success": True,
                "message": "Verification call initiated",
                "verification_token": "mock_token_123"
            }
        if method == "sms":
            return {
                "success": True,
                "message": "SMS verification code sent",
                "verification_code": "123456"
            }
        if method == "email":
            return {
                "success": True,
                "message": "Email verification sent",
                "verification_link": "https://example.com/verify/token123"
            }
        return {
            "success": False,
            "message": f"Unsupported verification method: {method}"
        }