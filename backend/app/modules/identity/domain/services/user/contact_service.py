"""
User Contact Service

Domain service for emergency contact management and verification.
"""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from ...entities.user.emergency_contact import EmergencyContact
from ...enums import ContactRelationship


class UserContactService:
    """Service for user emergency contact operations."""
    
    def validate_contact_limits(
        self,
        user_id: UUID,
        existing_contacts: list[EmergencyContact],
        max_contacts: int = 5
    ) -> None:
        """Validate contact limits for user."""
        if len(existing_contacts) >= max_contacts:
            raise ValueError(f"Maximum {max_contacts} emergency contacts allowed")
    
    def validate_primary_contact_rules(
        self,
        new_contact: EmergencyContact,
        existing_contacts: list[EmergencyContact]
    ) -> None:
        """Validate primary contact business rules."""
        if new_contact.is_primary:
            # Check if primary already exists
            existing_primary = self.get_primary_contact(existing_contacts)
            if existing_primary:
                raise ValueError("User already has a primary emergency contact")
    
    def get_primary_contact(
        self,
        contacts: list[EmergencyContact]
    ) -> EmergencyContact | None:
        """Get the primary emergency contact."""
        for contact in contacts:
            if contact.is_primary:
                return contact
        return None
    
    def set_new_primary_contact(
        self,
        new_primary: EmergencyContact,
        existing_contacts: list[EmergencyContact]
    ) -> list[EmergencyContact]:
        """Set new primary contact and unset others."""
        # Unset existing primary
        for contact in existing_contacts:
            if contact.is_primary and contact.id != new_primary.id:
                contact.unset_as_primary()
        
        # Set new primary
        new_primary.set_as_primary()
        
        return existing_contacts
    
    def validate_relationship_diversity(
        self,
        new_contact: EmergencyContact,
        existing_contacts: list[EmergencyContact],
        require_diversity: bool = True
    ) -> None:
        """Validate relationship diversity requirements."""
        if not require_diversity:
            return
        
        # Check for relationship limits
        relationship_counts = {}
        for contact in existing_contacts:
            rel = contact.relationship
            relationship_counts[rel] = relationship_counts.get(rel, 0) + 1
        
        # Limit same relationship types
        current_count = relationship_counts.get(new_contact.relationship, 0)
        
        # Allow max 2 of same relationship type
        if current_count >= 2:
            raise ValueError(f"Maximum 2 contacts with relationship '{new_contact.relationship.get_display_name()}' allowed")
        
        # Recommend at least one family member
        family_relationships = {
            ContactRelationship.SPOUSE,
            ContactRelationship.PARENT,
            ContactRelationship.SIBLING,
            ContactRelationship.CHILD
        }
        
        has_family = any(c.relationship in family_relationships for c in existing_contacts)
        if not has_family and new_contact.relationship not in family_relationships and len(existing_contacts) > 0:
            # This is a warning, not an error
            pass
    
    def prepare_verification_batch(
        self,
        contacts: list[EmergencyContact],
        verification_type: str = "initial"
    ) -> dict[str, Any]:
        """Prepare batch verification for multiple contacts."""
        verification_batch = {
            "batch_id": f"verify_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}",
            "verification_type": verification_type,
            "contacts": [],
            "total_count": len(contacts),
            "phone_verifications": 0,
            "email_verifications": 0
        }
        
        for contact in contacts:
            if not contact.verified:
                contact_data = contact.send_verification()
                verification_batch["contacts"].append(contact_data)
                
                if contact.phone:
                    verification_batch["phone_verifications"] += 1
                if contact.email:
                    verification_batch["email_verifications"] += 1
        
        return verification_batch
    
    def get_contact_reachability_report(
        self,
        contacts: list[EmergencyContact]
    ) -> dict[str, Any]:
        """Generate contact reachability report."""
        report = {
            "total_contacts": len(contacts),
            "verified_contacts": 0,
            "reachable_contacts": 0,
            "primary_contact_verified": False,
            "coverage_by_method": {
                "phone": 0,
                "sms": 0,
                "email": 0
            },
            "relationship_coverage": {},
            "recommendations": []
        }
        
        primary_contact = self.get_primary_contact(contacts)
        if primary_contact:
            report["primary_contact_verified"] = primary_contact.verified
        else:
            report["recommendations"].append("Set a primary emergency contact")
        
        for contact in contacts:
            if contact.verified:
                report["verified_contacts"] += 1
            
            if contact.can_be_contacted():
                report["reachable_contacts"] += 1
                
                # Count coverage by method
                methods = contact.get_contact_methods()
                for method in methods:
                    if method in report["coverage_by_method"]:
                        report["coverage_by_method"][method] += 1
            
            # Relationship coverage
            rel = contact.relationship.value
            if rel not in report["relationship_coverage"]:
                report["relationship_coverage"][rel] = {"total": 0, "verified": 0}
            
            report["relationship_coverage"][rel]["total"] += 1
            if contact.verified:
                report["relationship_coverage"][rel]["verified"] += 1
        
        # Generate recommendations
        if report["verified_contacts"] == 0:
            report["recommendations"].append("Verify at least one emergency contact")
        elif report["verified_contacts"] < 2:
            report["recommendations"].append("Add and verify additional emergency contacts")
        
        if report["coverage_by_method"]["phone"] == 0:
            report["recommendations"].append("Add emergency contact with phone number")
        
        if not report["primary_contact_verified"]:
            report["recommendations"].append("Verify your primary emergency contact")
        
        return report
    
    def suggest_contact_improvements(
        self,
        contacts: list[EmergencyContact]
    ) -> list[dict[str, Any]]:
        """Suggest improvements to emergency contact setup."""
        suggestions = []
        
        # Check for missing relationships
        relationships_present = {c.relationship for c in contacts}
        important_relationships = {
            ContactRelationship.SPOUSE,
            ContactRelationship.PARENT,
            ContactRelationship.SIBLING
        }
        
        missing_important = important_relationships - relationships_present
        if missing_important:
            suggestions.append({
                "type": "missing_relationship",
                "priority": "medium",
                "message": f"Consider adding contacts for: {', '.join(r.get_display_name() for r in missing_important)}",
                "action": "add_contact"
            })
        
        # Check for unverified contacts
        unverified = [c for c in contacts if not c.verified]
        if unverified:
            suggestions.append({
                "type": "unverified_contacts",
                "priority": "high",
                "message": f"{len(unverified)} emergency contacts need verification",
                "action": "verify_contacts",
                "contact_ids": [str(c.id) for c in unverified]
            })
        
        # Check for outdated information
        old_contacts = [
            c for c in contacts 
            if (datetime.now(UTC) - c.updated_at).days > 365
        ]
        if old_contacts:
            suggestions.append({
                "type": "outdated_info",
                "priority": "medium",
                "message": f"{len(old_contacts)} contacts haven't been updated in over a year",
                "action": "update_contacts",
                "contact_ids": [str(c.id) for c in old_contacts]
            })
        
        # Check for redundancy
        if len(contacts) > 3:
            relationship_counts = {}
            for contact in contacts:
                rel = contact.relationship
                relationship_counts[rel] = relationship_counts.get(rel, 0) + 1
            
            redundant_relationships = {
                rel: count for rel, count in relationship_counts.items() 
                if count > 2
            }
            
            if redundant_relationships:
                suggestions.append({
                    "type": "redundant_contacts",
                    "priority": "low",
                    "message": "Consider consolidating contacts with same relationship",
                    "action": "review_contacts"
                })
        
        return suggestions
    
    def validate_contact_data_quality(
        self,
        contact: EmergencyContact
    ) -> dict[str, Any]:
        """Validate contact data quality and completeness."""
        quality_report = {
            "score": 0,
            "max_score": 10,
            "issues": [],
            "strengths": []
        }
        
        # Name quality (2 points)
        if contact.contact_name and len(contact.contact_name.strip()) >= 2:
            quality_report["score"] += 2
            quality_report["strengths"].append("Contact name provided")
        else:
            quality_report["issues"].append("Contact name is too short")
        
        # Phone number (3 points)
        if contact.phone:
            quality_report["score"] += 3
            quality_report["strengths"].append("Phone number provided")
        else:
            quality_report["issues"].append("No phone number provided")
        
        # Email (2 points)
        if contact.email:
            quality_report["score"] += 2
            quality_report["strengths"].append("Email address provided")
        else:
            quality_report["issues"].append("No email address provided")
        
        # Address (1 point)
        if contact.address:
            quality_report["score"] += 1
            quality_report["strengths"].append("Address provided")
        
        # Verification (2 points)
        if contact.verified:
            quality_report["score"] += 2
            quality_report["strengths"].append("Contact verified")
        else:
            quality_report["issues"].append("Contact not verified")
        
        # Quality level
        score_percentage = (quality_report["score"] / quality_report["max_score"]) * 100
        
        if score_percentage >= 80:
            quality_report["level"] = "excellent"
        elif score_percentage >= 60:
            quality_report["level"] = "good"
        elif score_percentage >= 40:
            quality_report["level"] = "fair"
        else:
            quality_report["level"] = "poor"
        
        return quality_report
    
    def generate_emergency_contact_summary(
        self,
        contacts: list[EmergencyContact]
    ) -> dict[str, Any]:
        """Generate comprehensive emergency contact summary."""
        summary = {
            "overview": {
                "total_contacts": len(contacts),
                "verified_contacts": sum(1 for c in contacts if c.verified),
                "primary_contact": None,
                "last_updated": None
            },
            "reachability": self.get_contact_reachability_report(contacts),
            "quality_scores": [],
            "suggestions": self.suggest_contact_improvements(contacts),
            "verification_status": {
                "all_verified": True,
                "pending_verification": []
            }
        }
        
        # Primary contact info
        primary = self.get_primary_contact(contacts)
        if primary:
            summary["overview"]["primary_contact"] = {
                "name": primary.contact_name,
                "relationship": primary.relationship.get_display_name(),
                "verified": primary.verified
            }
        
        # Last updated
        if contacts:
            latest_update = max(c.updated_at for c in contacts)
            summary["overview"]["last_updated"] = latest_update.isoformat()
        
        # Quality scores
        for contact in contacts:
            quality = self.validate_contact_data_quality(contact)
            summary["quality_scores"].append({
                "contact_id": str(contact.id),
                "name": contact.contact_name,
                "score": quality["score"],
                "level": quality["level"]
            })
        
        # Verification status
        unverified = [c for c in contacts if not c.verified]
        if unverified:
            summary["verification_status"]["all_verified"] = False
            summary["verification_status"]["pending_verification"] = [
                {
                    "contact_id": str(c.id),
                    "name": c.contact_name,
                    "methods": c.get_contact_methods()
                }
                for c in unverified
            ]
        
        return summary
