"""
Remove emergency contact command implementation.

Handles removing emergency contacts with validation and notifications.
"""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    require_mfa,
    require_permission,
    validate_request,
)
from app.modules.identity.application.dtos.internal import (
    AuditContext,
    BackupContext,
    EmailContext,
    NotificationContext,
    SecurityIncidentContext,
    SMSContext,
)
from app.modules.identity.application.dtos.request import RemoveEmergencyContactRequest
from app.modules.identity.application.dtos.response import (
    EmergencyContactRemovalResponse,
)
from app.modules.identity.domain.entities import EmergencyContact, User
from app.modules.identity.domain.enums import (
    AuditAction,
    BackupType,
    ContactType,
    NotificationType,
    RiskLevel,
    SecurityEventType,
)
from app.modules.identity.domain.events import EmergencyContactRemoved
from app.modules.identity.domain.exceptions import (
    EmergencyContactNotFoundError,
    MinimumContactsError,
    UserNotFoundError,
)
from app.modules.identity.domain.interfaces.repositories.emergency_contact_repository import (
    IEmergencyContactRepository,
)
from app.modules.identity.domain.interfaces.repositories.user_repository import (
    IUserRepository,
)
from app.modules.identity.domain.interfaces.services.communication.notification_service import (
    IEmailService,
    INotificationService,
    ISMSService,
)
from app.modules.identity.domain.services import SecurityService, ValidationService


class RemoveEmergencyContactCommand(Command[EmergencyContactRemovalResponse]):
    """Command to remove an emergency contact."""
    
    def __init__(
        self,
        contact_id: UUID,
        removed_by: UUID,
        reason: str,
        notify_contact: bool = True,
        create_backup: bool = True,
        force_remove: bool = False,
        metadata: dict[str, Any] | None = None
    ):
        self.contact_id = contact_id
        self.removed_by = removed_by
        self.reason = reason.strip()
        self.notify_contact = notify_contact
        self.create_backup = create_backup
        self.force_remove = force_remove
        self.metadata = metadata or {}


class RemoveEmergencyContactCommandHandler(CommandHandler[RemoveEmergencyContactCommand, EmergencyContactRemovalResponse]):
    """Handler for removing emergency contacts."""
    
    def __init__(
        self,
        user_repository: IUserRepository,
        emergency_contact_repository: IEmergencyContactRepository,
        validation_service: ValidationService,
        security_service: SecurityService,
        notification_service: INotificationService,
        audit_service: IAuditService,
        email_service: IEmailService,
        sms_service: ISMSService,
        backup_service: IBackupService,
        event_bus: EventBus,
        unit_of_work: UnitOfWork
    ):
        self._user_repository = user_repository
        self._emergency_contact_repository = emergency_contact_repository
        self._validation_service = validation_service
        self._security_service = security_service
        self._notification_service = notification_service
        self._audit_service = audit_service
        self._email_service = email_service
        self._sms_service = sms_service
        self._backup_service = backup_service
        self._event_bus = event_bus
        self._unit_of_work = unit_of_work
    
    @audit_action(
        action=AuditAction.EMERGENCY_CONTACT_REMOVED,
        resource_type="emergency_contact",
        include_request=True,
        include_response=True,
        include_reason=True
    )
    @validate_request(RemoveEmergencyContactRequest)
    @rate_limit(
        max_requests=15,
        window_seconds=3600,
        strategy='user'
    )
    @require_permission("emergency_contacts.remove")
    @require_mfa(condition="removing_primary_contact")
    async def handle(self, command: RemoveEmergencyContactCommand) -> EmergencyContactRemovalResponse:
        """
        Remove emergency contact with validation and notifications.
        
        Process:
        1. Load contact and validate access
        2. Check minimum contacts requirement
        3. Handle primary contact removal
        4. Create backup if requested
        5. Remove contact
        6. Send notifications
        7. Log removal
        8. Check security implications
        
        Returns:
            EmergencyContactRemovalResponse with removal details
            
        Raises:
            EmergencyContactNotFoundError: If contact not found
            UnauthorizedError: If user cannot remove contact
            MinimumContactsError: If removing would violate minimum
            InvalidOperationError: If removal not allowed
        """
        async with self._unit_of_work:
            # 1. Load contact
            contact = await self._emergency_contact_repository.find_by_id(command.contact_id)
            if not contact:
                raise EmergencyContactNotFoundError(f"Emergency contact {command.contact_id} not found")
            
            # 2. Load user
            user = await self._user_repository.find_by_id(contact.user_id)
            if not user:
                raise UserNotFoundError(f"User {contact.user_id} not found")
            
            # 3. Check removal permissions
            await self._validate_removal_permissions(contact, command.removed_by)
            
            # 4. Check minimum contacts requirement
            if not command.force_remove:
                await self._check_minimum_contacts_requirement(user, contact)
            
            # 5. Capture contact state before removal
            self._capture_contact_data(contact)
            
            # 6. Check if removing primary contact
            primary_contact_removed = contact.is_primary
            replacement_primary = None
            
            if primary_contact_removed:
                replacement_primary = await self._handle_primary_contact_removal(
                    contact.user_id,
                    contact.contact_type,
                    contact.id
                )
            
            # 7. Create backup if requested
            backup_id = None
            if command.create_backup:
                backup_id = await self._create_removal_backup(
                    user,
                    contact,
                    command.reason
                )
            
            # 8. Mark contact as removed (soft delete)
            contact.is_active = False
            contact.removed_at = datetime.now(UTC)
            contact.removed_by = command.removed_by
            contact.removal_reason = command.reason
            
            await self._emergency_contact_repository.soft_delete(contact)
            
            # 9. Send removal notifications
            if command.notify_contact:
                await self._send_removal_notifications(
                    user,
                    contact,
                    command.reason
                )
            
            # 10. Notify user if removed by admin
            if command.removed_by != contact.user_id:
                await self._notify_user_of_contact_removal(
                    user,
                    contact,
                    command.removed_by,
                    command.reason
                )
            
            # 11. Log admin removal
            if command.removed_by != contact.user_id:
                await self._log_admin_contact_removal(
                    user,
                    contact,
                    command.removed_by,
                    command.reason
                )
            
            # 12. Check security implications
            security_impact = await self._assess_security_impact(user, contact)
            if security_impact["risk_level"] == "high":
                await self._log_security_impact(
                    user,
                    contact,
                    security_impact,
                    command
                )
            
            # 13. Publish domain event
            await self._event_bus.publish(
                EmergencyContactRemoved(
                    aggregate_id=contact.id,
                    user_id=contact.user_id,
                    contact_type=contact.contact_type,
                    contact_value=self._mask_contact_value(contact.contact_value),
                    was_primary=primary_contact_removed,
                    removed_by=command.removed_by,
                    reason=command.reason,
                    replacement_primary_id=replacement_primary.id if replacement_primary else None
                )
            )
            
            # 14. Commit transaction
            await self._unit_of_work.commit()
            
            # 15. Return response
            return EmergencyContactRemovalResponse(
                contact_id=contact.id,
                user_id=contact.user_id,
                contact_type=contact.contact_type,
                contact_value=self._mask_contact_value(contact.contact_value),
                was_primary=primary_contact_removed,
                replacement_primary=replacement_primary.contact_value if replacement_primary else None,
                backup_created=backup_id is not None,
                backup_id=backup_id,
                security_impact=security_impact["risk_level"],
                remaining_contacts=await self._emergency_contact_repository.count_active_by_user(user.id),
                removed_at=contact.removed_at,
                removed_by=contact.removed_by,
                message="Emergency contact removed successfully"
            )
    
    async def _validate_removal_permissions(
        self,
        contact: EmergencyContact,
        removed_by: UUID
    ) -> None:
        """Validate user can remove this contact."""
        # User can remove their own contacts
        if contact.user_id == removed_by:
            return
        
        # Check if remover has admin permissions
        # This would typically check for admin role or specific permission
        # For now, we'll allow it but log it as admin action
    
    async def _check_minimum_contacts_requirement(
        self,
        user: User,
        contact_to_remove: EmergencyContact
    ) -> None:
        """Check if removal would violate minimum contacts requirement."""
        # Get minimum required contacts based on user type/plan
        min_contacts = await self._get_minimum_contacts_for_user(user)
        
        if min_contacts > 0:
            current_count = await self._emergency_contact_repository.count_active_by_user(user.id)
            
            if current_count <= min_contacts:
                raise MinimumContactsError(
                    f"Cannot remove contact - user must have at least {min_contacts} emergency contacts"
                )
        
        # Check if removing the last verified contact
        if contact_to_remove.is_verified:
            verified_count = await self._emergency_contact_repository.count_verified_by_user(user.id)
            
            if verified_count <= 1:
                # This is the last verified contact
                user_plan = user.metadata.get("subscription_plan", "basic")
                if user_plan in ["premium", "enterprise"]:
                    raise MinimumContactsError(
                        "Cannot remove the last verified emergency contact for premium/enterprise users"
                    )
    
    async def _get_minimum_contacts_for_user(self, user: User) -> int:
        """Get minimum number of emergency contacts required for user."""
        user_plan = user.metadata.get("subscription_plan", "basic")
        
        min_contacts_by_plan = {
            "basic": 0,      # No minimum for basic users
            "premium": 1,    # At least one for premium
            "enterprise": 2  # At least two for enterprise
        }
        
        return min_contacts_by_plan.get(user_plan, 0)
    
    def _capture_contact_data(self, contact: EmergencyContact) -> dict[str, Any]:
        """Capture contact data for backup purposes."""
        return {
            "id": str(contact.id),
            "user_id": str(contact.user_id),
            "contact_type": contact.contact_type.value,
            "contact_value": contact.contact_value,
            "contact_name": contact.contact_name,
            "relationship": contact.relationship.value,
            "priority": contact.priority,
            "is_primary": contact.is_primary,
            "is_verified": contact.is_verified,
            "country_code": contact.country_code,
            "notes": contact.notes,
            "status": contact.status.value,
            "added_at": contact.added_at.isoformat(),
            "added_by": str(contact.added_by),
            "updated_at": contact.updated_at.isoformat() if contact.updated_at else None,
            "updated_by": str(contact.updated_by) if contact.updated_by else None,
            "verified_at": contact.verified_at.isoformat() if contact.verified_at else None,
            "metadata": contact.metadata
        }
    
    async def _handle_primary_contact_removal(
        self,
        user_id: UUID,
        contact_type: ContactType,
        removed_contact_id: UUID
    ) -> EmergencyContact | None:
        """Handle removal of primary contact by promoting another."""
        # Find other contacts of same type
        other_contacts = await self._emergency_contact_repository.find_by_user_and_type(
            user_id,
            contact_type
        )
        
        # Filter out the contact being removed
        candidates = [c for c in other_contacts if c.id != removed_contact_id and c.is_active]
        
        if candidates:
            # Promote the highest priority remaining contact
            candidates.sort(key=lambda x: x.priority)
            new_primary = candidates[0]
            
            new_primary.is_primary = True
            await self._emergency_contact_repository.update(new_primary)
            
            return new_primary
        
        return None
    
    async def _create_removal_backup(
        self,
        user: User,
        contact: EmergencyContact,
        reason: str
    ) -> UUID:
        """Create backup of removed contact."""
        backup_data = {
            "contact": self._capture_contact_data(contact),
            "user": {
                "id": str(user.id),
                "username": user.username,
                "email": user.email,
                "full_name": f"{user.first_name} {user.last_name}"
            },
            "removal": {
                "reason": reason,
                "timestamp": datetime.now(UTC).isoformat(),
                "removed_by": str(contact.removed_by)
            }
        }
        
        return await self._backup_service.create_backup(
            BackupContext(
                backup_type=BackupType.EMERGENCY_CONTACT_REMOVAL,
                resource_type="emergency_contact",
                resource_id=contact.id,
                data=backup_data,
                retention_days=90,  # Keep for 90 days
                encrypted=True
            )
        )
        
    
    async def _send_removal_notifications(
        self,
        user: User,
        contact: EmergencyContact,
        reason: str
    ) -> None:
        """Send notifications to the removed contact."""
        if contact.contact_type == ContactType.EMAIL:
            await self._email_service.send_email(
                EmailContext(
                    recipient=contact.contact_value,
                    template="emergency_contact_removed",
                    subject=f"You've been removed as an emergency contact for {user.first_name} {user.last_name}",
                    variables={
                        "contact_name": contact.contact_name,
                        "user_name": f"{user.first_name} {user.last_name}",
                        "user_email": user.email,
                        "relationship": contact.relationship.value,
                        "removal_reason": reason,
                        "support_link": "https://app.example.com/support"
                    }
                )
            )
        
        elif contact.contact_type in [ContactType.PHONE, ContactType.SMS]:
            await self._sms_service.send_sms(
                SMSContext(
                    recipient=contact.contact_value,
                    template="emergency_contact_removed",
                    variables={
                        "contact_name": contact.contact_name,
                        "user_name": f"{user.first_name} {user.last_name}",
                        "reason": reason
                    }
                )
            )
    
    async def _notify_user_of_contact_removal(
        self,
        user: User,
        contact: EmergencyContact,
        removed_by: UUID,
        reason: str
    ) -> None:
        """Notify user when admin removes their emergency contact."""
        await self._notification_service.create_notification(
            NotificationContext(
                notification_id=UUID(),
                recipient_id=user.id,
                notification_type=NotificationType.EMERGENCY_CONTACT_REMOVED,
                channel="in_app",
                template_id="emergency_contact_removed_by_admin",
                template_data={
                    "contact_name": contact.contact_name,
                    "contact_type": contact.contact_type.value,
                    "contact_value": self._mask_contact_value(contact.contact_value),
                    "removed_by": str(removed_by),
                    "reason": reason,
                    "was_primary": contact.is_primary
                },
                priority="high"
            )
        )
        
        # Send email notification
        if user.email_verified:
            await self._email_service.send_email(
                EmailContext(
                    recipient=user.email,
                    template="emergency_contact_removed_notification",
                    subject="Emergency Contact Removed from Your Account",
                    variables={
                        "username": user.username,
                        "contact_name": contact.contact_name,
                        "contact_type": contact.contact_type.value,
                        "contact_value": self._mask_contact_value(contact.contact_value),
                        "reason": reason,
                        "was_primary": contact.is_primary,
                        "manage_contacts_link": "https://app.example.com/settings/emergency-contacts"
                    }
                )
            )
    
    async def _log_admin_contact_removal(
        self,
        user: User,
        contact: EmergencyContact,
        removed_by: UUID,
        reason: str
    ) -> None:
        """Log when admin removes emergency contact for another user."""
        await self._audit_service.log_administrative_action(
            AuditContext(
                action=AuditAction.EMERGENCY_CONTACT_REMOVED,
                actor_id=removed_by,
                target_user_id=user.id,
                resource_type="emergency_contact",
                resource_id=contact.id,
                details={
                    "contact_type": contact.contact_type.value,
                    "contact_value": self._mask_contact_value(contact.contact_value),
                    "contact_name": contact.contact_name,
                    "relationship": contact.relationship.value,
                    "was_primary": contact.is_primary,
                    "was_verified": contact.is_verified,
                    "reason": reason,
                    "admin_action": True
                },
                risk_level="medium"
            )
        )
    
    async def _assess_security_impact(
        self,
        user: User,
        removed_contact: EmergencyContact
    ) -> dict[str, Any]:
        """Assess security impact of removing this contact."""
        impact = {
            "risk_level": "low",
            "concerns": [],
            "recommendations": []
        }
        
        # Check if removing primary contact
        if removed_contact.is_primary:
            impact["risk_level"] = "medium"
            impact["concerns"].append("Primary emergency contact removed")
            impact["recommendations"].append("Verify user has alternative emergency contacts")
        
        # Check if removing last verified contact
        if removed_contact.is_verified:
            verified_count = await self._emergency_contact_repository.count_verified_by_user(user.id)
            if verified_count <= 1:
                impact["risk_level"] = "high"
                impact["concerns"].append("Last verified emergency contact removed")
                impact["recommendations"].append("Require user to verify another contact immediately")
        
        # Check if user has recent security incidents
        recent_incidents = await self._security_service.get_recent_security_incidents(
            user.id,
            days=30
        )
        
        if recent_incidents:
            impact["risk_level"] = "high"
            impact["concerns"].append(f"User has {len(recent_incidents)} recent security incidents")
            impact["recommendations"].append("Monitor user account for suspicious activity")
        
        # Check user account status
        if user.status in ["SUSPENDED", "LOCKED"]:
            impact["risk_level"] = "high"
            impact["concerns"].append(f"User account is {user.status}")
            impact["recommendations"].append("Emergency contact removal during account issues")
        
        return impact
    
    async def _log_security_impact(
        self,
        user: User,
        contact: EmergencyContact,
        security_impact: dict[str, Any],
        command: RemoveEmergencyContactCommand
    ) -> None:
        """Log high-risk emergency contact removal."""
        await self._audit_service.log_security_incident(
            SecurityIncidentContext(
                incident_type=SecurityEventType.HIGH_RISK_CONTACT_REMOVAL,
                severity=RiskLevel.HIGH,
                user_id=user.id,
                details={
                    "contact_id": str(contact.id),
                    "contact_type": contact.contact_type.value,
                    "contact_value": self._mask_contact_value(contact.contact_value),
                    "was_primary": contact.is_primary,
                    "was_verified": contact.is_verified,
                    "removed_by": str(command.removed_by),
                    "reason": command.reason,
                    "security_concerns": security_impact["concerns"],
                    "admin_removal": command.removed_by != user.id
                },
                indicators=["high_risk_contact_removal"],
                recommended_actions=security_impact["recommendations"]
            )
        )
        
        # Notify security team
        await self._notification_service.notify_security_team(
            "High-Risk Emergency Contact Removal",
            {
                "user": user.username,
                "contact_type": contact.contact_type.value,
                "was_primary": contact.is_primary,
                "was_verified": contact.is_verified,
                "security_concerns": security_impact["concerns"],
                "removed_by": str(command.removed_by),
                "reason": command.reason
            }
        )
    
    def _mask_contact_value(self, contact_value: str) -> str:
        """Mask contact value for logging/display purposes."""
        if "@" in contact_value:  # Email
            parts = contact_value.split("@")
            if len(parts[0]) > 3:
                masked_local = parts[0][:2] + "*" * (len(parts[0]) - 4) + parts[0][-2:]
            else:
                masked_local = parts[0][0] + "*" * (len(parts[0]) - 1)
            return f"{masked_local}@{parts[1]}"
        # Phone
        if len(contact_value) > 4:
            return contact_value[:2] + "*" * (len(contact_value) - 4) + contact_value[-2:]
        return "*" * len(contact_value)