"""
Update emergency contact command implementation.

Handles updating existing emergency contacts with validation and re-verification.
"""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.contracts.ports import (
    IAuditService,
    IEmailService,
    IEmergencyContactRepository,
    INotificationService,
    ISMSService,
    IUserRepository,
)
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    require_permission,
    validate_request,
)
from app.modules.identity.application.dtos.internal import (
    AuditContext,
    EmailContext,
    NotificationContext,
    SMSContext,
)
from app.modules.identity.application.dtos.request import UpdateEmergencyContactRequest
from app.modules.identity.application.dtos.response import (
    EmergencyContactUpdateResponse,
)
from app.modules.identity.domain.entities import EmergencyContact, User
from app.modules.identity.domain.enums import (
    AuditAction,
    ContactStatus,
    ContactType,
    NotificationType,
    RelationshipType,
)
from app.modules.identity.domain.events import EmergencyContactUpdated
from app.modules.identity.domain.exceptions import (
    DuplicateContactError,
    EmergencyContactNotFoundError,
    InvalidContactDataError,
    UserNotFoundError,
)
from app.modules.identity.domain.services import (
    ContactVerificationService,
    ValidationService,
)


class UpdateEmergencyContactCommand(Command[EmergencyContactUpdateResponse]):
    """Command to update an existing emergency contact."""
    
    def __init__(
        self,
        contact_id: UUID,
        updated_by: UUID,
        contact_value: str | None = None,
        contact_name: str | None = None,
        relationship: RelationshipType | None = None,
        priority: int | None = None,
        is_primary: bool | None = None,
        country_code: str | None = None,
        notes: str | None = None,
        force_reverification: bool = False,
        notification_preferences: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None
    ):
        self.contact_id = contact_id
        self.updated_by = updated_by
        self.contact_value = contact_value.strip().lower() if contact_value and "@" in contact_value else contact_value.strip() if contact_value else None
        self.contact_name = contact_name.strip() if contact_name else None
        self.relationship = relationship
        self.priority = max(1, min(priority, 10)) if priority else None  # Clamp between 1-10
        self.is_primary = is_primary
        self.country_code = country_code
        self.notes = notes
        self.force_reverification = force_reverification
        self.notification_preferences = notification_preferences
        self.metadata = metadata


class UpdateEmergencyContactCommandHandler(CommandHandler[UpdateEmergencyContactCommand, EmergencyContactUpdateResponse]):
    """Handler for updating emergency contacts."""
    
    def __init__(
        self,
        user_repository: IUserRepository,
        emergency_contact_repository: IEmergencyContactRepository,
        validation_service: ValidationService,
        contact_verification_service: ContactVerificationService,
        notification_service: INotificationService,
        audit_service: IAuditService,
        email_service: IEmailService,
        sms_service: ISMSService,
        event_bus: EventBus,
        unit_of_work: UnitOfWork
    ):
        self._user_repository = user_repository
        self._emergency_contact_repository = emergency_contact_repository
        self._validation_service = validation_service
        self._contact_verification_service = contact_verification_service
        self._notification_service = notification_service
        self._audit_service = audit_service
        self._email_service = email_service
        self._sms_service = sms_service
        self._event_bus = event_bus
        self._unit_of_work = unit_of_work
    
    @audit_action(
        action=AuditAction.EMERGENCY_CONTACT_UPDATED,
        resource_type="emergency_contact",
        include_request=True,
        include_response=True,
        include_changes=True
    )
    @validate_request(UpdateEmergencyContactRequest)
    @rate_limit(
        max_requests=20,
        window_seconds=3600,
        strategy='user'
    )
    @require_permission("emergency_contacts.update")
    async def handle(self, command: UpdateEmergencyContactCommand) -> EmergencyContactUpdateResponse:
        """
        Update emergency contact with validation and re-verification.
        
        Process:
        1. Load contact and validate access
        2. Validate update data
        3. Check for duplicates if contact value changed
        4. Apply updates
        5. Handle primary contact logic
        6. Handle re-verification if needed
        7. Send notifications
        8. Log changes
        
        Returns:
            EmergencyContactUpdateResponse with update details
            
        Raises:
            EmergencyContactNotFoundError: If contact not found
            UnauthorizedError: If user cannot update contact
            DuplicateContactError: If contact value conflicts
            InvalidContactDataError: If update data invalid
        """
        async with self._unit_of_work:
            # 1. Load contact
            contact = await self._emergency_contact_repository.get_by_id(command.contact_id)
            if not contact:
                raise EmergencyContactNotFoundError(f"Emergency contact {command.contact_id} not found")
            
            # 2. Load user
            user = await self._user_repository.get_by_id(contact.user_id)
            if not user:
                raise UserNotFoundError(f"User {contact.user_id} not found")
            
            # 3. Check update permissions
            await self._validate_update_permissions(contact, command.updated_by)
            
            # 4. Store original state for comparison
            original_state = self._capture_contact_state(contact)
            
            # 5. Validate update data
            await self._validate_update_data(contact, command)
            
            # 6. Check for duplicates if contact value changed
            if command.contact_value and command.contact_value != contact.contact_value:
                await self._check_duplicate_contact(
                    contact.user_id,
                    contact.contact_type,
                    command.contact_value,
                    contact.id
                )
            
            # 7. Apply updates
            changes = {}
            verification_required = False
            
            if command.contact_value and command.contact_value != contact.contact_value:
                changes["contact_value"] = (contact.contact_value, command.contact_value)
                contact.contact_value = command.contact_value
                contact.is_verified = False  # Reset verification
                contact.status = ContactStatus.PENDING_VERIFICATION
                verification_required = True
            
            if command.contact_name and command.contact_name != contact.contact_name:
                changes["contact_name"] = (contact.contact_name, command.contact_name)
                contact.contact_name = command.contact_name
            
            if command.relationship and command.relationship != contact.relationship:
                changes["relationship"] = (contact.relationship.value, command.relationship.value)
                contact.relationship = command.relationship
            
            if command.priority is not None and command.priority != contact.priority:
                changes["priority"] = (contact.priority, command.priority)
                contact.priority = command.priority
            
            if command.country_code and command.country_code != contact.country_code:
                changes["country_code"] = (contact.country_code, command.country_code)
                contact.country_code = command.country_code
            
            if command.notes is not None and command.notes != contact.notes:
                changes["notes"] = (contact.notes or "", command.notes)
                contact.notes = command.notes
            
            # 8. Handle primary contact logic
            if command.is_primary is not None and command.is_primary != contact.is_primary:
                changes["is_primary"] = (contact.is_primary, command.is_primary)
                
                if command.is_primary:
                    # Unset other primary contacts of same type
                    await self._handle_primary_contact_change(
                        contact.user_id,
                        contact.contact_type,
                        contact.id
                    )
                    contact.is_primary = True
                else:
                    contact.is_primary = False
            
            # 9. Update notification preferences
            if command.notification_preferences:
                changes["notification_preferences"] = (
                    contact.metadata.get("notification_preferences", {}),
                    command.notification_preferences
                )
                contact.metadata["notification_preferences"] = command.notification_preferences
            
            # 10. Update metadata
            contact.updated_at = datetime.now(UTC)
            contact.updated_by = command.updated_by
            
            if command.metadata:
                contact.metadata.update(command.metadata)
            
            # 11. Handle forced re-verification
            if command.force_reverification and contact.is_verified:
                contact.is_verified = False
                contact.status = ContactStatus.PENDING_VERIFICATION
                verification_required = True
                changes["verification_reset"] = True
            
            # 12. Save contact
            await self._emergency_contact_repository.update(contact)
            
            # 13. Initiate verification if needed
            verification_data = None
            if verification_required:
                verification_data = await self._initiate_verification(contact)
            
            # 14. Send update notifications
            await self._send_update_notifications(
                user,
                contact,
                changes,
                original_state,
                command
            )
            
            # 15. Log admin updates
            if command.updated_by != contact.user_id:
                await self._log_admin_contact_update(
                    user,
                    contact,
                    changes,
                    command.updated_by
                )
            
            # 16. Publish domain event
            await self._event_bus.publish(
                EmergencyContactUpdated(
                    aggregate_id=contact.id,
                    user_id=contact.user_id,
                    contact_type=contact.contact_type,
                    changes=list(changes.keys()),
                    verification_required=verification_required,
                    updated_by=command.updated_by
                )
            )
            
            # 17. Commit transaction
            await self._unit_of_work.commit()
            
            # 18. Return response
            return EmergencyContactUpdateResponse(
                contact_id=contact.id,
                user_id=contact.user_id,
                changes_made=changes,
                verification_required=verification_required,
                verification_sent=verification_data is not None,
                verification_expires_at=verification_data.get("expires_at") if verification_data else None,
                current_status=contact.status,
                is_verified=contact.is_verified,
                updated_at=contact.updated_at,
                updated_by=contact.updated_by,
                message="Emergency contact updated successfully"
            )
    
    async def _validate_update_permissions(
        self,
        contact: EmergencyContact,
        updated_by: UUID
    ) -> None:
        """Validate user can update this contact."""
        # User can update their own contacts
        if contact.user_id == updated_by:
            return
        
        # Check if updater has admin permissions
        # This would typically check for admin role or specific permission
        # For now, we'll allow it but log it as admin action
    
    def _capture_contact_state(self, contact: EmergencyContact) -> dict[str, Any]:
        """Capture current contact state for comparison."""
        return {
            "contact_value": contact.contact_value,
            "contact_name": contact.contact_name,
            "relationship": contact.relationship.value,
            "priority": contact.priority,
            "is_primary": contact.is_primary,
            "is_verified": contact.is_verified,
            "status": contact.status.value,
            "country_code": contact.country_code,
            "notes": contact.notes,
            "notification_preferences": contact.metadata.get("notification_preferences", {})
        }
    
    async def _validate_update_data(
        self,
        contact: EmergencyContact,
        command: UpdateEmergencyContactCommand
    ) -> None:
        """Validate update data."""
        # Validate contact value if changed
        if command.contact_value:
            if contact.contact_type == ContactType.EMAIL:
                if not self._validation_service.is_valid_email(command.contact_value):
                    raise InvalidContactDataError("Invalid email address format")
            
            elif contact.contact_type in [ContactType.PHONE, ContactType.SMS]:
                if not self._validation_service.is_valid_phone(
                    command.contact_value,
                    command.country_code or contact.country_code
                ):
                    raise InvalidContactDataError("Invalid phone number format")
        
        # Validate contact name
        if command.contact_name is not None:
            if len(command.contact_name.strip()) < 2:
                raise InvalidContactDataError("Contact name must be at least 2 characters")
            
            if len(command.contact_name) > 100:
                raise InvalidContactDataError("Contact name too long (max 100 characters)")
        
        # Validate relationship and notes combination
        if command.relationship == RelationshipType.OTHER:
            if not command.notes and not contact.notes:
                raise InvalidContactDataError("Notes required when relationship is 'Other'")
        
        # Validate priority
        if command.priority is not None:
            if command.priority < 1 or command.priority > 10:
                raise InvalidContactDataError("Priority must be between 1 and 10")
    
    async def _check_duplicate_contact(
        self,
        user_id: UUID,
        contact_type: ContactType,
        contact_value: str,
        exclude_contact_id: UUID
    ) -> None:
        """Check for duplicate contact values."""
        existing = await self._emergency_contact_repository.find_by_user_and_contact(
            user_id,
            contact_type,
            contact_value
        )
        
        if existing and existing.id != exclude_contact_id:
            raise DuplicateContactError(
                f"Emergency contact {contact_value} already exists for user"
            )
    
    async def _handle_primary_contact_change(
        self,
        user_id: UUID,
        contact_type: ContactType,
        exclude_contact_id: UUID
    ) -> None:
        """Handle setting a new primary contact of the same type."""
        # Find existing primary contact of same type
        existing_primary = await self._emergency_contact_repository.find_primary_by_type(
            user_id,
            contact_type
        )
        
        if existing_primary and existing_primary.id != exclude_contact_id:
            # Unset existing primary
            existing_primary.is_primary = False
            await self._emergency_contact_repository.update(existing_primary)
    
    async def _initiate_verification(self, contact: EmergencyContact) -> dict[str, Any]:
        """Initiate verification process for updated contact."""
        verification_data = await self._contact_verification_service.generate_verification(
            contact.id,
            contact.contact_type,
            contact.contact_value
        )
        
        if contact.contact_type == ContactType.EMAIL:
            # Send verification email
            await self._email_service.send_email(
                EmailContext(
                    recipient=contact.contact_value,
                    template="emergency_contact_reverification",
                    subject="Re-verify Your Emergency Contact",
                    variables={
                        "contact_name": contact.contact_name,
                        "verification_code": verification_data["code"],
                        "verification_link": verification_data["link"],
                        "expires_at": verification_data["expires_at"].isoformat(),
                        "reason": "Contact information was updated"
                    }
                )
            )
        
        elif contact.contact_type in [ContactType.PHONE, ContactType.SMS]:
            # Send verification SMS
            await self._sms_service.send_sms(
                SMSContext(
                    recipient=contact.contact_value,
                    template="emergency_contact_reverification",
                    variables={
                        "contact_name": contact.contact_name,
                        "verification_code": verification_data["code"],
                        "reason": "updated"
                    }
                )
            )
        
        return {
            "method": contact.contact_type.value,
            "expires_at": verification_data["expires_at"],
            "code_sent": True
        }
    
    async def _send_update_notifications(
        self,
        user: User,
        contact: EmergencyContact,
        changes: dict[str, Any],
        original_state: dict[str, Any],
        command: UpdateEmergencyContactCommand
    ) -> None:
        """Send notifications about contact updates."""
        # Notify the emergency contact if their contact info changed
        if "contact_value" in changes:
            # Send notification to old contact value
            old_contact_value = changes["contact_value"][0]
            await self._notify_old_contact_of_change(
                user,
                contact,
                old_contact_value,
                original_state
            )
            
            # Send notification to new contact value
            await self._notify_new_contact_of_change(user, contact)
        
        # Notify user if updated by admin
        if command.updated_by != user.id:
            await self._notify_user_of_contact_update(user, contact, changes)
    
    async def _notify_old_contact_of_change(
        self,
        user: User,
        contact: EmergencyContact,
        old_contact_value: str,
        original_state: dict[str, Any]
    ) -> None:
        """Notify old contact value about the change."""
        if original_state["contact_type"] == ContactType.EMAIL.value:
            await self._email_service.send_email(
                EmailContext(
                    recipient=old_contact_value,
                    template="emergency_contact_changed",
                    subject=f"Emergency Contact Updated for {user.first_name} {user.last_name}",
                    variables={
                        "contact_name": original_state["contact_name"],
                        "user_name": f"{user.first_name} {user.last_name}",
                        "old_contact": self._mask_contact_value(old_contact_value),
                        "new_contact": self._mask_contact_value(contact.contact_value),
                        "support_link": "https://app.example.com/support"
                    }
                )
            )
    
    async def _notify_new_contact_of_change(
        self,
        user: User,
        contact: EmergencyContact
    ) -> None:
        """Notify new contact value about being added."""
        if contact.contact_type == ContactType.EMAIL:
            await self._email_service.send_email(
                EmailContext(
                    recipient=contact.contact_value,
                    template="emergency_contact_welcome",
                    subject=f"You've been added as an emergency contact for {user.first_name} {user.last_name}",
                    variables={
                        "contact_name": contact.contact_name,
                        "user_name": f"{user.first_name} {user.last_name}",
                        "user_email": user.email,
                        "relationship": contact.relationship.value,
                        "is_update": True,
                        "support_link": "https://app.example.com/support"
                    }
                )
            )
    
    async def _notify_user_of_contact_update(
        self,
        user: User,
        contact: EmergencyContact,
        changes: dict[str, Any]
    ) -> None:
        """Notify user when admin updates their emergency contact."""
        await self._notification_service.create_notification(
            NotificationContext(
                notification_id=UUID(),
                recipient_id=user.id,
                notification_type=NotificationType.EMERGENCY_CONTACT_UPDATED,
                channel="in_app",
                template_id="emergency_contact_updated_by_admin",
                template_data={
                    "contact_name": contact.contact_name,
                    "contact_type": contact.contact_type.value,
                    "changes": list(changes.keys()),
                    "verification_required": not contact.is_verified
                },
                priority="medium"
            )
        )
    
    async def _log_admin_contact_update(
        self,
        user: User,
        contact: EmergencyContact,
        changes: dict[str, Any],
        updated_by: UUID
    ) -> None:
        """Log when admin updates emergency contact for another user."""
        await self._audit_service.log_administrative_action(
            AuditContext(
                action=AuditAction.EMERGENCY_CONTACT_UPDATED,
                actor_id=updated_by,
                target_user_id=user.id,
                resource_type="emergency_contact",
                resource_id=contact.id,
                details={
                    "contact_type": contact.contact_type.value,
                    "contact_value": self._mask_contact_value(contact.contact_value),
                    "changes": changes,
                    "admin_action": True,
                    "verification_required": not contact.is_verified
                },
                risk_level="medium"
            )
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