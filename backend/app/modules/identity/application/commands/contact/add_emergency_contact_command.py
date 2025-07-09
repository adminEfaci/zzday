"""
Add emergency contact command implementation.

Handles adding new emergency contacts for users with validation and verification.
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
    require_permission,
    validate_request,
)
from app.modules.identity.application.dtos.internal import (
    AuditContext,
    EmailContext,
    NotificationContext,
    SMSContext,
)
from app.modules.identity.application.dtos.request import AddEmergencyContactRequest
from app.modules.identity.application.dtos.response import EmergencyContactResponse
from app.modules.identity.domain.entities import EmergencyContact, User
from app.modules.identity.domain.enums import (
    AuditAction,
    ContactStatus,
    ContactType,
    NotificationType,
    RelationshipType,
    VerificationMethod,
)
from app.modules.identity.domain.events import EmergencyContactAdded
from app.modules.identity.domain.exceptions import (
    ContactLimitExceededError,
    DuplicateContactError,
    InvalidContactDataError,
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
from app.modules.identity.domain.services import (
from app.modules.identity.domain.interfaces.services import (
    IAuditService,
)
    ContactVerificationService,
    ValidationService,
)


class AddEmergencyContactCommand(Command[EmergencyContactResponse]):
    """Command to add a new emergency contact."""
    
    def __init__(
        self,
        user_id: UUID,
        added_by: UUID | None = None,
        contact_type: ContactType = ContactType.EMAIL,
        contact_value: str = "",
        contact_name: str = "",
        relationship: RelationshipType = RelationshipType.OTHER,
        priority: int = 1,
        is_primary: bool = False,
        country_code: str | None = None,
        notes: str | None = None,
        verification_method: VerificationMethod = VerificationMethod.AUTOMATIC,
        send_welcome_message: bool = True,
        metadata: dict[str, Any] | None = None
    ):
        self.user_id = user_id
        self.added_by = added_by or user_id  # Default to self-adding
        self.contact_type = contact_type
        self.contact_value = contact_value.strip().lower() if contact_type == ContactType.EMAIL else contact_value.strip()
        self.contact_name = contact_name.strip()
        self.relationship = relationship
        self.priority = max(1, min(priority, 10))  # Clamp between 1-10
        self.is_primary = is_primary
        self.country_code = country_code
        self.notes = notes
        self.verification_method = verification_method
        self.send_welcome_message = send_welcome_message
        self.metadata = metadata or {}


class AddEmergencyContactCommandHandler(CommandHandler[AddEmergencyContactCommand, EmergencyContactResponse]):
    """Handler for adding emergency contacts."""
    
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
        action=AuditAction.EMERGENCY_CONTACT_ADDED,
        resource_type="emergency_contact",
        include_request=True,
        include_response=True
    )
    @validate_request(AddEmergencyContactRequest)
    @rate_limit(
        max_requests=10,
        window_seconds=3600,
        strategy='user'
    )
    @require_permission("emergency_contacts.add")
    async def handle(self, command: AddEmergencyContactCommand) -> EmergencyContactResponse:
        """
        Add emergency contact with comprehensive validation.
        
        Process:
        1. Load user and validate
        2. Validate contact data
        3. Check for duplicates
        4. Check contact limits
        5. Handle primary contact logic
        6. Create emergency contact
        7. Send verification
        8. Send welcome message
        9. Log and notify
        
        Returns:
            EmergencyContactResponse with contact details
            
        Raises:
            UserNotFoundError: If user not found
            DuplicateContactError: If contact already exists
            ContactLimitExceededError: If too many contacts
            InvalidContactDataError: If contact data invalid
        """
        async with self._unit_of_work:
            # 1. Load user
            user = await self._user_repository.find_by_id(command.user_id)
            if not user:
                raise UserNotFoundError(f"User {command.user_id} not found")
            
            # 2. Validate contact data
            await self._validate_contact_data(command)
            
            # 3. Check for duplicate contacts
            existing = await self._emergency_contact_repository.find_by_user_and_contact(
                command.user_id,
                command.contact_type,
                command.contact_value
            )
            
            if existing:
                raise DuplicateContactError(
                    f"Emergency contact {command.contact_value} already exists for user"
                )
            
            # 4. Check contact limits
            current_contacts = await self._emergency_contact_repository.count_by_user(command.user_id)
            max_contacts = await self._get_max_contacts_for_user(user)
            
            if current_contacts >= max_contacts:
                raise ContactLimitExceededError(
                    f"User already has maximum number of emergency contacts ({max_contacts})"
                )
            
            # 5. Handle primary contact logic
            if command.is_primary:
                await self._handle_primary_contact_change(
                    command.user_id,
                    command.contact_type
                )
            
            # 6. Create emergency contact
            contact = EmergencyContact(
                id=UUID(),
                user_id=command.user_id,
                contact_type=command.contact_type,
                contact_value=command.contact_value,
                contact_name=command.contact_name,
                relationship=command.relationship,
                priority=command.priority,
                is_primary=command.is_primary,
                is_verified=False,
                country_code=command.country_code,
                notes=command.notes,
                status=ContactStatus.PENDING_VERIFICATION,
                added_by=command.added_by,
                added_at=datetime.now(UTC),
                metadata=command.metadata
            )
            
            # 7. Save contact
            await self._emergency_contact_repository.create(contact)
            
            # 8. Generate verification if needed
            verification_data = None
            if command.verification_method == VerificationMethod.AUTOMATIC:
                verification_data = await self._initiate_verification(contact)
            
            # 9. Send welcome message
            if command.send_welcome_message:
                await self._send_welcome_message(user, contact)
            
            # 10. Log security event for admin additions
            if command.added_by != command.user_id:
                await self._log_admin_contact_addition(user, contact, command.added_by)
            
            # 11. Publish domain event
            await self._event_bus.publish(
                EmergencyContactAdded(
                    aggregate_id=contact.id,
                    user_id=user.id,
                    contact_type=contact.contact_type,
                    contact_value=contact.contact_value,
                    is_primary=contact.is_primary,
                    added_by=command.added_by
                )
            )
            
            # 12. Notify user if added by admin
            if command.added_by != command.user_id:
                await self._notify_user_of_contact_addition(user, contact)
            
            # 13. Commit transaction
            await self._unit_of_work.commit()
            
            # 14. Return response
            return EmergencyContactResponse(
                id=contact.id,
                user_id=contact.user_id,
                contact_type=contact.contact_type,
                contact_value=contact.contact_value,
                contact_name=contact.contact_name,
                relationship=contact.relationship,
                priority=contact.priority,
                is_primary=contact.is_primary,
                is_verified=contact.is_verified,
                status=contact.status,
                country_code=contact.country_code,
                notes=contact.notes,
                verification_sent=verification_data is not None,
                verification_method=verification_data.get("method") if verification_data else None,
                verification_expires_at=verification_data.get("expires_at") if verification_data else None,
                added_at=contact.added_at,
                added_by=contact.added_by,
                message=f"Emergency contact {contact.contact_value} added successfully"
            )
    
    async def _validate_contact_data(self, command: AddEmergencyContactCommand) -> None:
        """Validate contact data format and requirements."""
        # Validate contact value based on type
        if command.contact_type == ContactType.EMAIL:
            if not self._validation_service.is_valid_email(command.contact_value):
                raise InvalidContactDataError("Invalid email address format")
            
            # Check for prohibited domains
            if await self._validation_service.is_prohibited_email_domain(command.contact_value):
                raise InvalidContactDataError("Email domain not allowed for emergency contacts")
        
        elif command.contact_type == ContactType.PHONE:
            if not self._validation_service.is_valid_phone(
                command.contact_value,
                command.country_code
            ):
                raise InvalidContactDataError("Invalid phone number format")
            
            # Normalize phone number
            command.contact_value = self._validation_service.normalize_phone(
                command.contact_value,
                command.country_code
            )
        
        elif command.contact_type == ContactType.SMS:
            if not command.country_code:
                raise InvalidContactDataError("Country code required for SMS contacts")
            
            if not self._validation_service.is_valid_phone(
                command.contact_value,
                command.country_code
            ):
                raise InvalidContactDataError("Invalid phone number for SMS")
        
        # Validate contact name
        if not command.contact_name or len(command.contact_name.strip()) < 2:
            raise InvalidContactDataError("Contact name must be at least 2 characters")
        
        if len(command.contact_name) > 100:
            raise InvalidContactDataError("Contact name too long (max 100 characters)")
        
        # Validate relationship
        if command.relationship == RelationshipType.OTHER and not command.notes:
            raise InvalidContactDataError("Notes required when relationship is 'Other'")
        
        # Validate priority
        if command.priority < 1 or command.priority > 10:
            raise InvalidContactDataError("Priority must be between 1 and 10")
    
    async def _get_max_contacts_for_user(self, user: User) -> int:
        """Get maximum number of emergency contacts allowed for user."""
        # Check user plan/subscription
        user_plan = user.metadata.get("subscription_plan", "basic")
        
        max_contacts_by_plan = {
            "basic": 3,
            "premium": 7,
            "enterprise": 15
        }
        
        return max_contacts_by_plan.get(user_plan, 3)
    
    async def _handle_primary_contact_change(
        self,
        user_id: UUID,
        contact_type: ContactType
    ) -> None:
        """Handle setting a new primary contact of the same type."""
        # Find existing primary contact of same type
        existing_primary = await self._emergency_contact_repository.find_primary_by_type(
            user_id,
            contact_type
        )
        
        if existing_primary:
            # Unset existing primary
            existing_primary.is_primary = False
            await self._emergency_contact_repository.update(existing_primary)
    
    async def _initiate_verification(self, contact: EmergencyContact) -> dict[str, Any]:
        """Initiate verification process for the contact."""
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
                    template="emergency_contact_verification",
                    subject="Verify Your Emergency Contact",
                    variables={
                        "contact_name": contact.contact_name,
                        "verification_code": verification_data["code"],
                        "verification_link": verification_data["link"],
                        "expires_at": verification_data["expires_at"].isoformat()
                    }
                )
            )
        
        elif contact.contact_type in [ContactType.PHONE, ContactType.SMS]:
            # Send verification SMS
            await self._sms_service.send_sms(
                SMSContext(
                    recipient=contact.contact_value,
                    template="emergency_contact_verification",
                    variables={
                        "contact_name": contact.contact_name,
                        "verification_code": verification_data["code"]
                    }
                )
            )
        
        return {
            "method": contact.contact_type.value,
            "expires_at": verification_data["expires_at"],
            "code_sent": True
        }
    
    async def _send_welcome_message(self, user: User, contact: EmergencyContact) -> None:
        """Send welcome message to new emergency contact."""
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
                        "support_link": "https://app.example.com/support"
                    }
                )
            )
        
        elif contact.contact_type in [ContactType.PHONE, ContactType.SMS]:
            await self._sms_service.send_sms(
                SMSContext(
                    recipient=contact.contact_value,
                    template="emergency_contact_welcome",
                    variables={
                        "contact_name": contact.contact_name,
                        "user_name": f"{user.first_name} {user.last_name}",
                        "relationship": contact.relationship.value
                    }
                )
            )
    
    async def _log_admin_contact_addition(
        self,
        user: User,
        contact: EmergencyContact,
        added_by: UUID
    ) -> None:
        """Log when admin adds emergency contact for another user."""
        await self._audit_service.log_administrative_action(
            AuditContext(
                action=AuditAction.EMERGENCY_CONTACT_ADDED,
                actor_id=added_by,
                target_user_id=user.id,
                resource_type="emergency_contact",
                resource_id=contact.id,
                details={
                    "contact_type": contact.contact_type.value,
                    "contact_value": self._mask_contact_value(contact.contact_value),
                    "relationship": contact.relationship.value,
                    "is_primary": contact.is_primary,
                    "admin_action": True
                },
                risk_level="medium"
            )
        )
    
    async def _notify_user_of_contact_addition(
        self,
        user: User,
        contact: EmergencyContact
    ) -> None:
        """Notify user when admin adds emergency contact."""
        await self._notification_service.create_notification(
            NotificationContext(
                notification_id=UUID(),
                recipient_id=user.id,
                notification_type=NotificationType.EMERGENCY_CONTACT_ADDED,
                channel="in_app",
                template_id="emergency_contact_added_by_admin",
                template_data={
                    "contact_type": contact.contact_type.value,
                    "contact_value": self._mask_contact_value(contact.contact_value),
                    "contact_name": contact.contact_name,
                    "relationship": contact.relationship.value
                },
                priority="medium"
            )
        )
        
        # Also send email notification
        if user.email_verified:
            await self._email_service.send_email(
                EmailContext(
                    recipient=user.email,
                    template="emergency_contact_added_notification",
                    subject="Emergency Contact Added to Your Account",
                    variables={
                        "username": user.username,
                        "contact_type": contact.contact_type.value,
                        "contact_value": self._mask_contact_value(contact.contact_value),
                        "contact_name": contact.contact_name,
                        "relationship": contact.relationship.value,
                        "manage_contacts_link": "https://app.example.com/settings/emergency-contacts"
                    }
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