"""
Notify emergency contacts command implementation.

Handles sending notifications to emergency contacts for various events.
"""

from datetime import UTC, datetime
from enum import Enum
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
    SecurityIncidentContext,
    SMSContext,
)
from app.modules.identity.application.dtos.request import NotifyEmergencyContactsRequest
from app.modules.identity.application.dtos.response import (
    EmergencyContactNotificationResponse,
)
from app.modules.identity.domain.entities import EmergencyContact, User
from app.modules.identity.domain.enums import (
    AuditAction,
    ContactStatus,
    ContactType,
    NotificationPriority,
    RiskLevel,
    SecurityEventType,
)
from app.modules.identity.domain.events import (
    EmergencyContactsNotified,
)
from app.modules.identity.domain.exceptions import (
    NoEmergencyContactsError,
    RateLimitExceededError,
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
    NotificationTemplateService,
    SecurityService,
    ValidationService,
)


class NotificationReason(Enum):
    """Reasons for notifying emergency contacts."""
    SECURITY_INCIDENT = "security_incident"
    ACCOUNT_LOCKED = "account_locked"
    SUSPICIOUS_LOGIN = "suspicious_login"
    PASSWORD_CHANGED = "password_changed"  # noqa: S105
    MFA_DISABLED = "mfa_disabled"
    ACCOUNT_RECOVERY = "account_recovery"
    DATA_BREACH = "data_breach"
    EMERGENCY_ACCESS = "emergency_access"
    ACCOUNT_DELETION = "account_deletion"
    PRIVACY_SETTINGS_CHANGED = "privacy_settings_changed"
    CUSTOM = "custom"


class NotifyEmergencyContactsCommand(Command[EmergencyContactNotificationResponse]):
    """Command to notify emergency contacts."""
    
    def __init__(
        self,
        user_id: UUID,
        reason: NotificationReason,
        triggered_by: UUID | None = None,
        priority: NotificationPriority = NotificationPriority.MEDIUM,
        custom_message: str | None = None,
        template_override: str | None = None,
        template_variables: dict[str, Any] | None = None,
        contact_types: list[ContactType] | None = None,
        contact_ids: list[UUID] | None = None,
        verified_only: bool = True,
        primary_only: bool = False,
        include_user_data: bool = True,
        delivery_timeout_minutes: int = 30,
        retry_failed: bool = True,
        max_retries: int = 3,
        incident_data: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None
    ):
        self.user_id = user_id
        self.reason = reason
        self.triggered_by = triggered_by
        self.priority = priority
        self.custom_message = custom_message
        self.template_override = template_override
        self.template_variables = template_variables or {}
        self.contact_types = contact_types or [ContactType.EMAIL, ContactType.SMS]
        self.contact_ids = contact_ids or []
        self.verified_only = verified_only
        self.primary_only = primary_only
        self.include_user_data = include_user_data
        self.delivery_timeout_minutes = delivery_timeout_minutes
        self.retry_failed = retry_failed
        self.max_retries = max_retries
        self.incident_data = incident_data or {}
        self.metadata = metadata or {}


class NotifyEmergencyContactsCommandHandler(CommandHandler[NotifyEmergencyContactsCommand, EmergencyContactNotificationResponse]):
    """Handler for notifying emergency contacts."""
    
    def __init__(
        self,
        user_repository: IUserRepository,
        emergency_contact_repository: IEmergencyContactRepository,
        notification_history_repository: INotificationHistoryRepository,
        validation_service: ValidationService,
        notification_template_service: NotificationTemplateService,
        security_service: SecurityService,
        notification_service: INotificationService,
        audit_service: IAuditService,
        email_service: IEmailService,
        sms_service: ISMSService,
        event_bus: EventBus,
        unit_of_work: UnitOfWork
    ):
        self._user_repository = user_repository
        self._emergency_contact_repository = emergency_contact_repository
        self._notification_history_repository = notification_history_repository
        self._validation_service = validation_service
        self._notification_template_service = notification_template_service
        self._security_service = security_service
        self._notification_service = notification_service
        self._audit_service = audit_service
        self._email_service = email_service
        self._sms_service = sms_service
        self._event_bus = event_bus
        self._unit_of_work = unit_of_work
    
    @audit_action(
        action=AuditAction.EMERGENCY_CONTACTS_NOTIFIED,
        resource_type="user",
        include_request=True,
        include_response=True,
        include_reason=True
    )
    @validate_request(NotifyEmergencyContactsRequest)
    @rate_limit(
        max_requests=50,
        window_seconds=3600,
        strategy='user'
    )
    @require_permission("emergency_contacts.notify")
    async def handle(self, command: NotifyEmergencyContactsCommand) -> EmergencyContactNotificationResponse:
        """
        Notify emergency contacts with comprehensive delivery tracking.
        
        Process:
        1. Load user and validate
        2. Get eligible emergency contacts
        3. Check notification rate limits
        4. Prepare notification content
        5. Send notifications to contacts
        6. Track delivery status
        7. Handle failures and retries
        8. Log and audit activity
        
        Returns:
            EmergencyContactNotificationResponse with delivery details
            
        Raises:
            UserNotFoundError: If user not found
            NoEmergencyContactsError: If no eligible contacts
            RateLimitExceededError: If too many notifications
        """
        async with self._unit_of_work:
            # 1. Load user
            user = await self._user_repository.find_by_id(command.user_id)
            if not user:
                raise UserNotFoundError(f"User {command.user_id} not found")
            
            # 2. Get eligible emergency contacts
            eligible_contacts = await self._get_eligible_contacts(user, command)
            
            if not eligible_contacts:
                raise NoEmergencyContactsError(
                    "No eligible emergency contacts found for notification"
                )
            
            # 3. Check notification rate limits
            await self._check_notification_rate_limits(user.id, command.reason)
            
            # 4. Prepare notification content
            notification_content = await self._prepare_notification_content(
                user,
                command
            )
            
            # 5. Send notifications
            delivery_results = await self._send_notifications(
                user,
                eligible_contacts,
                notification_content,
                command
            )
            
            # 6. Record notification history
            notification_history = await self._record_notification_history(
                user,
                eligible_contacts,
                delivery_results,
                command
            )
            
            # 7. Handle high-priority security notifications
            if command.priority == NotificationPriority.CRITICAL:
                await self._handle_critical_notification(
                    user,
                    command,
                    delivery_results
                )
            
            # 8. Log security event if needed
            if command.reason in [
                NotificationReason.SECURITY_INCIDENT,
                NotificationReason.SUSPICIOUS_LOGIN,
                NotificationReason.DATA_BREACH
            ]:
                await self._log_security_notification(
                    user,
                    command,
                    delivery_results
                )
            
            # 9. Schedule retries for failed deliveries
            if command.retry_failed:
                await self._schedule_retry_attempts(
                    delivery_results["failed"],
                    notification_content,
                    command
                )
            
            # 10. Publish domain event
            await self._event_bus.publish(
                EmergencyContactsNotified(
                    aggregate_id=user.id,
                    reason=command.reason.value,
                    contacts_notified=len(delivery_results["successful"]),
                    delivery_failures=len(delivery_results["failed"]),
                    priority=command.priority,
                    triggered_by=command.triggered_by
                )
            )
            
            # 11. Commit transaction
            await self._unit_of_work.commit()
            
            # 12. Return response
            return EmergencyContactNotificationResponse(
                user_id=user.id,
                notification_id=notification_history.id,
                reason=command.reason,
                priority=command.priority,
                contacts_targeted=len(eligible_contacts),
                notifications_sent=len(delivery_results["successful"]),
                delivery_failures=len(delivery_results["failed"]),
                successful_deliveries=delivery_results["successful"],
                failed_deliveries=delivery_results["failed"],
                estimated_delivery_time=f"{command.delivery_timeout_minutes} minutes",
                retry_scheduled=command.retry_failed and len(delivery_results["failed"]) > 0,
                message="Emergency contacts notified successfully"
            )
    
    async def _get_eligible_contacts(
        self,
        user: User,
        command: NotifyEmergencyContactsCommand
    ) -> list[EmergencyContact]:
        """Get emergency contacts eligible for notification."""
        # Get all active contacts
        contacts = await self._emergency_contact_repository.find_active_by_user(user.id)
        
        # Apply filters
        eligible_contacts = []
        
        for contact in contacts:
            # Filter by specific contact IDs if provided
            if command.contact_ids and contact.id not in command.contact_ids:
                continue
            
            # Filter by contact type
            if contact.contact_type not in command.contact_types:
                continue
            
            # Filter by verification status
            if command.verified_only and not contact.is_verified:
                continue
            
            # Filter by primary status
            if command.primary_only and not contact.is_primary:
                continue
            
            # Check contact status
            if contact.status != ContactStatus.VERIFIED:
                continue
            
            eligible_contacts.append(contact)
        
        # Sort by priority (lower number = higher priority)
        eligible_contacts.sort(key=lambda x: (not x.is_primary, x.priority, x.added_at))
        
        return eligible_contacts
    
    async def _check_notification_rate_limits(
        self,
        user_id: UUID,
        reason: NotificationReason
    ) -> None:
        """Check if notification rate limits are exceeded."""
        # Check notifications in last hour
        recent_notifications = await self._notification_history_repository.count_by_user_and_timeframe(
            user_id,
            hours=1
        )
        
        # Check notifications for same reason in last 24 hours
        reason_notifications = await self._notification_history_repository.count_by_user_reason_and_timeframe(
            user_id,
            reason.value,
            hours=24
        )
        
        # Apply rate limits based on reason
        limits = {
            NotificationReason.SECURITY_INCIDENT: {"hourly": 10, "daily_same": 5},
            NotificationReason.SUSPICIOUS_LOGIN: {"hourly": 15, "daily_same": 10},
            NotificationReason.ACCOUNT_LOCKED: {"hourly": 5, "daily_same": 3},
            NotificationReason.PASSWORD_CHANGED: {"hourly": 3, "daily_same": 2},
            NotificationReason.DATA_BREACH: {"hourly": 2, "daily_same": 1},
        }
        
        default_limits = {"hourly": 20, "daily_same": 10}
        reason_limits = limits.get(reason, default_limits)
        
        if recent_notifications >= reason_limits["hourly"]:
            raise RateLimitExceededError(
                f"Hourly notification limit exceeded ({reason_limits['hourly']})"
            )
        
        if reason_notifications >= reason_limits["daily_same"]:
            raise RateLimitExceededError(
                f"Daily limit for {reason.value} notifications exceeded ({reason_limits['daily_same']})"
            )
    
    async def _prepare_notification_content(
        self,
        user: User,
        command: NotifyEmergencyContactsCommand
    ) -> dict[str, Any]:
        """Prepare notification content based on reason and template."""
        # Get base template
        template_name = command.template_override or self._get_default_template(command.reason)
        
        # Prepare template variables
        base_variables = {
            "user_name": f"{user.first_name} {user.last_name}",
            "user_username": user.username,
            "user_email": user.email,
            "incident_time": datetime.now(UTC).isoformat(),
            "priority": command.priority.value,
            "reason": command.reason.value,
            "support_link": "https://app.example.com/support",
            "security_center_link": "https://app.example.com/security"
        }
        
        # Add user data if requested
        if command.include_user_data:
            base_variables.update({
                "user_id": str(user.id),
                "account_created": user.created_at.isoformat(),
                "last_login": user.last_login_at.isoformat() if user.last_login_at else None,
                "account_status": user.status
            })
        
        # Add incident-specific data
        if command.incident_data:
            base_variables.update(command.incident_data)
        
        # Merge with custom variables
        base_variables.update(command.template_variables)
        
        # Add custom message if provided
        if command.custom_message:
            base_variables["custom_message"] = command.custom_message
        
        # Get localized content
        content = await self._notification_template_service.render_template(
            template_name,
            base_variables,
            user.preferred_language or "en"
        )
        
        return {
            "template_name": template_name,
            "variables": base_variables,
            "subject": content["subject"],
            "email_body": content["email_body"],
            "sms_body": content["sms_body"],
            "priority": command.priority
        }
    
    def _get_default_template(self, reason: NotificationReason) -> str:
        """Get default template name for notification reason."""
        template_mapping = {
            NotificationReason.SECURITY_INCIDENT: "emergency_security_incident",
            NotificationReason.ACCOUNT_LOCKED: "emergency_account_locked",
            NotificationReason.SUSPICIOUS_LOGIN: "emergency_suspicious_login",
            NotificationReason.PASSWORD_CHANGED: "emergency_password_changed",
            NotificationReason.MFA_DISABLED: "emergency_mfa_disabled",
            NotificationReason.ACCOUNT_RECOVERY: "emergency_account_recovery",
            NotificationReason.DATA_BREACH: "emergency_data_breach",
            NotificationReason.EMERGENCY_ACCESS: "emergency_access_granted",
            NotificationReason.ACCOUNT_DELETION: "emergency_account_deletion",
            NotificationReason.PRIVACY_SETTINGS_CHANGED: "emergency_privacy_changed",
            NotificationReason.CUSTOM: "emergency_custom_notification"
        }
        
        return template_mapping.get(reason, "emergency_general_notification")
    
    async def _send_notifications(
        self,
        user: User,
        contacts: list[EmergencyContact],
        content: dict[str, Any],
        command: NotifyEmergencyContactsCommand
    ) -> dict[str, list]:
        """Send notifications to emergency contacts."""
        results = {
            "successful": [],
            "failed": [],
            "partial": []
        }
        
        for contact in contacts:
            delivery_result = {
                "contact_id": contact.id,
                "contact_type": contact.contact_type.value,
                "contact_value": self._mask_contact_value(contact.contact_value),
                "contact_name": contact.contact_name,
                "attempts": [],
                "final_status": "pending"
            }
            
            try:
                if contact.contact_type == ContactType.EMAIL:
                    success = await self._send_email_notification(
                        contact,
                        content,
                        delivery_result
                    )
                
                elif contact.contact_type in [ContactType.PHONE, ContactType.SMS]:
                    success = await self._send_sms_notification(
                        contact,
                        content,
                        delivery_result
                    )
                
                else:
                    delivery_result["final_status"] = "unsupported_type"
                    success = False
                
                if success:
                    delivery_result["final_status"] = "delivered"
                    results["successful"].append(delivery_result)
                else:
                    delivery_result["final_status"] = "failed"
                    results["failed"].append(delivery_result)
                    
            except Exception as e:
                delivery_result["final_status"] = "error"
                delivery_result["error"] = str(e)
                results["failed"].append(delivery_result)
        
        return results
    
    async def _send_email_notification(
        self,
        contact: EmergencyContact,
        content: dict[str, Any],
        delivery_result: dict[str, Any]
    ) -> bool:
        """Send email notification to emergency contact."""
        try:
            await self._email_service.send_email(
                EmailContext(
                    recipient=contact.contact_value,
                    template=content["template_name"],
                    subject=content["subject"],
                    variables=content["variables"],
                    priority=content["priority"].value,
                    tracking_id=f"emergency_{contact.id}_{int(datetime.now(UTC).timestamp())}"
                )
            )
        except Exception as e:
            delivery_result["attempts"].append({
                "method": "email",
                "timestamp": datetime.now(UTC).isoformat(),
                "status": "failed",
                "error": str(e)
            })
            return False
        else:
            delivery_result["attempts"].append({
                "method": "email",
                "timestamp": datetime.now(UTC).isoformat(),
                "status": "sent"
            })
            return True
    
    async def _send_sms_notification(
        self,
        contact: EmergencyContact,
        content: dict[str, Any],
        delivery_result: dict[str, Any]
    ) -> bool:
        """Send SMS notification to emergency contact."""
        try:
            await self._sms_service.send_sms(
                SMSContext(
                    recipient=contact.contact_value,
                    template=content["template_name"],
                    variables=content["variables"],
                    priority=content["priority"].value,
                    tracking_id=f"emergency_{contact.id}_{int(datetime.now(UTC).timestamp())}"
                )
            )
        except Exception as e:
            delivery_result["attempts"].append({
                "method": "sms",
                "timestamp": datetime.now(UTC).isoformat(),
                "status": "failed",
                "error": str(e)
            })
            return False
        else:
            delivery_result["attempts"].append({
                "method": "sms",
                "timestamp": datetime.now(UTC).isoformat(),
                "status": "sent"
            })
            return True
    
    async def _record_notification_history(
        self,
        user: User,
        contacts: list[EmergencyContact],
        delivery_results: dict[str, list],
        command: NotifyEmergencyContactsCommand
    ) -> Any:
        """Record notification in history for tracking and analytics."""
        history_record = {
            "id": UUID(),
            "user_id": user.id,
            "reason": command.reason.value,
            "priority": command.priority.value,
            "triggered_by": command.triggered_by,
            "contacts_targeted": len(contacts),
            "successful_deliveries": len(delivery_results["successful"]),
            "failed_deliveries": len(delivery_results["failed"]),
            "delivery_details": delivery_results,
            "template_used": command.template_override or self._get_default_template(command.reason),
            "incident_data": command.incident_data,
            "created_at": datetime.now(UTC),
            "metadata": command.metadata
        }
        
        return await self._notification_history_repository.create(history_record)
    
    async def _handle_critical_notification(
        self,
        user: User,
        command: NotifyEmergencyContactsCommand,
        delivery_results: dict[str, list]
    ) -> None:
        """Handle critical priority notifications with additional measures."""
        # Notify security team
        await self._notification_service.notify_security_team(
            "Critical Emergency Contact Notification",
            {
                "user": user.username,
                "reason": command.reason.value,
                "successful_deliveries": len(delivery_results["successful"]),
                "failed_deliveries": len(delivery_results["failed"]),
                "triggered_by": str(command.triggered_by) if command.triggered_by else "system"
            }
        )
        
        # Log high-priority incident
        await self._audit_service.log_security_incident(
            SecurityIncidentContext(
                incident_type=SecurityEventType.CRITICAL_EMERGENCY_NOTIFICATION,
                severity=RiskLevel.CRITICAL,
                user_id=user.id,
                details={
                    "reason": command.reason.value,
                    "contacts_notified": len(delivery_results["successful"]),
                    "delivery_failures": len(delivery_results["failed"]),
                    "incident_data": command.incident_data
                },
                indicators=["critical_emergency_notification"],
                recommended_actions=[
                    "Verify notification delivery",
                    "Contact user through alternative channels if needed",
                    "Monitor for user response"
                ]
            )
        )
    
    async def _log_security_notification(
        self,
        user: User,
        command: NotifyEmergencyContactsCommand,
        delivery_results: dict[str, list]
    ) -> None:
        """Log security-related emergency notifications."""
        await self._audit_service.log_security_event(
            AuditContext(
                action=AuditAction.EMERGENCY_CONTACTS_NOTIFIED,
                actor_id=command.triggered_by or user.id,
                target_user_id=user.id,
                resource_type="emergency_contacts",
                resource_id=None,
                details={
                    "reason": command.reason.value,
                    "priority": command.priority.value,
                    "contacts_notified": len(delivery_results["successful"]),
                    "delivery_failures": len(delivery_results["failed"]),
                    "incident_data": command.incident_data,
                    "automated_notification": command.triggered_by is None
                },
                risk_level="high" if command.priority == NotificationPriority.CRITICAL else "medium"
            )
        )
    
    async def _schedule_retry_attempts(
        self,
        failed_deliveries: list[dict[str, Any]],
        content: dict[str, Any],
        command: NotifyEmergencyContactsCommand
    ) -> None:
        """Schedule retry attempts for failed deliveries."""
        # This would typically integrate with a job queue system
        # For now, we'll just log the retry scheduling
        for failed_delivery in failed_deliveries:
            await self._audit_service.log_action(
                AuditContext(
                    action=AuditAction.NOTIFICATION_RETRY_SCHEDULED,
                    actor_id=command.triggered_by,
                    target_user_id=command.user_id,
                    resource_type="emergency_contact",
                    resource_id=UUID(failed_delivery["contact_id"]),
                    details={
                        "original_reason": command.reason.value,
                        "retry_count": 0,
                        "max_retries": command.max_retries,
                        "failure_reason": failed_delivery.get("error", "unknown")
                    },
                    risk_level="low"
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