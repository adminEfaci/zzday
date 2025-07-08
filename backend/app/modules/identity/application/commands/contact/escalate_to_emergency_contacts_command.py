"""
Escalate to emergency contacts command implementation.

Handles escalating security incidents and critical issues to emergency contacts
when immediate intervention is required.
"""

from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.domain.interfaces.services.communication.notification_service import IEmailService
from app.modules.identity.domain.interfaces.repositories.emergency_contact_repository import IEmergencyContactRepository
from app.modules.identity.domain.interfaces.services.communication.notification_service import INotificationService
from app.modules.identity.domain.interfaces.services.communication.notification_service import ISMSService
from app.modules.identity.domain.interfaces.repositories.user_repository import IUserRepository
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    require_mfa,
    require_permission,
    validate_request,
)
from app.modules.identity.application.dtos.internal import (
    AuditContext,
    CallContext,
    EmailContext,
    SecurityIncidentContext,
    SMSContext,
)
from app.modules.identity.application.dtos.request import (
    EscalateToEmergencyContactsRequest,
)
from app.modules.identity.application.dtos.response import (
    EmergencyContactEscalationResponse,
)
from app.modules.identity.domain.entities import EmergencyContact, User
from app.modules.identity.domain.enums import (
    AuditAction,
    ContactType,
    EscalationLevel,
    EscalationStatus,
    IncidentSeverity,
    NotificationPriority,
    RiskLevel,
    SecurityEventType,
)
from app.modules.identity.domain.events import (
    EmergencyContactsEscalated,
)
from app.modules.identity.domain.exceptions import (
    EscalationLimitExceededError,
    IncidentNotFoundError,
    InvalidEscalationError,
    NoEmergencyContactsError,
    UserNotFoundError,
)
from app.modules.identity.domain.services import (
    EscalationService,
    SecurityService,
    ValidationService,
)


class EscalationTrigger(Enum):
    """Triggers for emergency contact escalation."""
    SECURITY_BREACH = "security_breach"
    ACCOUNT_COMPROMISE = "account_compromise"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    FAILED_RECOVERY = "failed_recovery"
    UNRESPONSIVE_USER = "unresponsive_user"
    CRITICAL_SYSTEM_ALERT = "critical_system_alert"
    MANUAL_ESCALATION = "manual_escalation"
    AUTOMATED_THREAT_DETECTION = "automated_threat_detection"
    COMPLIANCE_VIOLATION = "compliance_violation"
    DATA_EXFILTRATION = "data_exfiltration"


class EscalateToEmergencyContactsCommand(Command[EmergencyContactEscalationResponse]):
    """Command to escalate issues to emergency contacts."""
    
    def __init__(
        self,
        user_id: UUID,
        incident_id: UUID | None = None,
        escalation_trigger: EscalationTrigger = EscalationTrigger.MANUAL_ESCALATION,
        escalation_level: EscalationLevel = EscalationLevel.HIGH,
        severity: IncidentSeverity = IncidentSeverity.MEDIUM,
        escalated_by: UUID | None = None,
        escalation_reason: str = "",
        immediate_action_required: bool = False,
        include_call_escalation: bool = False,
        contact_all: bool = False,
        max_escalation_attempts: int = 3,
        escalation_timeout_hours: int = 24,
        incident_summary: str | None = None,
        recommended_actions: list[str] | None = None,
        evidence_links: list[str] | None = None,
        previous_escalation_id: UUID | None = None,
        custom_instructions: str | None = None,
        bypass_normal_channels: bool = False,
        legal_hold_required: bool = False,
        compliance_requirements: list[str] | None = None,
        metadata: dict[str, Any] | None = None
    ):
        self.user_id = user_id
        self.incident_id = incident_id
        self.escalation_trigger = escalation_trigger
        self.escalation_level = escalation_level
        self.severity = severity
        self.escalated_by = escalated_by
        self.escalation_reason = escalation_reason.strip()
        self.immediate_action_required = immediate_action_required
        self.include_call_escalation = include_call_escalation
        self.contact_all = contact_all
        self.max_escalation_attempts = max_escalation_attempts
        self.escalation_timeout_hours = escalation_timeout_hours
        self.incident_summary = incident_summary
        self.recommended_actions = recommended_actions or []
        self.evidence_links = evidence_links or []
        self.previous_escalation_id = previous_escalation_id
        self.custom_instructions = custom_instructions
        self.bypass_normal_channels = bypass_normal_channels
        self.legal_hold_required = legal_hold_required
        self.compliance_requirements = compliance_requirements or []
        self.metadata = metadata or {}


class EscalateToEmergencyContactsCommandHandler(CommandHandler[EscalateToEmergencyContactsCommand, EmergencyContactEscalationResponse]):
    """Handler for escalating to emergency contacts."""
    
    def __init__(
        self,
        user_repository: IUserRepository,
        emergency_contact_repository: IEmergencyContactRepository,
        escalation_repository: IEscalationRepository,
        incident_repository: IIncidentRepository,
        validation_service: ValidationService,
        security_service: SecurityService,
        escalation_service: EscalationService,
        notification_service: INotificationService,
        audit_service: IAuditService,
        email_service: IEmailService,
        sms_service: ISMSService,
        call_service: ICallService,
        event_bus: EventBus,
        unit_of_work: UnitOfWork
    ):
        self._user_repository = user_repository
        self._emergency_contact_repository = emergency_contact_repository
        self._escalation_repository = escalation_repository
        self._incident_repository = incident_repository
        self._validation_service = validation_service
        self._security_service = security_service
        self._escalation_service = escalation_service
        self._notification_service = notification_service
        self._audit_service = audit_service
        self._email_service = email_service
        self._sms_service = sms_service
        self._call_service = call_service
        self._event_bus = event_bus
        self._unit_of_work = unit_of_work
    
    @audit_action(
        action=AuditAction.EMERGENCY_ESCALATION_INITIATED,
        resource_type="user",
        include_request=True,
        include_response=True,
        include_reason=True
    )
    @validate_request(EscalateToEmergencyContactsRequest)
    @rate_limit(
        max_requests=10,
        window_seconds=3600,
        strategy='user'
    )
    @require_permission("emergency_contacts.escalate")
    @require_mfa(condition="critical_escalation")
    async def handle(self, command: EscalateToEmergencyContactsCommand) -> EmergencyContactEscalationResponse:
        """
        Escalate to emergency contacts with comprehensive incident management.
        
        Process:
        1. Load user and validate escalation
        2. Check existing escalations
        3. Prepare escalation context
        4. Determine escalation strategy
        5. Execute multi-channel escalation
        6. Track response and follow-up
        7. Log and audit escalation
        8. Monitor escalation progress
        
        Returns:
            EmergencyContactEscalationResponse with escalation details
            
        Raises:
            UserNotFoundError: If user not found
            EscalationLimitExceededError: If too many escalations
            NoEmergencyContactsError: If no emergency contacts
            InvalidEscalationError: If escalation invalid
        """
        async with self._unit_of_work:
            # 1. Load user
            user = await self._user_repository.find_by_id(command.user_id)
            if not user:
                raise UserNotFoundError(f"User {command.user_id} not found")
            
            # 2. Load incident if provided
            incident = None
            if command.incident_id:
                incident = await self._incident_repository.find_by_id(command.incident_id)
                if not incident:
                    raise IncidentNotFoundError(f"Incident {command.incident_id} not found")
            
            # 3. Validate escalation request
            await self._validate_escalation_request(user, incident, command)
            
            # 4. Check for existing active escalations
            await self._check_existing_escalations(user.id, command)
            
            # 5. Get emergency contacts for escalation
            escalation_contacts = await self._get_escalation_contacts(user, command)
            
            if not escalation_contacts:
                raise NoEmergencyContactsError(
                    "No emergency contacts available for escalation"
                )
            
            # 6. Create escalation record
            escalation = await self._create_escalation_record(
                user,
                incident,
                escalation_contacts,
                command
            )
            
            # 7. Prepare escalation content
            escalation_content = await self._prepare_escalation_content(
                user,
                incident,
                escalation,
                command
            )
            
            # 8. Execute escalation strategy
            escalation_results = await self._execute_escalation_strategy(
                user,
                escalation_contacts,
                escalation_content,
                command
            )
            
            # 9. Update escalation with results
            escalation.delivery_results = escalation_results
            escalation.contacts_reached = len(escalation_results["successful"])
            escalation.delivery_failures = len(escalation_results["failed"])
            await self._escalation_repository.update(escalation)
            
            # 10. Schedule follow-up and monitoring
            await self._schedule_escalation_monitoring(escalation, command)
            
            # 11. Notify security team and stakeholders
            await self._notify_escalation_stakeholders(
                user,
                escalation,
                escalation_results,
                command
            )
            
            # 12. Log high-severity escalations
            if command.severity in [IncidentSeverity.CRITICAL, IncidentSeverity.HIGH]:
                await self._log_high_severity_escalation(
                    user,
                    escalation,
                    command
                )
            
            # 13. Handle legal hold if required
            if command.legal_hold_required:
                await self._initiate_legal_hold_procedures(
                    user,
                    escalation,
                    command
                )
            
            # 14. Publish domain event
            await self._event_bus.publish(
                EmergencyContactsEscalated(
                    aggregate_id=user.id,
                    escalation_id=escalation.id,
                    incident_id=command.incident_id,
                    trigger=command.escalation_trigger.value,
                    level=command.escalation_level,
                    severity=command.severity,
                    contacts_notified=len(escalation_results["successful"]),
                    escalated_by=command.escalated_by
                )
            )
            
            # 15. Commit transaction
            await self._unit_of_work.commit()
            
            # 16. Return response
            return EmergencyContactEscalationResponse(
                escalation_id=escalation.id,
                user_id=user.id,
                incident_id=command.incident_id,
                escalation_level=command.escalation_level,
                severity=command.severity,
                trigger=command.escalation_trigger,
                contacts_targeted=len(escalation_contacts),
                contacts_reached=len(escalation_results["successful"]),
                delivery_failures=len(escalation_results["failed"]),
                escalation_methods=escalation_results["methods_used"],
                estimated_response_time=f"{command.escalation_timeout_hours} hours",
                follow_up_scheduled=True,
                security_team_notified=True,
                legal_hold_initiated=command.legal_hold_required,
                next_escalation_at=escalation.next_escalation_at,
                message="Emergency escalation initiated successfully"
            )
    
    async def _validate_escalation_request(
        self,
        user: User,
        incident: Any | None,
        command: EscalateToEmergencyContactsCommand
    ) -> None:
        """Validate the escalation request."""
        # Check if escalation reason is provided
        if not command.escalation_reason and not command.incident_summary:
            raise InvalidEscalationError("Escalation reason or incident summary required")
        
        # Validate escalation level vs severity
        if (command.escalation_level == EscalationLevel.CRITICAL and 
            command.severity == IncidentSeverity.LOW):
            raise InvalidEscalationError("Critical escalation level requires higher severity")
        
        # Check user account status
        if user.status in ["DELETED", "BANNED"]:
            raise InvalidEscalationError(
                f"Cannot escalate for user with status: {user.status}"
            )
        
        # Validate escalator permissions for high-level escalations
        if (command.escalation_level == EscalationLevel.CRITICAL and 
            command.escalated_by):
            can_escalate = await self._security_service.can_perform_critical_escalation(
                command.escalated_by
            )
            if not can_escalate:
                raise InvalidEscalationError(
                    "Insufficient permissions for critical escalation"
                )
    
    async def _check_existing_escalations(
        self,
        user_id: UUID,
        command: EscalateToEmergencyContactsCommand
    ) -> None:
        """Check for existing active escalations."""
        # Get active escalations for user
        active_escalations = await self._escalation_repository.find_active_by_user(user_id)
        
        # Check escalation limits
        if len(active_escalations) >= 3:  # Max 3 concurrent escalations
            raise EscalationLimitExceededError(
                "Maximum number of active escalations reached"
            )
        
        # Check for duplicate escalations in short timeframe
        recent_escalations = await self._escalation_repository.find_by_user_and_timeframe(
            user_id,
            hours=2
        )
        
        similar_escalations = [
            e for e in recent_escalations
            if (e.trigger == command.escalation_trigger.value and
                e.level == command.escalation_level and
                e.status in [EscalationStatus.ACTIVE, EscalationStatus.PENDING])
        ]
        
        if similar_escalations and not command.bypass_normal_channels:
            raise EscalationLimitExceededError(
                f"Similar escalation already active: {similar_escalations[0].id}"
            )
    
    async def _get_escalation_contacts(
        self,
        user: User,
        command: EscalateToEmergencyContactsCommand
    ) -> list[EmergencyContact]:
        """Get emergency contacts for escalation based on strategy."""
        # Get all verified emergency contacts
        contacts = await self._emergency_contact_repository.find_verified_by_user(user.id)
        
        if not contacts:
            return []
        
        escalation_contacts = []
        
        if command.contact_all:
            # Contact all available emergency contacts
            escalation_contacts = contacts
        
        elif command.escalation_level == EscalationLevel.CRITICAL:
            # For critical escalations, contact all primary contacts
            primary_contacts = [c for c in contacts if c.is_primary]
            if primary_contacts:
                escalation_contacts = primary_contacts
            else:
                # Fallback to top 2 contacts by priority
                sorted_contacts = sorted(contacts, key=lambda x: x.priority)
                escalation_contacts = sorted_contacts[:2]
        
        elif command.escalation_level == EscalationLevel.HIGH:
            # For high escalations, contact primary email and SMS
            email_primary = next((c for c in contacts if c.is_primary and c.contact_type == ContactType.EMAIL), None)
            sms_primary = next((c for c in contacts if c.is_primary and c.contact_type == ContactType.SMS), None)
            
            if email_primary:
                escalation_contacts.append(email_primary)
            if sms_primary:
                escalation_contacts.append(sms_primary)
            
            # If no primary contacts, use highest priority ones
            if not escalation_contacts:
                sorted_contacts = sorted(contacts, key=lambda x: x.priority)
                escalation_contacts = sorted_contacts[:1]
        
        else:
            # For medium/low escalations, contact single primary contact
            primary_contact = next((c for c in contacts if c.is_primary), None)
            if primary_contact:
                escalation_contacts = [primary_contact]
            else:
                # Use highest priority contact
                sorted_contacts = sorted(contacts, key=lambda x: x.priority)
                escalation_contacts = sorted_contacts[:1]
        
        return escalation_contacts
    
    async def _create_escalation_record(
        self,
        user: User,
        incident: Any | None,
        contacts: list[EmergencyContact],
        command: EscalateToEmergencyContactsCommand
    ) -> Any:
        """Create escalation record for tracking."""
        escalation_data = {
            "id": UUID(),
            "user_id": user.id,
            "incident_id": command.incident_id,
            "trigger": command.escalation_trigger.value,
            "level": command.escalation_level,
            "severity": command.severity,
            "escalated_by": command.escalated_by,
            "reason": command.escalation_reason,
            "status": EscalationStatus.ACTIVE,
            "contact_ids": [c.id for c in contacts],
            "max_attempts": command.max_escalation_attempts,
            "timeout_hours": command.escalation_timeout_hours,
            "immediate_action_required": command.immediate_action_required,
            "include_call_escalation": command.include_call_escalation,
            "custom_instructions": command.custom_instructions,
            "legal_hold_required": command.legal_hold_required,
            "compliance_requirements": command.compliance_requirements,
            "created_at": datetime.now(UTC),
            "next_escalation_at": datetime.now(UTC) + timedelta(hours=command.escalation_timeout_hours),
            "metadata": command.metadata
        }
        
        return await self._escalation_repository.create(escalation_data)
    
    async def _prepare_escalation_content(
        self,
        user: User,
        incident: Any | None,
        escalation: Any,
        command: EscalateToEmergencyContactsCommand
    ) -> dict[str, Any]:
        """Prepare escalation notification content."""
        # Base variables
        variables = {
            "user_name": f"{user.first_name} {user.last_name}",
            "user_username": user.username,
            "user_email": user.email,
            "escalation_id": str(escalation.id),
            "escalation_level": command.escalation_level.value,
            "severity": command.severity.value,
            "trigger": command.escalation_trigger.value,
            "escalation_reason": command.escalation_reason,
            "incident_time": datetime.now(UTC).isoformat(),
            "immediate_action": command.immediate_action_required,
            "emergency_portal_link": f"https://app.example.com/emergency/{escalation.id}",
            "support_link": "https://app.example.com/support",
            "security_hotline": "+1-555-SECURITY"
        }
        
        # Add incident data if available
        if incident:
            variables.update({
                "incident_id": str(incident.id),
                "incident_type": incident.type,
                "incident_summary": incident.summary,
                "incident_detected_at": incident.detected_at.isoformat()
            })
        
        # Add custom incident summary
        if command.incident_summary:
            variables["incident_summary"] = command.incident_summary
        
        # Add recommended actions
        if command.recommended_actions:
            variables["recommended_actions"] = "\n".join(
                f"• {action}" for action in command.recommended_actions
            )
        
        # Add evidence links
        if command.evidence_links:
            variables["evidence_links"] = "\n".join(command.evidence_links)
        
        # Add custom instructions
        if command.custom_instructions:
            variables["custom_instructions"] = command.custom_instructions
        
        # Get template based on escalation level and trigger
        template_name = self._get_escalation_template(
            command.escalation_trigger,
            command.escalation_level
        )
        
        return {
            "template_name": template_name,
            "variables": variables,
            "priority": NotificationPriority.CRITICAL if command.escalation_level == EscalationLevel.CRITICAL else NotificationPriority.HIGH
        }
    
    def _get_escalation_template(
        self,
        trigger: EscalationTrigger,
        level: EscalationLevel
    ) -> str:
        """Get appropriate template for escalation."""
        template_mapping = {
            (EscalationTrigger.SECURITY_BREACH, EscalationLevel.CRITICAL): "escalation_security_breach_critical",
            (EscalationTrigger.ACCOUNT_COMPROMISE, EscalationLevel.CRITICAL): "escalation_account_compromise_critical",
            (EscalationTrigger.DATA_EXFILTRATION, EscalationLevel.CRITICAL): "escalation_data_exfiltration_critical",
            (EscalationTrigger.SUSPICIOUS_ACTIVITY, EscalationLevel.HIGH): "escalation_suspicious_activity_high",
            (EscalationTrigger.FAILED_RECOVERY, EscalationLevel.HIGH): "escalation_failed_recovery_high",
            (EscalationTrigger.UNRESPONSIVE_USER, EscalationLevel.MEDIUM): "escalation_unresponsive_user_medium"
        }
        
        specific_template = template_mapping.get((trigger, level))
        if specific_template:
            return specific_template
        
        # Fallback to general escalation template
        return f"escalation_general_{level.value}"
    
    async def _execute_escalation_strategy(
        self,
        user: User,
        contacts: list[EmergencyContact],
        content: dict[str, Any],
        command: EscalateToEmergencyContactsCommand
    ) -> dict[str, Any]:
        """Execute multi-channel escalation strategy."""
        results = {
            "successful": [],
            "failed": [],
            "methods_used": [],
            "escalation_timeline": []
        }
        
        for contact in contacts:
            contact_result = {
                "contact_id": contact.id,
                "contact_type": contact.contact_type.value,
                "contact_value": self._mask_contact_value(contact.contact_value),
                "contact_name": contact.contact_name,
                "is_primary": contact.is_primary,
                "attempts": [],
                "final_status": "pending"
            }
            
            # Email escalation (always first if available)
            if contact.contact_type == ContactType.EMAIL:
                await self._send_escalation_email(
                    contact,
                    content,
                    contact_result,
                    command
                )
                results["methods_used"].append("email")
            
            # SMS escalation (for immediate alerts)
            if (contact.contact_type in [ContactType.SMS, ContactType.PHONE] or
                command.immediate_action_required):
                await self._send_escalation_sms(
                    contact,
                    content,
                    contact_result,
                    command
                )
                results["methods_used"].append("sms")
            
            # Call escalation (for critical incidents)
            if (command.include_call_escalation and
                contact.contact_type == ContactType.PHONE and
                command.escalation_level == EscalationLevel.CRITICAL):
                await self._initiate_escalation_call(
                    contact,
                    content,
                    contact_result,
                    command
                )
                results["methods_used"].append("call")
            
            # Determine overall success for this contact
            if any(attempt["status"] == "delivered" for attempt in contact_result["attempts"]):
                contact_result["final_status"] = "delivered"
                results["successful"].append(contact_result)
            else:
                contact_result["final_status"] = "failed"
                results["failed"].append(contact_result)
            
            # Add to timeline
            results["escalation_timeline"].append({
                "timestamp": datetime.now(UTC).isoformat(),
                "contact": contact.contact_name,
                "methods": [a["method"] for a in contact_result["attempts"]],
                "status": contact_result["final_status"]
            })
        
        # Remove duplicates from methods_used
        results["methods_used"] = list(set(results["methods_used"]))
        
        return results
    
    async def _send_escalation_email(
        self,
        contact: EmergencyContact,
        content: dict[str, Any],
        contact_result: dict[str, Any],
        command: EscalateToEmergencyContactsCommand
    ) -> bool:
        """Send escalation email."""
        try:
            await self._email_service.send_email(
                EmailContext(
                    recipient=contact.contact_value,
                    template=content["template_name"],
                    subject="URGENT: Security Escalation - Action Required",
                    variables=content["variables"],
                    priority=content["priority"].value,
                    tracking_id=f"escalation_{contact.id}_{int(datetime.now(UTC).timestamp())}",
                    delivery_receipt_required=True
                )
            )
        except Exception as e:
            contact_result["attempts"].append({
                "method": "email",
                "timestamp": datetime.now(UTC).isoformat(),
                "status": "failed",
                "error": str(e)
            })
            return False
        else:
            contact_result["attempts"].append({
                "method": "email",
                "timestamp": datetime.now(UTC).isoformat(),
                "status": "delivered"
            })
            return True
    
    async def _send_escalation_sms(
        self,
        contact: EmergencyContact,
        content: dict[str, Any],
        contact_result: dict[str, Any],
        command: EscalateToEmergencyContactsCommand
    ) -> bool:
        """Send escalation SMS."""
        try:
            # Use shorter template for SMS
            sms_variables = content["variables"].copy()
            sms_variables["message_short"] = True
            
            await self._sms_service.send_sms(
                SMSContext(
                    recipient=contact.contact_value,
                    template=f"{content['template_name']}_sms",
                    variables=sms_variables,
                    priority=content["priority"].value,
                    tracking_id=f"escalation_sms_{contact.id}_{int(datetime.now(UTC).timestamp())}"
                )
            )
        except Exception as e:
            contact_result["attempts"].append({
                "method": "sms",
                "timestamp": datetime.now(UTC).isoformat(),
                "status": "failed",
                "error": str(e)
            })
            return False
        else:
            contact_result["attempts"].append({
                "method": "sms",
                "timestamp": datetime.now(UTC).isoformat(),
                "status": "delivered"
            })
            return True
    
    async def _initiate_escalation_call(
        self,
        contact: EmergencyContact,
        content: dict[str, Any],
        contact_result: dict[str, Any],
        command: EscalateToEmergencyContactsCommand
    ) -> bool:
        """Initiate escalation phone call."""
        try:
            call_script = self._generate_call_script(content["variables"], command)
            
            await self._call_service.initiate_call(
                CallContext(
                    recipient=contact.contact_value,
                    script=call_script,
                    priority="emergency",
                    max_attempts=3,
                    callback_required=True,
                    escalation_id=str(content["variables"]["escalation_id"]),
                    tracking_id=f"escalation_call_{contact.id}_{int(datetime.now(UTC).timestamp())}"
                )
            )
        except Exception as e:
            contact_result["attempts"].append({
                "method": "call",
                "timestamp": datetime.now(UTC).isoformat(),
                "status": "failed",
                "error": str(e)
            })
            return False
        else:
            contact_result["attempts"].append({
                "method": "call",
                "timestamp": datetime.now(UTC).isoformat(),
                "status": "initiated"
            })
            return True
    
    def _generate_call_script(
        self,
        variables: dict[str, Any],
        command: EscalateToEmergencyContactsCommand
    ) -> str:
        """Generate automated call script for escalation."""
        script = f"""
        This is an urgent security notification for {variables['user_name']}.
        
        We have detected a {variables['severity']} security incident 
        involving the account for {variables['user_username']}.
        
        Escalation Level: {variables['escalation_level']}
        Incident Type: {variables['trigger']}
        
        {variables['escalation_reason']}
        
        """
        
        if command.immediate_action_required:
            script += """
            IMMEDIATE ACTION IS REQUIRED.
            """
        
        script += f"""
        Please visit {variables['emergency_portal_link']} or call our security hotline 
        at {variables['security_hotline']} immediately.
        
        Press 1 to acknowledge this escalation.
        Press 2 to speak with a security representative.
        Press 3 to hear this message again.
        """
        
        return script.strip()
    
    async def _schedule_escalation_monitoring(
        self,
        escalation: Any,
        command: EscalateToEmergencyContactsCommand
    ) -> None:
        """Schedule monitoring and follow-up for escalation."""
        # This would integrate with a job scheduling system
        monitoring_schedule = {
            "escalation_id": escalation.id,
            "follow_up_intervals": [30, 60, 120, 240],  # minutes
            "timeout_hours": command.escalation_timeout_hours,
            "auto_close_after_hours": 48,
            "escalate_further_if_no_response": True
        }
        
        # Log the scheduling (in real implementation, this would create actual scheduled jobs)
        await self._audit_service.log_action(
            AuditContext(
                action=AuditAction.ESCALATION_MONITORING_SCHEDULED,
                actor_id=command.escalated_by,
                target_user_id=command.user_id,
                resource_type="escalation",
                resource_id=escalation.id,
                details=monitoring_schedule,
                risk_level="medium"
            )
        )
    
    async def _notify_escalation_stakeholders(
        self,
        user: User,
        escalation: Any,
        results: dict[str, Any],
        command: EscalateToEmergencyContactsCommand
    ) -> None:
        """Notify relevant stakeholders about the escalation."""
        # Notify security team
        await self._notification_service.notify_security_team(
            "Emergency Contact Escalation Initiated",
            {
                "escalation_id": str(escalation.id),
                "user": user.username,
                "trigger": command.escalation_trigger.value,
                "level": command.escalation_level.value,
                "severity": command.severity.value,
                "contacts_reached": len(results["successful"]),
                "methods_used": results["methods_used"],
                "immediate_action_required": command.immediate_action_required
            }
        )
        
        # Notify compliance team if required
        if command.compliance_requirements:
            await self._notification_service.notify_compliance_team(
                "Compliance-Related Escalation",
                {
                    "escalation_id": str(escalation.id),
                    "user": user.username,
                    "compliance_requirements": command.compliance_requirements,
                    "legal_hold_required": command.legal_hold_required
                }
            )
        
        # Notify management for critical escalations
        if command.escalation_level == EscalationLevel.CRITICAL:
            await self._notification_service.notify_management(
                "Critical Security Escalation",
                {
                    "escalation_id": str(escalation.id),
                    "user": user.username,
                    "trigger": command.escalation_trigger.value,
                    "severity": command.severity.value,
                    "escalation_reason": command.escalation_reason
                }
            )
    
    async def _log_high_severity_escalation(
        self,
        user: User,
        escalation: Any,
        command: EscalateToEmergencyContactsCommand
    ) -> None:
        """Log high-severity escalations as security incidents."""
        await self._audit_service.log_security_incident(
            SecurityIncidentContext(
                incident_type=SecurityEventType.HIGH_SEVERITY_ESCALATION,
                severity=RiskLevel.HIGH if command.severity == IncidentSeverity.HIGH else RiskLevel.CRITICAL,
                user_id=user.id,
                details={
                    "escalation_id": str(escalation.id),
                    "trigger": command.escalation_trigger.value,
                    "level": command.escalation_level.value,
                    "severity": command.severity.value,
                    "escalated_by": str(command.escalated_by) if command.escalated_by else "system",
                    "reason": command.escalation_reason,
                    "immediate_action_required": command.immediate_action_required,
                    "incident_id": str(command.incident_id) if command.incident_id else None
                },
                indicators=["high_severity_emergency_escalation"],
                recommended_actions=[
                    "Monitor escalation response",
                    "Prepare for incident response",
                    "Contact user through alternative channels",
                    "Review security logs for additional threats"
                ]
            )
        )
    
    async def _initiate_legal_hold_procedures(
        self,
        user: User,
        escalation: Any,
        command: EscalateToEmergencyContactsCommand
    ) -> None:
        """Initiate legal hold procedures for escalation."""
        legal_hold_data = {
            "escalation_id": str(escalation.id),
            "user_id": str(user.id),
            "initiated_by": str(command.escalated_by) if command.escalated_by else "system",
            "reason": command.escalation_reason,
            "compliance_requirements": command.compliance_requirements,
            "hold_type": "emergency_escalation",
            "initiated_at": datetime.now(UTC).isoformat()
        }
        
        # Log legal hold initiation
        await self._audit_service.log_action(
            AuditContext(
                action=AuditAction.LEGAL_HOLD_INITIATED,
                actor_id=command.escalated_by,
                target_user_id=user.id,
                resource_type="escalation",
                resource_id=escalation.id,
                details=legal_hold_data,
                risk_level="high"
            )
        )
        
        # Notify legal team
        await self._notification_service.notify_legal_team(
            "Legal Hold Initiated - Emergency Escalation",
            legal_hold_data
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