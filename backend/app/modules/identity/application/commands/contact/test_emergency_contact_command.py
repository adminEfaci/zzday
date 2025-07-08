"""
Test emergency contact command implementation.

Handles testing emergency contact delivery and responsiveness.
"""

from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.contracts.ports import (
    IAuditService,
    ICallService,
    IContactTestRepository,
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
from app.modules.identity.application.dtos.request import TestEmergencyContactRequest
from app.modules.identity.application.dtos.response import EmergencyContactTestResponse
from app.modules.identity.domain.entities import EmergencyContact
from app.modules.identity.domain.enums import (
    AuditAction,
    ContactType,
    NotificationPriority,
    NotificationType,
    TestStatus,
    TestType,
)
from app.modules.identity.domain.events import (
    EmergencyContactTested,
)
from app.modules.identity.domain.exceptions import (
    ContactTestLimitExceededError,
    EmergencyContactNotFoundError,
    InvalidTestRequestError,
)
from app.modules.identity.domain.services import (
    ContactTestingService,
    SecurityService,
    ValidationService,
)


class TestScope(Enum):
    """Scope of emergency contact testing."""
    SINGLE_CONTACT = "single_contact"
    USER_CONTACTS = "user_contacts"
    CONTACT_TYPE = "contact_type"
    ALL_VERIFIED = "all_verified"
    PRIMARY_ONLY = "primary_only"


class TestEmergencyContactCommand(Command[EmergencyContactTestResponse]):
    """Command to test emergency contact delivery."""
    
    def __init__(
        self,
        initiated_by: UUID,
        test_scope: TestScope = TestScope.SINGLE_CONTACT,
        user_id: UUID | None = None,
        contact_id: UUID | None = None,
        contact_type: ContactType | None = None,
        test_type: TestType = TestType.CONNECTIVITY,
        include_delivery_confirmation: bool = True,
        include_response_test: bool = False,
        test_message_override: str | None = None,
        simulate_emergency: bool = False,
        test_all_methods: bool = False,
        verify_contact_responsiveness: bool = False,
        response_timeout_minutes: int = 15,
        schedule_follow_up: bool = False,
        compliance_test: bool = False,
        anonymize_test_data: bool = True,
        dry_run: bool = False,
        metadata: dict[str, Any] | None = None
    ):
        self.initiated_by = initiated_by
        self.test_scope = test_scope
        self.user_id = user_id
        self.contact_id = contact_id
        self.contact_type = contact_type
        self.test_type = test_type
        self.include_delivery_confirmation = include_delivery_confirmation
        self.include_response_test = include_response_test
        self.test_message_override = test_message_override
        self.simulate_emergency = simulate_emergency
        self.test_all_methods = test_all_methods
        self.verify_contact_responsiveness = verify_contact_responsiveness
        self.response_timeout_minutes = response_timeout_minutes
        self.schedule_follow_up = schedule_follow_up
        self.compliance_test = compliance_test
        self.anonymize_test_data = anonymize_test_data
        self.dry_run = dry_run
        self.metadata = metadata or {}


class TestEmergencyContactCommandHandler(CommandHandler[TestEmergencyContactCommand, EmergencyContactTestResponse]):
    """Handler for testing emergency contacts."""
    
    def __init__(
        self,
        user_repository: IUserRepository,
        emergency_contact_repository: IEmergencyContactRepository,
        contact_test_repository: IContactTestRepository,
        validation_service: ValidationService,
        contact_testing_service: ContactTestingService,
        security_service: SecurityService,
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
        self._contact_test_repository = contact_test_repository
        self._validation_service = validation_service
        self._contact_testing_service = contact_testing_service
        self._security_service = security_service
        self._notification_service = notification_service
        self._audit_service = audit_service
        self._email_service = email_service
        self._sms_service = sms_service
        self._call_service = call_service
        self._event_bus = event_bus
        self._unit_of_work = unit_of_work
    
    @audit_action(
        action=AuditAction.EMERGENCY_CONTACT_TESTED,
        resource_type="emergency_contact",
        include_request=True,
        include_response=True
    )
    @validate_request(TestEmergencyContactRequest)
    @rate_limit(
        max_requests=30,
        window_seconds=3600,
        strategy='user'
    )
    @require_permission("emergency_contacts.test")
    async def handle(self, command: TestEmergencyContactCommand) -> EmergencyContactTestResponse:
        """
        Test emergency contact delivery and responsiveness.
        
        Process:
        1. Validate test request and scope
        2. Get contacts to test
        3. Check test rate limits
        4. Prepare test content
        5. Execute tests based on type
        6. Monitor delivery and responses
        7. Generate test report
        8. Schedule follow-up if needed
        
        Returns:
            EmergencyContactTestResponse with test results
            
        Raises:
            EmergencyContactNotFoundError: If contact not found
            ContactTestLimitExceededError: If too many tests
            InvalidTestRequestError: If test request invalid
        """
        async with self._unit_of_work:
            # 1. Validate test request
            await self._validate_test_request(command)
            
            # 2. Get contacts to test
            test_contacts = await self._get_test_contacts(command)
            
            if not test_contacts:
                raise EmergencyContactNotFoundError("No contacts found for testing")
            
            # 3. Check test rate limits
            await self._check_test_rate_limits(command, test_contacts)
            
            # 4. Create test session
            test_session = await self._create_test_session(command, test_contacts)
            
            # 5. Prepare test content
            test_content = await self._prepare_test_content(command, test_session)
            
            # 6. Execute tests if not dry run
            test_results = {}
            if not command.dry_run:
                test_results = await self._execute_contact_tests(
                    test_contacts,
                    test_content,
                    test_session,
                    command
                )
                
                # 7. Monitor response collection if enabled
                if command.include_response_test or command.verify_contact_responsiveness:
                    await self._initiate_response_monitoring(
                        test_session,
                        test_results,
                        command
                    )
            else:
                # Generate preview for dry run
                test_results = await self._generate_test_preview(
                    test_contacts,
                    test_content,
                    command
                )
            
            # 8. Update test session with results
            test_session.test_results = test_results
            test_session.completed_at = datetime.now(UTC) if not command.dry_run else None
            test_session.status = TestStatus.COMPLETED if not command.dry_run else TestStatus.PREVIEW
            await self._contact_test_repository.update(test_session)
            
            # 9. Generate compliance report if required
            compliance_report = None
            if command.compliance_test:
                compliance_report = await self._generate_compliance_report(
                    test_session,
                    test_results
                )
            
            # 10. Schedule follow-up tests if requested
            if command.schedule_follow_up and not command.dry_run:
                await self._schedule_follow_up_tests(test_session, command)
            
            # 11. Notify stakeholders of test results
            if not command.dry_run:
                await self._notify_test_completion(
                    test_session,
                    test_results,
                    command
                )
            
            # 12. Publish domain event
            if not command.dry_run:
                await self._event_bus.publish(
                    EmergencyContactTested(
                        aggregate_id=test_session.id,
                        initiated_by=command.initiated_by,
                        test_scope=command.test_scope.value,
                        test_type=command.test_type,
                        contacts_tested=len(test_contacts),
                        successful_tests=len([r for r in test_results.values() if r.get("status") == "success"]),
                        failed_tests=len([r for r in test_results.values() if r.get("status") == "failed"])
                    )
                )
            
            # 13. Commit transaction
            await self._unit_of_work.commit()
            
            # 14. Return response
            return EmergencyContactTestResponse(
                test_session_id=test_session.id,
                test_scope=command.test_scope,
                test_type=command.test_type,
                contacts_tested=len(test_contacts),
                successful_deliveries=len([r for r in test_results.values() if r.get("delivery_status") == "delivered"]),
                failed_deliveries=len([r for r in test_results.values() if r.get("delivery_status") == "failed"]),
                response_rate=self._calculate_response_rate(test_results) if command.include_response_test else None,
                average_delivery_time=self._calculate_average_delivery_time(test_results),
                test_results=test_results if not command.anonymize_test_data else self._anonymize_test_results(test_results),
                compliance_report=compliance_report,
                dry_run=command.dry_run,
                follow_up_scheduled=command.schedule_follow_up and not command.dry_run,
                completed_at=test_session.completed_at,
                message="Emergency contact test completed successfully" if not command.dry_run else "Emergency contact test preview generated"
            )
    
    async def _validate_test_request(self, command: TestEmergencyContactCommand) -> None:
        """Validate the test request parameters."""
        # Check scope-specific requirements
        if command.test_scope == TestScope.SINGLE_CONTACT and not command.contact_id:
            raise InvalidTestRequestError("Contact ID required for single contact test")
        
        if command.test_scope == TestScope.USER_CONTACTS and not command.user_id:
            raise InvalidTestRequestError("User ID required for user contacts test")
        
        if command.test_scope == TestScope.CONTACT_TYPE and not command.contact_type:
            raise InvalidTestRequestError("Contact type required for contact type test")
        
        # Validate test type compatibility
        if command.test_type == TestType.EMERGENCY_SIMULATION and not command.simulate_emergency:
            raise InvalidTestRequestError("Emergency simulation requires simulate_emergency=True")
        
        # Check permissions for emergency simulation
        if command.simulate_emergency:
            can_simulate = await self._security_service.can_simulate_emergency(command.initiated_by)
            if not can_simulate:
                raise InvalidTestRequestError("Insufficient permissions for emergency simulation")
        
        # Validate response timeout
        if command.response_timeout_minutes < 1 or command.response_timeout_minutes > 60:
            raise InvalidTestRequestError("Response timeout must be between 1 and 60 minutes")
    
    async def _get_test_contacts(self, command: TestEmergencyContactCommand) -> list[EmergencyContact]:
        """Get emergency contacts based on test scope."""
        contacts = []
        
        if command.test_scope == TestScope.SINGLE_CONTACT:
            contact = await self._emergency_contact_repository.get_by_id(command.contact_id)
            if contact:
                contacts = [contact]
        
        elif command.test_scope == TestScope.USER_CONTACTS:
            contacts = await self._emergency_contact_repository.find_active_by_user(command.user_id)
        
        elif command.test_scope == TestScope.CONTACT_TYPE:
            contacts = await self._emergency_contact_repository.find_by_type(command.contact_type)
        
        elif command.test_scope == TestScope.ALL_VERIFIED:
            contacts = await self._emergency_contact_repository.find_all_verified()
        
        elif command.test_scope == TestScope.PRIMARY_ONLY:
            if command.user_id:
                contacts = await self._emergency_contact_repository.find_primary_by_user(command.user_id)
            else:
                contacts = await self._emergency_contact_repository.find_all_primary()
        
        # Filter by additional criteria
        filtered_contacts = []
        for contact in contacts:
            # Skip unverified contacts unless explicitly testing verification
            if not contact.is_verified and command.test_type != TestType.VERIFICATION:
                continue
            
            # Skip inactive contacts
            if not contact.is_active:
                continue
            
            filtered_contacts.append(contact)
        
        return filtered_contacts
    
    async def _check_test_rate_limits(
        self,
        command: TestEmergencyContactCommand,
        contacts: list[EmergencyContact]
    ) -> None:
        """Check if test rate limits are exceeded."""
        # Check tests per user in last hour
        recent_tests = await self._contact_test_repository.count_by_initiator_and_timeframe(
            command.initiated_by,
            hours=1
        )
        
        # Apply rate limits based on test type
        limits = {
            TestType.CONNECTIVITY: 50,
            TestType.DELIVERY: 30,
            TestType.RESPONSIVENESS: 20,
            TestType.EMERGENCY_SIMULATION: 5,
            TestType.COMPLIANCE: 10
        }
        
        limit = limits.get(command.test_type, 20)
        
        if recent_tests >= limit:
            raise ContactTestLimitExceededError(
                f"Test rate limit exceeded: {recent_tests}/{limit} tests in last hour"
            )
        
        # Check specific contact test limits
        if command.test_scope == TestScope.SINGLE_CONTACT:
            contact_tests = await self._contact_test_repository.count_by_contact_and_timeframe(
                command.contact_id,
                hours=24
            )
            
            if contact_tests >= 10:  # Max 10 tests per contact per day
                raise ContactTestLimitExceededError(
                    f"Contact test limit exceeded: {contact_tests}/10 tests in last 24 hours"
                )
    
    async def _create_test_session(
        self,
        command: TestEmergencyContactCommand,
        contacts: list[EmergencyContact]
    ) -> Any:
        """Create test session for tracking."""
        session_data = {
            "id": UUID(),
            "initiated_by": command.initiated_by,
            "test_scope": command.test_scope.value,
            "test_type": command.test_type,
            "contact_ids": [c.id for c in contacts],
            "status": TestStatus.IN_PROGRESS,
            "include_delivery_confirmation": command.include_delivery_confirmation,
            "include_response_test": command.include_response_test,
            "simulate_emergency": command.simulate_emergency,
            "verify_contact_responsiveness": command.verify_contact_responsiveness,
            "response_timeout_minutes": command.response_timeout_minutes,
            "compliance_test": command.compliance_test,
            "dry_run": command.dry_run,
            "created_at": datetime.now(UTC),
            "metadata": command.metadata
        }
        
        return await self._contact_test_repository.create(session_data)
    
    async def _prepare_test_content(
        self,
        command: TestEmergencyContactCommand,
        test_session: Any
    ) -> dict[str, Any]:
        """Prepare test message content."""
        # Base variables
        variables = {
            "test_session_id": str(test_session.id),
            "test_type": command.test_type.value,
            "test_timestamp": datetime.now(UTC).isoformat(),
            "response_link": f"https://app.example.com/test-response/{test_session.id}",
            "test_confirmation_code": self._generate_test_code(),
            "support_link": "https://app.example.com/support"
        }
        
        # Add emergency simulation context
        if command.simulate_emergency:
            variables.update({
                "is_emergency_simulation": True,
                "simulation_notice": "THIS IS A TEST - NOT A REAL EMERGENCY",
                "emergency_type": "simulated_security_incident"
            })
        
        # Add custom message if provided
        if command.test_message_override:
            variables["custom_message"] = command.test_message_override
        
        # Get appropriate template
        template_name = self._get_test_template(command.test_type, command.simulate_emergency)
        
        return {
            "template_name": template_name,
            "variables": variables,
            "priority": NotificationPriority.HIGH if command.simulate_emergency else NotificationPriority.MEDIUM,
            "test_code": variables["test_confirmation_code"]
        }
    
    def _get_test_template(self, test_type: TestType, simulate_emergency: bool) -> str:
        """Get appropriate template for test type."""
        if simulate_emergency:
            return "emergency_contact_test_simulation"
        
        template_mapping = {
            TestType.CONNECTIVITY: "emergency_contact_test_connectivity",
            TestType.DELIVERY: "emergency_contact_test_delivery",
            TestType.RESPONSIVENESS: "emergency_contact_test_response",
            TestType.VERIFICATION: "emergency_contact_test_verification",
            TestType.COMPLIANCE: "emergency_contact_test_compliance"
        }
        
        return template_mapping.get(test_type, "emergency_contact_test_general")
    
    def _generate_test_code(self) -> str:
        """Generate unique test confirmation code."""
        import secrets
        import string
        return ''.join(secrets.choices(string.ascii_uppercase + string.digits, k=8))
    
    async def _execute_contact_tests(
        self,
        contacts: list[EmergencyContact],
        content: dict[str, Any],
        test_session: Any,
        command: TestEmergencyContactCommand
    ) -> dict[str, Any]:
        """Execute tests on emergency contacts."""
        results = {}
        
        for contact in contacts:
            contact_id = str(contact.id)
            contact_result = {
                "contact_id": contact_id,
                "contact_type": contact.contact_type.value,
                "contact_value": self._mask_contact_value(contact.contact_value) if command.anonymize_test_data else contact.contact_value,
                "contact_name": contact.contact_name,
                "is_primary": contact.is_primary,
                "test_attempts": [],
                "delivery_status": "pending",
                "response_status": "pending" if command.include_response_test else "not_required",
                "test_timestamp": datetime.now(UTC).isoformat()
            }
            
            # Execute delivery test
            await self._test_contact_delivery(
                contact,
                content,
                contact_result,
                command
            )
            
            # Test all methods if requested
            if command.test_all_methods and contact.contact_type == ContactType.EMAIL:
                # Also test SMS if phone number available
                if contact.phone_number:
                    await self._test_sms_delivery(
                        contact,
                        content,
                        contact_result,
                        command
                    )
            
            # Update final delivery status
            if any(attempt["status"] == "delivered" for attempt in contact_result["test_attempts"]):
                contact_result["delivery_status"] = "delivered"
            else:
                contact_result["delivery_status"] = "failed"
            
            results[contact_id] = contact_result
        
        return results
    
    async def _test_contact_delivery(
        self,
        contact: EmergencyContact,
        content: dict[str, Any],
        contact_result: dict[str, Any],
        command: TestEmergencyContactCommand
    ) -> bool:
        """Test delivery to specific contact."""
        delivery_start = datetime.now(UTC)
        
        try:
            if contact.contact_type == ContactType.EMAIL:
                success = await self._test_email_delivery(
                    contact,
                    content,
                    contact_result,
                    command
                )
            
            elif contact.contact_type in [ContactType.SMS, ContactType.PHONE]:
                success = await self._test_sms_delivery(
                    contact,
                    content,
                    contact_result,
                    command
                )
            
            else:
                contact_result["test_attempts"].append({
                    "method": contact.contact_type.value,
                    "timestamp": delivery_start.isoformat(),
                    "status": "unsupported",
                    "delivery_time_ms": 0
                })
                return False
        except Exception as e:
            contact_result["test_attempts"].append({
                "method": contact.contact_type.value,
                "timestamp": delivery_start.isoformat(),
                "status": "error",
                "error": str(e),
                "delivery_time_ms": (datetime.now(UTC) - delivery_start).total_seconds() * 1000
            })
            return False
        else:
            return success
    
    async def _test_email_delivery(
        self,
        contact: EmergencyContact,
        content: dict[str, Any],
        contact_result: dict[str, Any],
        command: TestEmergencyContactCommand
    ) -> bool:
        """Test email delivery."""
        delivery_start = datetime.now(UTC)
        
        try:
            await self._email_service.send_email(
                EmailContext(
                    recipient=contact.contact_value,
                    template=content["template_name"],
                    subject="Emergency Contact Test - Please Acknowledge",
                    variables=content["variables"],
                    priority=content["priority"].value,
                    tracking_id=f"test_{contact.id}_{int(datetime.now(UTC).timestamp())}",
                    delivery_receipt_required=command.include_delivery_confirmation,
                    test_mode=True
                )
            )
            
            delivery_time = (datetime.now(UTC) - delivery_start).total_seconds() * 1000
            
            contact_result["test_attempts"].append({
                "method": "email",
                "timestamp": delivery_start.isoformat(),
                "status": "delivered",
                "delivery_time_ms": delivery_time,
                "test_code": content["test_code"]
            })
            
            return True
            
        except Exception as e:
            delivery_time = (datetime.now(UTC) - delivery_start).total_seconds() * 1000
            
            contact_result["test_attempts"].append({
                "method": "email",
                "timestamp": delivery_start.isoformat(),
                "status": "failed",
                "error": str(e),
                "delivery_time_ms": delivery_time
            })
            
            return False
    
    async def _test_sms_delivery(
        self,
        contact: EmergencyContact,
        content: dict[str, Any],
        contact_result: dict[str, Any],
        command: TestEmergencyContactCommand
    ) -> bool:
        """Test SMS delivery."""
        delivery_start = datetime.now(UTC)
        
        try:
            # Use shorter content for SMS
            sms_variables = content["variables"].copy()
            sms_variables["message_short"] = True
            
            await self._sms_service.send_sms(
                SMSContext(
                    recipient=contact.contact_value,
                    template=f"{content['template_name']}_sms",
                    variables=sms_variables,
                    priority=content["priority"].value,
                    tracking_id=f"test_sms_{contact.id}_{int(datetime.now(UTC).timestamp())}",
                    test_mode=True
                )
            )
            
            delivery_time = (datetime.now(UTC) - delivery_start).total_seconds() * 1000
            
            contact_result["test_attempts"].append({
                "method": "sms",
                "timestamp": delivery_start.isoformat(),
                "status": "delivered",
                "delivery_time_ms": delivery_time,
                "test_code": content["test_code"]
            })
            
            return True
            
        except Exception as e:
            delivery_time = (datetime.now(UTC) - delivery_start).total_seconds() * 1000
            
            contact_result["test_attempts"].append({
                "method": "sms",
                "timestamp": delivery_start.isoformat(),
                "status": "failed",
                "error": str(e),
                "delivery_time_ms": delivery_time
            })
            
            return False
    
    async def _generate_test_preview(
        self,
        contacts: list[EmergencyContact],
        content: dict[str, Any],
        command: TestEmergencyContactCommand
    ) -> dict[str, Any]:
        """Generate preview of what would be tested."""
        preview_results = {}
        
        for contact in contacts:
            contact_id = str(contact.id)
            preview_results[contact_id] = {
                "contact_id": contact_id,
                "contact_type": contact.contact_type.value,
                "contact_value": self._mask_contact_value(contact.contact_value),
                "contact_name": contact.contact_name,
                "is_primary": contact.is_primary,
                "would_test_methods": self._get_test_methods(contact, command),
                "preview_mode": True,
                "test_template": content["template_name"]
            }
        
        return preview_results
    
    def _get_test_methods(self, contact: EmergencyContact, command: TestEmergencyContactCommand) -> list[str]:
        """Get methods that would be tested for contact."""
        methods = [contact.contact_type.value]
        
        if command.test_all_methods:
            if contact.contact_type == ContactType.EMAIL and hasattr(contact, 'phone_number'):
                methods.append("sms")
            elif contact.contact_type == ContactType.SMS:
                methods.append("email")
        
        return methods
    
    async def _initiate_response_monitoring(
        self,
        test_session: Any,
        test_results: dict[str, Any],
        command: TestEmergencyContactCommand
    ) -> None:
        """Initiate monitoring for contact responses."""
        # This would integrate with a job scheduling system
        monitoring_config = {
            "test_session_id": str(test_session.id),
            "response_timeout_minutes": command.response_timeout_minutes,
            "contacts_expecting_response": [
                contact_id for contact_id, result in test_results.items()
                if result.get("delivery_status") == "delivered"
            ],
            "response_tracking_enabled": True
        }
        
        # Log the monitoring initiation
        await self._audit_service.log_action(
            AuditContext(
                action=AuditAction.TEST_RESPONSE_MONITORING_INITIATED,
                actor_id=command.initiated_by,
                target_user_id=None,
                resource_type="contact_test",
                resource_id=test_session.id,
                details=monitoring_config,
                risk_level="low"
            )
        )
    
    async def _generate_compliance_report(
        self,
        test_session: Any,
        test_results: dict[str, Any]
    ) -> dict[str, Any]:
        """Generate compliance report for test results."""
        total_contacts = len(test_results)
        successful_deliveries = len([r for r in test_results.values() if r.get("delivery_status") == "delivered"])
        failed_deliveries = len([r for r in test_results.values() if r.get("delivery_status") == "failed"])
        
        delivery_rate = (successful_deliveries / total_contacts * 100) if total_contacts > 0 else 0
        
        compliance_status = "PASS" if delivery_rate >= 95 else "FAIL" if delivery_rate < 80 else "WARNING"
        
        return {
            "test_session_id": str(test_session.id),
            "test_timestamp": test_session.created_at.isoformat(),
            "total_contacts_tested": total_contacts,
            "successful_deliveries": successful_deliveries,
            "failed_deliveries": failed_deliveries,
            "delivery_rate_percentage": round(delivery_rate, 2),
            "compliance_status": compliance_status,
            "compliance_threshold": 95.0,
            "recommendations": self._generate_compliance_recommendations(delivery_rate, test_results),
            "next_test_due": (datetime.now(UTC) + timedelta(days=90)).isoformat()
        }
    
    def _generate_compliance_recommendations(
        self,
        delivery_rate: float,
        test_results: dict[str, Any]
    ) -> list[str]:
        """Generate compliance recommendations based on test results."""
        recommendations = []
        
        if delivery_rate < 95:
            recommendations.append("Delivery rate below compliance threshold - review failed contacts")
        
        if delivery_rate < 80:
            recommendations.append("Critical delivery rate - immediate action required")
            recommendations.append("Consider adding backup emergency contacts")
        
        # Check for specific failure patterns
        email_failures = len([r for r in test_results.values() 
                            if r.get("contact_type") == "email" and r.get("delivery_status") == "failed"])
        sms_failures = len([r for r in test_results.values() 
                          if r.get("contact_type") == "sms" and r.get("delivery_status") == "failed"])
        
        if email_failures > 0:
            recommendations.append(f"Review {email_failures} failed email deliveries")
        
        if sms_failures > 0:
            recommendations.append(f"Review {sms_failures} failed SMS deliveries")
        
        if not recommendations:
            recommendations.append("All tests passed - emergency contact system functioning properly")
        
        return recommendations
    
    async def _schedule_follow_up_tests(
        self,
        test_session: Any,
        command: TestEmergencyContactCommand
    ) -> None:
        """Schedule follow-up tests."""
        follow_up_schedule = {
            "original_test_session_id": str(test_session.id),
            "follow_up_intervals": [7, 30, 90],  # days
            "test_type": command.test_type,
            "test_scope": command.test_scope.value,
            "initiated_by": command.initiated_by
        }
        
        # Log the scheduling
        await self._audit_service.log_action(
            AuditContext(
                action=AuditAction.FOLLOW_UP_TESTS_SCHEDULED,
                actor_id=command.initiated_by,
                target_user_id=None,
                resource_type="contact_test",
                resource_id=test_session.id,
                details=follow_up_schedule,
                risk_level="low"
            )
        )
    
    async def _notify_test_completion(
        self,
        test_session: Any,
        test_results: dict[str, Any],
        command: TestEmergencyContactCommand
    ) -> None:
        """Notify stakeholders of test completion."""
        successful_tests = len([r for r in test_results.values() if r.get("delivery_status") == "delivered"])
        failed_tests = len([r for r in test_results.values() if r.get("delivery_status") == "failed"])
        
        # Notify administrator
        await self._notification_service.create_notification(
            NotificationContext(
                notification_id=UUID(),
                recipient_id=command.initiated_by,
                notification_type=NotificationType.TEST_COMPLETED,
                channel="in_app",
                template_id="emergency_contact_test_completed",
                template_data={
                    "test_session_id": str(test_session.id),
                    "test_type": command.test_type.value,
                    "successful_tests": successful_tests,
                    "failed_tests": failed_tests,
                    "total_tests": len(test_results)
                },
                priority="low"
            )
        )
        
        # Notify security team if high failure rate
        failure_rate = (failed_tests / len(test_results) * 100) if test_results else 0
        
        if failure_rate > 20:  # More than 20% failure rate
            await self._notification_service.notify_security_team(
                "Emergency Contact Test - High Failure Rate",
                {
                    "test_session_id": str(test_session.id),
                    "failure_rate": round(failure_rate, 2),
                    "failed_tests": failed_tests,
                    "total_tests": len(test_results),
                    "test_type": command.test_type.value
                }
            )
    
    def _calculate_response_rate(self, test_results: dict[str, Any]) -> float | None:
        """Calculate response rate for tests that included response verification."""
        responses_received = len([r for r in test_results.values() if r.get("response_status") == "responded"])
        responses_expected = len([r for r in test_results.values() if r.get("response_status") != "not_required"])
        
        if responses_expected == 0:
            return None
        
        return round((responses_received / responses_expected * 100), 2)
    
    def _calculate_average_delivery_time(self, test_results: dict[str, Any]) -> float | None:
        """Calculate average delivery time for successful deliveries."""
        delivery_times = []
        
        for result in test_results.values():
            for attempt in result.get("test_attempts", []):
                if attempt.get("status") == "delivered":
                    delivery_times.append(attempt.get("delivery_time_ms", 0))
        
        if not delivery_times:
            return None
        
        return round(sum(delivery_times) / len(delivery_times), 2)
    
    def _anonymize_test_results(self, test_results: dict[str, Any]) -> dict[str, Any]:
        """Anonymize test results for privacy."""
        anonymized = {}
        
        for contact_id, result in test_results.items():
            anonymized_result = result.copy()
            
            # Mask contact value
            if "contact_value" in anonymized_result:
                anonymized_result["contact_value"] = self._mask_contact_value(
                    anonymized_result["contact_value"]
                )
            
            # Remove sensitive tracking information
            if "test_attempts" in anonymized_result:
                for attempt in anonymized_result["test_attempts"]:
                    if "test_code" in attempt:
                        attempt["test_code"] = "***REDACTED***"
            
            anonymized[contact_id] = anonymized_result
        
        return anonymized
    
    def _mask_contact_value(self, contact_value: str) -> str:
        """Mask contact value for privacy."""
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