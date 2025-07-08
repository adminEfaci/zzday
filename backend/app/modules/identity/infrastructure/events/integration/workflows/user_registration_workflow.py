"""
UserRegistrationWorkflow - Complete User Registration Business Process

Implements a comprehensive user registration workflow that orchestrates the complete
user onboarding process including validation, verification, profile setup, and
initial security configuration.

Key Features:
- Multi-step registration validation
- Email and phone verification
- Profile completion guidance
- Security setup (password policies, MFA)
- Welcome email and notifications
- Audit trail and compliance tracking
- Failed registration cleanup
- Integration with external systems
"""

import asyncio
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from app.core.logging import get_logger
from app.modules.identity.domain.entities.user.user_events import (
    EmailVerificationRequested,
    EmailVerified,
    ProfileCompleted,
    UserActivated,
    UserCreated,
)

from ..engine import BaseWorkflow, WorkflowContext, WorkflowStep

logger = get_logger(__name__)


class UserRegistrationWorkflow(BaseWorkflow):
    """
    Comprehensive user registration workflow.
    
    Orchestrates the complete user registration process from initial signup
    to fully activated user account with proper verification and setup.
    """
    
    def __init__(self, workflow_id: UUID | None = None):
        """Initialize the user registration workflow."""
        super().__init__(workflow_id)
        
        # Registration state tracking
        self.user_id: UUID | None = None
        self.email: str | None = None
        self.registration_data: dict[str, Any] = {}
        
        # Verification tracking
        self.email_verified = False
        self.phone_verified = False
        self.profile_completed = False
        
        # Setup workflow event handlers
        self.add_event_handler('UserCreated', self._handle_user_created)
        self.add_event_handler('EmailVerificationRequested', self._handle_email_verification_requested)
        self.add_event_handler('EmailVerified', self._handle_email_verified)
        self.add_event_handler('PhoneNumberVerified', self._handle_phone_verified)
        self.add_event_handler('ProfileCompleted', self._handle_profile_completed)
        self.add_event_handler('UserActivated', self._handle_user_activated)
    
    def define_steps(self) -> list[WorkflowStep]:
        """Define the user registration workflow steps."""
        return [
            # Step 1: Validate registration data
            WorkflowStep(
                step_id="validate_registration",
                name="Validate Registration Data",
                handler=self._validate_registration_data,
                compensation_handler=self._cleanup_failed_validation,
                timeout_seconds=30,
                retry_attempts=2,
                required=True
            ),
            
            # Step 2: Create user account
            WorkflowStep(
                step_id="create_user_account",
                name="Create User Account",
                handler=self._create_user_account,
                compensation_handler=self._delete_user_account,
                timeout_seconds=60,
                retry_attempts=3,
                required=True,
                depends_on=["validate_registration"]
            ),
            
            # Step 3: Send email verification
            WorkflowStep(
                step_id="send_email_verification",
                name="Send Email Verification",
                handler=self._send_email_verification,
                compensation_handler=self._cancel_email_verification,
                timeout_seconds=30,
                retry_attempts=3,
                required=True,
                depends_on=["create_user_account"]
            ),
            
            # Step 4: Setup initial security profile
            WorkflowStep(
                step_id="setup_security_profile",
                name="Setup Initial Security Profile",
                handler=self._setup_security_profile,
                compensation_handler=self._cleanup_security_profile,
                timeout_seconds=60,
                retry_attempts=2,
                required=False,
                depends_on=["create_user_account"],
                parallel_group="security_setup"
            ),
            
            # Step 5: Create audit log entry
            WorkflowStep(
                step_id="create_audit_log",
                name="Create Registration Audit Log",
                handler=self._create_audit_log,
                compensation_handler=None,  # Audit logs are not rolled back
                timeout_seconds=30,
                retry_attempts=2,
                required=False,
                depends_on=["create_user_account"],
                parallel_group="security_setup"
            ),
            
            # Step 6: Wait for email verification (event-driven)
            WorkflowStep(
                step_id="wait_email_verification",
                name="Wait for Email Verification",
                handler=self._wait_for_email_verification,
                compensation_handler=None,
                timeout_seconds=3600,  # 1 hour timeout
                retry_attempts=1,
                required=True,
                depends_on=["send_email_verification"]
            ),
            
            # Step 7: Send phone verification (optional)
            WorkflowStep(
                step_id="send_phone_verification",
                name="Send Phone Verification",
                handler=self._send_phone_verification,
                compensation_handler=self._cancel_phone_verification,
                timeout_seconds=30,
                retry_attempts=3,
                required=False,
                condition=lambda data: data.get('phone_number') is not None,
                depends_on=["wait_email_verification"]
            ),
            
            # Step 8: Setup user profile
            WorkflowStep(
                step_id="setup_user_profile",
                name="Setup User Profile",
                handler=self._setup_user_profile,
                compensation_handler=self._cleanup_user_profile,
                timeout_seconds=60,
                retry_attempts=2,
                required=False,
                depends_on=["wait_email_verification"]
            ),
            
            # Step 9: Activate user account
            WorkflowStep(
                step_id="activate_user_account",
                name="Activate User Account",
                handler=self._activate_user_account,
                compensation_handler=self._deactivate_user_account,
                timeout_seconds=30,
                retry_attempts=3,
                required=True,
                depends_on=["wait_email_verification"]
            ),
            
            # Step 10: Send welcome notification
            WorkflowStep(
                step_id="send_welcome_notification",
                name="Send Welcome Notification",
                handler=self._send_welcome_notification,
                compensation_handler=None,
                timeout_seconds=30,
                retry_attempts=2,
                required=False,
                depends_on=["activate_user_account"]
            ),
            
            # Step 11: Register with external systems
            WorkflowStep(
                step_id="register_external_systems",
                name="Register with External Systems",
                handler=self._register_external_systems,
                compensation_handler=self._unregister_external_systems,
                timeout_seconds=120,
                retry_attempts=3,
                required=False,
                depends_on=["activate_user_account"]
            ),
            
            # Step 12: Complete registration
            WorkflowStep(
                step_id="complete_registration",
                name="Complete Registration Process",
                handler=self._complete_registration,
                compensation_handler=None,
                timeout_seconds=30,
                retry_attempts=1,
                required=True,
                depends_on=["activate_user_account"]
            )
        ]
    
    # Event Handlers
    
    async def _handle_user_created(self, event: UserCreated, context: WorkflowContext) -> None:
        """Handle UserCreated event."""
        self.user_id = event.user_id
        self.email = event.email
        context.merge_output({
            'user_id': str(event.user_id),
            'email': event.email,
            'user_created_at': event.occurred_at.isoformat()
        })
        
        logger.info(
            "User created in registration workflow",
            workflow_id=str(context.workflow_id),
            user_id=str(event.user_id),
            email=event.email
        )
    
    async def _handle_email_verification_requested(
        self, 
        event: EmailVerificationRequested, 
        context: WorkflowContext
    ) -> None:
        """Handle EmailVerificationRequested event."""
        context.merge_output({
            'email_verification_token': event.verification_token,
            'email_verification_expires_at': event.expires_at.isoformat()
        })
        
        logger.info(
            "Email verification requested in registration workflow",
            workflow_id=str(context.workflow_id),
            user_id=str(event.user_id),
            email=event.email
        )
    
    async def _handle_email_verified(self, event: EmailVerified, context: WorkflowContext) -> None:
        """Handle EmailVerified event."""
        self.email_verified = True
        context.merge_output({
            'email_verified': True,
            'email_verified_at': event.verified_at.isoformat()
        })
        
        logger.info(
            "Email verified in registration workflow",
            workflow_id=str(context.workflow_id),
            user_id=str(event.user_id),
            email=event.email
        )
    
    async def _handle_phone_verified(self, event, context: WorkflowContext) -> None:
        """Handle PhoneNumberVerified event."""
        self.phone_verified = True
        context.merge_output({
            'phone_verified': True,
            'phone_verified_at': event.verified_at.isoformat()
        })
        
        logger.info(
            "Phone verified in registration workflow",
            workflow_id=str(context.workflow_id),
            user_id=str(event.user_id),
            phone_number=event.phone_number
        )
    
    async def _handle_profile_completed(self, event: ProfileCompleted, context: WorkflowContext) -> None:
        """Handle ProfileCompleted event."""
        self.profile_completed = True
        context.merge_output({
            'profile_completed': True,
            'profile_completed_at': event.completed_at.isoformat(),
            'completion_percentage': event.completion_percentage
        })
        
        logger.info(
            "Profile completed in registration workflow",
            workflow_id=str(context.workflow_id),
            user_id=str(event.user_id),
            completion_percentage=event.completion_percentage
        )
    
    async def _handle_user_activated(self, event: UserActivated, context: WorkflowContext) -> None:
        """Handle UserActivated event."""
        context.merge_output({
            'user_activated': True,
            'activated_at': event.occurred_at.isoformat(),
            'activation_method': event.activation_method
        })
        
        logger.info(
            "User activated in registration workflow",
            workflow_id=str(context.workflow_id),
            user_id=str(event.user_id),
            activation_method=event.activation_method
        )
    
    # Workflow Step Handlers
    
    async def _validate_registration_data(self, step_input: dict[str, Any]) -> dict[str, Any]:
        """Validate registration data before creating user."""
        context = step_input['context']
        input_data = step_input['input_data']
        
        # Extract registration data
        email = input_data.get('email')
        password = input_data.get('password')
        name = input_data.get('name')
        
        # Basic validation
        if not email or '@' not in email:
            raise ValueError("Invalid email address")
        
        if not password or len(password) < 8:
            raise ValueError("Password must be at least 8 characters")
        
        if not name or len(name.strip()) < 2:
            raise ValueError("Name must be at least 2 characters")
        
        # Check for duplicate email (this would be a real database check)
        # For now, we'll simulate this
        if email.endswith('@blocked.com'):
            raise ValueError("Email domain is not allowed")
        
        # Store validated data
        self.registration_data = {
            'email': email.lower().strip(),
            'name': name.strip(),
            'phone_number': input_data.get('phone_number'),
            'date_of_birth': input_data.get('date_of_birth'),
            'marketing_consent': input_data.get('marketing_consent', False),
            'terms_accepted': input_data.get('terms_accepted', False),
            'validated_at': datetime.utcnow().isoformat()
        }
        
        logger.info(
            "Registration data validated",
            workflow_id=str(context.workflow_id),
            email=email,
            has_phone=bool(input_data.get('phone_number'))
        )
        
        return {
            'validation_status': 'passed',
            'validated_data': self.registration_data,
            'validation_errors': []
        }
    
    async def _create_user_account(self, step_input: dict[str, Any]) -> dict[str, Any]:
        """Create the user account in the system."""
        context = step_input['context']
        
        # Generate user ID
        user_id = uuid4()
        self.user_id = user_id
        
        # Simulate user creation (this would be a real database operation)
        user_data = {
            'user_id': str(user_id),
            'email': self.registration_data['email'],
            'name': self.registration_data['name'],
            'phone_number': self.registration_data.get('phone_number'),
            'status': 'pending_verification',
            'created_at': datetime.utcnow().isoformat(),
            'email_verified': False,
            'phone_verified': False
        }
        
        # Simulate delay for database operation
        await asyncio.sleep(0.1)
        
        logger.info(
            "User account created",
            workflow_id=str(context.workflow_id),
            user_id=str(user_id),
            email=self.registration_data['email']
        )
        
        return {
            'user_created': True,
            'user_data': user_data,
            'creation_timestamp': datetime.utcnow().isoformat()
        }
    
    async def _send_email_verification(self, step_input: dict[str, Any]) -> dict[str, Any]:
        """Send email verification to the user."""
        context = step_input['context']
        
        if not self.user_id or not self.email:
            raise ValueError("User ID and email are required")
        
        # Generate verification token
        verification_token = str(uuid4())
        expires_at = datetime.utcnow() + timedelta(hours=24)
        
        # Simulate sending email (this would be a real email service call)
        email_data = {
            'to': self.email,
            'subject': 'Verify your email address',
            'template': 'email_verification',
            'data': {
                'verification_token': verification_token,
                'verification_url': f"https://app.example.com/verify-email?token={verification_token}",
                'expires_at': expires_at.isoformat()
            }
        }
        
        # Simulate email sending delay
        await asyncio.sleep(0.2)
        
        logger.info(
            "Email verification sent",
            workflow_id=str(context.workflow_id),
            user_id=str(self.user_id),
            email=self.email,
            expires_at=expires_at.isoformat()
        )
        
        return {
            'email_sent': True,
            'verification_token': verification_token,
            'expires_at': expires_at.isoformat(),
            'email_data': email_data
        }
    
    async def _setup_security_profile(self, step_input: dict[str, Any]) -> dict[str, Any]:
        """Setup initial security profile for the user."""
        context = step_input['context']
        
        if not self.user_id:
            raise ValueError("User ID is required")
        
        # Create security profile
        security_profile = {
            'user_id': str(self.user_id),
            'password_policy': 'standard',
            'mfa_required': False,
            'login_attempts_limit': 5,
            'session_timeout_minutes': 60,
            'password_expiry_days': 90,
            'security_questions_required': False,
            'created_at': datetime.utcnow().isoformat()
        }
        
        # Simulate security profile creation
        await asyncio.sleep(0.1)
        
        logger.info(
            "Security profile created",
            workflow_id=str(context.workflow_id),
            user_id=str(self.user_id)
        )
        
        return {
            'security_profile_created': True,
            'security_profile': security_profile
        }
    
    async def _create_audit_log(self, step_input: dict[str, Any]) -> dict[str, Any]:
        """Create audit log entry for registration."""
        context = step_input['context']
        
        if not self.user_id:
            raise ValueError("User ID is required")
        
        # Create audit log entry
        audit_entry = {
            'event_type': 'user_registration_started',
            'user_id': str(self.user_id),
            'email': self.email,
            'ip_address': context.input_data.get('ip_address', 'unknown'),
            'user_agent': context.input_data.get('user_agent', 'unknown'),
            'timestamp': datetime.utcnow().isoformat(),
            'workflow_id': str(context.workflow_id),
            'registration_data': {
                'email': self.email,
                'has_phone': bool(self.registration_data.get('phone_number')),
                'marketing_consent': self.registration_data.get('marketing_consent', False),
                'terms_accepted': self.registration_data.get('terms_accepted', False)
            }
        }
        
        # Simulate audit log creation
        await asyncio.sleep(0.05)
        
        logger.info(
            "Audit log created for registration",
            workflow_id=str(context.workflow_id),
            user_id=str(self.user_id),
            event_type='user_registration_started'
        )
        
        return {
            'audit_log_created': True,
            'audit_entry': audit_entry
        }
    
    async def _wait_for_email_verification(self, step_input: dict[str, Any]) -> dict[str, Any]:
        """Wait for email verification to complete."""
        context = step_input['context']
        
        # This is an event-driven step that waits for the EmailVerified event
        # In a real implementation, this would set up a listener or check the database
        
        # For simulation, we'll wait a bit and then check if verification occurred
        max_wait_time = 30  # seconds for simulation
        check_interval = 1  # second
        
        for i in range(max_wait_time):
            if self.email_verified:
                logger.info(
                    "Email verification completed",
                    workflow_id=str(context.workflow_id),
                    user_id=str(self.user_id),
                    wait_time_seconds=i
                )
                
                return {
                    'email_verification_completed': True,
                    'verified_at': datetime.utcnow().isoformat(),
                    'wait_time_seconds': i
                }
            
            await asyncio.sleep(check_interval)
        
        # For simulation purposes, we'll mark as verified after timeout
        self.email_verified = True
        
        logger.info(
            "Email verification simulated as completed",
            workflow_id=str(context.workflow_id),
            user_id=str(self.user_id)
        )
        
        return {
            'email_verification_completed': True,
            'verified_at': datetime.utcnow().isoformat(),
            'simulated': True
        }
    
    async def _send_phone_verification(self, step_input: dict[str, Any]) -> dict[str, Any]:
        """Send phone verification if phone number provided."""
        context = step_input['context']
        
        phone_number = self.registration_data.get('phone_number')
        if not phone_number:
            return {'phone_verification_skipped': True, 'reason': 'no_phone_number'}
        
        # Generate verification code
        verification_code = "123456"  # In real implementation, this would be random
        
        # Simulate sending SMS
        sms_data = {
            'to': phone_number,
            'message': f'Your verification code is: {verification_code}',
            'expires_in_minutes': 10
        }
        
        await asyncio.sleep(0.1)
        
        logger.info(
            "Phone verification sent",
            workflow_id=str(context.workflow_id),
            user_id=str(self.user_id),
            phone_number=phone_number
        )
        
        return {
            'phone_verification_sent': True,
            'verification_code': verification_code,
            'sms_data': sms_data
        }
    
    async def _setup_user_profile(self, step_input: dict[str, Any]) -> dict[str, Any]:
        """Setup initial user profile."""
        context = step_input['context']
        
        if not self.user_id:
            raise ValueError("User ID is required")
        
        # Create user profile
        profile_data = {
            'user_id': str(self.user_id),
            'display_name': self.registration_data['name'],
            'first_name': self.registration_data['name'].split()[0] if self.registration_data['name'] else '',
            'last_name': ' '.join(self.registration_data['name'].split()[1:]) if len(self.registration_data['name'].split()) > 1 else '',
            'email': self.email,
            'phone_number': self.registration_data.get('phone_number'),
            'date_of_birth': self.registration_data.get('date_of_birth'),
            'profile_completion_percentage': 60.0,
            'created_at': datetime.utcnow().isoformat(),
            'preferences': {
                'marketing_emails': self.registration_data.get('marketing_consent', False),
                'notification_emails': True,
                'theme': 'default',
                'language': 'en'
            }
        }
        
        await asyncio.sleep(0.1)
        
        logger.info(
            "User profile created",
            workflow_id=str(context.workflow_id),
            user_id=str(self.user_id),
            completion_percentage=profile_data['profile_completion_percentage']
        )
        
        return {
            'profile_created': True,
            'profile_data': profile_data
        }
    
    async def _activate_user_account(self, step_input: dict[str, Any]) -> dict[str, Any]:
        """Activate the user account."""
        context = step_input['context']
        
        if not self.user_id or not self.email_verified:
            raise ValueError("User ID and email verification are required")
        
        # Activate user account
        activation_data = {
            'user_id': str(self.user_id),
            'status': 'active',
            'activated_at': datetime.utcnow().isoformat(),
            'activation_method': 'email_verification',
            'activated_by': str(self.user_id)  # Self-activated
        }
        
        await asyncio.sleep(0.1)
        
        logger.info(
            "User account activated",
            workflow_id=str(context.workflow_id),
            user_id=str(self.user_id),
            email=self.email
        )
        
        return {
            'account_activated': True,
            'activation_data': activation_data
        }
    
    async def _send_welcome_notification(self, step_input: dict[str, Any]) -> dict[str, Any]:
        """Send welcome notification to the user."""
        context = step_input['context']
        
        # Send welcome email
        welcome_email = {
            'to': self.email,
            'subject': 'Welcome to EzzDay!',
            'template': 'welcome_email',
            'data': {
                'user_name': self.registration_data['name'],
                'email': self.email,
                'next_steps': [
                    'Complete your profile',
                    'Set up two-factor authentication',
                    'Explore the dashboard'
                ]
            }
        }
        
        await asyncio.sleep(0.1)
        
        logger.info(
            "Welcome notification sent",
            workflow_id=str(context.workflow_id),
            user_id=str(self.user_id),
            email=self.email
        )
        
        return {
            'welcome_notification_sent': True,
            'welcome_email': welcome_email
        }
    
    async def _register_external_systems(self, step_input: dict[str, Any]) -> dict[str, Any]:
        """Register user with external systems."""
        context = step_input['context']
        
        # Simulate registering with external systems
        external_registrations = []
        
        # CRM system
        if context.input_data.get('register_crm', True):
            crm_data = {
                'system': 'crm',
                'user_id': str(self.user_id),
                'email': self.email,
                'name': self.registration_data['name'],
                'registered_at': datetime.utcnow().isoformat()
            }
            external_registrations.append(crm_data)
            await asyncio.sleep(0.1)
        
        # Analytics system
        if context.input_data.get('register_analytics', True):
            analytics_data = {
                'system': 'analytics',
                'user_id': str(self.user_id),
                'email': self.email,
                'registration_date': datetime.utcnow().isoformat(),
                'source': context.input_data.get('registration_source', 'direct')
            }
            external_registrations.append(analytics_data)
            await asyncio.sleep(0.1)
        
        logger.info(
            "External systems registration completed",
            workflow_id=str(context.workflow_id),
            user_id=str(self.user_id),
            systems_count=len(external_registrations)
        )
        
        return {
            'external_registrations_completed': True,
            'registrations': external_registrations
        }
    
    async def _complete_registration(self, step_input: dict[str, Any]) -> dict[str, Any]:
        """Complete the registration process."""
        context = step_input['context']
        
        # Final registration summary
        registration_summary = {
            'user_id': str(self.user_id),
            'email': self.email,
            'name': self.registration_data['name'],
            'registration_completed_at': datetime.utcnow().isoformat(),
            'workflow_id': str(context.workflow_id),
            'email_verified': self.email_verified,
            'phone_verified': self.phone_verified,
            'profile_completed': self.profile_completed,
            'status': 'completed',
            'next_steps': [
                'Login to your account',
                'Complete profile information',
                'Set up security preferences'
            ]
        }
        
        logger.info(
            "User registration completed successfully",
            workflow_id=str(context.workflow_id),
            user_id=str(self.user_id),
            email=self.email,
            email_verified=self.email_verified,
            phone_verified=self.phone_verified
        )
        
        return {
            'registration_completed': True,
            'registration_summary': registration_summary
        }
    
    # Compensation Handlers
    
    async def _cleanup_failed_validation(self, compensation_input: dict[str, Any]) -> None:
        """Cleanup after failed validation."""
        logger.info("Cleaning up failed validation")
        # No specific cleanup needed for validation failure
    
    async def _delete_user_account(self, compensation_input: dict[str, Any]) -> None:
        """Delete user account on failure."""
        if self.user_id:
            logger.info(
                "Deleting user account due to registration failure",
                user_id=str(self.user_id)
            )
            # Simulate user deletion
            await asyncio.sleep(0.1)
    
    async def _cancel_email_verification(self, compensation_input: dict[str, Any]) -> None:
        """Cancel email verification."""
        if self.user_id:
            logger.info(
                "Cancelling email verification",
                user_id=str(self.user_id)
            )
            # Simulate cancellation
            await asyncio.sleep(0.05)
    
    async def _cleanup_security_profile(self, compensation_input: dict[str, Any]) -> None:
        """Cleanup security profile."""
        if self.user_id:
            logger.info(
                "Cleaning up security profile",
                user_id=str(self.user_id)
            )
            await asyncio.sleep(0.05)
    
    async def _cancel_phone_verification(self, compensation_input: dict[str, Any]) -> None:
        """Cancel phone verification."""
        logger.info("Cancelling phone verification")
        await asyncio.sleep(0.05)
    
    async def _cleanup_user_profile(self, compensation_input: dict[str, Any]) -> None:
        """Cleanup user profile."""
        if self.user_id:
            logger.info(
                "Cleaning up user profile",
                user_id=str(self.user_id)
            )
            await asyncio.sleep(0.05)
    
    async def _deactivate_user_account(self, compensation_input: dict[str, Any]) -> None:
        """Deactivate user account."""
        if self.user_id:
            logger.info(
                "Deactivating user account",
                user_id=str(self.user_id)
            )
            await asyncio.sleep(0.05)
    
    async def _unregister_external_systems(self, compensation_input: dict[str, Any]) -> None:
        """Unregister from external systems."""
        if self.user_id:
            logger.info(
                "Unregistering from external systems",
                user_id=str(self.user_id)
            )
            await asyncio.sleep(0.1)