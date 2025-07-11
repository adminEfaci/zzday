"""
SAML SSO command implementation.

Handles SAML-based single sign-on authentication and user provisioning.
"""

import xml.etree.ElementTree as ET
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    validate_request,
)
from app.modules.identity.application.dtos.internal import (
    AuditContext,
    EmailContext,
    NotificationContext,
    SamlContext,
    SessionContext,
)
from app.modules.identity.application.dtos.request import SamlSsoRequest
from app.modules.identity.application.dtos.response import SamlSsoResponse
from app.modules.identity.domain.entities import Session, User
from app.modules.identity.domain.enums import (
    AuditAction,
    NotificationType,
    RiskLevel,
    SamlBindingType,
    SecurityEventType,
    SessionType,
)
from app.modules.identity.domain.events import (
    SamlSsoAuthenticated,
)
from app.modules.identity.domain.exceptions import (
    InvalidSamlResponseError,
    SamlAuthenticationError,
    SamlConfigurationError,
    SamlSignatureError,
    SamlValidationError,
    UserProvisioningError,
)
from app.modules.identity.domain.interfaces.repositories.device_registration_repository import (
    IDeviceRepository,
)
from app.modules.identity.domain.interfaces.repositories.session_repository import (
    ISessionRepository,
)
from app.modules.identity.domain.interfaces.repositories.user_repository import (
    IUserRepository,
)
from app.modules.identity.domain.interfaces.services.communication.notification_service import (
    IEmailService,
    INotificationService,
)
from app.modules.identity.domain.services import (
    SecurityService,
    SessionService,
    UserService,
    ValidationService,
)


class SamlSsoCommand(Command[SamlSsoResponse]):
    """Command to handle SAML SSO authentication."""
    
    def __init__(
        self,
        saml_response: str,
        relay_state: str | None = None,
        saml_provider_id: UUID | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        device_fingerprint: str | None = None,
        requested_url: str | None = None,
        binding_type: SamlBindingType = SamlBindingType.HTTP_POST,
        validate_signature: bool = True,
        validate_assertion: bool = True,
        validate_conditions: bool = True,
        auto_provision_users: bool = True,
        update_existing_users: bool = True,
        create_session: bool = True,
        session_duration_hours: int = 8,
        require_encryption: bool = False,
        allowed_clock_skew_minutes: int = 5,
        store_saml_response: bool = False,
        notify_on_first_login: bool = True,
        metadata: dict[str, Any] | None = None
    ):
        self.saml_response = saml_response
        self.relay_state = relay_state
        self.saml_provider_id = saml_provider_id
        self.ip_address = ip_address
        self.user_agent = user_agent
        self.device_fingerprint = device_fingerprint
        self.requested_url = requested_url
        self.binding_type = binding_type
        self.validate_signature = validate_signature
        self.validate_assertion = validate_assertion
        self.validate_conditions = validate_conditions
        self.auto_provision_users = auto_provision_users
        self.update_existing_users = update_existing_users
        self.create_session = create_session
        self.session_duration_hours = session_duration_hours
        self.require_encryption = require_encryption
        self.allowed_clock_skew_minutes = allowed_clock_skew_minutes
        self.store_saml_response = store_saml_response
        self.notify_on_first_login = notify_on_first_login
        self.metadata = metadata or {}


class SamlSsoCommandHandler(CommandHandler[SamlSsoCommand, SamlSsoResponse]):
    """Handler for SAML SSO authentication."""
    
    def __init__(
        self,
        user_repository: IUserRepository,
        session_repository: ISessionRepository,
        device_repository: IDeviceRepository,
        saml_repository: ISamlRepository,
        saml_service: ISamlService,
        user_service: UserService,
        session_service: SessionService,
        validation_service: ValidationService,
        security_service: SecurityService,
        notification_service: INotificationService,
        audit_service: IAuditService,
        email_service: IEmailService,
        event_bus: EventBus,
        unit_of_work: UnitOfWork
    ):
        self._user_repository = user_repository
        self._session_repository = session_repository
        self._device_repository = device_repository
        self._saml_repository = saml_repository
        self._saml_service = saml_service
        self._user_service = user_service
        self._session_service = session_service
        self._validation_service = validation_service
        self._security_service = security_service
        self._notification_service = notification_service
        self._audit_service = audit_service
        self._email_service = email_service
        self._event_bus = event_bus
        self._unit_of_work = unit_of_work
    
    @audit_action(
        action=AuditAction.SAML_SSO_ATTEMPTED,
        resource_type="saml_authentication",
        include_request=True,
        include_response=True,
        include_ip_address=True
    )
    @validate_request(SamlSsoRequest)
    @rate_limit(
        max_requests=30,
        window_seconds=900,  # 15 minutes
        strategy='ip'
    )
    async def handle(self, command: SamlSsoCommand) -> SamlSsoResponse:
        """
        Process SAML SSO authentication with comprehensive validation.
        
        Process:
        1. Load SAML provider configuration
        2. Validate and parse SAML response
        3. Verify SAML response signature and conditions
        4. Extract user attributes from SAML assertion
        5. Find or provision user account
        6. Perform security checks and risk assessment
        7. Create user session if successful
        8. Handle device registration/trust
        9. Send notifications and log events
        10. Generate authentication response
        
        Returns:
            SamlSsoResponse with authentication details
            
        Raises:
            SamlAuthenticationError: If SAML authentication fails
            SamlValidationError: If SAML response validation fails
            InvalidSamlResponseError: If SAML response is invalid
            UserProvisioningError: If user provisioning fails
            SamlSignatureError: If signature validation fails
        """
        async with self._unit_of_work:
            # 1. Load SAML provider configuration
            saml_provider = await self._saml_repository.find_by_id(command.saml_provider_id)
            if not saml_provider:
                raise SamlConfigurationError(f"SAML provider {command.saml_provider_id} not found")
            
            if not saml_provider.enabled:
                raise SamlConfigurationError("SAML provider is disabled")
            
            # 2. Parse and validate SAML response
            saml_data = await self._parse_and_validate_saml_response(
                command.saml_response,
                saml_provider,
                command
            )
            
            # 3. Extract user information from SAML assertion
            user_attributes = await self._extract_user_attributes(
                saml_data,
                saml_provider,
                command
            )
            
            # 4. Find or provision user
            user, is_new_user = await self._find_or_provision_user(
                user_attributes,
                saml_provider,
                command
            )
            
            # 5. Perform security risk assessment
            risk_assessment = await self._assess_authentication_risk(
                user,
                saml_data,
                command
            )
            
            # 6. Handle device registration/trust if device info provided
            device = None
            if command.device_fingerprint:
                device = await self._handle_device_authentication(
                    user,
                    command.device_fingerprint,
                    command.ip_address,
                    command.user_agent,
                    risk_assessment
                )
            
            # 7. Create user session if requested
            session = None
            if command.create_session:
                session = await self._create_authentication_session(
                    user,
                    device,
                    saml_data,
                    risk_assessment,
                    command
                )
            
            # 8. Handle first-time login notifications
            if is_new_user and command.notify_on_first_login:
                await self._send_first_login_notifications(user, saml_provider, command)
            
            # 9. Store SAML response if requested (for debugging/audit)
            saml_response_id = None
            if command.store_saml_response:
                saml_response_id = await self._store_saml_response(
                    saml_data,
                    user,
                    session,
                    command
                )
            
            # 10. Log successful authentication
            await self._log_successful_authentication(
                user,
                session,
                saml_provider,
                saml_data,
                risk_assessment,
                command
            )
            
            # 11. Publish domain event
            await self._event_bus.publish(
                SamlSsoAuthenticated(
                    aggregate_id=user.id,
                    user_id=user.id,
                    session_id=session.id if session else None,
                    device_id=device.id if device else None,
                    saml_provider_id=command.saml_provider_id,
                    saml_provider_name=saml_provider.name,
                    name_id=saml_data["name_id"],
                    name_id_format=saml_data["name_id_format"],
                    is_new_user=is_new_user,
                    ip_address=command.ip_address,
                    user_agent=command.user_agent,
                    risk_level=risk_assessment["risk_level"],
                    authentication_method="saml_sso"
                )
            )
            
            # 12. Commit transaction
            await self._unit_of_work.commit()
            
            # 13. Generate response
            return SamlSsoResponse(
                success=True,
                user_id=user.id,
                session_id=session.id if session else None,
                device_id=device.id if device else None,
                username=user.username,
                email=user.email,
                full_name=user.full_name,
                is_new_user=is_new_user,
                saml_provider_id=command.saml_provider_id,
                saml_provider_name=saml_provider.name,
                name_id=saml_data["name_id"],
                name_id_format=saml_data["name_id_format"],
                relay_state=command.relay_state,
                session_expires_at=session.expires_at if session else None,
                risk_level=risk_assessment["risk_level"],
                risk_factors=risk_assessment["risk_factors"],
                authentication_time=datetime.now(UTC),
                saml_response_id=saml_response_id,
                redirect_url=self._determine_redirect_url(command.relay_state, command.requested_url),
                message="SAML SSO authentication successful"
            )
    
    async def _parse_and_validate_saml_response(
        self,
        saml_response: str,
        saml_provider: Any,
        command: SamlSsoCommand
    ) -> dict[str, Any]:
        """Parse and validate SAML response."""
        try:
            # Parse SAML response XML
            parsed_response = await self._saml_service.parse_response(
                SamlContext(
                    saml_response=saml_response,
                    binding_type=command.binding_type,
                    relay_state=command.relay_state,
                    provider_config=saml_provider.configuration
                )
            )
            
            # Validate response structure
            if not parsed_response.get("assertion"):
                raise InvalidSamlResponseError("SAML response missing assertion")
            
            # Validate signature if required
            if command.validate_signature:
                await self._validate_saml_signature(
                    parsed_response,
                    saml_provider,
                    command
                )
            
            # Validate assertion conditions
            if command.validate_assertion:
                await self._validate_saml_assertion(
                    parsed_response["assertion"],
                    saml_provider,
                    command
                )
            
            # Validate time conditions
            if command.validate_conditions:
                await self._validate_saml_conditions(
                    parsed_response["assertion"],
                    command.allowed_clock_skew_minutes
                )
            
            # Check encryption requirements
            if command.require_encryption and not parsed_response.get("encrypted"):
                raise SamlValidationError("SAML response must be encrypted")
            
            return parsed_response
            
        except ET.ParseError as e:
            raise InvalidSamlResponseError(f"Invalid SAML XML: {e!s}") from e
        except Exception as e:
            raise SamlAuthenticationError(f"SAML response validation failed: {e!s}") from e
    
    async def _validate_saml_signature(
        self,
        parsed_response: dict[str, Any],
        saml_provider: Any,
        command: SamlSsoCommand
    ) -> None:
        """Validate SAML response signature."""
        try:
            signature_valid = await self._saml_service.verify_signature(
                parsed_response,
                saml_provider.configuration.get("idp_certificate"),
                saml_provider.configuration.get("signature_algorithm")
            )
            
            if not signature_valid:
                raise SamlSignatureError("SAML response signature validation failed")
                
        except Exception as e:
            raise SamlSignatureError(f"Signature validation error: {e!s}") from e
    
    async def _validate_saml_assertion(
        self,
        assertion: dict[str, Any],
        saml_provider: Any,
        command: SamlSsoCommand
    ) -> None:
        """Validate SAML assertion content."""
        # Validate audience
        audience = assertion.get("audience")
        expected_audience = saml_provider.configuration.get("sp_entity_id")
        
        if audience != expected_audience:
            raise SamlValidationError(f"Invalid audience: {audience}, expected: {expected_audience}")
        
        # Validate issuer
        issuer = assertion.get("issuer")
        expected_issuer = saml_provider.configuration.get("idp_entity_id")
        
        if issuer != expected_issuer:
            raise SamlValidationError(f"Invalid issuer: {issuer}, expected: {expected_issuer}")
        
        # Validate NameID format
        name_id_format = assertion.get("name_id_format")
        allowed_formats = saml_provider.configuration.get("allowed_name_id_formats", [])
        
        if allowed_formats and name_id_format not in allowed_formats:
            raise SamlValidationError(f"Unsupported NameID format: {name_id_format}")
    
    async def _validate_saml_conditions(
        self,
        assertion: dict[str, Any],
        allowed_clock_skew_minutes: int
    ) -> None:
        """Validate SAML assertion time conditions."""
        now = datetime.now(UTC)
        clock_skew = timedelta(minutes=allowed_clock_skew_minutes)
        
        # Validate NotBefore condition
        not_before = assertion.get("not_before")
        if not_before:
            not_before_dt = datetime.fromisoformat(not_before.replace('Z', '+00:00'))
            if now < (not_before_dt - clock_skew):
                raise SamlValidationError(f"SAML assertion not yet valid (NotBefore: {not_before})")
        
        # Validate NotOnOrAfter condition
        not_on_or_after = assertion.get("not_on_or_after")
        if not_on_or_after:
            not_on_or_after_dt = datetime.fromisoformat(not_on_or_after.replace('Z', '+00:00'))
            if now >= (not_on_or_after_dt + clock_skew):
                raise SamlValidationError(f"SAML assertion expired (NotOnOrAfter: {not_on_or_after})")
        
        # Validate authentication instant
        auth_instant = assertion.get("authentication_instant")
        if auth_instant:
            auth_instant_dt = datetime.fromisoformat(auth_instant.replace('Z', '+00:00'))
            # Authentication should not be too old (e.g., more than 1 hour)
            if now > (auth_instant_dt + timedelta(hours=1) + clock_skew):
                raise SamlValidationError(f"Authentication too old (AuthnInstant: {auth_instant})")
    
    async def _extract_user_attributes(
        self,
        saml_data: dict[str, Any],
        saml_provider: Any,
        command: SamlSsoCommand
    ) -> dict[str, Any]:
        """Extract user attributes from SAML assertion."""
        assertion = saml_data["assertion"]
        attributes = assertion.get("attributes", {})
        
        # Get attribute mapping configuration
        attribute_mapping = saml_provider.configuration.get("attribute_mapping", {})
        
        # Default attribute extraction
        user_attributes = {
            "name_id": assertion.get("name_id"),
            "name_id_format": assertion.get("name_id_format"),
            "saml_provider_id": command.saml_provider_id,
            "authentication_instant": assertion.get("authentication_instant"),
            "session_index": assertion.get("session_index")
        }
        
        # Map SAML attributes to user fields
        field_mapping = {
            "email": ["email", "emailAddress", "mail", "Email", "EmailAddress"],
            "username": ["username", "uid", "sAMAccountName", "UserName"],
            "first_name": ["firstName", "givenName", "FirstName", "GivenName"],
            "last_name": ["lastName", "sn", "surname", "LastName", "Surname"],
            "full_name": ["displayName", "fullName", "cn", "DisplayName", "FullName"],
            "phone_number": ["phoneNumber", "telephoneNumber", "Phone", "PhoneNumber"],
            "department": ["department", "Department"],
            "title": ["title", "jobTitle", "Title", "JobTitle"],
            "employee_id": ["employeeId", "employeeNumber", "EmployeeId", "EmployeeNumber"],
            "groups": ["groups", "memberOf", "Groups", "MemberOf"]
        }
        
        # Apply custom attribute mapping if configured
        for saml_attr, user_field in attribute_mapping.items():
            if saml_attr in attributes:
                user_attributes[user_field] = attributes[saml_attr]
        
        # Apply default field mapping
        for user_field, possible_saml_attrs in field_mapping.items():
            if user_field not in user_attributes:  # Don't override custom mapping
                for saml_attr in possible_saml_attrs:
                    if saml_attr in attributes:
                        user_attributes[user_field] = attributes[saml_attr]
                        break
        
        # Validate required attributes
        required_attrs = saml_provider.configuration.get("required_attributes", ["email"])
        for required_attr in required_attrs:
            if not user_attributes.get(required_attr):
                raise SamlValidationError(f"Required attribute missing: {required_attr}")
        
        # Process groups if present
        if "groups" in user_attributes:
            groups = user_attributes["groups"]
            if isinstance(groups, str):
                user_attributes["groups"] = [g.strip() for g in groups.split(",")]
            elif not isinstance(groups, list):
                user_attributes["groups"] = [str(groups)]
        
        return user_attributes
    
    async def _find_or_provision_user(
        self,
        user_attributes: dict[str, Any],
        saml_provider: Any,
        command: SamlSsoCommand
    ) -> tuple[User, bool]:
        """Find existing user or provision new user from SAML attributes."""
        # Try to find existing user by SAML NameID
        name_id = user_attributes["name_id"]
        existing_user = await self._user_repository.find_by_saml_name_id(
            command.saml_provider_id,
            name_id
        )
        
        if existing_user:
            # Update existing user if enabled
            if command.update_existing_users:
                await self._update_user_from_saml(existing_user, user_attributes, command)
            return existing_user, False
        
        # Try to find by email if NameID lookup failed
        email = user_attributes.get("email")
        if email:
            existing_user = await self._user_repository.find_by_email(email)
            if existing_user:
                # Link existing user to SAML provider
                await self._link_user_to_saml_provider(
                    existing_user,
                    user_attributes,
                    command
                )
                return existing_user, False
        
        # Provision new user if auto-provisioning is enabled
        if command.auto_provision_users:
            new_user = await self._provision_user_from_saml(
                user_attributes,
                saml_provider,
                command
            )
            return new_user, True
        raise UserProvisioningError(
            f"User not found and auto-provisioning disabled for NameID: {name_id}"
        )
    
    async def _update_user_from_saml(
        self,
        user: User,
        user_attributes: dict[str, Any],
        command: SamlSsoCommand
    ) -> None:
        """Update existing user with SAML attributes."""
        update_data = {}
        
        # Fields that can be updated from SAML
        updatable_fields = [
            "first_name", "last_name", "full_name", "phone_number",
            "department", "title", "employee_id"
        ]
        
        for field in updatable_fields:
            if user_attributes.get(field):
                current_value = getattr(user, field, None)
                new_value = user_attributes[field]
                
                if current_value != new_value:
                    update_data[field] = new_value
        
        # Update SAML-specific metadata
        update_data["saml_last_login"] = datetime.now(UTC)
        update_data["saml_session_index"] = user_attributes.get("session_index")
        
        if update_data:
            await self._user_service.update_user(user.id, update_data)
    
    async def _link_user_to_saml_provider(
        self,
        user: User,
        user_attributes: dict[str, Any],
        command: SamlSsoCommand
    ) -> None:
        """Link existing user to SAML provider."""
        saml_link_data = {
            "saml_provider_id": command.saml_provider_id,
            "saml_name_id": user_attributes["name_id"],
            "saml_name_id_format": user_attributes["name_id_format"],
            "saml_session_index": user_attributes.get("session_index"),
            "saml_first_linked": datetime.now(UTC),
            "saml_last_login": datetime.now(UTC)
        }
        
        await self._user_service.add_saml_identity(user.id, saml_link_data)
    
    async def _provision_user_from_saml(
        self,
        user_attributes: dict[str, Any],
        saml_provider: Any,
        command: SamlSsoCommand
    ) -> User:
        """Provision new user from SAML attributes."""
        # Generate username if not provided
        username = user_attributes.get("username")
        if not username:
            email = user_attributes.get("email")
            if email:
                username = email.split("@")[0]
            else:
                username = f"saml_user_{user_attributes['name_id'][:8]}"
        
        # Ensure username is unique
        username = await self._user_service.ensure_unique_username(username)
        
        user_data = {
            "username": username,
            "email": user_attributes.get("email"),
            "first_name": user_attributes.get("first_name"),
            "last_name": user_attributes.get("last_name"),
            "full_name": user_attributes.get("full_name"),
            "phone_number": user_attributes.get("phone_number"),
            "department": user_attributes.get("department"),
            "title": user_attributes.get("title"),
            "employee_id": user_attributes.get("employee_id"),
            "email_verified": True,  # Assume SAML emails are verified
            "is_active": True,
            "source": "saml_sso",
            "saml_provider_id": command.saml_provider_id,
            "saml_name_id": user_attributes["name_id"],
            "saml_name_id_format": user_attributes["name_id_format"],
            "saml_session_index": user_attributes.get("session_index"),
            "saml_first_login": datetime.now(UTC),
            "saml_last_login": datetime.now(UTC)
        }
        
        # Remove None values
        user_data = {k: v for k, v in user_data.items() if v is not None}
        
        try:
            user = await self._user_service.create_user_from_external_source(user_data)
            
            # Handle group memberships if provided
            if user_attributes.get("groups"):
                await self._handle_saml_group_memberships(
                    user,
                    user_attributes["groups"],
                    saml_provider
                )
            
            return user
            
        except Exception as e:
            raise UserProvisioningError(f"Failed to provision user: {e!s}") from e
    
    async def _handle_saml_group_memberships(
        self,
        user: User,
        groups: list[str],
        saml_provider: Any
    ) -> None:
        """Handle user group memberships from SAML."""
        # Get group mapping configuration
        group_mapping = saml_provider.configuration.get("group_mapping", {})
        
        # Map SAML groups to application roles
        roles_to_assign = []
        for saml_group in groups:
            # Check if group is mapped to a role
            if saml_group in group_mapping:
                role_name = group_mapping[saml_group]
                role = await self._role_repository.find_by_name(role_name)
                if role:
                    roles_to_assign.append(role.id)
        
        # Assign roles to user
        if roles_to_assign:
            await self._user_service.assign_roles(user.id, roles_to_assign)
    
    async def _assess_authentication_risk(
        self,
        user: User,
        saml_data: dict[str, Any],
        command: SamlSsoCommand
    ) -> dict[str, Any]:
        """Assess risk level for SAML authentication."""
        risk_factors = []
        risk_score = 0
        
        # Check if this is a new user
        if user.created_at and (datetime.now(UTC) - user.created_at).total_seconds() < 300:
            risk_factors.append("new_user_account")
            risk_score += 20
        
        # Check authentication method context
        auth_context = saml_data["assertion"].get("authentication_context")
        if auth_context:
            # Lower risk for strong authentication methods
            strong_auth_methods = [
                "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
                "urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient",
                "urn:oasis:names:tc:SAML:2.0:ac:classes:X509"
            ]
            
            if auth_context not in strong_auth_methods:
                risk_factors.append("weak_authentication_method")
                risk_score += 15
        
        # Check IP address reputation if available
        if command.ip_address:
            # TODO: Integrate with threat intelligence service for IP reputation checks
            pass
        
        # Check time since last login
        if user.last_login_at:
            time_since_last_login = datetime.now(UTC) - user.last_login_at
            if time_since_last_login.days > 90:
                risk_factors.append("long_time_since_last_login")
                risk_score += 10
        
        # Check for unusual login patterns
        if command.ip_address and user.login_history:
            # Check if this IP is new for the user
            recent_ips = [login.ip_address for login in user.login_history[-10:]]
            if command.ip_address not in recent_ips:
                risk_factors.append("new_ip_address")
                risk_score += 15
        
        # Determine risk level
        if risk_score >= 60:
            risk_level = "high"
        elif risk_score >= 30:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "risk_factors": risk_factors,
            "assessment_timestamp": datetime.now(UTC).isoformat()
        }
    
    async def _handle_device_authentication(
        self,
        user: User,
        device_fingerprint: str,
        ip_address: str | None,
        user_agent: str | None,
        risk_assessment: dict[str, Any]
    ) -> Any | None:
        """Handle device registration/authentication."""
        # Try to find existing device
        device = await self._device_repository.find_by_fingerprint(device_fingerprint)
        
        if device:
            # Update existing device
            device.last_seen_at = datetime.now(UTC)
            device.ip_address = ip_address
            device.user_agent = user_agent
            await self._device_repository.update(device)
            return device
        # Register new device
        device_data = {
            "user_id": user.id,
            "device_fingerprint": device_fingerprint,
            "device_type": "web",  # Assuming web SSO
            "device_name": "SAML SSO Device",
            "ip_address": ip_address,
            "user_agent": user_agent,
            "trust_level": "untrusted",  # Start as untrusted
            "source": "saml_sso",
            "registered_at": datetime.now(UTC),
            "last_seen_at": datetime.now(UTC)
        }
        
        # Auto-trust device if low risk
        if risk_assessment["risk_level"] == "low":
            device_data["trust_level"] = "partially_trusted"
        
        return await self._device_repository.create(device_data)
    
    async def _create_authentication_session(
        self,
        user: User,
        device: Any | None,
        saml_data: dict[str, Any],
        risk_assessment: dict[str, Any],
        command: SamlSsoCommand
    ) -> Session:
        """Create authentication session."""
        session_data = {
            "user_id": user.id,
            "device_id": device.id if device else None,
            "session_type": SessionType.SAML_SSO,
            "ip_address": command.ip_address,
            "user_agent": command.user_agent,
            "expires_at": datetime.now(UTC) + timedelta(hours=command.session_duration_hours),
            "saml_provider_id": command.saml_provider_id,
            "saml_session_index": saml_data["assertion"].get("session_index"),
            "saml_name_id": saml_data["assertion"].get("name_id"),
            "authentication_method": "saml_sso",
            "risk_level": risk_assessment["risk_level"],
            "created_at": datetime.now(UTC),
            "last_activity": datetime.now(UTC)
        }
        
        return await self._session_service.create_session(
            SessionContext(**session_data)
        )
    
    async def _send_first_login_notifications(
        self,
        user: User,
        saml_provider: Any,
        command: SamlSsoCommand
    ) -> None:
        """Send notifications for first-time SAML login."""
        # In-app notification
        await self._notification_service.create_notification(
            NotificationContext(
                notification_id=UUID(),
                recipient_id=user.id,
                notification_type=NotificationType.FIRST_SAML_LOGIN,
                channel="in_app",
                template_id="first_saml_login",
                template_data={
                    "saml_provider_name": saml_provider.name,
                    "login_time": datetime.now(UTC).isoformat(),
                    "ip_address": command.ip_address
                },
                priority="medium"
            )
        )
        
        # Email notification if email is verified
        if user.email_verified and user.email:
            await self._email_service.send_email(
                EmailContext(
                    recipient=user.email,
                    template="first_saml_login",
                    subject=f"Welcome - First login via {saml_provider.name}",
                    variables={
                        "username": user.username,
                        "full_name": user.full_name,
                        "saml_provider_name": saml_provider.name,
                        "login_time": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"),
                        "ip_address": command.ip_address,
                        "support_link": "https://app.example.com/support"
                    }
                )
            )
    
    async def _store_saml_response(
        self,
        saml_data: dict[str, Any],
        user: User,
        session: Session | None,
        command: SamlSsoCommand
    ) -> UUID:
        """Store SAML response for audit/debugging purposes."""
        saml_response_record = {
            "id": UUID(),
            "user_id": user.id,
            "session_id": session.id if session else None,
            "saml_provider_id": command.saml_provider_id,
            "saml_response_xml": command.saml_response,
            "parsed_data": saml_data,
            "relay_state": command.relay_state,
            "ip_address": command.ip_address,
            "user_agent": command.user_agent,
            "stored_at": datetime.now(UTC),
            "expires_at": datetime.now(UTC) + timedelta(days=30)  # Retain for 30 days
        }
        
        return await self._saml_repository.store_response(saml_response_record)
    
    async def _log_successful_authentication(
        self,
        user: User,
        session: Session | None,
        saml_provider: Any,
        saml_data: dict[str, Any],
        risk_assessment: dict[str, Any],
        command: SamlSsoCommand
    ) -> None:
        """Log successful SAML authentication."""
        await self._audit_service.log_action(
            AuditContext(
                action=AuditAction.SAML_SSO_SUCCESS,
                actor_id=user.id,
                resource_type="authentication",
                resource_id=session.id if session else None,
                details={
                    "saml_provider_id": str(command.saml_provider_id),
                    "saml_provider_name": saml_provider.name,
                    "name_id": saml_data["assertion"].get("name_id"),
                    "name_id_format": saml_data["assertion"].get("name_id_format"),
                    "session_index": saml_data["assertion"].get("session_index"),
                    "authentication_instant": saml_data["assertion"].get("authentication_instant"),
                    "ip_address": command.ip_address,
                    "user_agent": command.user_agent,
                    "risk_assessment": risk_assessment,
                    "binding_type": command.binding_type.value,
                    "session_duration_hours": command.session_duration_hours
                },
                risk_level=risk_assessment["risk_level"]
            )
        )
        
        # Log as security event if high risk
        if risk_assessment["risk_level"] == "high":
            await self._audit_service.log_security_incident(
                {
                    "incident_type": SecurityEventType.HIGH_RISK_LOGIN,
                    "severity": RiskLevel.HIGH,
                    "user_id": user.id,
                    "details": {
                        "authentication_method": "saml_sso",
                        "saml_provider": saml_provider.name,
                        "risk_factors": risk_assessment["risk_factors"],
                        "risk_score": risk_assessment["risk_score"]
                    },
                    "indicators": risk_assessment["risk_factors"]
                }
            )
    
    def _determine_redirect_url(
        self,
        relay_state: str | None,
        requested_url: str | None
    ) -> str:
        """Determine where to redirect user after successful authentication."""
        if relay_state:
            # RelayState typically contains the original URL
            return relay_state
        if requested_url:
            return requested_url
        # Default redirect URL
        return "https://app.example.com/dashboard"