"""
Anonymize user data command implementation.

Handles GDPR-compliant data anonymization for user privacy.
"""

import hashlib
import json
import os
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    require_approval,
    require_mfa,
    require_permission,
    validate_request,
)
from app.modules.identity.application.dtos.administrative import (
    AdminContext,
    AnonymizationConfig,
    InfrastructureDependencies,
    ServiceDependencies,
)
from app.modules.identity.application.dtos.internal import (
    EmailContext,
    NotificationContext,
    SecurityIncidentContext,
)
from app.modules.identity.application.dtos.request import AnonymizeUserDataRequest
from app.modules.identity.application.dtos.response import DataAnonymizationResponse
from app.modules.identity.domain.entities import User
from app.modules.identity.domain.enums import (
    AuditAction,
    NotificationType,
    RiskLevel,
    SecurityEventType,
    UserStatus,
)
from app.modules.identity.domain.events import DataRetentionApplied, UserDataAnonymized
from app.modules.identity.domain.exceptions import (
    InvalidOperationError,
    UnauthorizedError,
    UserNotFoundError,
)
from app.modules.identity.domain.services import (
    DataPrivacyService,
)


class AnonymizationLevel(Enum):
    """Levels of data anonymization."""
    MINIMAL = "minimal"  # Only PII
    STANDARD = "standard"  # PII + behavioral data
    COMPLETE = "complete"  # Everything except required audit trail
    CUSTOM = "custom"  # User-defined categories


class AnonymizeUserDataCommand(Command[DataAnonymizationResponse]):
    """Command to anonymize user data."""
    
    def __init__(
        self,
        admin_context: AdminContext,
        anonymization_config: AnonymizationConfig
    ):
        self.admin_context = admin_context
        self.anonymization_config = anonymization_config
        
        # For backward compatibility, expose common fields
        self.target_user_id = admin_context.target_user_id
        self.admin_user_id = admin_context.admin_user_id
        self.reason = admin_context.reason
        self.data_categories = anonymization_config.data_categories
        self.anonymization_level = AnonymizationLevel(
            anonymization_config.anonymization_level
        )
        self.retain_for_legal = anonymization_config.retain_for_legal
        self.legal_retention_days = anonymization_config.legal_retention_days or 2555
        self.create_backup = anonymization_config.create_backup
        self.notify_user = anonymization_config.notify_user
        self.immediate_deletion = anonymization_config.immediate_deletion
        self.custom_rules = anonymization_config.custom_rules
        self.metadata = {**admin_context.metadata, **anonymization_config.metadata}


class AnonymizeUserDataCommandHandler(
    CommandHandler[AnonymizeUserDataCommand, DataAnonymizationResponse]
):
    """Handler for user data anonymization."""
    
    def __init__(
        self,
        services: ServiceDependencies,
        infrastructure: InfrastructureDependencies,
        data_privacy_service: DataPrivacyService
    ):
        self._user_repository = services.user_repository
        self._session_repository = services.session_repository
        self._audit_repository = services.audit_repository
        self._notification_repository = services.notification_repository
        self._authorization_service = services.authorization_service
        self._security_service = services.security_service
        self._email_service = services.email_service
        self._backup_service = services.backup_service
        self._data_privacy_service = data_privacy_service
        self._event_bus = infrastructure.event_bus
        self._unit_of_work = infrastructure.unit_of_work
    
    @audit_action(
        action=AuditAction.DATA_ANONYMIZATION,
        resource_type="user",
        include_request=True,
        include_response=True,
        gdpr_compliant=True,
        high_priority=True
    )
    @validate_request(AnonymizeUserDataRequest)
    @rate_limit(
        max_requests=50,
        window_seconds=86400,
        strategy='global'
    )
    @require_permission(
        "users.anonymize_data",
        resource_type="user",
        resource_id_param="target_user_id"
    )
    @require_mfa()
    @require_approval(
        approval_type="data_anonymization",
        approvers=["data_protection_officer", "legal_team"]
    )
    async def handle(
        self, command: AnonymizeUserDataCommand
    ) -> DataAnonymizationResponse:
        """
        Anonymize user data with comprehensive privacy protection.
        
        Process:
        1. Validate anonymization request
        2. Create backup if required
        3. Apply anonymization rules
        4. Update all related records
        5. Clear caches and sessions
        6. Generate anonymization certificate
        7. Send notifications
        
        Returns:
            DataAnonymizationResponse with results
            
        Raises:
            UserNotFoundError: If user not found
            UnauthorizedError: If lacks permission
            InvalidOperationError: If operation invalid
            DataAnonymizationError: If anonymization fails
        """
        async with self._unit_of_work:
            # Validate users and permissions
            admin_user, target_user = await self._validate_users_and_permissions(
                command.admin_user_id,
                command.target_user_id
            )
            
            # Validate operation and check legal holds
            await self._validate_anonymization_operation(
                target_user,
                command
            )
            
            # Create backup if required
            backup_id = None
            if command.create_backup:
                backup_id = await self._create_pre_anonymization_backup(
                    target_user,
                    command
                )
            
            # Prepare anonymization
            anonymization_id = UUID()
            anonymized_at = datetime.now(UTC)
            
            # Execute anonymization
            result = await self._execute_anonymization(
                target_user,
                command,
                anonymization_id
            )
            
            # Post-anonymization processing
            certificate = await self._post_anonymization_processing(
                target_user,
                command,
                anonymization_id,
                result,
                backup_id
            )
            
            # Commit transaction
            await self._unit_of_work.commit()
            
            # Post-commit notifications
            await self._send_post_commit_notifications(
                target_user,
                command,
                anonymization_id,
                certificate
            )
            
            return DataAnonymizationResponse(
                user_id=target_user.id,
                anonymization_id=anonymization_id,
                data_categories=command.data_categories,
                status="completed",
                anonymized_fields=result["anonymized_fields"],
                retained_fields=result["retained_fields"],
                completion_date=anonymized_at,
                certificate_url=certificate["url"],
                backup_id=backup_id,
                message="User data successfully anonymized"
            )
    
    async def _validate_anonymization(
        self,
        user: User,
        command: AnonymizeUserDataCommand
    ) -> None:
        """Validate anonymization request."""
        # Cannot anonymize active users
        if user.status == UserStatus.ACTIVE:
            raise InvalidOperationError(
                "Cannot anonymize active user. Deactivate first."
            )
        
        # Check if already anonymized
        if user.metadata.get("anonymized"):
            raise InvalidOperationError(
                f"User already anonymized on {user.metadata.get('anonymized_at')}"
            )
        
        # Validate data categories
        valid_categories = [
            "profile", "authentication", "sessions", "preferences",
            "notifications", "audit_logs", "permissions", "devices",
            "integrations", "emergency_contacts"
        ]
        
        invalid_categories = [
            cat for cat in command.data_categories
            if cat not in valid_categories and cat != "all"
        ]
        
        if invalid_categories:
            raise InvalidOperationError(
                f"Invalid data categories: {invalid_categories}"
            )
    
    async def _create_pre_anonymization_backup(
        self,
        user: User,
        command: AnonymizeUserDataCommand
    ) -> UUID:
        """Create backup before anonymization."""
        # Export all user data
        export_data = await self._collect_user_data(user.id)
        
        # Create encrypted backup
        return await self._backup_service.create_backup(
            data=export_data,
            backup_type="pre_anonymization",
            user_id=user.id,
            retention_days=(
                command.legal_retention_days if command.retain_for_legal else 30
            ),
            encrypted=True,
            metadata={
                "reason": command.reason,
                "admin_user": str(command.admin_user_id),
                "anonymization_level": command.anonymization_level.value
            }
        )
        
    
    async def _apply_minimal_anonymization(
        self,
        user: User,
        command: AnonymizeUserDataCommand
    ) -> dict[str, list[str]]:
        """Apply minimal anonymization (PII only)."""
        anonymized_fields = []
        retained_fields = []
        
        # Generate anonymous ID
        anon_id = self._generate_anonymous_id(user.id)
        
        # Anonymize PII fields
        if user.username:
            user.username = f"user_{anon_id}"
            anonymized_fields.append("username")
        
        if user.email:
            user.email = f"{anon_id}@anonymized.local"
            user.email_verified = False
            anonymized_fields.append("email")
        
        if user.first_name:
            user.first_name = "Anonymous"
            anonymized_fields.append("first_name")
        
        if user.last_name:
            user.last_name = "User"
            anonymized_fields.append("last_name")
        
        if user.phone_number:
            user.phone_number = None
            anonymized_fields.append("phone_number")
        
        # Retain non-PII fields
        retained_fields = [
            "id", "created_at", "status", "last_login_at"
        ]
        
        # Update metadata
        user.metadata = {
            "anonymized": True,
            "anonymized_at": datetime.now(UTC).isoformat(),
            "anonymization_level": "minimal",
            "original_id_hash": hashlib.sha256(str(user.id).encode()).hexdigest()
        }
        
        return {
            "anonymized_fields": anonymized_fields,
            "retained_fields": retained_fields
        }
    
    async def _apply_standard_anonymization(
        self,
        user: User,
        command: AnonymizeUserDataCommand
    ) -> dict[str, list[str]]:
        """Apply standard anonymization (PII + behavioral)."""
        # Start with minimal anonymization
        result = await self._apply_minimal_anonymization(user, command)
        
        # Additionally anonymize behavioral data
        user.last_login_at = None
        user.login_count = 0
        user.failed_login_count = 0
        
        result["anonymized_fields"].extend([
            "last_login_at", "login_count", "failed_login_count"
        ])
        
        # Clear preferences
        user.preferences = {}
        result["anonymized_fields"].append("preferences")
        
        # Clear device information
        user.trusted_devices = []
        result["anonymized_fields"].append("trusted_devices")
        
        return result
    
    async def _apply_complete_anonymization(
        self,
        user: User,
        command: AnonymizeUserDataCommand
    ) -> dict[str, list[str]]:
        """Apply complete anonymization (everything except audit trail)."""
        # Start with standard anonymization
        result = await self._apply_standard_anonymization(user, command)
        
        # Additionally anonymize all remaining fields
        self._generate_anonymous_id(user.id)
        
        # Replace dates with epoch
        user.created_at = datetime(1970, 1, 1)
        user.updated_at = datetime.now(UTC)
        
        result["anonymized_fields"].extend([
            "created_at", "all_metadata", "all_relationships"
        ])
        
        # Only retain legally required fields
        result["retained_fields"] = ["id", "anonymized_at"]
        
        return result
    
    async def _apply_custom_anonymization(
        self,
        user: User,
        command: AnonymizeUserDataCommand
    ) -> dict[str, list[str]]:
        """Apply custom anonymization rules."""
        anonymized_fields = []
        retained_fields = []
        
        rules = command.custom_rules
        anon_id = self._generate_anonymous_id(user.id)
        
        # Apply field-specific rules
        for field, rule in rules.get("fields", {}).items():
            if hasattr(user, field):
                if rule == "anonymize":
                    setattr(user, field, self._anonymize_field_value(field, anon_id))
                    anonymized_fields.append(field)
                elif rule == "delete":
                    setattr(user, field, None)
                    anonymized_fields.append(field)
                elif rule == "retain":
                    retained_fields.append(field)
        
        # Apply category rules
        if "profile" in command.data_categories:
            for field in [
                "username", "email", "first_name", "last_name", "phone_number"
            ]:
                if field not in retained_fields:
                    setattr(user, field, self._anonymize_field_value(field, anon_id))
                    anonymized_fields.append(field)
        
        return {
            "anonymized_fields": list(set(anonymized_fields)),
            "retained_fields": retained_fields
        }
    
    def _generate_anonymous_id(self, user_id: UUID) -> str:
        """Generate anonymous identifier."""
        # Use first 8 chars of UUID hash
        return hashlib.sha256(str(user_id).encode()).hexdigest()[:8]
    
    def _anonymize_field_value(self, field_name: str, anon_id: str) -> Any:
        """Anonymize field value based on type."""
        # Use configurable anonymized IP address
        anonymized_ip = os.environ.get("ANONYMIZED_IP_ADDRESS", "127.0.0.1")
        
        field_patterns = {
            "username": f"user_{anon_id}",
            "email": f"{anon_id}@anonymized.local",
            "first_name": "Anonymous",
            "last_name": "User",
            "phone_number": None,
            "ip_address": anonymized_ip,
            "user_agent": "Anonymized/1.0"
        }
        
        return field_patterns.get(field_name, f"ANON_{anon_id}")
    
    async def _anonymize_related_data(
        self,
        user_id: UUID,
        data_categories: list[str],
        anonymization_id: UUID
    ) -> None:
        """Anonymize related data across all systems."""
        if "all" in data_categories:
            data_categories = [
                "sessions", "audit_logs", "notifications", "permissions",
                "devices", "integrations", "emergency_contacts"
            ]
        
        # Anonymize sessions
        if "sessions" in data_categories:
            await self._anonymize_sessions(user_id)
        
        # Anonymize audit logs
        if "audit_logs" in data_categories:
            await self._anonymize_audit_logs(user_id, anonymization_id)
        
        # Anonymize notifications
        if "notifications" in data_categories:
            await self._anonymize_notifications(user_id)
        
        # Anonymize permissions
        if "permissions" in data_categories:
            await self._anonymize_permissions(user_id)
        
        # Anonymize devices
        if "devices" in data_categories:
            await self._anonymize_devices(user_id)
        
        # Anonymize integrations
        if "integrations" in data_categories:
            await self._anonymize_integrations(user_id)
        
        # Anonymize emergency contacts
        if "emergency_contacts" in data_categories:
            await self._anonymize_emergency_contacts(user_id)
    
    async def _anonymize_sessions(self, user_id: UUID) -> None:
        """Anonymize session data."""
        sessions = await self._session_repository.get_all_by_user(user_id)
        anonymized_ip = os.environ.get("ANONYMIZED_IP_ADDRESS", "127.0.0.1")
        
        for session in sessions:
            session.ip_address = anonymized_ip
            session.user_agent = "Anonymized/1.0"
            session.location = None
            session.device_info = {"anonymized": True}
            await self._session_repository.update(session)
    
    async def _anonymize_audit_logs(
        self, user_id: UUID, anonymization_id: UUID
    ) -> None:
        """Anonymize audit logs while maintaining integrity."""
        # Get all audit logs
        actor_logs = await self._audit_repository.get_by_actor(user_id)
        target_logs = await self._audit_repository.get_by_target(user_id)
        anonymized_ip = os.environ.get("ANONYMIZED_IP_ADDRESS", "127.0.0.1")
        
        # Anonymize but keep audit trail
        anon_user_ref = f"ANON_USER_{anonymization_id.hex[:8]}"
        
        for log in actor_logs + target_logs:
            # Replace user ID with anonymized reference
            if log.actor_id == user_id:
                log.metadata["original_actor_hash"] = hashlib.sha256(
                    str(user_id).encode()
                ).hexdigest()
                log.actor_id = None
                log.metadata["actor_ref"] = anon_user_ref
            
            # Anonymize IP and user agent
            log.ip_address = anonymized_ip
            log.user_agent = "Anonymized/1.0"
            
            # Remove PII from changes
            if log.changes:
                log.changes = self._sanitize_audit_changes(log.changes)
            
            await self._audit_repository.update(log)
    
    def _sanitize_audit_changes(self, changes: dict[str, Any]) -> dict[str, Any]:
        """Remove PII from audit log changes."""
        pii_fields = [
            "email", "phone_number", "first_name", "last_name",
            "username", "ip_address", "address", "ssn"
        ]
        
        sanitized = {}
        for key, value in changes.items():
            if any(pii in key.lower() for pii in pii_fields):
                sanitized[key] = "[ANONYMIZED]"
            elif isinstance(value, dict):
                sanitized[key] = self._sanitize_audit_changes(value)
            else:
                sanitized[key] = value
        
        return sanitized
    
    async def _anonymize_notifications(self, user_id: UUID) -> None:
        """Anonymize notification data."""
        notifications = await self._notification_repository.get_all_by_user(user_id)
        
        for notification in notifications:
            # Remove PII from notification content
            notification.message = self._anonymize_text(notification.message)
            if notification.metadata:
                notification.metadata = self._sanitize_audit_changes(
                    notification.metadata
                )
            
            await self._notification_repository.update(notification)
    
    def _anonymize_text(self, text: str) -> str:
        """Anonymize PII in text content."""
        # This would use more sophisticated NLP in production
        # For now, simple pattern matching
        import re
        
        # Email pattern
        text = re.sub(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            '[EMAIL]',
            text
        )
        
        # Phone pattern
        text = re.sub(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', '[PHONE]', text)
        
        # Name patterns (simplified)
        return re.sub(r'\b(?:Mr\.|Mrs\.|Ms\.|Dr\.)\s+\w+\s+\w+\b', '[NAME]', text)
        
    
    async def _anonymize_permissions(self, user_id: UUID) -> None:
        """Anonymize permission records."""
        # Revoke all permissions
        await self._authorization_service.revoke_all_permissions(user_id)
        
        # Remove from all roles
        await self._authorization_service.remove_all_roles(user_id)
    
    async def _anonymize_devices(self, user_id: UUID) -> None:
        """Anonymize device data."""
        devices = await self._security_service.get_user_devices(user_id)
        
        for device in devices:
            device.device_name = f"Anonymized_Device_{device.id.hex[:8]}"
            device.device_fingerprint = hashlib.sha256(
                device.device_fingerprint.encode()
            ).hexdigest()
            
            await self._security_service.update_device(device)
    
    async def _anonymize_integrations(self, user_id: UUID) -> None:
        """Anonymize third-party integrations."""
        integrations = await self._user_repository.get_user_integrations(user_id)
        
        for integration in integrations:
            # Revoke access tokens
            integration.access_token = None
            integration.refresh_token = None
            
            # Anonymize external IDs
            integration.external_user_id = hashlib.sha256(
                integration.external_user_id.encode()
            ).hexdigest()
            
            integration.status = "revoked"
            integration.revoked_at = datetime.now(UTC)
            
            await self._user_repository.update_integration(integration)
    
    async def _anonymize_emergency_contacts(self, user_id: UUID) -> None:
        """Anonymize emergency contacts."""
        contacts = await self._user_repository.get_emergency_contacts(user_id)
        
        for i, contact in enumerate(contacts):
            contact.name = f"Emergency Contact {i+1}"
            contact.phone_number = "000-000-0000"
            contact.email = f"contact{i+1}@anonymized.local"
            
            await self._user_repository.update_emergency_contact(contact)
    
    async def _clear_user_sessions(self, user_id: UUID) -> None:
        """Clear all user sessions."""
        sessions = await self._session_repository.get_active_sessions(user_id)
        
        for session in sessions:
            await self._security_service.revoke_session(session.id)
    
    async def _clear_user_caches(self, user_id: UUID) -> None:
        """Clear all user-related caches."""
        cache_patterns = [
            f"user:{user_id}:*",
            f"session:user:{user_id}:*",
            f"permissions:{user_id}:*",
            f"profile:{user_id}",
            f"preferences:{user_id}"
        ]
        
        for pattern in cache_patterns:
            await self._cache_service.delete_pattern(pattern)
    
    async def _apply_legal_retention(
        self,
        user_id: UUID,
        retention_days: int,
        reason: str
    ) -> None:
        """Apply legal retention policy."""
        retention_date = datetime.now(UTC) + timedelta(days=retention_days)
        
        await self._data_privacy_service.create_retention_policy(
            user_id=user_id,
            retention_type="legal_hold",
            retention_until=retention_date,
            reason=reason,
            data_categories=["audit_logs", "legal_records"],
            auto_delete=True
        )
        
        # Publish retention event
        await self._event_bus.publish(
            DataRetentionApplied(
                aggregate_id=user_id,
                retention_type="legal_hold",
                retention_days=retention_days,
                auto_delete_date=retention_date
            )
        )
    
    async def _generate_anonymization_certificate(
        self,
        anonymization_id: UUID,
        user_id: UUID,
        anonymized_fields: list[str],
        retained_fields: list[str],
        command: AnonymizeUserDataCommand
    ) -> dict[str, Any]:
        """Generate anonymization certificate for compliance."""
        certificate = {
            "id": anonymization_id,
            "type": "data_anonymization_certificate",
            "user_id": str(user_id),
            "anonymized_at": datetime.now(UTC).isoformat(),
            "anonymization_level": command.anonymization_level.value,
            "anonymized_by": str(command.admin_user_id),
            "reason": command.reason,
            "data_categories": command.data_categories,
            "anonymized_fields": anonymized_fields,
            "retained_fields": retained_fields,
            "legal_retention": command.retain_for_legal,
            "retention_period_days": (
                command.legal_retention_days if command.retain_for_legal else 0
            ),
            "verification_hash": None,
            "digital_signature": None
        }
        
        # Generate verification hash
        cert_data = json.dumps(certificate, sort_keys=True)
        certificate["verification_hash"] = hashlib.sha256(cert_data.encode()).hexdigest()
        
        # Digital signature (would use real PKI in production)
        certificate["digital_signature"] = self._sign_certificate(certificate)
        
        # Store certificate
        cert_url = await self._data_privacy_service.store_certificate(
            certificate,
            retention_years=10  # Keep certificates for 10 years
        )
        
        certificate["url"] = cert_url
        
        return certificate
    
    def _sign_certificate(self, certificate: dict[str, Any]) -> str:
        """Digitally sign certificate (mock implementation)."""
        # In production, this would use proper PKI
        cert_string = json.dumps(certificate, sort_keys=True)
        signature = hashlib.sha512(cert_string.encode()).hexdigest()
        
        return f"MOCK_SIGNATURE:{signature[:32]}"
    
    async def _immediate_data_deletion(self, user_id: UUID) -> None:
        """Immediately delete user data from all systems."""
        # This would coordinate with all microservices
        # to ensure complete data deletion
        
        # Delete from primary database
        await self._user_repository.hard_delete(user_id)
        
        # Delete from all secondary stores
        await self._data_privacy_service.cascade_delete(user_id)
        
        # Delete from backups (mark for deletion in next cleanup)
        await self._backup_service.mark_for_deletion(user_id)
    
    async def _send_anonymization_notification(
        self,
        user: User,
        anonymization_id: UUID,
        certificate_url: str
    ) -> None:
        """Send anonymization notification if possible."""
        # Since email is anonymized, check if we have alternate contact
        if user.metadata.get("gdpr_contact_email"):
            await self._email_service.send_email(
                EmailContext(
                    recipient=user.metadata["gdpr_contact_email"],
                    template="data_anonymization_complete",
                    subject="Your Data Has Been Anonymized",
                    variables={
                        "anonymization_id": str(anonymization_id),
                        "certificate_url": certificate_url,
                        "support_email": "privacy@example.com"
                    }
                )
            )
    
    async def _notify_compliance_team(
        self,
        anonymization_id: UUID,
        user_id: UUID,
        command: AnonymizeUserDataCommand
    ) -> None:
        """Notify compliance team of anonymization."""
        await self._notification_service.notify_group(
            "compliance_team",
            NotificationContext(
                notification_id=UUID(),
                recipient_id=None,  # Group notification
                notification_type=NotificationType.COMPLIANCE_ACTION,
                channel="email",
                template_id="anonymization_completed",
                template_data={
                    "anonymization_id": str(anonymization_id),
                    "user_id": str(user_id),
                    "level": command.anonymization_level.value,
                    "admin": str(command.admin_user_id),
                    "reason": command.reason,
                    "timestamp": datetime.now(UTC).isoformat()
                },
                priority="high"
            )
        )
    
    async def _restore_from_backup(self, backup_id: UUID) -> None:
        """Restore data from backup in case of failure."""
        try:
            await self._backup_service.restore(backup_id)
        except Exception as e:
            # Log critical error but don't fail
            await self._security_service.log_critical_error(
                "Failed to restore from backup during anonymization rollback",
                {"backup_id": str(backup_id), "error": str(e)}
            )
    
    async def _collect_user_data(self, user_id: UUID) -> dict[str, Any]:
        """Collect all user data for backup."""
        # This would be similar to export functionality
        # but includes all internal data
        
        return {
            "user": await self._user_repository.get_by_id(user_id),
            "sessions": await self._session_repository.get_all_by_user(user_id),
            "permissions": await self._authorization_service.get_all_permissions(user_id),
            "audit_logs": await self._audit_repository.get_all_by_user(user_id),
            "notifications": await self._notification_repository.get_all_by_user(user_id),
            "devices": await self._security_service.get_user_devices(user_id),
            "integrations": await self._user_repository.get_user_integrations(user_id),
            "emergency_contacts": await self._user_repository.get_emergency_contacts(user_id)
        }
    
    async def _validate_users_and_permissions(
        self,
        admin_user_id: UUID,
        target_user_id: UUID
    ) -> tuple[User, User]:
        """Validate users exist and have proper permissions."""
        admin_user = await self._user_repository.get_by_id(admin_user_id)
        if not admin_user:
            raise UnauthorizedError("Admin user not found")
        
        target_user = await self._user_repository.get_by_id(target_user_id)
        if not target_user:
            raise UserNotFoundError(f"User {target_user_id} not found")
        
        return admin_user, target_user
    
    async def _validate_anonymization_operation(
        self,
        target_user: User,
        command: AnonymizeUserDataCommand
    ) -> None:
        """Validate anonymization operation and check for legal holds."""
        await self._validate_anonymization(target_user, command)
        
        legal_holds = await self._data_privacy_service.check_legal_holds(
            target_user.id
        )
        if legal_holds and not command.retain_for_legal:
            raise InvalidOperationError(
                f"Cannot anonymize: Active legal holds exist: {legal_holds}"
            )
    
    async def _execute_anonymization(
        self,
        target_user: User,
        command: AnonymizeUserDataCommand,
        anonymization_id: UUID
    ) -> dict[str, list[str]]:
        """Execute the anonymization based on the specified level."""
        if command.anonymization_level == AnonymizationLevel.MINIMAL:
            result = await self._apply_minimal_anonymization(
                target_user,
                command
            )
        elif command.anonymization_level == AnonymizationLevel.STANDARD:
            result = await self._apply_standard_anonymization(
                target_user,
                command
            )
        elif command.anonymization_level == AnonymizationLevel.COMPLETE:
            result = await self._apply_complete_anonymization(
                target_user,
                command
            )
        else:  # CUSTOM
            result = await self._apply_custom_anonymization(
                target_user,
                command
            )
        
        # Update user status
        target_user.update_status(
            UserStatus.TERMINATED,
            f"Data anonymized: {command.reason}",
            command.admin_user_id
        )
        
        # Clear sessions and anonymize related data
        await self._clear_user_sessions(target_user.id)
        await self._anonymize_related_data(
            target_user.id,
            command.data_categories,
            anonymization_id
        )
        await self._clear_user_caches(target_user.id)
        
        return result
    
    async def _post_anonymization_processing(
        self,
        target_user: User,
        command: AnonymizeUserDataCommand,
        anonymization_id: UUID,
        result: dict[str, list[str]],
        backup_id: UUID | None
    ) -> dict[str, Any]:
        """Handle post-anonymization processing."""
        # Apply retention policy if needed
        if command.retain_for_legal:
            await self._apply_legal_retention(
                target_user.id,
                command.legal_retention_days,
                command.reason
            )
        
        # Generate certificate
        certificate = await self._generate_anonymization_certificate(
            anonymization_id,
            target_user.id,
            result["anonymized_fields"],
            result["retained_fields"],
            command
        )
        
        # Save user changes
        await self._user_repository.update(target_user)
        
        # Publish event
        await self._event_bus.publish(
            UserDataAnonymized(
                aggregate_id=target_user.id,
                anonymization_id=anonymization_id,
                anonymized_by=command.admin_user_id,
                anonymization_level=command.anonymization_level.value,
                fields_anonymized=len(result["anonymized_fields"]),
                certificate_id=certificate["id"]
            )
        )
        
        # Log security event
        await self._security_service.log_security_incident(
            SecurityIncidentContext(
                incident_type=SecurityEventType.DATA_ANONYMIZATION,
                severity=RiskLevel.HIGH,
                user_id=target_user.id,
                details={
                    "anonymization_id": str(anonymization_id),
                    "level": command.anonymization_level.value,
                    "categories": command.data_categories,
                    "admin_user": str(command.admin_user_id),
                    "reason": command.reason,
                    "backup_created": backup_id is not None
                }
            )
        )
        
        # Immediate deletion if requested
        if command.immediate_deletion:
            await self._immediate_data_deletion(target_user.id)
        
        return certificate
    
    async def _send_post_commit_notifications(
        self,
        target_user: User,
        command: AnonymizeUserDataCommand,
        anonymization_id: UUID,
        certificate: dict[str, Any]
    ) -> None:
        """Send notifications after the transaction is committed."""
        # Send user notification
        if command.notify_user and not command.immediate_deletion:
            await self._send_anonymization_notification(
                target_user,
                anonymization_id,
                certificate["url"]
            )
        
        # Notify compliance team
        await self._notify_compliance_team(
            anonymization_id,
            target_user.id,
            command
        )