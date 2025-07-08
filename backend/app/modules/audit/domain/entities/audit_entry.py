"""Audit entry entity.

This module defines the AuditEntry entity that represents
an individual audit record in the system with enhanced security,
validation, and integrity features.
"""

import hashlib
import hmac
import json
from datetime import datetime, timedelta
from typing import Any, ClassVar
from uuid import UUID, uuid4

from app.core.domain.base import Entity
from app.core.errors import DomainError, ValidationError
from app.modules.audit.domain.enums.audit_enums import AuditCategory, AuditSeverity
from app.modules.audit.domain.value_objects.audit_action import AuditAction
from app.modules.audit.domain.value_objects.audit_context import AuditContext
from app.modules.audit.domain.value_objects.audit_metadata import AuditMetadata
from app.modules.audit.domain.value_objects.resource_identifier import (
    ResourceIdentifier,
)


class AuditEntry(Entity):
    """
    Production-ready audit record with enhanced security and integrity.

    This entity captures a single auditable event in the system with
    comprehensive validation, integrity checking, and security features.

    Attributes:
        user_id: ID of the user who performed the action
        action: The action that was performed
        resource: The resource that was affected
        context: Context in which the action occurred
        metadata: Additional metadata for the entry
        severity: Severity level of the audit event
        category: Category of the audit event
        outcome: Result of the action (success/failure/partial)
        error_details: Details if the action failed
        duration_ms: Duration of the action in milliseconds
        changes: Field-level changes (for update actions)
        correlation_id: ID for correlating related entries
        session_id: Audit session ID
        integrity_hash: Cryptographic hash for tamper detection
        signature: Digital signature for non-repudiation
        version: Entry format version
        retention_until: Retention expiry date
        compliance_tags: Compliance-related tags
        risk_score: Calculated risk score (0-100)

    Business Rules:
        - Entries are immutable once created and signed
        - All entries must have valid action and resource
        - Failed actions must have error details
        - Changes are only valid for update actions
        - High-risk entries require additional validation
        - Integrity hash must be valid
    """

    # Class constants for validation
    MAX_ERROR_DETAIL_SIZE: ClassVar[int] = 10240  # 10KB
    MAX_CHANGES_COUNT: ClassVar[int] = 100
    MAX_CORRELATION_ID_LENGTH: ClassVar[int] = 255
    CURRENT_VERSION: ClassVar[str] = "1.2.0"
    
    # Risk score thresholds
    LOW_RISK_THRESHOLD: ClassVar[int] = 30
    MEDIUM_RISK_THRESHOLD: ClassVar[int] = 60
    HIGH_RISK_THRESHOLD: ClassVar[int] = 80

    def __init__(
        self,
        user_id: UUID | None,
        action: AuditAction,
        resource: ResourceIdentifier,
        context: AuditContext,
        metadata: AuditMetadata | None = None,
        severity: AuditSeverity | None = None,
        category: AuditCategory | None = None,
        outcome: str = "success",
        error_details: dict[str, Any] | None = None,
        duration_ms: int | None = None,
        changes: list["AuditField"] | None = None,
        correlation_id: str | None = None,
        session_id: UUID | None = None,
        entity_id: UUID | None = None,
        signing_key: str | None = None,
        retention_policy_override: str | None = None,
        compliance_tags: list[str] | None = None,
    ):
        """
        Initialize production-ready audit entry with enhanced validation.

        Args:
            user_id: User who performed the action (None for system actions)
            action: Action performed
            resource: Resource affected
            context: Context information
            metadata: Additional metadata
            severity: Event severity
            category: Event category
            outcome: Action outcome (success/failure/partial)
            error_details: Error information if failed
            duration_ms: Action duration
            changes: Field-level changes
            correlation_id: Correlation identifier
            session_id: Audit session identifier
            entity_id: Entry identifier
            signing_key: Key for digital signature
            retention_policy_override: Override retention policy
            compliance_tags: Compliance-related tags

        Raises:
            ValidationError: If required fields are invalid
            DomainError: If business rules are violated
        """
        super().__init__(entity_id)

        # Set required fields with enhanced validation
        self.user_id = user_id  # Can be None for system actions
        self.action = self._validate_action(action)
        self.resource = self._validate_resource(resource)
        self.context = self._validate_context(context)

        # Set metadata with defaults
        self.metadata = metadata or AuditMetadata.create_default()

        # Set severity (auto-determine if not provided)
        if severity:
            self.severity = severity
        else:
            self.severity = self._determine_severity()

        # Set category (auto-determine if not provided)
        if category:
            self.category = category
        else:
            self.category = self._determine_category()

        # Set outcome and validate
        self.outcome = self._validate_outcome(outcome)

        # Enhanced error details validation
        self.error_details = self._validate_error_details(error_details)

        # Set optional fields with validation
        self.duration_ms = self._validate_duration(duration_ms)
        self.correlation_id = self._validate_correlation_id(correlation_id)
        self.session_id = session_id

        # Enhanced changes validation
        self.changes = self._validate_changes(changes)

        # Set version and compliance info
        self.version = self.CURRENT_VERSION
        self.compliance_tags = compliance_tags or []
        
        # Calculate retention date
        self.retention_until = self._calculate_retention_date(retention_policy_override)
        
        # Calculate risk score
        self.risk_score = self._calculate_risk_score()
        
        # Generate integrity hash and signature
        self.integrity_hash = self._generate_integrity_hash()
        self.signature = self._generate_signature(signing_key) if signing_key else None
        
        # Timestamp for creation
        self.signed_at = datetime.utcnow() if self.signature else None

        # Mark as immutable after all initialization
        self._immutable = True
        self._sealed = True

    def _validate_action(self, action: AuditAction) -> AuditAction:
        """Enhanced action validation."""
        if not isinstance(action, AuditAction):
            raise ValidationError("Action must be an AuditAction instance")
        
        # Additional business rule validations
        if action.action_type == "delete" and not action.operation.startswith("delete_"):
            raise ValidationError("Delete actions must have delete_ operation prefix")
            
        return action

    def _validate_resource(self, resource: ResourceIdentifier) -> ResourceIdentifier:
        """Enhanced resource validation."""
        if not isinstance(resource, ResourceIdentifier):
            raise ValidationError("Resource must be a ResourceIdentifier instance")
            
        # Validate resource ID format for sensitive resources
        if resource.resource_type in ("user", "admin", "system"):
            try:
                UUID(resource.resource_id)
            except ValueError:
                raise ValidationError(f"Sensitive resource {resource.resource_type} must use UUID identifier")
                
        return resource

    def _validate_context(self, context: AuditContext) -> AuditContext:
        """Enhanced context validation."""
        if not isinstance(context, AuditContext):
            raise ValidationError("Context must be an AuditContext instance")
            
        # Validate IP address for suspicious patterns
        if context.ip_address:
            if context.ip_address in ("0.0.0.0", "255.255.255.255"):
                raise ValidationError("Invalid IP address detected")
                
        return context

    def _validate_outcome(self, outcome: str) -> str:
        """Enhanced outcome validation."""
        valid_outcomes = {"success", "failure", "partial", "timeout", "cancelled"}
        normalized = outcome.lower().strip()

        if normalized not in valid_outcomes:
            raise ValidationError(
                f"Invalid outcome: {outcome}. Must be one of: {', '.join(valid_outcomes)}"
            )

        return normalized

    def _validate_error_details(self, error_details: dict[str, Any] | None) -> dict[str, Any] | None:
        """Enhanced error details validation."""
        if self.outcome in ("failure", "timeout", "cancelled") and not error_details:
            raise DomainError(f"Error details are required for {self.outcome} outcomes")
            
        if error_details:
            # Validate size
            serialized_size = len(json.dumps(error_details, default=str))
            if serialized_size > self.MAX_ERROR_DETAIL_SIZE:
                raise ValidationError(f"Error details exceed maximum size of {self.MAX_ERROR_DETAIL_SIZE} bytes")
                
            # Sanitize sensitive information
            return self._sanitize_error_details(error_details)
            
        return error_details

    def _validate_duration(self, duration_ms: int | None) -> int | None:
        """Enhanced duration validation."""
        if duration_ms is not None:
            if duration_ms < 0:
                raise ValidationError("Duration cannot be negative")
            if duration_ms > 86400000:  # 24 hours in milliseconds
                raise ValidationError("Duration exceeds maximum allowed (24 hours)")
                
        return duration_ms

    def _validate_correlation_id(self, correlation_id: str | None) -> str:
        """Enhanced correlation ID validation."""
        if correlation_id:
            if len(correlation_id) > self.MAX_CORRELATION_ID_LENGTH:
                raise ValidationError(f"Correlation ID exceeds maximum length of {self.MAX_CORRELATION_ID_LENGTH}")
            # Sanitize correlation ID
            sanitized = correlation_id.strip()
            if not sanitized:
                return str(uuid4())
            return sanitized
        return str(uuid4())

    def _validate_changes(self, changes: list["AuditField"] | None) -> list["AuditField"]:
        """Enhanced changes validation."""
        if changes:
            if not self.action.is_write_action():
                raise DomainError("Changes can only be specified for write actions")
                
            if len(changes) > self.MAX_CHANGES_COUNT:
                raise ValidationError(f"Too many changes: {len(changes)}. Maximum allowed: {self.MAX_CHANGES_COUNT}")
                
            # Validate each change
            for change in changes:
                if not isinstance(change, AuditField):
                    raise ValidationError("All changes must be AuditField instances")
                    
            return changes
        return []

    def _sanitize_error_details(self, error_details: dict[str, Any]) -> dict[str, Any]:
        """Sanitize error details to remove sensitive information."""
        sensitive_keys = {
            "password", "token", "secret", "key", "credential", 
            "authorization", "cookie", "session", "private"
        }
        
        sanitized = {}
        for key, value in error_details.items():
            if any(sensitive in key.lower() for sensitive in sensitive_keys):
                sanitized[key] = "***REDACTED***"
            elif isinstance(value, dict):
                sanitized[key] = self._sanitize_error_details(value)
            elif isinstance(value, str) and len(value) > 1000:
                # Truncate very long strings
                sanitized[key] = value[:1000] + "...[TRUNCATED]"
            else:
                sanitized[key] = value
                
        return sanitized

    def _calculate_retention_date(self, retention_override: str | None) -> datetime | None:
        """Calculate retention expiry date."""
        if retention_override == "permanent":
            return None
            
        # Default retention based on severity and category
        if self.severity == AuditSeverity.CRITICAL:
            retention_days = 2555  # 7 years
        elif self.severity == AuditSeverity.HIGH:
            retention_days = 1095  # 3 years
        elif self.category in (AuditCategory.SECURITY, AuditCategory.AUTHENTICATION):
            retention_days = 365  # 1 year
        else:
            retention_days = 90  # 90 days
            
        return datetime.utcnow() + timedelta(days=retention_days)

    def _calculate_risk_score(self) -> int:
        """Calculate risk score based on various factors."""
        score = 0
        
        # Base score from severity
        severity_scores = {
            AuditSeverity.LOW: 10,
            AuditSeverity.MEDIUM: 30,
            AuditSeverity.HIGH: 60,
            AuditSeverity.CRITICAL: 80,
        }
        score += severity_scores.get(self.severity, 10)
        
        # Outcome impact
        if self.outcome == "failure":
            score += 20
        elif self.outcome in ("timeout", "cancelled"):
            score += 10
            
        # Action type impact
        if self.action.action_type == "delete":
            score += 15
        elif self.action.is_auth_action():
            score += 10
            
        # Context factors
        if self.context.ip_address and self.context.get_location_hint() == "external":
            score += 5
            
        # System actions are generally lower risk
        if self.is_system_action():
            score = max(0, score - 10)
            
        return min(100, score)

    def _generate_integrity_hash(self) -> str:
        """Generate cryptographic hash for integrity verification."""
        # Create canonical representation
        canonical_data = {
            "id": str(self.id),
            "user_id": str(self.user_id) if self.user_id else None,
            "action": str(self.action),
            "resource": str(self.resource),
            "outcome": self.outcome,
            "created_at": self.created_at.isoformat(),
            "version": self.version,
        }
        
        # Sort keys for consistent hashing
        canonical_json = json.dumps(canonical_data, sort_keys=True, separators=(',', ':'))
        
        # Generate SHA-256 hash
        return hashlib.sha256(canonical_json.encode('utf-8')).hexdigest()

    def _generate_signature(self, signing_key: str) -> str | None:
        """Generate HMAC signature for non-repudiation."""
        if not signing_key:
            return None
            
        # Use integrity hash as the message to sign
        message = self.integrity_hash.encode('utf-8')
        key = signing_key.encode('utf-8')
        
        # Generate HMAC-SHA256 signature
        return hmac.new(key, message, hashlib.sha256).hexdigest()

    def _determine_severity(self) -> AuditSeverity:
        """Auto-determine severity based on action and outcome."""
        # Failed actions are higher severity
        if self.outcome == "failure":
            if (
                self.action.action_type == AuditAction.ACTION_DELETE
                or self.action.is_auth_action()
            ):
                return AuditSeverity.HIGH
            return AuditSeverity.MEDIUM

        # Use action's severity hint
        hint = self.action.get_severity_hint()
        return AuditSeverity.from_string(hint)

    def _determine_category(self) -> AuditCategory:
        """Auto-determine category based on action."""
        if self.action.is_auth_action():
            if self.action.operation in ("login", "logout"):
                return AuditCategory.AUTHENTICATION
            return AuditCategory.AUTHORIZATION
        if self.action.resource_type in ("configuration", "setting", "preference"):
            return AuditCategory.CONFIGURATION
        if self.action.resource_type in ("integration", "webhook", "api"):
            return AuditCategory.INTEGRATION
        return AuditCategory.DATA_ACCESS

    def _validate_entity(self) -> None:
        """Additional validation for audit entries."""
        super()._validate_entity()

        # Ensure immutability check
        if hasattr(self, "_immutable") and self._immutable:
            # This should not be called after initialization
            raise DomainError("Audit entries are immutable and cannot be modified")

    def mark_modified(self) -> None:
        """Override to prevent modification of audit entries."""
        if hasattr(self, "_immutable") and self._immutable:
            raise DomainError("Audit entries are immutable and cannot be modified")
        super().mark_modified()

    def is_successful(self) -> bool:
        """Check if the audited action was successful."""
        return self.outcome == "success"

    def is_failed(self) -> bool:
        """Check if the audited action failed."""
        return self.outcome == "failure"

    def is_partial(self) -> bool:
        """Check if the audited action was partially successful."""
        return self.outcome == "partial"

    def is_system_action(self) -> bool:
        """Check if this was a system-initiated action."""
        return self.user_id is None

    def is_high_severity(self) -> bool:
        """Check if this is a high or critical severity event."""
        return self.severity in (AuditSeverity.HIGH, AuditSeverity.CRITICAL)

    def has_changes(self) -> bool:
        """Check if this entry has field-level changes."""
        return bool(self.changes)

    def get_changed_fields(self) -> list[str]:
        """Get list of field names that were changed."""
        return [field.field_name for field in self.changes]

    def get_change_summary(self) -> dict[str, dict[str, Any]]:
        """
        Get a summary of changes.

        Returns:
            Dictionary mapping field names to old/new values
        """
        summary = {}
        for field in self.changes:
            summary[field.field_name] = {
                "old_value": field.old_value,
                "new_value": field.new_value,
            }
        return summary

    def matches_user(self, user_id: UUID) -> bool:
        """Check if this entry was created by a specific user."""
        return self.user_id == user_id

    def matches_resource(
        self, resource_type: str, resource_id: str | None = None
    ) -> bool:
        """
        Check if this entry matches a resource.

        Args:
            resource_type: Type of resource to match
            resource_id: Optional specific resource ID

        Returns:
            True if matches
        """
        if not self.resource.matches_type(resource_type):
            return False

        if resource_id:
            return self.resource.resource_id == resource_id

        return True

    def matches_session(self, session_id: UUID) -> bool:
        """Check if this entry belongs to a specific session."""
        return self.session_id == session_id

    def to_log_string(self) -> str:
        """
        Generate a log-friendly string representation.

        Returns:
            Formatted string for logging
        """
        user_str = str(self.user_id) if self.user_id else "SYSTEM"
        outcome_str = f" [{self.outcome.upper()}]" if self.outcome != "success" else ""

        return (
            f"[{self.created_at.isoformat()}] "
            f"User={user_str} "
            f"Action={self.action} "
            f"Resource={self.resource.to_audit_string()} "
            f"Severity={self.severity.value}"
            f"{outcome_str}"
        )

    def verify_integrity(self, expected_hash: str | None = None) -> bool:
        """Verify the integrity of the audit entry."""
        if expected_hash:
            return self.integrity_hash == expected_hash
            
        # Recalculate hash and compare
        recalculated_hash = self._generate_integrity_hash()
        return self.integrity_hash == recalculated_hash

    def verify_signature(self, signing_key: str) -> bool:
        """Verify the digital signature of the audit entry."""
        if not self.signature:
            return False
            
        expected_signature = self._generate_signature(signing_key)
        return hmac.compare_digest(self.signature, expected_signature or "")

    def is_high_risk(self) -> bool:
        """Check if this is a high-risk audit entry."""
        return self.risk_score >= self.HIGH_RISK_THRESHOLD

    def is_medium_risk(self) -> bool:
        """Check if this is a medium-risk audit entry."""
        return self.MEDIUM_RISK_THRESHOLD <= self.risk_score < self.HIGH_RISK_THRESHOLD

    def is_low_risk(self) -> bool:
        """Check if this is a low-risk audit entry."""
        return self.risk_score < self.MEDIUM_RISK_THRESHOLD

    def is_expired(self) -> bool:
        """Check if the entry has exceeded its retention period."""
        if not self.retention_until:
            return False  # Permanent retention
        return datetime.utcnow() > self.retention_until

    def get_compliance_status(self) -> dict[str, Any]:
        """Get compliance status for this entry."""
        return {
            "has_signature": bool(self.signature),
            "integrity_verified": self.verify_integrity(),
            "retention_compliant": not self.is_expired(),
            "risk_level": self.get_risk_level(),
            "compliance_tags": self.compliance_tags,
            "data_classification": self.metadata.data_classification,
        }

    def get_risk_level(self) -> str:
        """Get human-readable risk level."""
        if self.is_high_risk():
            return "HIGH"
        if self.is_medium_risk():
            return "MEDIUM"
        return "LOW"

    def get_security_summary(self) -> dict[str, Any]:
        """Get security-focused summary of the entry."""
        return {
            "entry_id": str(self.id),
            "risk_score": self.risk_score,
            "risk_level": self.get_risk_level(),
            "severity": self.severity.value,
            "outcome": self.outcome,
            "is_system_action": self.is_system_action(),
            "has_failures": self.is_failed(),
            "requires_investigation": self.is_high_risk() and self.is_failed(),
            "integrity_hash": self.integrity_hash[:16] + "...",  # Truncated for display
            "signed": bool(self.signature),
            "created_at": self.created_at.isoformat(),
        }

    def to_dict(self, include_sensitive: bool = False) -> dict[str, Any]:
        """Convert to dictionary representation with security controls."""
        data = super().to_dict()

        # Add audit-specific fields
        data.update(
            {
                "user_id": str(self.user_id) if self.user_id else None,
                "action": self.action.to_dict(),
                "resource": self.resource.to_dict(),
                "context": self.context.to_dict() if include_sensitive else self.context.mask_sensitive_data().to_dict(),
                "metadata": self.metadata.to_dict(),
                "severity": self.severity.value,
                "category": self.category.value,
                "outcome": self.outcome,
                "error_details": self.error_details if include_sensitive else self._get_sanitized_error_details(),
                "duration_ms": self.duration_ms,
                "changes": [field.to_dict() for field in self.changes],
                "correlation_id": self.correlation_id,
                "session_id": str(self.session_id) if self.session_id else None,
                "version": self.version,
                "risk_score": self.risk_score,
                "compliance_tags": self.compliance_tags,
                "retention_until": self.retention_until.isoformat() if self.retention_until else None,
                "integrity_hash": self.integrity_hash,
                "signed": bool(self.signature),
                "signed_at": self.signed_at.isoformat() if self.signed_at else None,
            }
        )

        # Include signature only if specifically requested and authorized
        if include_sensitive and self.signature:
            data["signature"] = self.signature

        return data

    def _get_sanitized_error_details(self) -> dict[str, Any] | None:
        """Get sanitized error details for non-sensitive contexts."""
        if not self.error_details:
            return None
            
        return {
            "error_type": self.error_details.get("error_type", "unknown"),
            "error_code": self.error_details.get("error_code"),
            "timestamp": self.error_details.get("timestamp"),
            "has_details": True,
        }

    @classmethod
    def create_system_entry(
        cls,
        action: AuditAction,
        resource: ResourceIdentifier,
        context: AuditContext,
        outcome: str = "success",
        **kwargs
    ) -> "AuditEntry":
        """Factory method for system-generated audit entries."""
        return cls(
            user_id=None,
            action=action,
            resource=resource,
            context=context,
            outcome=outcome,
            metadata=AuditMetadata.create_default().with_tag("system"),
            **kwargs
        )

    @classmethod
    def create_security_entry(
        cls,
        user_id: UUID | None,
        action: AuditAction,
        resource: ResourceIdentifier,
        context: AuditContext,
        severity: AuditSeverity = AuditSeverity.HIGH,
        **kwargs
    ) -> "AuditEntry":
        """Factory method for security-related audit entries."""
        return cls(
            user_id=user_id,
            action=action,
            resource=resource,
            context=context,
            severity=severity,
            category=AuditCategory.SECURITY,
            metadata=AuditMetadata.create_for_security_event(severity.value),
            compliance_tags=["security", "monitoring"],
            **kwargs
        )


class AuditField(Entity):
    """
    Represents a field-level change in an audit entry.

    This entity captures individual field changes for detailed
    change tracking in update operations.

    Attributes:
        field_name: Name of the field that changed
        field_path: Full path for nested fields (e.g., "address.city")
        old_value: Previous value
        new_value: New value
        value_type: Type of the value
        is_sensitive: Whether this field contains sensitive data
    """

    def __init__(
        self,
        field_name: str,
        old_value: Any,
        new_value: Any,
        field_path: str | None = None,
        value_type: str | None = None,
        is_sensitive: bool = False,
        entity_id: UUID | None = None,
    ):
        """
        Initialize audit field.

        Args:
            field_name: Name of the field
            old_value: Previous value
            new_value: New value
            field_path: Full field path
            value_type: Type of value
            is_sensitive: Whether field is sensitive
            entity_id: Field identifier
        """
        super().__init__(entity_id)

        self.validate_not_empty(field_name, "field_name")
        self.field_name = field_name

        self.field_path = field_path or field_name
        self.old_value = old_value
        self.new_value = new_value

        # Determine value type if not provided
        if value_type:
            self.value_type = value_type
        else:
            self.value_type = type(new_value).__name__

        self.is_sensitive = is_sensitive

    def get_display_value(self, value: Any) -> str:
        """Get display-safe value (masks sensitive data)."""
        if self.is_sensitive:
            return "***REDACTED***"

        if value is None:
            return "null"

        return str(value)

    def has_changed(self) -> bool:
        """Check if the value actually changed."""
        return self.old_value != self.new_value

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "field_name": self.field_name,
            "field_path": self.field_path,
            "old_value": self.get_display_value(self.old_value),
            "new_value": self.get_display_value(self.new_value),
            "value_type": self.value_type,
            "is_sensitive": self.is_sensitive,
        }


__all__ = ["AuditEntry", "AuditField"]
