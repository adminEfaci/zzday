"""Audit metadata value object.

This module defines the AuditMetadata value object that captures
additional metadata for audit entries.
"""

from typing import Any

from app.core.domain.base import ValueObject
from app.core.errors import ValidationError


class AuditMetadata(ValueObject):
    """
    Represents additional metadata for an audit entry.

    This value object captures supplementary information that enhances
    the audit trail with business-specific context and compliance data.

    Attributes:
        tags: List of tags for categorization
        business_context: Business-specific context information
        compliance_flags: Compliance-related flags
        data_classification: Data sensitivity classification
        retention_override: Override for standard retention policy
        custom_fields: Additional custom metadata fields

    Usage:
        metadata = AuditMetadata(
            tags=["security", "authentication"],
            business_context={"department": "finance", "cost_center": "CC123"},
            compliance_flags={"gdpr": True, "sox": False},
            data_classification="confidential"
        )
    """

    # Data classification levels
    CLASSIFICATION_PUBLIC = "public"
    CLASSIFICATION_INTERNAL = "internal"
    CLASSIFICATION_CONFIDENTIAL = "confidential"
    CLASSIFICATION_RESTRICTED = "restricted"

    def __init__(
        self,
        tags: list[str] | None = None,
        business_context: dict[str, Any] | None = None,
        compliance_flags: dict[str, bool] | None = None,
        data_classification: str = CLASSIFICATION_INTERNAL,
        retention_override: str | None = None,
        custom_fields: dict[str, Any] | None = None,
    ):
        """
        Initialize audit metadata.

        Args:
            tags: List of categorization tags
            business_context: Business-specific context
            compliance_flags: Compliance-related flags
            data_classification: Data sensitivity level
            retention_override: Override retention policy
            custom_fields: Additional custom fields

        Raises:
            ValidationError: If data classification is invalid
        """
        super().__init__()

        # Set and validate tags (immutable)
        if tags:
            self.tags = tuple(self._validate_tags(tags))
        else:
            self.tags = ()

        # Set business context (immutable)
        if business_context:
            self.business_context = frozenset(business_context.items())
        else:
            self.business_context = frozenset()

        # Set compliance flags (immutable)
        if compliance_flags:
            self.compliance_flags = frozenset(compliance_flags.items())
        else:
            self.compliance_flags = frozenset()

        # Validate and set data classification
        self.data_classification = self._validate_classification(data_classification)

        # Set retention override
        self.retention_override = retention_override

        # Set custom fields (immutable)
        if custom_fields:
            self.custom_fields = frozenset(custom_fields.items())
        else:
            self.custom_fields = frozenset()

        # Freeze the value object
        self._freeze()

    def _validate_tags(self, tags: list[str]) -> list[str]:
        """
        Validate and normalize tags.

        Args:
            tags: List of tags to validate

        Returns:
            Normalized list of tags

        Raises:
            ValidationError: If tags are invalid
        """
        if not isinstance(tags, list):
            raise ValidationError("Tags must be a list")

        # Normalize and validate each tag
        normalized_tags = []
        for tag in tags:
            if not isinstance(tag, str):
                raise ValidationError("Each tag must be a string")

            normalized_tag = tag.lower().strip()
            if not normalized_tag:
                continue

            if len(normalized_tag) > 50:
                raise ValidationError(
                    f"Tag '{tag}' exceeds maximum length of 50 characters"
                )

            if normalized_tag not in normalized_tags:
                normalized_tags.append(normalized_tag)

        return normalized_tags

    def _validate_classification(self, classification: str) -> str:
        """
        Validate data classification level.

        Args:
            classification: Classification level to validate

        Returns:
            Validated classification level

        Raises:
            ValidationError: If classification is invalid
        """
        valid_classifications = {
            self.CLASSIFICATION_PUBLIC,
            self.CLASSIFICATION_INTERNAL,
            self.CLASSIFICATION_CONFIDENTIAL,
            self.CLASSIFICATION_RESTRICTED,
        }

        normalized = classification.lower().strip()
        if normalized not in valid_classifications:
            raise ValidationError(
                f"Invalid data classification: {classification}. "
                f"Must be one of: {', '.join(valid_classifications)}"
            )

        return normalized

    def has_tag(self, tag: str) -> bool:
        """Check if metadata has a specific tag."""
        return tag.lower() in self.tags

    def has_any_tag(self, tags: list[str]) -> bool:
        """Check if metadata has any of the specified tags."""
        normalized_tags = {tag.lower() for tag in tags}
        return any(tag in normalized_tags for tag in self.tags)

    def has_all_tags(self, tags: list[str]) -> bool:
        """Check if metadata has all of the specified tags."""
        normalized_tags = {tag.lower() for tag in tags}
        return all(tag in self.tags for tag in normalized_tags)

    def is_compliant_with(self, regulation: str) -> bool:
        """Check if metadata indicates compliance with a regulation."""
        compliance_dict = dict(self.compliance_flags)
        return compliance_dict.get(regulation.lower(), False)

    def requires_encryption(self) -> bool:
        """Check if data classification requires encryption."""
        return self.data_classification in (
            self.CLASSIFICATION_CONFIDENTIAL,
            self.CLASSIFICATION_RESTRICTED,
        )

    def requires_restricted_access(self) -> bool:
        """Check if data classification requires restricted access."""
        return self.data_classification == self.CLASSIFICATION_RESTRICTED

    def get_retention_period_days(self) -> int:
        """Get recommended retention period in days based on classification."""
        retention_map = {
            self.CLASSIFICATION_PUBLIC: 365,      # 1 year
            self.CLASSIFICATION_INTERNAL: 2555,   # 7 years
            self.CLASSIFICATION_CONFIDENTIAL: 3650,  # 10 years
            self.CLASSIFICATION_RESTRICTED: 7300,    # 20 years
        }
        return retention_map.get(self.data_classification, 2555)

    def requires_approval_for_access(self) -> bool:
        """Check if data classification requires approval for access."""
        return self.data_classification in (
            self.CLASSIFICATION_CONFIDENTIAL,
            self.CLASSIFICATION_RESTRICTED,
        )

    def get_compliance_requirements(self) -> list[str]:
        """Get list of compliance requirements based on flags."""
        compliance_dict = dict(self.compliance_flags)
        return [regulation for regulation, required in compliance_dict.items() if required]

    def with_tag(self, tag: str) -> "AuditMetadata":
        """
        Create new metadata with an additional tag.

        Args:
            tag: Tag to add

        Returns:
            New AuditMetadata instance with added tag
        """
        new_tags = list(self.tags)
        normalized_tag = tag.lower().strip()
        if normalized_tag and normalized_tag not in new_tags:
            new_tags.append(normalized_tag)

        return AuditMetadata(
            tags=new_tags,
            business_context=dict(self.business_context),
            compliance_flags=dict(self.compliance_flags),
            data_classification=self.data_classification,
            retention_override=self.retention_override,
            custom_fields=dict(self.custom_fields),
        )

    def with_compliance_flag(self, regulation: str, compliant: bool) -> "AuditMetadata":
        """
        Create new metadata with updated compliance flag.

        Args:
            regulation: Regulation name
            compliant: Compliance status

        Returns:
            New AuditMetadata instance with updated flag
        """
        new_flags = dict(self.compliance_flags)
        new_flags[regulation.lower()] = compliant

        return AuditMetadata(
            tags=list(self.tags),
            business_context=dict(self.business_context),
            compliance_flags=new_flags,
            data_classification=self.data_classification,
            retention_override=self.retention_override,
            custom_fields=dict(self.custom_fields),
        )

    def merge_with(self, other: "AuditMetadata") -> "AuditMetadata":
        """
        Merge this metadata with another instance.

        Args:
            other: Other metadata to merge with

        Returns:
            New AuditMetadata instance with merged data
        """
        # Merge tags (union)
        merged_tags = list(set(list(self.tags) + list(other.tags)))

        # Merge business context
        merged_context = dict(self.business_context)
        merged_context.update(dict(other.business_context))

        # Merge compliance flags
        merged_flags = dict(self.compliance_flags)
        merged_flags.update(dict(other.compliance_flags))

        # Merge custom fields
        merged_custom = dict(self.custom_fields)
        merged_custom.update(dict(other.custom_fields))

        # Use more restrictive classification
        classification_priority = {
            self.CLASSIFICATION_PUBLIC: 1,
            self.CLASSIFICATION_INTERNAL: 2,
            self.CLASSIFICATION_CONFIDENTIAL: 3,
            self.CLASSIFICATION_RESTRICTED: 4,
        }

        if classification_priority.get(
            other.data_classification, 0
        ) > classification_priority.get(self.data_classification, 0):
            merged_classification = other.data_classification
        else:
            merged_classification = self.data_classification

        return AuditMetadata(
            tags=merged_tags,
            business_context=merged_context,
            compliance_flags=merged_flags,
            data_classification=merged_classification,
            retention_override=other.retention_override or self.retention_override,
            custom_fields=merged_custom,
        )

    def _get_atomic_values(self) -> tuple[Any, ...]:
        """Get atomic values for equality comparison."""
        return (
            self.tags,
            self.business_context,
            self.compliance_flags,
            self.data_classification,
            self.retention_override,
            self.custom_fields,
        )

    def __str__(self) -> str:
        """String representation of the audit metadata."""
        parts = [f"classification={self.data_classification}"]

        if self.tags:
            parts.append(f"tags={','.join(self.tags)}")

        compliance_dict = dict(self.compliance_flags)
        if compliance_dict:
            compliant = [k for k, v in compliance_dict.items() if v]
            if compliant:
                parts.append(f"compliance={','.join(compliant)}")

        return f"AuditMetadata({'; '.join(parts)})"

    @classmethod
    def create_default(cls) -> "AuditMetadata":
        """Factory method for default metadata."""
        return cls(
            tags=[],
            business_context={},
            compliance_flags={},
            data_classification=cls.CLASSIFICATION_INTERNAL,
        )

    @classmethod
    def create_for_security_event(
        cls, severity: str, compliance_regulations: list[str] | None = None
    ) -> "AuditMetadata":
        """Factory method for security-related audit metadata."""
        compliance_flags = {}
        if compliance_regulations:
            compliance_flags = dict.fromkeys(compliance_regulations, True)

        classification = cls.CLASSIFICATION_CONFIDENTIAL
        if severity == "critical":
            classification = cls.CLASSIFICATION_RESTRICTED

        return cls(
            tags=["security", severity],
            compliance_flags=compliance_flags,
            data_classification=classification,
        )

    @classmethod
    def create_for_authentication_event(
        cls, outcome: str, mfa_used: bool = False
    ) -> "AuditMetadata":
        """Factory method for authentication-related audit metadata."""
        tags = ["authentication"]
        if outcome == "failure":
            tags.append("failed_auth")
        if mfa_used:
            tags.append("mfa")
            
        classification = cls.CLASSIFICATION_CONFIDENTIAL if outcome == "failure" else cls.CLASSIFICATION_INTERNAL
        
        custom_fields = {"mfa_used": mfa_used, "outcome": outcome}
        
        return cls(
            tags=tags,
            compliance_flags={"security_monitoring": True},
            data_classification=classification,
            custom_fields=custom_fields,
        )

    @classmethod
    def create_for_data_access(
        cls, data_sensitivity: str, purpose: str | None = None
    ) -> "AuditMetadata":
        """Factory method for data access audit metadata."""
        classification_map = {
            "public": cls.CLASSIFICATION_PUBLIC,
            "internal": cls.CLASSIFICATION_INTERNAL,
            "confidential": cls.CLASSIFICATION_CONFIDENTIAL,
            "restricted": cls.CLASSIFICATION_RESTRICTED,
        }
        
        classification = classification_map.get(data_sensitivity, cls.CLASSIFICATION_INTERNAL)
        
        tags = ["data_access", data_sensitivity]
        if purpose:
            tags.append(f"purpose_{purpose}")
            
        compliance_flags = {}
        if data_sensitivity in ("confidential", "restricted"):
            compliance_flags = {"gdpr": True, "privacy_review": True}
            
        custom_fields = {"data_sensitivity": data_sensitivity}
        if purpose:
            custom_fields["access_purpose"] = purpose
            
        return cls(
            tags=tags,
            compliance_flags=compliance_flags,
            data_classification=classification,
            custom_fields=custom_fields,
        )

    @classmethod
    def create_for_compliance_event(
        cls, regulation: str, compliance_status: str
    ) -> "AuditMetadata":
        """Factory method for compliance-related audit metadata."""
        return cls(
            tags=["compliance", regulation.lower(), compliance_status],
            compliance_flags={regulation.lower(): compliance_status == "compliant"},
            data_classification=cls.CLASSIFICATION_CONFIDENTIAL,
            retention_override="permanent",  # Compliance events often need permanent retention
            custom_fields={"regulation": regulation, "status": compliance_status},
        )


__all__ = ["AuditMetadata"]
