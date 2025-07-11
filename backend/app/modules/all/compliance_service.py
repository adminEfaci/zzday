"""
Compliance Service Interface

Protocol for identity-specific compliance operations including GDPR, data retention, and consent management.
"""

from datetime import datetime
from typing import TYPE_CHECKING, Any, Protocol
from uuid import UUID

if TYPE_CHECKING:
    from ...value_objects.data_export import DataExport


class IComplianceService(Protocol):
    """Protocol for identity-specific compliance operations."""
    
    async def validate_data_collection_consent(
        self,
        user_id: UUID,
        data_types: list[str]
    ) -> tuple[bool, list[str]]:
        """
        Validate consent for data collection.
        
        Args:
            user_id: User identifier
            data_types: Types of data to collect
            
        Returns:
            Tuple of (has_consent, missing_consents)
        """
    
    async def check_user_data_retention(
        self,
        user_id: UUID,
        data_type: str
    ) -> tuple[bool, datetime]:
        """
        Check data retention policy.
        
        Args:
            user_id: User identifier
            data_type: Type of data
            
        Returns:
            Tuple of (should_retain, expiry_date)
        """
    
    async def anonymize_user_data(
        self,
        user_id: UUID,
        retention_policy: str
    ) -> dict[str, Any]:
        """
        Anonymize user data per retention policy.
        
        Args:
            user_id: User identifier
            retention_policy: Policy to apply
            
        Returns:
            Summary of anonymized data
        """
    
    async def generate_user_data_export(
        self,
        user_id: UUID,
        export_format: str = "json"
    ) -> "DataExport":
        """
        Generate user data export.
        
        Args:
            user_id: User identifier
            export_format: Export format (json/csv/xml)
            
        Returns:
            DataExport value object containing export metadata
        """
    
    async def validate_user_consent_changes(
        self,
        user_id: UUID,
        consent_changes: dict[str, bool]
    ) -> bool:
        """
        Validate consent changes.
        
        Args:
            user_id: User identifier
            consent_changes: Consent updates
            
        Returns:
            True if changes are valid
        """
    
    async def log_compliance_event(
        self,
        user_id: UUID,
        event_type: str,
        details: dict[str, Any]
    ) -> None:
        """
        Log compliance-related event.
        
        Args:
            user_id: User identifier
            event_type: Type of compliance event
            details: Event details
        """
