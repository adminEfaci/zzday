"""Audit retention service interface.

This module defines the interface for audit data retention management,
handling policy enforcement and data lifecycle operations.
"""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Protocol
from uuid import UUID

from app.modules.audit.domain.enums.audit_enums import RetentionPolicy
from app.modules.audit.domain.value_objects.time_range import TimeRange


class IAuditRetentionService(Protocol):
    """
    Domain service interface for audit retention management.
    
    This service handles the complex business logic around
    audit data retention, archival, and deletion policies.
    """

    async def evaluate_retention_policy(
        self, audit_log_id: UUID, current_policy: RetentionPolicy
    ) -> dict[str, Any]:
        """
        Evaluate if current retention policy is appropriate.
        
        Returns recommendations for policy adjustments based on
        data patterns, compliance requirements, and storage costs.
        """

    async def identify_records_for_archival(
        self, policy: RetentionPolicy, batch_size: int = 1000
    ) -> list[UUID]:
        """Identify audit records ready for archival."""

    async def identify_records_for_deletion(
        self, policy: RetentionPolicy, batch_size: int = 1000
    ) -> list[UUID]:
        """Identify audit records ready for deletion."""

    async def calculate_storage_impact(
        self, time_range: TimeRange, policy: RetentionPolicy
    ) -> dict[str, Any]:
        """Calculate storage impact of retention policy changes."""

    async def validate_retention_compliance(
        self, audit_log_id: UUID
    ) -> dict[str, Any]:
        """Validate that retention policies meet compliance requirements."""

    async def estimate_archival_size(
        self, audit_log_id: UUID, compression_ratio: float = 0.3
    ) -> dict[str, Any]:
        """Estimate size and cost of archiving audit data."""

    async def schedule_retention_maintenance(
        self, policy: RetentionPolicy, schedule_time: datetime
    ) -> dict[str, Any]:
        """Schedule automated retention maintenance tasks."""
