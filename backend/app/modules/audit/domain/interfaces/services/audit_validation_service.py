"""Audit validation service interface.

This module defines the interface for audit data validation,
ensuring data integrity and business rule compliance.
"""

from abc import ABC, abstractmethod
from typing import Any
from uuid import UUID

from app.modules.audit.domain.aggregates.audit_log import AuditLog
from app.modules.audit.domain.aggregates.audit_session import AuditSession
from app.modules.audit.domain.entities.audit_entry import AuditEntry
from app.modules.audit.domain.value_objects.audit_action import AuditAction
from app.modules.audit.domain.value_objects.audit_context import AuditContext
from app.modules.audit.domain.value_objects.resource_identifier import (
    ResourceIdentifier,
)


class IAuditValidationService(ABC):
    """
    Domain service interface for audit validation operations.
    
    This service handles complex validation logic that spans
    multiple domain objects or requires external validation.
    """

    @abstractmethod
    async def validate_audit_entry_creation(
        self,
        action: AuditAction,
        resource: ResourceIdentifier,
        context: AuditContext,
        user_id: UUID | None = None,
    ) -> dict[str, Any]:
        """
        Validate that an audit entry can be created.
        
        Performs comprehensive validation including business rules,
        security constraints, and data consistency checks.
        """

    @abstractmethod
    async def validate_session_hierarchy(
        self, session: AuditSession, parent_session: AuditSession | None = None
    ) -> dict[str, Any]:
        """Validate audit session hierarchy and nesting rules."""

    @abstractmethod
    async def validate_log_capacity(self, audit_log: AuditLog) -> dict[str, Any]:
        """Validate audit log capacity and performance constraints."""

    @abstractmethod
    async def validate_data_consistency(
        self, audit_log_id: UUID
    ) -> dict[str, Any]:
        """Validate data consistency within an audit log."""

    @abstractmethod
    async def validate_temporal_ordering(
        self, audit_log_id: UUID
    ) -> dict[str, Any]:
        """Validate that audit entries maintain proper temporal ordering."""

    @abstractmethod
    async def validate_security_constraints(
        self,
        user_id: UUID | None,
        action: AuditAction,
        resource: ResourceIdentifier,
        context: AuditContext,
    ) -> dict[str, Any]:
        """Validate security constraints for audit operations."""

    @abstractmethod
    async def validate_compliance_requirements(
        self, audit_entry: AuditEntry
    ) -> dict[str, Any]:
        """Validate that audit entry meets compliance requirements."""
