"""
Compliance Service Interface

Interface for managing compliance requirements
and regulatory adherence for audit operations.
"""

from abc import ABC, abstractmethod
from typing import Any

from app.modules.audit.domain.entities.audit_entry import AuditEntry
from app.modules.audit.domain.enums.audit_enums import ComplianceRegulation


class IComplianceService(ABC):
    """
    Interface for compliance management.
    
    Handles regulatory compliance validation, requirement checking,
    and compliance reporting for audit operations.
    """

    @abstractmethod
    def validate_compliance(self, audit_entry: AuditEntry, regulations: list[ComplianceRegulation]) -> dict[str, Any]:
        """
        Validate an audit entry against compliance regulations.
        
        Args:
            audit_entry: Audit entry to validate
            regulations: List of regulations to check against
            
        Returns:
            Dictionary containing compliance validation results
        """

    @abstractmethod
    def check_data_retention_compliance(self, audit_entry: AuditEntry, regulation: ComplianceRegulation) -> bool:
        """
        Check if audit entry meets data retention compliance requirements.
        
        Args:
            audit_entry: Audit entry to check
            regulation: Compliance regulation to validate against
            
        Returns:
            True if compliant, False otherwise
        """

    @abstractmethod
    def check_right_to_deletion_compliance(self, audit_entry: AuditEntry, regulation: ComplianceRegulation) -> dict[str, Any]:
        """
        Check compliance with right to deletion requirements.
        
        Args:
            audit_entry: Audit entry to check
            regulation: Compliance regulation to validate against
            
        Returns:
            Dictionary containing deletion compliance analysis
        """

    @abstractmethod
    def generate_compliance_report(self, entries: list[AuditEntry], regulation: ComplianceRegulation) -> dict[str, Any]:
        """
        Generate a compliance report for a set of audit entries.
        
        Args:
            entries: List of audit entries to analyze
            regulation: Compliance regulation to report on
            
        Returns:
            Dictionary containing compliance report data
        """
