"""
Audit Integrity Service Interface

Interface for managing audit record integrity,
including hash verification and tamper detection.
"""

from typing import Any, Protocol

from app.modules.audit.domain.entities.audit_entry import AuditEntry


class IAuditIntegrityService(Protocol):
    """
    Interface for audit record integrity management.
    
    Provides cryptographic verification and tamper detection
    for audit records to ensure data integrity and compliance.
    """

    def verify_integrity(self, audit_entry: AuditEntry) -> bool:
        """
        Verify the integrity of an audit entry.
        
        Args:
            audit_entry: Audit entry to verify
            
        Returns:
            True if integrity is valid, False otherwise
            
        Raises:
            AuditIntegrityError: If integrity check fails
        """
        ...

    def verify_chain_integrity(self, audit_entries: list[AuditEntry]) -> bool:
        """
        Verify the integrity of a chain of audit entries.
        
        Args:
            audit_entries: List of audit entries in chronological order
            
        Returns:
            True if chain integrity is valid, False otherwise
        """
        ...

    def detect_tampering(self, audit_entry: AuditEntry) -> dict[str, Any]:
        """
        Detect potential tampering in an audit entry.
        
        Args:
            audit_entry: Audit entry to analyze
            
        Returns:
            Dictionary containing tampering analysis results
        """
        ...

    def calculate_hash(self, audit_entry: AuditEntry) -> str:
        """
        Calculate the integrity hash for an audit entry.
        
        Args:
            audit_entry: Audit entry to hash
            
        Returns:
            Calculated hash string
        """
        ...
