"""
Audit Integrity Service

Domain service for managing audit record integrity,
including hash verification and tamper detection.
"""

import hashlib
from datetime import datetime
from typing import Any

from app.modules.audit.domain.entities.audit_entry import AuditEntry
from app.modules.audit.domain.errors.audit_errors import AuditIntegrityError
from app.modules.audit.domain.interfaces.services.audit_integrity_service import (
    IAuditIntegrityService,
)


class AuditIntegrityService(IAuditIntegrityService):
    """
    Domain service for audit record integrity management.
    
    Provides cryptographic verification and tamper detection
    for audit records to ensure data integrity and compliance.
    """

    def __init__(self, secret_key: str | None = None):
        """
        Initialize integrity service.
        
        Args:
            secret_key: Secret key for HMAC operations
        """
        self._secret_key = secret_key

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
        try:
            expected_hash = self._calculate_hash(audit_entry)
            return audit_entry.integrity_hash == expected_hash
        except Exception as e:
            raise AuditIntegrityError(
                message=f"Failed to verify audit entry integrity: {e!s}",
                audit_id=audit_entry.id,
                integrity_check="hash_verification",
            ) from e

    def verify_chain_integrity(self, audit_entries: list[AuditEntry]) -> bool:
        """
        Verify the integrity of a chain of audit entries.
        
        Args:
            audit_entries: List of audit entries in chronological order
            
        Returns:
            True if chain integrity is valid, False otherwise
        """
        if not audit_entries:
            return True

        # Sort by timestamp to ensure proper order
        sorted_entries = sorted(audit_entries, key=lambda x: x.created_at)
        
        for i, entry in enumerate(sorted_entries):
            # Verify individual entry integrity
            if not self.verify_integrity(entry):
                return False
            
            # Verify chain linkage (if implemented)
            if i > 0:
                previous_entry = sorted_entries[i - 1]
                if not self._verify_chain_link(previous_entry, entry):
                    return False
        
        return True

    def detect_tampering(self, audit_entry: AuditEntry) -> dict[str, Any]:
        """
        Detect potential tampering in an audit entry.
        
        Args:
            audit_entry: Audit entry to analyze
            
        Returns:
            Dictionary containing tampering analysis results
        """
        analysis = {
            "is_tampered": False,
            "integrity_valid": True,
            "anomalies": [],
            "risk_score": 0,
        }

        # Check hash integrity
        if not self.verify_integrity(audit_entry):
            analysis["is_tampered"] = True
            analysis["integrity_valid"] = False
            analysis["anomalies"].append("Hash mismatch detected")
            analysis["risk_score"] += 50

        # Check for timestamp anomalies
        if self._has_timestamp_anomaly(audit_entry):
            analysis["anomalies"].append("Timestamp anomaly detected")
            analysis["risk_score"] += 20

        # Check for structural anomalies
        structural_issues = self._check_structural_integrity(audit_entry)
        if structural_issues:
            analysis["anomalies"].extend(structural_issues)
            analysis["risk_score"] += len(structural_issues) * 10

        analysis["is_tampered"] = analysis["risk_score"] > 30

        return analysis

    def calculate_hash(self, audit_entry: AuditEntry) -> str:
        """Calculate the integrity hash for an audit entry."""
        return self._calculate_hash(audit_entry)

    def _calculate_hash(self, audit_entry: AuditEntry) -> str:
        """Internal method to calculate the integrity hash for an audit entry."""
        # Create a canonical representation of the audit entry
        canonical_data = {
            "id": str(audit_entry.id),
            "user_id": str(audit_entry.user_id) if audit_entry.user_id else None,
            "action": {
                "action_type": audit_entry.action.action_type,
                "resource_type": audit_entry.action.resource_type,
                "operation": audit_entry.action.operation,
            },
            "resource": {
                "resource_type": audit_entry.resource.resource_type,
                "resource_id": audit_entry.resource.resource_id,
            },
            "outcome": audit_entry.outcome,
            "created_at": audit_entry.created_at.isoformat(),
        }

        # Convert to string and hash
        canonical_string = str(sorted(canonical_data.items()))
        return hashlib.sha256(canonical_string.encode()).hexdigest()

    def _verify_chain_link(self, previous: AuditEntry, current: AuditEntry) -> bool:
        """Verify the link between two consecutive audit entries."""
        # Simple implementation - could be enhanced with blockchain-like linking
        return current.created_at >= previous.created_at

    def _has_timestamp_anomaly(self, audit_entry: AuditEntry) -> bool:
        """Check for timestamp anomalies."""
        now = datetime.utcnow()
        
        # Check if timestamp is in the future
        if audit_entry.created_at > now:
            return True
        
        # Check if timestamp is too far in the past (configurable threshold)
        # This is a simple check - could be more sophisticated
        return False

    def _check_structural_integrity(self, audit_entry: AuditEntry) -> list[str]:
        """Check for structural integrity issues."""
        issues = []
        
        # Check required fields
        if not audit_entry.action:
            issues.append("Missing action information")
        
        if not audit_entry.resource:
            issues.append("Missing resource information")
        
        if not audit_entry.outcome:
            issues.append("Missing outcome information")
        
        return issues
