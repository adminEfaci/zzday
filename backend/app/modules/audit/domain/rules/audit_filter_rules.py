"""
Audit Filter Business Rules

Business rules and validation logic for audit filter operations.
"""

from typing import Any

from app.core.errors import DomainError
from app.modules.audit.domain.enums.audit_enums import AuditSeverity


class AuditFilterBusinessRules:
    """Business rules for audit filter validation and constraints."""
    
    # Performance limits
    MAX_TIME_RANGE_DAYS = 365
    MAX_USER_IDS = 50
    MAX_RESOURCE_IDS = 100
    MAX_LIMIT_WITHOUT_TIME_CONSTRAINT = 100
    MIN_SEARCH_TEXT_LENGTH = 3
    
    def validate_performance_constraints(
        self,
        time_range_days: int | None,
        user_id_count: int,
        resource_id_count: int,
        limit: int,
        has_search_text: bool,
    ) -> None:
        """Validate performance-related constraints."""
        
        # Time range validation
        if time_range_days and time_range_days > self.MAX_TIME_RANGE_DAYS:
            raise DomainError(
                f"Time range cannot exceed {self.MAX_TIME_RANGE_DAYS} days for performance reasons"
            )
        
        # Large queries without time constraints
        if not time_range_days and limit > self.MAX_LIMIT_WITHOUT_TIME_CONSTRAINT:
            raise DomainError(
                f"Queries without time constraints cannot exceed {self.MAX_LIMIT_WITHOUT_TIME_CONSTRAINT} results"
            )
        
        # User ID limits
        if user_id_count > self.MAX_USER_IDS:
            raise DomainError(f"Cannot filter by more than {self.MAX_USER_IDS} user IDs at once")
        
        # Resource ID limits
        if resource_id_count > self.MAX_RESOURCE_IDS:
            raise DomainError(f"Cannot filter by more than {self.MAX_RESOURCE_IDS} resource IDs at once")
    
    def validate_security_constraints(
        self,
        severities: list[AuditSeverity],
        include_system: bool,
        user_requesting: str | None = None,
    ) -> None:
        """Validate security-related constraints."""
        
        # High-privilege queries require special permissions
        if AuditSeverity.CRITICAL in severities and not user_requesting:
            raise DomainError("Critical severity queries require authenticated user")
        
        # System action access
        if not include_system:
            # This is fine, user is explicitly excluding system actions
            pass
    
    def validate_compliance_constraints(
        self,
        categories: list[str],
        retention_aware: bool = True,
    ) -> None:
        """Validate compliance-related constraints."""
        
        # Certain categories require retention awareness
        sensitive_categories = {"authentication", "authorization", "security"}
        if any(cat in sensitive_categories for cat in categories):
            if not retention_aware:
                raise DomainError(
                    "Queries for sensitive categories must be retention-aware"
                )


class AuditEntryBusinessRules:
    """Business rules for audit entry validation and constraints."""
    
    # Size limits
    MAX_ERROR_DETAIL_SIZE = 10240  # 10KB
    MAX_CHANGES_COUNT = 100
    MAX_CORRELATION_ID_LENGTH = 255
    
    # Risk thresholds
    HIGH_RISK_THRESHOLD = 80
    CRITICAL_RISK_THRESHOLD = 95
    
    def validate_entry_constraints(
        self,
        action_type: str,
        outcome: str,
        error_details: dict[str, Any] | None,
        changes_count: int,
        risk_score: int,
    ) -> None:
        """Validate audit entry business constraints."""
        
        # Failed actions must have error details
        if outcome in ("failure", "timeout", "cancelled") and not error_details:
            raise DomainError(f"Error details are required for {outcome} outcomes")
        
        # Changes validation
        if changes_count > self.MAX_CHANGES_COUNT:
            raise DomainError(f"Too many changes: {changes_count}. Maximum: {self.MAX_CHANGES_COUNT}")
        
        # High-risk entries require additional validation
        if risk_score >= self.CRITICAL_RISK_THRESHOLD:
            if action_type == "delete" and outcome == "success":
                # Critical risk delete operations should be flagged
                pass  # This would trigger additional monitoring
    
    def validate_integrity_requirements(
        self,
        severity: AuditSeverity,
        category: str,
        requires_signature: bool = False,
    ) -> dict[str, bool]:
        """Determine integrity requirements based on entry characteristics."""
        
        requirements = {
            "requires_hash": True,  # All entries need hash
            "requires_signature": requires_signature,
            "requires_encryption": False,
            "requires_backup": False,
        }
        
        # High severity entries require signatures
        if severity in (AuditSeverity.HIGH, AuditSeverity.CRITICAL):
            requirements["requires_signature"] = True
        
        # Security and authentication entries require signatures
        if category in ("security", "authentication"):
            requirements["requires_signature"] = True
        
        # Critical entries require backup
        if severity == AuditSeverity.CRITICAL:
            requirements["requires_backup"] = True
        
        return requirements


__all__ = ["AuditEntryBusinessRules", "AuditFilterBusinessRules"]
