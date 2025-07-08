"""Audit log aggregate.

This module defines the AuditLog aggregate root that manages
audit trail entries and enforces business rules.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any
from uuid import UUID

from app.core.domain.base import AggregateRoot
from app.core.errors import DomainError, ValidationError
from app.modules.audit.domain.enums.audit_enums import (
    AuditCategory,
    AuditSeverity,
    AuditStatus,
    RetentionPolicy,
)
from app.modules.audit.domain.errors.audit_errors import AuditRetentionError
from app.modules.audit.domain.events.audit_events import (
    AuditArchived,
    AuditEntryRecorded,
    AuditLogCreated,
)
from app.modules.audit.domain.value_objects.audit_action import AuditAction
from app.modules.audit.domain.value_objects.audit_context import AuditContext
from app.modules.audit.domain.value_objects.audit_metadata import AuditMetadata
from app.modules.audit.domain.value_objects.resource_identifier import (
    ResourceIdentifier,
)

if TYPE_CHECKING:
    from app.modules.audit.domain.entities.audit_entry import AuditEntry, AuditField
    from app.modules.audit.domain.entities.audit_filter import AuditFilter


class AuditLog(AggregateRoot):
    """
    Aggregate root for audit trail management.

    This aggregate manages a collection of audit entries and enforces
    business rules around audit logging, retention, and archival.

    Attributes:
        title: Title of the audit log
        description: Description of the log purpose
        retention_policy: Policy for retaining entries
        status: Current status of the log
        entries: Collection of audit entries
        entry_count: Total number of entries
        last_entry_at: Timestamp of last entry
        archived_at: Timestamp when archived
        archive_location: Location of archived data

    Business Rules:
        - Entries are immutable once added
        - Entries must be added in chronological order
        - Retention policy cannot be shortened
        - Archived logs cannot accept new entries
        - Critical severity entries have extended retention
    """

    MAX_ENTRIES_PER_LOG = 100000  # Maximum entries before requiring new log
    PERFORMANCE_WARNING_THRESHOLD = 80000  # Warn when approaching limit
    BATCH_SIZE_LIMIT = 1000  # Maximum batch size for operations
    INDEX_REBUILD_THRESHOLD = 50000  # Rebuild indexes after this many entries

    def __init__(
        self,
        title: str,
        retention_policy: RetentionPolicy,
        description: str | None = None,
        created_by: UUID | None = None,
        entity_id: UUID | None = None,
    ):
        """
        Initialize audit log.

        Args:
            title: Log title
            retention_policy: Retention policy
            description: Optional description
            created_by: User creating the log
            entity_id: Log identifier

        Raises:
            ValidationError: If required fields are invalid
        """
        super().__init__(entity_id)

        # Validate and set title
        self.validate_not_empty(title, "title")
        self.title = title.strip()

        # Set description
        self.description = description.strip() if description else None

        # Set retention policy
        if not isinstance(retention_policy, RetentionPolicy):
            raise ValidationError("Invalid retention policy")
        self.retention_policy = retention_policy

        # Initialize status
        self.status = AuditStatus.ACTIVE

        # Initialize collections with performance tracking
        self.entries: list[AuditEntry] = []
        self.entry_count = 0
        self.last_entry_at: datetime | None = None
        
        # Performance metrics
        self.performance_metrics = {
            "total_size_bytes": 0,
            "average_entry_size": 0,
            "index_last_rebuilt": self.created_at,
            "query_performance_score": 100,
            "compression_ratio": 1.0,
        }
        
        # Health monitoring
        self.health_status = "healthy"
        self.health_issues: list[str] = []
        self.last_health_check: datetime | None = None

        # Archive fields
        self.archived_at: datetime | None = None
        self.archive_location: str | None = None
        self.archive_metadata: dict[str, Any] = {}

        # Add creation event
        self.add_event(
            AuditLogCreated(
                audit_log_id=self.id,
                title=self.title,
                description=self.description,
                retention_policy=str(self.retention_policy),
                created_by=created_by,
            )
        )

    def add_entry(
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
        changes: list[AuditField] | None = None,
        correlation_id: str | None = None,
        session_id: UUID | None = None,
    ) -> AuditEntry:
        """
        Add an audit entry to the log.

        Args:
            user_id: User who performed action
            action: Action performed
            resource: Affected resource
            context: Action context
            metadata: Additional metadata
            severity: Event severity
            category: Event category
            outcome: Action outcome
            error_details: Error details if failed
            duration_ms: Action duration
            changes: Field-level changes
            correlation_id: Correlation ID
            session_id: Session ID

        Returns:
            Created audit entry

        Raises:
            DomainError: If business rules are violated
        """
        # Check if log can accept new entries
        if not self.can_add_entries():
            raise DomainError("Cannot add entries to this audit log")

        # Check entry limit
        if self.entry_count >= self.MAX_ENTRIES_PER_LOG:
            raise DomainError(
                f"Audit log has reached maximum capacity of {self.MAX_ENTRIES_PER_LOG} entries"
            )

        # Create audit entry
        entry = AuditEntry(
            user_id=user_id,
            action=action,
            resource=resource,
            context=context,
            metadata=metadata,
            severity=severity,
            category=category,
            outcome=outcome,
            error_details=error_details,
            duration_ms=duration_ms,
            changes=changes,
            correlation_id=correlation_id,
            session_id=session_id,
        )

        # Validate chronological order
        if self.last_entry_at and entry.created_at < self.last_entry_at:
            raise DomainError("Entries must be added in chronological order")

        # Add entry
        self.entries.append(entry)
        self.entry_count += 1
        self.last_entry_at = entry.created_at

        # Mark as modified
        self.mark_modified()

        # Add event
        self.add_event(
            AuditEntryRecorded(
                entry_id=entry.id,
                user_id=user_id,
                action_type=action.action_type,
                resource_type=resource.resource_type,
                resource_id=resource.resource_id,
                severity=severity.value if severity else entry.severity.value,
                category=category.value if category else entry.category.value,
                outcome=outcome,
                session_id=session_id,
                correlation_id=correlation_id,
            )
        )

        return entry

    def can_add_entries(self) -> bool:
        """Check if log can accept new entries."""
        return self.status == AuditStatus.ACTIVE

    def is_full(self) -> bool:
        """Check if log has reached capacity."""
        return self.entry_count >= self.MAX_ENTRIES_PER_LOG

    def get_retention_expiry(self) -> datetime | None:
        """
        Get the retention expiry date.

        Returns:
            Expiry date, or None if permanent retention
        """
        if self.retention_policy.is_permanent():
            return None

        if not self.last_entry_at:
            # Use creation date if no entries
            reference_date = self.created_at
        else:
            reference_date = self.last_entry_at

        return reference_date + timedelta(
            days=self.retention_policy.get_retention_days()
        )

    def is_expired(self) -> bool:
        """Check if log has exceeded retention period."""
        expiry = self.get_retention_expiry()
        if not expiry:
            return False

        return datetime.utcnow() > expiry

    def update_retention_policy(self, new_policy: RetentionPolicy) -> None:
        """
        Update retention policy.

        Args:
            new_policy: New retention policy

        Raises:
            DomainError: If policy would shorten retention
        """
        if self.status != AuditStatus.ACTIVE:
            raise DomainError("Cannot update retention policy for non-active log")

        # Check if new policy is shorter
        if not new_policy.is_permanent() and not self.retention_policy.is_permanent():
            if (
                new_policy.get_retention_days()
                < self.retention_policy.get_retention_days()
            ):
                raise AuditRetentionError(
                    "Cannot shorten retention policy", policy=str(new_policy)
                )

        self.retention_policy = new_policy
        self.mark_modified()

    def prepare_for_archive(self) -> None:
        """
        Prepare log for archival.

        Raises:
            DomainError: If log cannot be archived
        """
        if self.status != AuditStatus.ACTIVE:
            raise DomainError(f"Cannot archive log in status: {self.status}")

        if self.entry_count == 0:
            raise DomainError("Cannot archive empty log")

        self.status = AuditStatus.PENDING_ARCHIVE
        self.mark_modified()

    def complete_archive(
        self, archive_location: str, compressed_size: int | None = None
    ) -> None:
        """
        Complete the archive process.

        Args:
            archive_location: Location of archived data
            compressed_size: Size after compression

        Raises:
            DomainError: If not in pending archive status
        """
        if self.status != AuditStatus.PENDING_ARCHIVE:
            raise DomainError(f"Cannot complete archive from status: {self.status}")

        self.status = AuditStatus.ARCHIVED
        self.archived_at = datetime.utcnow()
        self.archive_location = archive_location

        # Clear entries to save memory (they're in archive now)
        self.entries.clear()

        self.mark_modified()

        # Add archive event
        if self.last_entry_at:
            time_range_start = self.created_at
            time_range_end = self.last_entry_at
        else:
            time_range_start = time_range_end = self.created_at

        self.add_event(
            AuditArchived(
                archive_id=self.id,
                archived_count=self.entry_count,
                time_range_start=time_range_start,
                time_range_end=time_range_end,
                archive_location=archive_location,
                retention_policy=str(self.retention_policy),
                compressed_size_bytes=compressed_size,
            )
        )

    def filter_entries(self, filter: AuditFilter) -> list[AuditEntry]:
        """
        Filter entries based on criteria.

        Args:
            filter: Filter criteria

        Returns:
            Filtered list of entries
        """
        filtered = self.entries

        # Apply time range filter
        if filter.time_range:
            filtered = [e for e in filtered if filter.time_range.contains(e.created_at)]

        # Apply user filter
        if filter.user_ids:
            filtered = [e for e in filtered if e.user_id in filter.user_ids]
        elif not filter.include_system:
            filtered = [e for e in filtered if e.user_id is not None]

        # Apply resource filters
        if filter.resource_types:
            filtered = [
                e for e in filtered if e.resource.resource_type in filter.resource_types
            ]

        if filter.resource_ids:
            filtered = [
                e for e in filtered if e.resource.resource_id in filter.resource_ids
            ]

        # Apply action filters
        if filter.action_types:
            filtered = [
                e for e in filtered if e.action.action_type in filter.action_types
            ]

        if filter.operations:
            filtered = [e for e in filtered if e.action.operation in filter.operations]

        # Apply severity filter
        if filter.severities:
            filtered = [e for e in filtered if e.severity in filter.severities]

        # Apply category filter
        if filter.categories:
            filtered = [e for e in filtered if e.category in filter.categories]

        # Apply outcome filter
        if filter.outcomes:
            filtered = [e for e in filtered if e.outcome in filter.outcomes]

        # Apply session filter
        if filter.session_ids:
            filtered = [e for e in filtered if e.session_id in filter.session_ids]

        # Apply correlation filter
        if filter.correlation_ids:
            filtered = [
                e for e in filtered if e.correlation_id in filter.correlation_ids
            ]

        # Apply text search
        if filter.search_text:
            search_lower = filter.search_text.lower()
            filtered = [
                e
                for e in filtered
                if (
                    search_lower in e.action.description.lower()
                    or search_lower in e.resource.get_display_name().lower()
                    or (
                        e.context.user_agent
                        and search_lower in e.context.user_agent.lower()
                    )
                )
            ]

        # Apply sorting
        if filter.sort_by == "created_at":
            filtered.sort(
                key=lambda e: e.created_at, reverse=(filter.sort_order == "desc")
            )
        elif filter.sort_by == "severity":
            filtered.sort(
                key=lambda e: e.severity, reverse=(filter.sort_order == "desc")
            )

        # Apply pagination
        start = filter.offset
        end = start + filter.limit

        return filtered[start:end]

    def update_performance_metrics(self) -> None:
        """Update performance metrics for the log."""
        if not self.entries:
            return
            
        # Calculate total size
        total_size = sum(len(str(entry.to_dict())) for entry in self.entries)
        self.performance_metrics["total_size_bytes"] = total_size
        
        # Calculate average entry size
        if self.entry_count > 0:
            self.performance_metrics["average_entry_size"] = total_size / self.entry_count
            
        # Update query performance score based on size and fragmentation
        if self.entry_count > self.PERFORMANCE_WARNING_THRESHOLD:
            self.performance_metrics["query_performance_score"] = max(
                20, 100 - ((self.entry_count - self.PERFORMANCE_WARNING_THRESHOLD) / 1000)
            )
        
        self.mark_modified()

    def check_health(self) -> dict[str, Any]:
        """Perform comprehensive health check."""
        self.health_issues.clear()
        
        # Check capacity
        if self.entry_count > self.PERFORMANCE_WARNING_THRESHOLD:
            self.health_issues.append(f"Approaching capacity limit: {self.entry_count}/{self.MAX_ENTRIES_PER_LOG}")
            
        # Check performance
        if self.performance_metrics["query_performance_score"] < 50:
            self.health_issues.append("Query performance degraded")
            
        # Check retention compliance
        if self.is_expired():
            self.health_issues.append("Log has exceeded retention period")
            
        # Check integrity
        integrity_issues = self._check_integrity()
        self.health_issues.extend(integrity_issues)
        
        # Determine overall health status
        if not self.health_issues:
            self.health_status = "healthy"
        elif len(self.health_issues) <= 2:
            self.health_status = "warning"
        else:
            self.health_status = "critical"
            
        self.last_health_check = datetime.utcnow()
        self.mark_modified()
        
        return {
            "status": self.health_status,
            "issues": self.health_issues,
            "last_check": self.last_health_check.isoformat(),
            "performance_score": self.performance_metrics["query_performance_score"],
            "capacity_usage": (self.entry_count / self.MAX_ENTRIES_PER_LOG) * 100,
        }

    def _check_integrity(self) -> list[str]:
        """Check data integrity and return list of issues."""
        issues = []
        
        # Check for duplicate entries
        entry_ids = [entry.id for entry in self.entries]
        if len(entry_ids) != len(set(entry_ids)):
            issues.append("Duplicate entry IDs detected")
            
        # Check chronological order
        timestamps = [entry.created_at for entry in self.entries]
        if timestamps != sorted(timestamps):
            issues.append("Entries not in chronological order")
            
        # Check for corrupted entries
        corrupted_count = 0
        for entry in self.entries:
            if not entry.verify_integrity():
                corrupted_count += 1
                
        if corrupted_count > 0:
            issues.append(f"{corrupted_count} entries failed integrity verification")
            
        return issues

    def optimize_performance(self) -> dict[str, Any]:
        """Optimize log performance and return optimization results."""
        optimization_results = {
            "actions_taken": [],
            "performance_improvement": 0,
            "space_saved_bytes": 0,
        }
        
        initial_score = self.performance_metrics["query_performance_score"]
        
        # Remove duplicate entries (shouldn't happen, but safety check)
        initial_count = len(self.entries)
        unique_entries = []
        seen_ids = set()
        
        for entry in self.entries:
            if entry.id not in seen_ids:
                unique_entries.append(entry)
                seen_ids.add(entry.id)
                
        if len(unique_entries) < initial_count:
            removed_count = initial_count - len(unique_entries)
            self.entries = unique_entries
            self.entry_count = len(unique_entries)
            optimization_results["actions_taken"].append(f"Removed {removed_count} duplicate entries")
            
        # Sort entries by timestamp for better query performance
        self.entries.sort(key=lambda e: e.created_at)
        optimization_results["actions_taken"].append("Sorted entries chronologically")
        
        # Update performance metrics
        self.update_performance_metrics()
        
        # Calculate improvement
        final_score = self.performance_metrics["query_performance_score"]
        optimization_results["performance_improvement"] = final_score - initial_score
        
        self.mark_modified()
        return optimization_results

    def get_statistics(self) -> dict[str, Any]:
        """Get comprehensive statistics about the audit log."""
        stats = {
            "total_entries": self.entry_count,
            "status": self.status.value,
            "retention_policy": str(self.retention_policy),
            "created_at": self.created_at.isoformat(),
            "last_entry_at": self.last_entry_at.isoformat()
            if self.last_entry_at
            else None,
            "is_expired": self.is_expired(),
            "is_full": self.is_full(),
            "health_status": self.health_status,
            "performance_metrics": self.performance_metrics.copy(),
        }

        if self.entries:
            # Calculate severity distribution
            severity_dist = {}
            category_dist = {}
            outcome_dist = {}
            risk_dist = {"low": 0, "medium": 0, "high": 0}
            
            total_duration = 0
            duration_count = 0
            
            for entry in self.entries:
                # Severity distribution
                severity = entry.severity.value
                severity_dist[severity] = severity_dist.get(severity, 0) + 1
                
                # Category distribution
                category = entry.category.value
                category_dist[category] = category_dist.get(category, 0) + 1
                
                # Outcome distribution
                outcome = entry.outcome
                outcome_dist[outcome] = outcome_dist.get(outcome, 0) + 1
                
                # Risk distribution
                if entry.is_high_risk():
                    risk_dist["high"] += 1
                elif entry.is_medium_risk():
                    risk_dist["medium"] += 1
                else:
                    risk_dist["low"] += 1
                    
                # Duration statistics
                if entry.duration_ms:
                    total_duration += entry.duration_ms
                    duration_count += 1
                    
            stats.update({
                "severity_distribution": severity_dist,
                "category_distribution": category_dist,
                "outcome_distribution": outcome_dist,
                "risk_distribution": risk_dist,
                "average_duration_ms": total_duration / duration_count if duration_count > 0 else 0,
                "failure_rate": (outcome_dist.get("failure", 0) / self.entry_count) * 100,
                "high_risk_percentage": (risk_dist["high"] / self.entry_count) * 100,
            })

        return stats

    def get_security_summary(self) -> dict[str, Any]:
        """Get security-focused summary of the log."""
        if not self.entries:
            return {"total_entries": 0, "security_events": 0}
            
        security_events = 0
        failed_auth_attempts = 0
        high_risk_events = 0
        external_access_attempts = 0
        
        for entry in self.entries:
            if entry.category == AuditCategory.SECURITY:
                security_events += 1
                
            if entry.action.is_auth_action() and entry.is_failed():
                failed_auth_attempts += 1
                
            if entry.is_high_risk():
                high_risk_events += 1
                
            if (entry.context.ip_address and 
                entry.context.get_location_hint() == "external"):
                external_access_attempts += 1
                
        return {
            "total_entries": self.entry_count,
            "security_events": security_events,
            "failed_auth_attempts": failed_auth_attempts,
            "high_risk_events": high_risk_events,
            "external_access_attempts": external_access_attempts,
            "security_event_percentage": (security_events / self.entry_count) * 100,
            "risk_score": high_risk_events / self.entry_count * 100 if self.entry_count > 0 else 0,
        }

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        data = super().to_dict()

        data.update(
            {
                "title": self.title,
                "description": self.description,
                "retention_policy": str(self.retention_policy),
                "status": self.status.value,
                "entry_count": self.entry_count,
                "last_entry_at": self.last_entry_at.isoformat()
                if self.last_entry_at
                else None,
                "archived_at": self.archived_at.isoformat()
                if self.archived_at
                else None,
                "archive_location": self.archive_location,
            }
        )

        # Don't include all entries in dict representation (too large)
        # Entries should be fetched separately when needed

        return data


__all__ = ["AuditLog"]
