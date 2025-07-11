"""
Audit Domain Service

Implements comprehensive audit logging and compliance tracking.
"""

import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from app.core.security import generate_token
from app.utils.crypto import hash_data, mask_sensitive_data
from app.utils.date import format_relative_time
from app.utils.validation import validate_uuid

from ...interfaces.repositories.audit_repository import IAuditRepository
from ...interfaces.services.infrastructure.cache_port import ICachePort
from ...interfaces.services.infrastructure.configuration_port import IConfigurationPort
from ...interfaces.services.infrastructure.event_publisher_port import IEventPublisherPort
from ...interfaces.services.monitoring.audit_service import IAuditService
from ...enums import AuditAction, RiskLevel, SecurityEventType
from ...value_objects.audit_entry import AuditEntry


class AuditSeverity(Enum):
    """Audit entry severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class AuditContext:
    """Context for audit operations."""
    user_id: Optional[UUID]
    session_id: Optional[str]
    ip_address: Optional[str]
    user_agent: Optional[str]
    request_id: Optional[str]
    correlation_id: Optional[str]


@dataclass
class ComplianceMetrics:
    """Compliance tracking metrics."""
    total_events: int
    events_by_type: Dict[str, int]
    events_by_severity: Dict[str, int]
    high_risk_events: int
    failed_events: int
    compliance_score: float
    period_start: datetime
    period_end: datetime


class AuditService(IAuditService):
    """Domain service for audit logging and compliance tracking."""
    
    def __init__(
        self,
        audit_repository: IAuditRepository,
        cache_port: ICachePort,
        configuration_port: IConfigurationPort,
        event_publisher: IEventPublisherPort
    ) -> None:
        self._audit_repository = audit_repository
        self._cache = cache_port
        self._config = configuration_port
        self._event_publisher = event_publisher
        
    async def log_event(
        self,
        event_type: str,
        user_id: Optional[UUID] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        action: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
        severity: str = "medium"
    ) -> str:
        """Log an audit event."""
        
        # Generate audit entry ID
        audit_id = str(uuid4())
        
        # Validate and sanitize inputs
        if not event_type:
            raise ValueError("Event type is required")
        
        if user_id and not validate_uuid(str(user_id)):
            raise ValueError("Invalid user ID format")
        
        # Prepare audit entry
        now = datetime.utcnow()
        audit_entry = AuditEntry(
            id=audit_id,
            event_type=event_type,
            user_id=user_id,
            resource_type=resource_type,
            resource_id=resource_id,
            action=action or "unknown",
            details=self._sanitize_audit_details(details or {}),
            context=self._sanitize_audit_context(context or {}),
            severity=severity,
            timestamp=now,
            risk_level=self._calculate_risk_level(event_type, severity, details),
            compliance_relevant=self._is_compliance_relevant(event_type),
            retention_period=await self._get_retention_period(event_type, severity)
        )
        
        # Store audit entry
        await self._audit_repository.create_audit_entry(audit_entry)
        
        # Update audit cache for recent queries
        await self._update_audit_cache(audit_entry)
        
        # Publish audit event for real-time monitoring
        await self._publish_audit_event(audit_entry)
        
        # Check for compliance alerts
        await self._check_compliance_alerts(audit_entry)
        
        return audit_id
    
    async def get_audit_trail(
        self,
        user_id: Optional[UUID] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        event_types: Optional[List[str]] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """Get audit trail with filtering options."""
        
        # Validate inputs
        if limit <= 0 or limit > 1000:
            limit = 100
        
        if user_id and not validate_uuid(str(user_id)):
            return []
        
        # Set default date range if not provided
        if not end_date:
            end_date = datetime.utcnow()
        if not start_date:
            start_date = end_date - timedelta(days=30)
        
        # Check cache for common queries
        cache_key = self._generate_audit_cache_key(
            user_id, resource_type, resource_id, event_types, start_date, end_date, limit, offset
        )
        cached_result = await self._cache.get(cache_key)
        if cached_result:
            return cached_result
        
        # Get audit entries from repository
        audit_entries = await self._audit_repository.get_audit_entries(
            user_id=user_id,
            resource_type=resource_type,
            resource_id=resource_id,
            event_types=event_types,
            start_date=start_date,
            end_date=end_date,
            limit=limit,
            offset=offset
        )
        
        # Format audit entries for response
        formatted_entries = []
        for entry in audit_entries:
            formatted_entries.append({
                "id": entry.id,
                "event_type": entry.event_type,
                "user_id": str(entry.user_id) if entry.user_id else None,
                "resource_type": entry.resource_type,
                "resource_id": entry.resource_id,
                "action": entry.action,
                "details": entry.details,
                "context": entry.context,
                "severity": entry.severity,
                "risk_level": entry.risk_level.value if entry.risk_level else None,
                "timestamp": entry.timestamp.isoformat(),
                "relative_time": format_relative_time(entry.timestamp),
                "compliance_relevant": entry.compliance_relevant
            })
        
        # Cache result for 5 minutes
        await self._cache.set(cache_key, formatted_entries, expiry_seconds=300)
        
        return formatted_entries
    
    async def get_compliance_report(
        self,
        start_date: datetime,
        end_date: datetime,
        include_details: bool = False
    ) -> Dict[str, Any]:
        """Generate compliance report for date range."""
        
        # Validate date range
        if start_date >= end_date:
            raise ValueError("Start date must be before end date")
        
        if (end_date - start_date).days > 365:
            raise ValueError("Date range cannot exceed 365 days")
        
        # Check for cached report
        cache_key = f"compliance_report:{start_date.date()}:{end_date.date()}:{include_details}"
        cached_report = await self._cache.get(cache_key)
        if cached_report:
            return cached_report
        
        # Get compliance-relevant audit entries
        compliance_entries = await self._audit_repository.get_compliance_entries(
            start_date=start_date,
            end_date=end_date
        )
        
        # Generate compliance metrics
        metrics = self._calculate_compliance_metrics(compliance_entries, start_date, end_date)
        
        # Generate report
        report = {
            "report_id": str(uuid4()),
            "period": {
                "start_date": start_date.isoformat(),
                "end_date": end_date.isoformat(),
                "duration_days": (end_date - start_date).days
            },
            "metrics": {
                "total_events": metrics.total_events,
                "events_by_type": metrics.events_by_type,
                "events_by_severity": metrics.events_by_severity,
                "high_risk_events": metrics.high_risk_events,
                "failed_events": metrics.failed_events,
                "compliance_score": metrics.compliance_score
            },
            "summary": {
                "compliance_status": self._determine_compliance_status(metrics.compliance_score),
                "top_event_types": self._get_top_event_types(metrics.events_by_type, 5),
                "risk_assessment": self._assess_compliance_risk(metrics),
                "recommendations": self._generate_compliance_recommendations(metrics)
            },
            "generated_at": datetime.utcnow().isoformat()
        }
        
        # Add detailed entries if requested
        if include_details:
            report["detailed_entries"] = [
                {
                    "id": entry.id,
                    "event_type": entry.event_type,
                    "user_id": str(entry.user_id) if entry.user_id else None,
                    "action": entry.action,
                    "severity": entry.severity,
                    "risk_level": entry.risk_level.value if entry.risk_level else None,
                    "timestamp": entry.timestamp.isoformat(),
                    "compliance_relevant": entry.compliance_relevant
                }
                for entry in compliance_entries[:1000]  # Limit detailed entries
            ]
        
        # Cache report for 1 hour
        await self._cache.set(cache_key, report, expiry_seconds=3600)
        
        return report
    
    async def search_audit_logs(
        self,
        query: str,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Search audit logs with text query and filters."""
        
        if not query or len(query.strip()) < 2:
            return []
        
        if limit <= 0 or limit > 1000:
            limit = 100
        
        # Search audit entries
        search_results = await self._audit_repository.search_audit_entries(
            query=query.strip(),
            filters=filters or {},
            limit=limit
        )
        
        # Format search results
        formatted_results = []
        for entry in search_results:
            formatted_results.append({
                "id": entry.id,
                "event_type": entry.event_type,
                "user_id": str(entry.user_id) if entry.user_id else None,
                "resource_type": entry.resource_type,
                "resource_id": entry.resource_id,
                "action": entry.action,
                "details": entry.details,
                "severity": entry.severity,
                "timestamp": entry.timestamp.isoformat(),
                "relevance_score": getattr(entry, 'relevance_score', 0.0),
                "matched_fields": getattr(entry, 'matched_fields', [])
            })
        
        return formatted_results
    
    async def archive_old_logs(
        self,
        older_than_days: int,
        archive_location: str
    ) -> Dict[str, Any]:
        """Archive old audit logs for compliance."""
        
        if older_than_days < 1:
            raise ValueError("Archive period must be at least 1 day")
        
        cutoff_date = datetime.utcnow() - timedelta(days=older_than_days)
        
        # Get entries to archive
        entries_to_archive = await self._audit_repository.get_entries_before_date(cutoff_date)
        
        if not entries_to_archive:
            return {
                "archived_count": 0,
                "archive_location": archive_location,
                "cutoff_date": cutoff_date.isoformat(),
                "status": "no_entries_to_archive"
            }
        
        # Archive entries (implementation would depend on storage backend)
        archive_result = await self._archive_entries(entries_to_archive, archive_location)
        
        # Delete archived entries from active storage
        deleted_count = await self._audit_repository.delete_entries_before_date(cutoff_date)
        
        # Log archival operation
        await self.log_event(
            event_type="audit_logs_archived",
            action="archive",
            details={
                "archived_count": len(entries_to_archive),
                "deleted_count": deleted_count,
                "cutoff_date": cutoff_date.isoformat(),
                "archive_location": archive_location
            },
            severity="medium"
        )
        
        return {
            "archived_count": len(entries_to_archive),
            "deleted_count": deleted_count,
            "archive_location": archive_location,
            "cutoff_date": cutoff_date.isoformat(),
            "status": "success",
            "archive_id": archive_result.get("archive_id")
        }
    
    # Private helper methods
    
    def _sanitize_audit_details(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize audit details by masking sensitive data."""
        sanitized = {}
        
        sensitive_keys = ["password", "token", "secret", "api_key", "ssn", "credit_card"]
        
        for key, value in details.items():
            if key.lower() in sensitive_keys:
                sanitized[key] = "[REDACTED]"
            elif key.lower() in ["email", "phone"]:
                if isinstance(value, str):
                    sanitized[key] = mask_sensitive_data(value, 4)
                else:
                    sanitized[key] = value
            else:
                sanitized[key] = value
        
        return sanitized
    
    def _sanitize_audit_context(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize audit context."""
        sanitized = {}
        
        for key, value in context.items():
            if key.lower() == "ip_address" and isinstance(value, str):
                sanitized[key] = mask_sensitive_data(value, 6)
            else:
                sanitized[key] = value
        
        return sanitized
    
    def _calculate_risk_level(
        self, 
        event_type: str, 
        severity: str, 
        details: Optional[Dict[str, Any]]
    ) -> RiskLevel:
        """Calculate risk level for audit entry."""
        
        # High-risk event types
        high_risk_events = [
            "user_deleted", "permission_granted", "admin_access", 
            "security_breach", "compliance_violation"
        ]
        
        # Medium-risk event types
        medium_risk_events = [
            "password_changed", "email_changed", "mfa_disabled",
            "role_assigned", "data_exported"
        ]
        
        if event_type in high_risk_events or severity == "critical":
            return RiskLevel.HIGH
        elif event_type in medium_risk_events or severity == "high":
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def _is_compliance_relevant(self, event_type: str) -> bool:
        """Determine if event type is compliance-relevant."""
        compliance_events = [
            "user_created", "user_deleted", "permission_changed",
            "data_accessed", "data_modified", "data_exported",
            "login_success", "login_failed", "password_changed",
            "mfa_enabled", "mfa_disabled", "admin_access"
        ]
        return event_type in compliance_events
    
    async def _get_retention_period(self, event_type: str, severity: str) -> int:
        """Get retention period in days for event."""
        config = await self._config.get_audit_settings()
        
        # Default retention periods
        retention_periods = {
            "critical": config.get("critical_retention_days", 2555),  # 7 years
            "high": config.get("high_retention_days", 1825),  # 5 years
            "medium": config.get("medium_retention_days", 1095),  # 3 years
            "low": config.get("low_retention_days", 365)  # 1 year
        }
        
        return retention_periods.get(severity, retention_periods["medium"])
    
    async def _update_audit_cache(self, audit_entry: AuditEntry) -> None:
        """Update recent audit cache."""
        cache_key = f"recent_audit_entries"
        recent_entries = await self._cache.get(cache_key) or []
        
        # Add new entry and keep only last 100
        recent_entries.insert(0, audit_entry)
        recent_entries = recent_entries[:100]
        
        # Cache for 1 hour
        await self._cache.set(cache_key, recent_entries, expiry_seconds=3600)
    
    async def _publish_audit_event(self, audit_entry: AuditEntry) -> None:
        """Publish audit event for real-time monitoring."""
        event_data = {
            "audit_id": audit_entry.id,
            "event_type": audit_entry.event_type,
            "user_id": str(audit_entry.user_id) if audit_entry.user_id else None,
            "severity": audit_entry.severity,
            "risk_level": audit_entry.risk_level.value if audit_entry.risk_level else None,
            "timestamp": audit_entry.timestamp.isoformat(),
            "compliance_relevant": audit_entry.compliance_relevant
        }
        
        await self._event_publisher.publish(
            topic="audit.events",
            event_type="audit_entry_created",
            data=event_data
        )
    
    async def _check_compliance_alerts(self, audit_entry: AuditEntry) -> None:
        """Check if audit entry triggers compliance alerts."""
        
        # Check for critical events
        if audit_entry.severity == "critical":
            await self._event_publisher.publish(
                topic="compliance.alerts",
                event_type="critical_audit_event",
                data={
                    "audit_id": audit_entry.id,
                    "event_type": audit_entry.event_type,
                    "user_id": str(audit_entry.user_id) if audit_entry.user_id else None,
                    "timestamp": audit_entry.timestamp.isoformat()
                }
            )
        
        # Check for compliance violations
        if "violation" in audit_entry.event_type.lower():
            await self._event_publisher.publish(
                topic="compliance.violations",
                event_type="compliance_violation_detected",
                data={
                    "audit_id": audit_entry.id,
                    "violation_type": audit_entry.event_type,
                    "user_id": str(audit_entry.user_id) if audit_entry.user_id else None,
                    "details": audit_entry.details
                }
            )
    
    def _generate_audit_cache_key(
        self,
        user_id: Optional[UUID],
        resource_type: Optional[str],
        resource_id: Optional[str],
        event_types: Optional[List[str]],
        start_date: Optional[datetime],
        end_date: Optional[datetime],
        limit: int,
        offset: int
    ) -> str:
        """Generate cache key for audit queries."""
        key_parts = [
            f"user:{user_id}" if user_id else "user:all",
            f"resource_type:{resource_type}" if resource_type else "resource_type:all",
            f"resource_id:{resource_id}" if resource_id else "resource_id:all",
            f"events:{','.join(event_types)}" if event_types else "events:all",
            f"start:{start_date.date()}" if start_date else "start:none",
            f"end:{end_date.date()}" if end_date else "end:none",
            f"limit:{limit}",
            f"offset:{offset}"
        ]
        
        cache_key = "audit_query:" + "|".join(key_parts)
        return hash_data(cache_key)[:32]  # Truncate for cache key length
    
    def _calculate_compliance_metrics(
        self,
        entries: List[AuditEntry],
        start_date: datetime,
        end_date: datetime
    ) -> ComplianceMetrics:
        """Calculate compliance metrics from audit entries."""
        
        total_events = len(entries)
        events_by_type = {}
        events_by_severity = {}
        high_risk_events = 0
        failed_events = 0
        
        for entry in entries:
            # Count by type
            events_by_type[entry.event_type] = events_by_type.get(entry.event_type, 0) + 1
            
            # Count by severity
            events_by_severity[entry.severity] = events_by_severity.get(entry.severity, 0) + 1
            
            # Count high risk events
            if entry.risk_level == RiskLevel.HIGH:
                high_risk_events += 1
            
            # Count failed events (assuming "failed" in event type indicates failure)
            if "failed" in entry.event_type.lower() or "error" in entry.event_type.lower():
                failed_events += 1
        
        # Calculate compliance score (0-100)
        compliance_score = self._calculate_compliance_score(
            total_events, high_risk_events, failed_events
        )
        
        return ComplianceMetrics(
            total_events=total_events,
            events_by_type=events_by_type,
            events_by_severity=events_by_severity,
            high_risk_events=high_risk_events,
            failed_events=failed_events,
            compliance_score=compliance_score,
            period_start=start_date,
            period_end=end_date
        )
    
    def _calculate_compliance_score(
        self,
        total_events: int,
        high_risk_events: int,
        failed_events: int
    ) -> float:
        """Calculate compliance score based on metrics."""
        if total_events == 0:
            return 100.0
        
        # Base score starts at 100
        score = 100.0
        
        # Deduct points for high-risk events
        high_risk_ratio = high_risk_events / total_events
        score -= (high_risk_ratio * 30)  # Up to 30 points deduction
        
        # Deduct points for failed events
        failed_ratio = failed_events / total_events
        score -= (failed_ratio * 20)  # Up to 20 points deduction
        
        return max(score, 0.0)
    
    def _determine_compliance_status(self, compliance_score: float) -> str:
        """Determine compliance status based on score."""
        if compliance_score >= 95:
            return "excellent"
        elif compliance_score >= 85:
            return "good"
        elif compliance_score >= 70:
            return "fair"
        else:
            return "poor"
    
    def _get_top_event_types(self, events_by_type: Dict[str, int], limit: int) -> List[Dict[str, Any]]:
        """Get top event types by count."""
        sorted_events = sorted(events_by_type.items(), key=lambda x: x[1], reverse=True)
        return [
            {"event_type": event_type, "count": count}
            for event_type, count in sorted_events[:limit]
        ]
    
    def _assess_compliance_risk(self, metrics: ComplianceMetrics) -> str:
        """Assess overall compliance risk."""
        if metrics.compliance_score >= 90 and metrics.high_risk_events == 0:
            return "low"
        elif metrics.compliance_score >= 80 and metrics.high_risk_events < 5:
            return "medium"
        else:
            return "high"
    
    def _generate_compliance_recommendations(self, metrics: ComplianceMetrics) -> List[str]:
        """Generate compliance improvement recommendations."""
        recommendations = []
        
        if metrics.compliance_score < 85:
            recommendations.append("Review and strengthen security policies")
        
        if metrics.high_risk_events > 0:
            recommendations.append("Investigate and address high-risk security events")
        
        if metrics.failed_events > metrics.total_events * 0.05:  # More than 5% failed
            recommendations.append("Reduce system failure rates through monitoring improvements")
        
        if not recommendations:
            recommendations.append("Maintain current compliance practices")
        
        return recommendations
    
    async def _archive_entries(self, entries: List[AuditEntry], archive_location: str) -> Dict[str, Any]:
        """Archive audit entries to specified location."""
        # This would implement actual archiving based on storage backend
        # For now, return placeholder result
        archive_id = str(uuid4())
        
        return {
            "archive_id": archive_id,
            "location": archive_location,
            "entry_count": len(entries),
            "archived_at": datetime.utcnow().isoformat()
        }
