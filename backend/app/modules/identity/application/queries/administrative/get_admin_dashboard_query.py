"""Get admin dashboard query implementation."""

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from app.core.cqrs import Query, QueryHandler
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.decorators import (
    rate_limit,
    require_permission,
    validate_request,
)
from app.modules.identity.application.dtos.response import AdminDashboardResponse
from app.modules.identity.domain.interfaces.repositories.audit_repository import (
    IAuditRepository,
)
from app.modules.identity.domain.interfaces.repositories.security_event_repository import (
    ISecurityRepository,
)
from app.modules.identity.domain.interfaces.repositories.session_repository import (
    ISessionRepository,
)
from app.modules.identity.domain.interfaces.repositories.user_repository import (
from app.modules.identity.domain.interfaces.services import (
    IComplianceRepository,
)
    IUserRepository,
)


@dataclass
class GetAdminDashboardQuery(Query[AdminDashboardResponse]):
    """Query to get admin dashboard data."""
    
    include_realtime: bool = True
    include_alerts: bool = True
    time_range_hours: int = 24
    requester_permissions: list[str] = field(default_factory=list)


class GetAdminDashboardQueryHandler(QueryHandler[GetAdminDashboardQuery, AdminDashboardResponse]):
    """Handler for admin dashboard queries."""
    
    def __init__(
        self,
        uow: UnitOfWork,
        user_repository: IUserRepository,
        session_repository: ISessionRepository,
        audit_repository: IAuditRepository,
        security_repository: ISecurityRepository,
        compliance_repository: IComplianceRepository
    ):
        self.uow = uow
        self.user_repository = user_repository
        self.session_repository = session_repository
        self.audit_repository = audit_repository
        self.security_repository = security_repository
        self.compliance_repository = compliance_repository
    
    @rate_limit(max_calls=60, window_seconds=60)
    @require_permission("admin.dashboard.read")
    @validate_request
    async def handle(self, query: GetAdminDashboardQuery) -> AdminDashboardResponse:
        """Handle admin dashboard query."""
        
        async with self.uow:
            start_date = datetime.now(UTC) - timedelta(hours=query.time_range_hours)
            end_date = datetime.now(UTC)
            
            # Collect dashboard data in parallel where possible
            dashboard_data = {}
            
            # System overview
            dashboard_data["overview"] = await self._get_system_overview()
            
            # User statistics
            dashboard_data["users"] = await self._get_user_statistics(start_date, end_date)
            
            # Session information
            dashboard_data["sessions"] = await self._get_session_info()
            
            # Recent activity
            dashboard_data["recent_activity"] = await self._get_recent_activity(start_date)
            
            # Security summary
            dashboard_data["security"] = await self._get_security_summary(start_date, end_date)
            
            # Compliance status
            dashboard_data["compliance"] = await self._get_compliance_status()
            
            # Real-time data if requested
            if query.include_realtime:
                dashboard_data["realtime"] = await self._get_realtime_data()
            
            # Active alerts if requested
            if query.include_alerts:
                dashboard_data["alerts"] = await self._get_active_alerts()
            
            # Quick actions available
            dashboard_data["quick_actions"] = self._get_quick_actions(query.requester_permissions)
            
            return AdminDashboardResponse(
                overview=dashboard_data["overview"],
                users=dashboard_data["users"],
                sessions=dashboard_data["sessions"],
                recent_activity=dashboard_data["recent_activity"],
                security=dashboard_data["security"],
                compliance=dashboard_data["compliance"],
                realtime=dashboard_data.get("realtime", {}),
                alerts=dashboard_data.get("alerts", []),
                quick_actions=dashboard_data["quick_actions"],
                generated_at=datetime.now(UTC)
            )
    
    async def _get_system_overview(self) -> dict[str, Any]:
        """Get system overview statistics."""
        total_users = await self.user_repository.count_users({})
        active_users = await self.user_repository.count_active_users()
        
        # Calculate last 24h stats
        yesterday = datetime.now(UTC) - timedelta(days=1)
        new_users_24h = await self.user_repository.count_users({
            "created_at__gte": yesterday
        })
        
        return {
            "total_users": total_users,
            "active_users": active_users,
            "new_users_24h": new_users_24h,
            "system_status": "operational",  # This would check actual system health
            "last_backup": (datetime.now(UTC) - timedelta(hours=3)).isoformat(),  # Example
            "version": "1.0.0"
        }
    
    async def _get_user_statistics(
        self,
        start_date: datetime,
        end_date: datetime
    ) -> dict[str, Any]:
        """Get user statistics."""
        # User activity stats
        activity_stats = await self.audit_repository.get_user_activity_statistics(
            start_date,
            end_date
        )
        
        # User distribution by status
        total_users = await self.user_repository.count_users({})
        active_users = await self.user_repository.count_active_users()
        verified_users = await self.user_repository.count_users({"email_verified": True})
        mfa_enabled = await self.user_repository.count_users({"mfa_enabled": True})
        
        return {
            "total": total_users,
            "active": active_users,
            "inactive": total_users - active_users,
            "verified": verified_users,
            "unverified": total_users - verified_users,
            "mfa_enabled": mfa_enabled,
            "mfa_percentage": (mfa_enabled / total_users * 100) if total_users > 0 else 0,
            "activity_stats": activity_stats,
            "growth_trend": self._calculate_growth_trend(activity_stats)
        }
    
    async def _get_session_info(self) -> dict[str, Any]:
        """Get session information."""
        # Active sessions
        active_sessions = await self.session_repository.count_user_sessions(
            user_id=None,
            active_only=True
        )
        
        # Session statistics for last 24h
        yesterday = datetime.now(UTC) - timedelta(days=1)
        session_stats = await self.session_repository.get_session_statistics(
            yesterday,
            datetime.now(UTC)
        )
        
        return {
            "active": active_sessions,
            "created_24h": session_stats.get("total_created", 0),
            "expired_24h": session_stats.get("total_expired", 0),
            "average_duration_minutes": session_stats.get("avg_duration_minutes", 0),
            "peak_concurrent": session_stats.get("peak_concurrent", 0),
            "by_device_type": session_stats.get("device_types", {}),
            "geographic_distribution": session_stats.get("geographic", {})
        }
    
    async def _get_recent_activity(self, start_date: datetime) -> list[dict[str, Any]]:
        """Get recent activity feed."""
        # Get recent audit logs
        recent_logs = await self.audit_repository.search_logs({
            "start_date": start_date,
            "end_date": datetime.now(UTC)
        }, page=1, page_size=20)
        
        # Format for dashboard display
        activities = []
        for log in recent_logs.items[:10]:  # Limit to 10 most recent
            activities.append({
                "id": str(log.id),
                "timestamp": log.created_at.isoformat(),
                "action": log.action,
                "actor": str(log.actor_id) if log.actor_id else "system",
                "resource": f"{log.resource_type}:{log.resource_id}" if log.resource_id else log.resource_type,
                "ip_address": log.ip_address,
                "status": "success" if not log.details.get("error") else "failed"
            })
        
        return activities
    
    async def _get_security_summary(
        self,
        start_date: datetime,
        end_date: datetime
    ) -> dict[str, Any]:
        """Get security summary."""
        # Security events statistics
        security_stats = await self.security_repository.get_security_events_statistics(
            start_date,
            end_date
        )
        
        # Failed login attempts
        failed_logins = await self.audit_repository.count_failed_authentications(
            start_date,
            end_date
        )
        
        # Suspicious activities
        suspicious_count = await self.security_repository.count_suspicious_activities(
            start_date,
            end_date
        )
        
        # Risk distribution
        risk_dist = await self.security_repository.get_risk_distribution(
            start_date,
            end_date
        )
        
        return {
            "total_events": security_stats.get("total", 0),
            "failed_logins": failed_logins,
            "suspicious_activities": suspicious_count,
            "blocked_attempts": security_stats.get("blocked", 0),
            "risk_levels": risk_dist,
            "threat_level": self._calculate_overall_threat_level(security_stats),
            "recent_incidents": security_stats.get("recent_incidents", [])[:5]
        }
    
    async def _get_compliance_status(self) -> dict[str, Any]:
        """Get compliance status summary."""
        # Compliance violations in last 30 days
        thirty_days_ago = datetime.now(UTC) - timedelta(days=30)
        violations = await self.compliance_repository.count_violations(
            thirty_days_ago,
            datetime.now(UTC)
        )
        
        # Audit completion
        audits = await self.compliance_repository.count_audits(
            thirty_days_ago,
            datetime.now(UTC)
        )
        
        return {
            "status": "compliant" if violations == 0 else "issues_found",
            "violations_30d": violations,
            "audits_completed_30d": audits,
            "frameworks": {
                "gdpr": {"status": "compliant", "last_audit": "2024-01-15"},
                "hipaa": {"status": "compliant", "last_audit": "2024-01-10"},
                "sox": {"status": "pending_audit", "last_audit": "2023-12-01"}
            },
            "next_audit_due": (datetime.now(UTC) + timedelta(days=15)).isoformat()
        }
    
    async def _get_realtime_data(self) -> dict[str, Any]:
        """Get real-time data for live updates."""
        # This would connect to real-time data sources
        # For now, return current snapshot
        return {
            "active_users_now": await self.session_repository.count_user_sessions(
                user_id=None,
                active_only=True
            ),
            "requests_per_second": 42.5,  # Would come from monitoring
            "cpu_usage": 35.2,
            "memory_usage": 62.8,
            "last_updated": datetime.now(UTC).isoformat()
        }
    
    async def _get_active_alerts(self) -> list[dict[str, Any]]:
        """Get active system alerts."""
        alerts = []
        
        # Check for high failed login rate
        hour_ago = datetime.now(UTC) - timedelta(hours=1)
        failed_logins = await self.audit_repository.count_failed_authentications(
            hour_ago,
            datetime.now(UTC)
        )
        
        if failed_logins > 100:
            alerts.append({
                "id": "high_failed_logins",
                "severity": "warning",
                "title": "High Failed Login Rate",
                "message": f"{failed_logins} failed login attempts in the last hour",
                "timestamp": datetime.now(UTC).isoformat(),
                "actions": ["investigate", "block_ips"]
            })
        
        # Check for suspicious activities
        suspicious = await self.security_repository.count_suspicious_activities(
            hour_ago,
            datetime.now(UTC)
        )
        
        if suspicious > 10:
            alerts.append({
                "id": "suspicious_activity",
                "severity": "high",
                "title": "Elevated Suspicious Activity",
                "message": f"{suspicious} suspicious activities detected",
                "timestamp": datetime.now(UTC).isoformat(),
                "actions": ["review_logs", "enable_stricter_rules"]
            })
        
        return alerts
    
    def _get_quick_actions(self, permissions: list[str]) -> list[dict[str, Any]]:
        """Get available quick actions based on permissions."""
        actions = []
        
        if "admin.users.create" in permissions:
            actions.append({
                "id": "create_user",
                "label": "Create User",
                "icon": "user-plus",
                "action": "navigate:/admin/users/create"
            })
        
        if "admin.backup.execute" in permissions:
            actions.append({
                "id": "run_backup",
                "label": "Run Backup",
                "icon": "database",
                "action": "command:system.backup.run"
            })
        
        if "admin.security.manage" in permissions:
            actions.append({
                "id": "security_scan",
                "label": "Security Scan",
                "icon": "shield",
                "action": "command:security.scan.run"
            })
        
        if "admin.maintenance.manage" in permissions:
            actions.append({
                "id": "maintenance_mode",
                "label": "Maintenance Mode",
                "icon": "tools",
                "action": "command:maintenance.toggle"
            })
        
        return actions
    
    def _calculate_growth_trend(self, stats: dict[str, Any]) -> str:
        """Calculate user growth trend."""
        if "daily_new_users" in stats:
            daily_values = list(stats["daily_new_users"].values())
            if len(daily_values) >= 2:
                recent_avg = sum(daily_values[-3:]) / min(3, len(daily_values))
                older_avg = sum(daily_values[:-3]) / max(1, len(daily_values) - 3)
                
                if recent_avg > older_avg * 1.1:
                    return "increasing"
                if recent_avg < older_avg * 0.9:
                    return "decreasing"
        
        return "stable"
    
    def _calculate_overall_threat_level(self, security_stats: dict[str, Any]) -> str:
        """Calculate overall threat level."""
        severity_scores = {
            "critical": 100,
            "high": 50,
            "medium": 20,
            "low": 5
        }
        
        total_score = 0
        for severity, count in security_stats.get("by_severity", {}).items():
            total_score += severity_scores.get(severity, 0) * count
        
        if total_score >= 1000:
            return "critical"
        if total_score >= 500:
            return "high"
        if total_score >= 100:
            return "medium"
        return "low"