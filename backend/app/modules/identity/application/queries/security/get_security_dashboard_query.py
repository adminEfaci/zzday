"""Get security dashboard query implementation."""

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from app.core.cqrs import Query, QueryHandler
from app.core.infrastructure import UnitOfWork
from app.modules.identity.domain.interfaces.repositories.audit_repository import IAuditRepository
from app.modules.identity.domain.interfaces.repositories.security_event_repository import ISecurityRepository
from app.modules.identity.application.decorators import (
    rate_limit,
    require_permission,
    validate_request,
)
from app.modules.identity.application.dtos.response import SecurityDashboardResponse


@dataclass
class GetSecurityDashboardQuery(Query[SecurityDashboardResponse]):
    """Query to get security dashboard data."""
    
    time_range_hours: int = 24
    include_realtime: bool = True
    include_predictions: bool = True
    requester_permissions: list[str] = field(default_factory=list)


class GetSecurityDashboardQueryHandler(QueryHandler[GetSecurityDashboardQuery, SecurityDashboardResponse]):
    """Handler for security dashboard queries."""
    
    def __init__(
        self,
        uow: UnitOfWork,
        security_repository: ISecurityRepository,
        audit_repository: IAuditRepository,
        incident_repository: IIncidentRepository
    ):
        self.uow = uow
        self.security_repository = security_repository
        self.audit_repository = audit_repository
        self.incident_repository = incident_repository
    
    @rate_limit(max_calls=60, window_seconds=60)
    @require_permission("security.dashboard.read")
    @validate_request
    async def handle(self, query: GetSecurityDashboardQuery) -> SecurityDashboardResponse:
        """Handle security dashboard query."""
        
        async with self.uow:
            start_date = datetime.now(UTC) - timedelta(hours=query.time_range_hours)
            end_date = datetime.now(UTC)
            
            # Collect dashboard components
            dashboard_data = {}
            
            # Threat overview
            dashboard_data["threat_overview"] = await self._get_threat_overview(start_date, end_date)
            
            # Recent incidents
            dashboard_data["recent_incidents"] = await self._get_recent_incidents(start_date)
            
            # Security metrics
            dashboard_data["security_metrics"] = await self._get_security_metrics(start_date, end_date)
            
            # Risk assessment summary
            dashboard_data["risk_summary"] = await self._get_risk_summary(start_date, end_date)
            
            # Authentication statistics
            dashboard_data["auth_stats"] = await self._get_auth_statistics(start_date, end_date)
            
            # Policy violations
            dashboard_data["policy_violations"] = await self._get_policy_violations(start_date, end_date)
            
            # Real-time monitoring if requested
            if query.include_realtime:
                dashboard_data["realtime"] = await self._get_realtime_security_data()
            
            # Predictions if requested
            if query.include_predictions:
                dashboard_data["predictions"] = await self._get_security_predictions(dashboard_data)
            
            # Active alerts
            dashboard_data["active_alerts"] = await self._get_active_security_alerts()
            
            # Recommended actions
            dashboard_data["recommendations"] = self._generate_recommendations(dashboard_data)
            
            return SecurityDashboardResponse(
                threat_overview=dashboard_data["threat_overview"],
                recent_incidents=dashboard_data["recent_incidents"],
                security_metrics=dashboard_data["security_metrics"],
                risk_summary=dashboard_data["risk_summary"],
                auth_stats=dashboard_data["auth_stats"],
                policy_violations=dashboard_data["policy_violations"],
                realtime_data=dashboard_data.get("realtime", {}),
                predictions=dashboard_data.get("predictions", {}),
                active_alerts=dashboard_data["active_alerts"],
                recommendations=dashboard_data["recommendations"],
                generated_at=datetime.now(UTC)
            )
    
    async def _get_threat_overview(self, start_date: datetime, end_date: datetime) -> dict[str, Any]:
        """Get threat overview statistics."""
        # Get security events
        security_stats = await self.security_repository.get_security_events_statistics(
            start_date,
            end_date
        )
        
        # Get risk distribution
        risk_dist = await self.security_repository.get_detailed_risk_distribution(
            start_date,
            end_date
        )
        
        # Get top risk factors
        top_risks = await self.security_repository.get_top_risk_factors(
            start_date,
            end_date
        )
        
        return {
            "total_threats": security_stats.get("total", 0),
            "blocked_attempts": security_stats.get("blocked", 0),
            "active_threats": security_stats.get("active", 0),
            "threat_level": self._calculate_threat_level(security_stats),
            "risk_distribution": risk_dist,
            "top_risk_factors": top_risks[:5],
            "threat_categories": security_stats.get("by_category", {}),
            "geographic_threats": security_stats.get("geographic", {})
        }
    
    async def _get_recent_incidents(self, start_date: datetime) -> list[dict[str, Any]]:
        """Get recent security incidents."""
        incidents = await self.incident_repository.get_incidents(
            start_date=start_date,
            end_date=datetime.now(UTC)
        )
        
        # Format for dashboard
        formatted_incidents = []
        for incident in incidents[:10]:  # Limit to 10 most recent
            formatted_incidents.append({
                "id": str(incident["id"]),
                "timestamp": incident["created_at"],
                "type": incident["type"],
                "severity": incident["severity"],
                "status": incident["status"],
                "affected_users": incident.get("affected_users", 0),
                "description": incident.get("description", ""),
                "response_time_minutes": incident.get("response_time_minutes")
            })
        
        return formatted_incidents
    
    async def _get_security_metrics(self, start_date: datetime, end_date: datetime) -> dict[str, Any]:
        """Get security metrics."""
        # Failed authentications
        failed_auth = await self.audit_repository.count_failed_authentications(
            start_date,
            end_date
        )
        
        # Privilege escalations
        priv_escalations = await self.audit_repository.count_privilege_escalations(
            start_date,
            end_date
        )
        
        # Suspicious activities
        suspicious = await self.security_repository.count_suspicious_activities(
            start_date,
            end_date
        )
        
        # Security event trends
        trends = await self.security_repository.get_security_trends(
            start_date,
            end_date,
            "hour"
        )
        
        return {
            "failed_authentications": failed_auth,
            "privilege_escalations": priv_escalations,
            "suspicious_activities": suspicious,
            "security_score": self._calculate_security_score({
                "failed_auth": failed_auth,
                "escalations": priv_escalations,
                "suspicious": suspicious
            }),
            "trends": trends,
            "mean_time_to_detect": 12.5,  # Minutes - would be calculated
            "mean_time_to_respond": 45.2  # Minutes - would be calculated
        }
    
    async def _get_risk_summary(self, start_date: datetime, end_date: datetime) -> dict[str, Any]:
        """Get risk assessment summary."""
        # Risk distribution
        risk_dist = await self.security_repository.get_risk_distribution(
            start_date,
            end_date
        )
        
        # Risk trends
        risk_trends = await self.security_repository.get_risk_trends(
            start_date,
            end_date,
            "day"
        )
        
        return {
            "current_risk_level": self._determine_overall_risk(risk_dist),
            "risk_distribution": risk_dist,
            "risk_trends": risk_trends,
            "high_risk_users": 12,  # Would query actual high-risk users
            "high_risk_assets": 5,
            "risk_factors": {
                "external_threats": 35,
                "insider_threats": 15,
                "misconfigurations": 25,
                "vulnerabilities": 25
            }
        }
    
    async def _get_auth_statistics(self, start_date: datetime, end_date: datetime) -> dict[str, Any]:
        """Get authentication statistics."""
        # Login patterns
        login_patterns = await self.audit_repository.get_login_patterns(
            start_date,
            end_date
        )
        
        # Activity breakdown
        activity_breakdown = await self.audit_repository.get_activity_breakdown_by_type(
            start_date,
            end_date
        )
        
        # Calculate success rate
        total_auth = activity_breakdown.get("login", 0)
        failed_auth = await self.audit_repository.count_failed_authentications(
            start_date,
            end_date
        )
        success_rate = ((total_auth - failed_auth) / total_auth * 100) if total_auth > 0 else 100
        
        return {
            "total_attempts": total_auth,
            "successful": total_auth - failed_auth,
            "failed": failed_auth,
            "success_rate": round(success_rate, 1),
            "authentication_methods": {
                "password": activity_breakdown.get("password_auth", 0),
                "mfa": activity_breakdown.get("mfa_auth", 0),
                "sso": activity_breakdown.get("sso_auth", 0),
                "biometric": activity_breakdown.get("biometric_auth", 0)
            },
            "peak_hours": login_patterns.get("peak_hours", []),
            "unusual_patterns": login_patterns.get("anomalies", [])
        }
    
    async def _get_policy_violations(self, start_date: datetime, end_date: datetime) -> dict[str, Any]:
        """Get policy violations."""
        violations = await self.security_repository.get_policy_violations(
            start_date,
            end_date
        )
        
        # Categorize violations
        by_type = {}
        by_severity = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        
        for violation in violations:
            vtype = violation.get("type", "unknown")
            by_type[vtype] = by_type.get(vtype, 0) + 1
            
            severity = violation.get("severity", "low")
            by_severity[severity] = by_severity.get(severity, 0) + 1
        
        return {
            "total": len(violations),
            "by_type": by_type,
            "by_severity": by_severity,
            "recent_violations": violations[:5],  # Top 5 recent
            "repeat_offenders": self._identify_repeat_offenders(violations)
        }
    
    async def _get_realtime_security_data(self) -> dict[str, Any]:
        """Get real-time security data."""
        # This would connect to real-time monitoring systems
        return {
            "active_threats": 3,
            "blocked_ips": 47,
            "rate_limit_hits": 152,
            "active_sessions": 1234,
            "requests_per_second": 89.3,
            "threat_feed_status": "connected",
            "last_threat_detected": (datetime.now(UTC) - timedelta(minutes=3)).isoformat()
        }
    
    async def _get_security_predictions(self, current_data: dict[str, Any]) -> dict[str, Any]:
        """Get security predictions based on current data."""
        # This would use ML models for actual predictions
        threat_trend = "increasing" if current_data["threat_overview"]["total_threats"] > 100 else "stable"
        
        return {
            "threat_forecast_24h": threat_trend,
            "predicted_incidents": 2,
            "risk_trend": "increasing" if threat_trend == "increasing" else "stable",
            "recommended_threat_level": "elevated" if threat_trend == "increasing" else "normal",
            "anomaly_probability": 0.23
        }
    
    async def _get_active_security_alerts(self) -> list[dict[str, Any]]:
        """Get active security alerts."""
        alerts = []
        
        # Check for high threat level
        recent_threats = await self.security_repository.count_security_events({
            "start_date": datetime.now(UTC) - timedelta(hours=1)
        })
        
        if recent_threats > 50:
            alerts.append({
                "id": "high_threat_activity",
                "severity": "high",
                "title": "High Threat Activity Detected",
                "message": f"{recent_threats} security events in the last hour",
                "timestamp": datetime.now(UTC).isoformat(),
                "actions": ["investigate", "increase_monitoring"]
            })
        
        # Check for failed login spike
        failed_logins = await self.audit_repository.count_failed_authentications(
            datetime.now(UTC) - timedelta(minutes=15),
            datetime.now(UTC)
        )
        
        if failed_logins > 20:
            alerts.append({
                "id": "failed_login_spike",
                "severity": "medium",
                "title": "Failed Login Spike",
                "message": f"{failed_logins} failed login attempts in 15 minutes",
                "timestamp": datetime.now(UTC).isoformat(),
                "actions": ["review_logs", "check_brute_force"]
            })
        
        return alerts
    
    def _generate_recommendations(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        """Generate security recommendations based on dashboard data."""
        recommendations = []
        
        # Check threat level
        if data["threat_overview"]["threat_level"] in ["high", "critical"]:
            recommendations.append({
                "priority": "high",
                "title": "Increase Security Monitoring",
                "description": "Threat level is elevated. Consider increasing monitoring frequency.",
                "action": "enhance_monitoring"
            })
        
        # Check failed authentications
        if data["auth_stats"]["failed"] > 100:
            recommendations.append({
                "priority": "medium",
                "title": "Review Authentication Policies",
                "description": "High number of failed authentications detected.",
                "action": "review_auth_policies"
            })
        
        # Check policy violations
        if data["policy_violations"]["total"] > 20:
            recommendations.append({
                "priority": "medium",
                "title": "Policy Enforcement Review",
                "description": "Multiple policy violations detected. Review and update policies.",
                "action": "update_policies"
            })
        
        return recommendations
    
    def _calculate_threat_level(self, stats: dict[str, Any]) -> str:
        """Calculate overall threat level."""
        critical_events = stats.get("critical", 0)
        high_events = stats.get("high", 0)
        total_events = stats.get("total", 0)
        
        if critical_events > 5 or total_events > 500:
            return "critical"
        if high_events > 20 or total_events > 200:
            return "high"
        if total_events > 50:
            return "medium"
        return "low"
    
    def _calculate_security_score(self, metrics: dict[str, Any]) -> float:
        """Calculate overall security score (0-100)."""
        base_score = 100
        
        # Deduct for failed authentications
        base_score -= min(metrics.get("failed_auth", 0) / 10, 20)
        
        # Deduct for privilege escalations
        base_score -= min(metrics.get("escalations", 0) * 5, 30)
        
        # Deduct for suspicious activities
        base_score -= min(metrics.get("suspicious", 0) / 5, 30)
        
        return max(0, round(base_score, 1))
    
    def _determine_overall_risk(self, risk_dist: dict[str, Any]) -> str:
        """Determine overall risk level from distribution."""
        if risk_dist.get("critical", 0) > 0:
            return "critical"
        if risk_dist.get("high", 0) > 5:
            return "high"
        if risk_dist.get("medium", 0) > 20:
            return "medium"
        return "low"
    
    def _identify_repeat_offenders(self, violations: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Identify users with repeated violations."""
        user_violations = {}
        
        for violation in violations:
            user_id = violation.get("user_id")
            if user_id:
                user_violations[user_id] = user_violations.get(user_id, 0) + 1
        
        # Return top repeat offenders
        repeat_offenders = []
        for user_id, count in sorted(user_violations.items(), key=lambda x: x[1], reverse=True)[:5]:
            if count > 2:
                repeat_offenders.append({
                    "user_id": user_id,
                    "violation_count": count
                })
        
        return repeat_offenders