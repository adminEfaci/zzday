"""Get security events query.

This module implements the query and handler for retrieving security-related
audit events with threat analysis and incident correlation.
"""

from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from app.core.cqrs.base import Query, QueryHandler
from app.core.errors import ValidationError
from app.core.logging import get_logger
from app.modules.audit.application.dtos.audit_entry_dto import AuditEntryDTO

logger = get_logger(__name__)


class GetSecurityEventsQuery(Query):
    """
    Query to retrieve security-related audit events.

    Provides security event analysis including threat detection,
    incident correlation, and risk assessment.
    """

    def __init__(
        self,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        severity_filter: list[str] | None = None,
        event_types: list[str] | None = None,
        user_ids: list[UUID] | None = None,
        include_analysis: bool = True,
        include_correlations: bool = True,
        include_risk_assessment: bool = False,
        limit: int | None = None,
    ):
        """
        Initialize get security events query.

        Args:
            start_date: Start of analysis period
            end_date: End of analysis period
            severity_filter: Filter by severity levels
            event_types: Filter by specific event types
            user_ids: Filter by specific users
            include_analysis: Whether to include threat analysis
            include_correlations: Whether to correlate related events
            include_risk_assessment: Whether to include risk scoring
            limit: Maximum number of events to return
        """
        super().__init__()

        self.start_date = start_date or (datetime.utcnow() - timedelta(hours=24))
        self.end_date = end_date or datetime.utcnow()
        self.severity_filter = severity_filter or ["medium", "high", "critical"]
        self.event_types = event_types or []
        self.user_ids = user_ids or []
        self.include_analysis = include_analysis
        self.include_correlations = include_correlations
        self.include_risk_assessment = include_risk_assessment
        self.limit = self._validate_limit(limit)

        # Validate date range
        if self.start_date >= self.end_date:
            raise ValidationError("Start date must be before end date")

        # Set pagination
        self.page_size = limit or 1000

        self._freeze()

    def _validate_limit(self, limit: int | None) -> int | None:
        """Validate limit parameter."""
        if limit is not None and (limit < 1 or limit > 10000):
            raise ValidationError("Limit must be between 1 and 10000")
        return limit


class GetSecurityEventsQueryHandler(
    QueryHandler[GetSecurityEventsQuery, dict[str, Any]]
):
    """
    Handler for retrieving security events.

    This handler analyzes security events and provides threat intelligence,
    incident correlation, and risk assessment capabilities.
    """

    def __init__(
        self,
        audit_repository: Any,
        security_service: Any,
        threat_intelligence_service: Any,
        correlation_service: Any,
        user_service: Any,
    ):
        """
        Initialize handler.

        Args:
            audit_repository: Repository for audit data access
            security_service: Service for security analysis
            threat_intelligence_service: Service for threat intelligence
            correlation_service: Service for event correlation
            user_service: Service for user information
        """
        super().__init__()
        self.audit_repository = audit_repository
        self.security_service = security_service
        self.threat_intelligence_service = threat_intelligence_service
        self.correlation_service = correlation_service
        self.user_service = user_service

    async def handle(self, query: GetSecurityEventsQuery) -> dict[str, Any]:
        """
        Handle the get security events query.

        Args:
            query: Query containing security event parameters

        Returns:
            Dictionary containing security events and analysis
        """
        logger.debug(
            "Retrieving security events",
            date_range=f"{query.start_date} to {query.end_date}",
            severity_filter=query.severity_filter,
        )

        # Build security event filters
        filters = {
            "created_at__gte": query.start_date,
            "created_at__lte": query.end_date,
            "category": "security",  # Focus on security category events
        }

        # Add severity filter
        if query.severity_filter:
            filters["severity__in"] = query.severity_filter

        # Add event type filter
        if query.event_types:
            filters["action_type__in"] = query.event_types

        # Add user filter
        if query.user_ids:
            filters["user_id__in"] = query.user_ids

        # Fetch security events
        search_result = await self.audit_repository.search_entries(
            filters=filters,
            limit=query.limit or 1000,
            order_by="created_at",
            order_direction="desc",
        )

        events = search_result["entries"]

        # Convert to DTOs with user information
        event_dtos = []
        user_cache = {}

        for event in events:
            user_info = None
            if event.user_id:
                if event.user_id not in user_cache:
                    user_cache[event.user_id] = await self.user_service.get_user_info(
                        event.user_id
                    )
                user_info = user_cache[event.user_id]

            event_dto = AuditEntryDTO.from_domain(event, user_info)
            event_dtos.append(event_dto.to_dict())

        # Build base response
        response = {
            "events": event_dtos,
            "query_metadata": {
                "start_date": query.start_date.isoformat(),
                "end_date": query.end_date.isoformat(),
                "severity_filter": query.severity_filter,
                "event_count": len(event_dtos),
                "total_available": search_result.get("total_count", len(event_dtos)),
            },
        }

        # Include threat analysis if requested
        if query.include_analysis and events:
            analysis = await self._perform_threat_analysis(events, query)
            response["threat_analysis"] = analysis

        # Include event correlations if requested
        if query.include_correlations and events:
            correlations = await self._perform_event_correlation(events, query)
            response["event_correlations"] = correlations

        # Include risk assessment if requested
        if query.include_risk_assessment and events:
            risk_assessment = await self._perform_risk_assessment(events, query)
            response["risk_assessment"] = risk_assessment

        # Add security summary
        response["security_summary"] = await self._generate_security_summary(
            events, query
        )

        logger.debug(
            "Security events retrieved successfully",
            event_count=len(event_dtos),
            analysis_included=query.include_analysis,
        )

        return response

    async def _perform_threat_analysis(
        self, events: list[Any], query: GetSecurityEventsQuery
    ) -> dict[str, Any]:
        """
        Perform threat analysis on security events.

        Args:
            events: Security events to analyze
            query: Original query

        Returns:
            Threat analysis results
        """
        # Categorize events by threat type
        threat_categories = {
            "authentication_failures": [],
            "privilege_escalations": [],
            "data_breaches": [],
            "malicious_activity": [],
            "policy_violations": [],
            "unauthorized_access": [],
        }

        for event in events:
            action_type = event.action.action_type.lower()
            outcome = event.outcome.lower()

            if "authenticate" in action_type and outcome == "failure":
                threat_categories["authentication_failures"].append(event)
            elif "permission" in action_type or "role" in action_type:
                threat_categories["privilege_escalations"].append(event)
            elif "data" in action_type and event.severity.value == "critical":
                threat_categories["data_breaches"].append(event)
            elif event.severity.value == "critical":
                threat_categories["malicious_activity"].append(event)
            elif outcome == "failure":
                threat_categories["policy_violations"].append(event)
            else:
                threat_categories["unauthorized_access"].append(event)

        # Calculate threat scores
        threat_scores = {}
        for category, category_events in threat_categories.items():
            if category_events:
                # Simple scoring based on event count and severity
                score = len(category_events)
                critical_events = len(
                    [e for e in category_events if e.severity.value == "critical"]
                )
                score += critical_events * 2  # Weight critical events more
                threat_scores[category] = min(score, 100)  # Cap at 100

        # Identify threat patterns
        patterns = await self._identify_threat_patterns(events)

        # Get threat intelligence
        intelligence = await self.threat_intelligence_service.analyze_events(events)

        return {
            "threat_categories": {
                cat: len(events_list) for cat, events_list in threat_categories.items()
            },
            "threat_scores": threat_scores,
            "patterns_detected": patterns,
            "threat_intelligence": intelligence,
            "overall_threat_level": self._calculate_overall_threat_level(threat_scores),
            "recommendations": self._generate_threat_recommendations(
                threat_categories, patterns
            ),
        }

    async def _perform_event_correlation(
        self, events: list[Any], query: GetSecurityEventsQuery
    ) -> dict[str, Any]:
        """
        Perform event correlation analysis.

        Args:
            events: Security events to correlate
            query: Original query

        Returns:
            Event correlation results
        """
        # Group events by correlation ID
        by_correlation = {}
        for event in events:
            if event.correlation_id:
                if event.correlation_id not in by_correlation:
                    by_correlation[event.correlation_id] = []
                by_correlation[event.correlation_id].append(event)

        # Group events by user and time window
        user_sequences = await self._find_user_event_sequences(events)

        # Group events by IP address
        ip_clusters = await self._find_ip_based_clusters(events)

        # Identify suspicious patterns
        suspicious_patterns = (
            await self.correlation_service.identify_suspicious_patterns(events)
        )

        return {
            "correlated_events": {
                "by_correlation_id": len(by_correlation),
                "by_user_sequence": len(user_sequences),
                "by_ip_cluster": len(ip_clusters),
            },
            "correlation_details": {
                "correlation_chains": [
                    {"correlation_id": cid, "event_count": len(events_list)}
                    for cid, events_list in by_correlation.items()
                ],
                "user_sequences": user_sequences,
                "ip_clusters": ip_clusters,
            },
            "suspicious_patterns": suspicious_patterns,
            "correlation_confidence": await self._calculate_correlation_confidence(
                events
            ),
        }

    async def _perform_risk_assessment(
        self, events: list[Any], query: GetSecurityEventsQuery
    ) -> dict[str, Any]:
        """
        Perform risk assessment on security events.

        Args:
            events: Security events to assess
            query: Original query

        Returns:
            Risk assessment results
        """
        # Calculate risk scores for different dimensions
        risk_dimensions = {
            "data_risk": await self._assess_data_risk(events),
            "access_risk": await self._assess_access_risk(events),
            "compliance_risk": await self._assess_compliance_risk(events),
            "operational_risk": await self._assess_operational_risk(events),
        }

        # Calculate overall risk score
        overall_risk = sum(risk_dimensions.values()) / len(risk_dimensions)

        # Identify high-risk entities
        high_risk_users = await self._identify_high_risk_users(events)
        high_risk_resources = await self._identify_high_risk_resources(events)

        return {
            "risk_dimensions": risk_dimensions,
            "overall_risk_score": round(overall_risk, 2),
            "risk_level": self._categorize_risk_level(overall_risk),
            "high_risk_entities": {
                "users": high_risk_users,
                "resources": high_risk_resources,
            },
            "risk_trends": await self._analyze_risk_trends(events, query),
            "mitigation_priorities": self._generate_mitigation_priorities(
                risk_dimensions, events
            ),
        }

    async def _generate_security_summary(
        self, events: list[Any], query: GetSecurityEventsQuery
    ) -> dict[str, Any]:
        """
        Generate security summary.

        Args:
            events: Security events
            query: Original query

        Returns:
            Security summary
        """
        if not events:
            return {
                "total_events": 0,
                "security_status": "no_events",
                "recommendations": [
                    "No security events detected in the specified period"
                ],
            }

        # Basic statistics
        by_severity = {}
        by_outcome = {}
        unique_users = set()
        unique_ips = set()

        for event in events:
            # Severity distribution
            severity = event.severity.value
            by_severity[severity] = by_severity.get(severity, 0) + 1

            # Outcome distribution
            outcome = event.outcome
            by_outcome[outcome] = by_outcome.get(outcome, 0) + 1

            # Unique entities
            if event.user_id:
                unique_users.add(event.user_id)
            if event.context.ip_address:
                unique_ips.add(event.context.ip_address)

        # Determine security status
        critical_count = by_severity.get("critical", 0)
        high_count = by_severity.get("high", 0)
        failure_count = by_outcome.get("failure", 0)

        if critical_count > 0:
            security_status = "critical"
        elif high_count > 5 or failure_count > 10:
            security_status = "elevated"
        elif failure_count > 0:
            security_status = "monitoring"
        else:
            security_status = "normal"

        return {
            "total_events": len(events),
            "unique_users_involved": len(unique_users),
            "unique_ip_addresses": len(unique_ips),
            "by_severity": by_severity,
            "by_outcome": by_outcome,
            "security_status": security_status,
            "critical_events": critical_count,
            "failed_events": failure_count,
            "time_span_hours": (query.end_date - query.start_date).total_seconds()
            / 3600,
            "event_rate_per_hour": len(events)
            / max(1, (query.end_date - query.start_date).total_seconds() / 3600),
        }

    # Helper methods for analysis (simplified implementations)

    async def _identify_threat_patterns(
        self, events: list[Any]
    ) -> list[dict[str, Any]]:
        """Identify threat patterns in events."""
        patterns = []

        # Pattern: Multiple failed authentications from same IP
        ip_failures = {}
        for event in events:
            if (
                "authenticate" in event.action.action_type.lower()
                and event.outcome == "failure"
            ):
                ip = event.context.ip_address
                if ip:
                    ip_failures[ip] = ip_failures.get(ip, 0) + 1

        for ip, count in ip_failures.items():
            if count >= 5:
                patterns.append(
                    {
                        "type": "brute_force_attack",
                        "description": f"Multiple failed authentications from IP {ip}",
                        "severity": "high",
                        "event_count": count,
                        "indicators": {"ip_address": ip},
                    }
                )

        return patterns

    async def _find_user_event_sequences(
        self, events: list[Any]
    ) -> list[dict[str, Any]]:
        """Find suspicious user event sequences."""
        # Group events by user and sort by time
        user_events = {}
        for event in events:
            if event.user_id:
                if event.user_id not in user_events:
                    user_events[event.user_id] = []
                user_events[event.user_id].append(event)

        sequences = []
        for user_id, user_event_list in user_events.items():
            if len(user_event_list) >= 3:  # Minimum sequence length
                user_event_list.sort(key=lambda e: e.created_at)
                sequences.append(
                    {
                        "user_id": str(user_id),
                        "event_count": len(user_event_list),
                        "time_span_minutes": (
                            user_event_list[-1].created_at
                            - user_event_list[0].created_at
                        ).total_seconds()
                        / 60,
                        "pattern_type": "user_activity_sequence",
                    }
                )

        return sequences

    async def _find_ip_based_clusters(self, events: list[Any]) -> list[dict[str, Any]]:
        """Find IP-based event clusters."""
        ip_events = {}
        for event in events:
            if event.context.ip_address:
                ip = event.context.ip_address
                if ip not in ip_events:
                    ip_events[ip] = []
                ip_events[ip].append(event)

        clusters = []
        for ip, ip_event_list in ip_events.items():
            if len(ip_event_list) >= 2:
                clusters.append(
                    {
                        "ip_address": ip,
                        "event_count": len(ip_event_list),
                        "unique_users": len(
                            {e.user_id for e in ip_event_list if e.user_id}
                        ),
                        "pattern_type": "ip_activity_cluster",
                    }
                )

        return clusters

    def _calculate_overall_threat_level(self, threat_scores: dict[str, float]) -> str:
        """Calculate overall threat level."""
        if not threat_scores:
            return "low"

        avg_score = sum(threat_scores.values()) / len(threat_scores)
        max_score = max(threat_scores.values())

        if max_score >= 80 or avg_score >= 60:
            return "critical"
        if max_score >= 60 or avg_score >= 40:
            return "high"
        if max_score >= 40 or avg_score >= 20:
            return "medium"
        return "low"

    def _generate_threat_recommendations(
        self, threat_categories: dict[str, list[Any]], patterns: list[dict[str, Any]]
    ) -> list[str]:
        """Generate threat-based recommendations."""
        recommendations = []

        if threat_categories["authentication_failures"]:
            recommendations.append(
                "Implement account lockout policies to prevent brute force attacks"
            )

        if threat_categories["privilege_escalations"]:
            recommendations.append("Review and audit privilege escalation procedures")

        if threat_categories["data_breaches"]:
            recommendations.append(
                "Conduct immediate data breach assessment and notification procedures"
            )

        if len(patterns) > 0:
            recommendations.append(
                "Investigate detected threat patterns for potential security incidents"
            )

        recommendations.append("Enable real-time security monitoring and alerting")

        return recommendations

    async def _calculate_correlation_confidence(self, events: list[Any]) -> float:
        """Calculate confidence in event correlations."""
        # Simplified confidence calculation
        if not events:
            return 0.0

        correlated_events = len([e for e in events if e.correlation_id])
        return (correlated_events / len(events)) * 100

    # Risk assessment helper methods (simplified)

    async def _assess_data_risk(self, events: list[Any]) -> float:
        """Assess data-related risk."""
        data_events = [e for e in events if "data" in e.action.action_type.lower()]
        critical_data_events = [
            e for e in data_events if e.severity.value == "critical"
        ]

        if not data_events:
            return 0.0

        return (len(critical_data_events) / len(data_events)) * 100

    async def _assess_access_risk(self, events: list[Any]) -> float:
        """Assess access-related risk."""
        access_events = [
            e
            for e in events
            if any(
                term in e.action.action_type.lower()
                for term in ["access", "login", "authenticate"]
            )
        ]
        failed_access = [e for e in access_events if e.outcome == "failure"]

        if not access_events:
            return 0.0

        return (len(failed_access) / len(access_events)) * 100

    async def _assess_compliance_risk(self, events: list[Any]) -> float:
        """Assess compliance-related risk."""
        compliance_events = [e for e in events if e.category.value == "compliance"]
        violations = [e for e in compliance_events if e.outcome == "failure"]

        if not compliance_events:
            return 0.0

        return (len(violations) / len(compliance_events)) * 100

    async def _assess_operational_risk(self, events: list[Any]) -> float:
        """Assess operational risk."""
        system_events = [e for e in events if e.category.value == "system"]
        failed_operations = [e for e in system_events if e.outcome == "failure"]

        if not system_events:
            return 0.0

        return (len(failed_operations) / len(system_events)) * 100

    async def _identify_high_risk_users(
        self, events: list[Any]
    ) -> list[dict[str, Any]]:
        """Identify high-risk users."""
        user_risk = {}
        for event in events:
            if event.user_id:
                if event.user_id not in user_risk:
                    user_risk[event.user_id] = {
                        "total": 0,
                        "failures": 0,
                        "critical": 0,
                    }

                user_risk[event.user_id]["total"] += 1
                if event.outcome == "failure":
                    user_risk[event.user_id]["failures"] += 1
                if event.severity.value == "critical":
                    user_risk[event.user_id]["critical"] += 1

        # Calculate risk scores and identify high-risk users
        high_risk_users = []
        for user_id, stats in user_risk.items():
            failure_rate = (
                (stats["failures"] / stats["total"]) * 100 if stats["total"] > 0 else 0
            )
            risk_score = failure_rate + (stats["critical"] * 10)

            if risk_score >= 50:  # Threshold for high risk
                high_risk_users.append(
                    {
                        "user_id": str(user_id),
                        "risk_score": round(risk_score, 2),
                        "total_events": stats["total"],
                        "failure_rate": round(failure_rate, 2),
                        "critical_events": stats["critical"],
                    }
                )

        return sorted(high_risk_users, key=lambda x: x["risk_score"], reverse=True)[:10]

    async def _identify_high_risk_resources(
        self, events: list[Any]
    ) -> list[dict[str, Any]]:
        """Identify high-risk resources."""
        resource_risk = {}
        for event in events:
            resource_key = (
                f"{event.resource.resource_type}:{event.resource.resource_id}"
            )
            if resource_key not in resource_risk:
                resource_risk[resource_key] = {"total": 0, "failures": 0, "critical": 0}

            resource_risk[resource_key]["total"] += 1
            if event.outcome == "failure":
                resource_risk[resource_key]["failures"] += 1
            if event.severity.value == "critical":
                resource_risk[resource_key]["critical"] += 1

        # Calculate risk scores
        high_risk_resources = []
        for resource_key, stats in resource_risk.items():
            failure_rate = (
                (stats["failures"] / stats["total"]) * 100 if stats["total"] > 0 else 0
            )
            risk_score = failure_rate + (stats["critical"] * 10)

            if risk_score >= 30:  # Lower threshold for resources
                resource_type, resource_id = resource_key.split(":", 1)
                high_risk_resources.append(
                    {
                        "resource_type": resource_type,
                        "resource_id": resource_id,
                        "risk_score": round(risk_score, 2),
                        "total_events": stats["total"],
                        "failure_rate": round(failure_rate, 2),
                        "critical_events": stats["critical"],
                    }
                )

        return sorted(high_risk_resources, key=lambda x: x["risk_score"], reverse=True)[
            :10
        ]

    async def _analyze_risk_trends(
        self, events: list[Any], query: GetSecurityEventsQuery
    ) -> dict[str, Any]:
        """Analyze risk trends over time."""
        # Group events by hour
        hourly_risk = {}
        for event in events:
            hour_key = event.created_at.strftime("%Y-%m-%d %H:00")
            if hour_key not in hourly_risk:
                hourly_risk[hour_key] = {"total": 0, "high_risk": 0}

            hourly_risk[hour_key]["total"] += 1
            if (
                event.severity.value in ["high", "critical"]
                or event.outcome == "failure"
            ):
                hourly_risk[hour_key]["high_risk"] += 1

        # Calculate trend
        if len(hourly_risk) >= 2:
            hours = sorted(hourly_risk.keys())
            first_half = hours[: len(hours) // 2]
            second_half = hours[len(hours) // 2 :]

            first_half_avg = sum(hourly_risk[h]["high_risk"] for h in first_half) / len(
                first_half
            )
            second_half_avg = sum(
                hourly_risk[h]["high_risk"] for h in second_half
            ) / len(second_half)

            trend_direction = (
                "increasing" if second_half_avg > first_half_avg else "decreasing"
            )
            change_percentage = (
                (second_half_avg - first_half_avg) / max(1, first_half_avg)
            ) * 100
        else:
            trend_direction = "stable"
            change_percentage = 0.0

        return {
            "trend_direction": trend_direction,
            "change_percentage": round(change_percentage, 2),
            "hourly_data": hourly_risk,
        }

    def _categorize_risk_level(self, risk_score: float) -> str:
        """Categorize risk level."""
        if risk_score >= 80:
            return "critical"
        if risk_score >= 60:
            return "high"
        if risk_score >= 40:
            return "medium"
        return "low"

    def _generate_mitigation_priorities(
        self, risk_dimensions: dict[str, float], events: list[Any]
    ) -> list[dict[str, Any]]:
        """Generate mitigation priorities."""
        priorities = []

        for dimension, score in risk_dimensions.items():
            if score >= 60:
                priority = "high"
            elif score >= 40:
                priority = "medium"
            else:
                priority = "low"

            priorities.append(
                {
                    "risk_dimension": dimension,
                    "risk_score": score,
                    "priority": priority,
                    "recommended_actions": self._get_dimension_recommendations(
                        dimension, score
                    ),
                }
            )

        return sorted(priorities, key=lambda x: x["risk_score"], reverse=True)

    def _get_dimension_recommendations(self, dimension: str, score: float) -> list[str]:
        """Get recommendations for a risk dimension."""
        recommendations = {
            "data_risk": [
                "Implement data loss prevention (DLP) controls",
                "Review data access permissions",
                "Enable data encryption at rest and in transit",
            ],
            "access_risk": [
                "Strengthen authentication mechanisms",
                "Implement multi-factor authentication",
                "Review and update access control policies",
            ],
            "compliance_risk": [
                "Conduct compliance gap analysis",
                "Update policies and procedures",
                "Implement continuous compliance monitoring",
            ],
            "operational_risk": [
                "Improve system monitoring and alerting",
                "Implement automated incident response",
                "Conduct system reliability assessments",
            ],
        }

        return recommendations.get(dimension, ["Review and address identified issues"])

    @property
    def query_type(self) -> type[GetSecurityEventsQuery]:
        """Get query type this handler processes."""
        return GetSecurityEventsQuery


__all__ = ["GetSecurityEventsQuery", "GetSecurityEventsQueryHandler"]
