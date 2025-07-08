"""
Test cases for security command and query handlers.

Tests all security-related handlers including risk assessment,
threat detection, security policies, and incident response.
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, Mock
from uuid import uuid4

import pytest

from app.modules.identity.application.commands.security import (
    RiskAssessmentCommand,
    RiskAssessmentCommandHandler,
    SecurityAuditCommand,
    SecurityAuditCommandHandler,
    ThreatDetectionCommand,
    ThreatDetectionCommandHandler,
)
from app.modules.identity.application.queries.security import (
    GetSecurityDashboardQuery,
    GetSecurityDashboardQueryHandler,
    GetThreatAnalysisQuery,
    GetThreatAnalysisQueryHandler,
)
from app.modules.identity.domain.enums import RiskLevel, ThreatType


class TestRiskAssessmentCommandHandler:
    """Test risk assessment command handler."""

    @pytest.fixture
    def handler(self):
        """Create handler with mocked dependencies."""
        mock_user_repo = Mock()
        mock_session_repo = Mock()
        mock_risk_analyzer = Mock()
        mock_security_service = Mock()
        mock_event_bus = Mock()
        mock_audit_logger = Mock()

        return RiskAssessmentCommandHandler(
            user_repository=mock_user_repo,
            session_repository=mock_session_repo,
            risk_analyzer=mock_risk_analyzer,
            security_service=mock_security_service,
            event_bus=mock_event_bus,
            audit_logger=mock_audit_logger,
        )

    @pytest.mark.asyncio
    async def test_successful_low_risk_assessment(self, handler):
        """Test successful low risk assessment."""
        # Arrange
        user_id = str(uuid4())
        session_id = str(uuid4())

        risk_context = {
            "ip_address": "192.168.1.100",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "location": "New York, US",
            "time_of_day": 10,  # 10 AM
            "device_fingerprint": "known_device_123",
        }

        risk_assessment = {
            "risk_level": RiskLevel.LOW,
            "risk_score": 0.2,
            "factors": ["known_location", "known_device", "business_hours"],
            "recommendations": ["monitor_session"],
        }

        handler.risk_analyzer.assess_login_risk = AsyncMock(
            return_value=risk_assessment
        )
        handler.security_service.apply_risk_policies = AsyncMock()

        command = RiskAssessmentCommand(
            user_id=user_id,
            session_id=session_id,
            context=risk_context,
            assessment_type="login",
        )

        # Act
        result = await handler.handle(command)

        # Assert
        assert result.success is True
        assert result.risk_level == RiskLevel.LOW
        assert result.risk_score == 0.2
        assert "known_location" in result.risk_factors
        assert "monitor_session" in result.recommendations
        handler.risk_analyzer.assess_login_risk.assert_called_once()

    @pytest.mark.asyncio
    async def test_high_risk_assessment_with_blocking(self, handler):
        """Test high risk assessment that triggers blocking."""
        # Arrange
        user_id = str(uuid4())

        risk_context = {
            "ip_address": "185.220.101.1",  # Known Tor exit node
            "user_agent": "curl/7.68.0",
            "location": "Unknown",
            "time_of_day": 3,  # 3 AM
            "failed_attempts": 5,
        }

        risk_assessment = {
            "risk_level": RiskLevel.CRITICAL,
            "risk_score": 0.95,
            "factors": [
                "tor_exit_node",
                "suspicious_user_agent",
                "unusual_time",
                "multiple_failures",
            ],
            "recommendations": [
                "block_login",
                "require_additional_verification",
                "alert_security_team",
            ],
        }

        handler.risk_analyzer.assess_login_risk = AsyncMock(
            return_value=risk_assessment
        )
        handler.security_service.apply_risk_policies = AsyncMock()

        command = RiskAssessmentCommand(
            user_id=user_id, context=risk_context, assessment_type="login"
        )

        # Act
        result = await handler.handle(command)

        # Assert
        assert result.risk_level == RiskLevel.CRITICAL
        assert result.risk_score == 0.95
        assert result.action_taken == "block_login"
        assert "tor_exit_node" in result.risk_factors
        assert "alert_security_team" in result.recommendations

    @pytest.mark.asyncio
    async def test_behavioral_anomaly_detection(self, handler):
        """Test risk assessment with behavioral anomaly detection."""
        # Arrange
        user_id = str(uuid4())

        # User's typical behavior patterns
        behavioral_profile = {
            "typical_login_times": [8, 9, 10, 17, 18],  # 8-10 AM, 5-6 PM
            "common_locations": ["New York", "California"],
            "usual_devices": ["known_device_123", "known_device_456"],
            "typical_ip_ranges": ["192.168.1.0/24", "10.0.0.0/16"],
        }

        # Current login context shows anomaly
        risk_context = {
            "ip_address": "203.0.113.100",  # Unusual IP
            "location": "Singapore",  # Unusual location
            "time_of_day": 2,  # 2 AM - unusual time
            "device_fingerprint": "unknown_device_789",  # New device
        }

        risk_assessment = {
            "risk_level": RiskLevel.HIGH,
            "risk_score": 0.8,
            "factors": [
                "location_anomaly",
                "time_anomaly",
                "new_device",
                "ip_geolocation_mismatch",
            ],
            "behavioral_score": 0.85,
            "recommendations": ["require_mfa", "notify_user", "monitor_closely"],
        }

        handler.risk_analyzer.get_user_behavioral_profile = AsyncMock(
            return_value=behavioral_profile
        )
        handler.risk_analyzer.assess_login_risk = AsyncMock(
            return_value=risk_assessment
        )
        handler.security_service.apply_risk_policies = AsyncMock()

        command = RiskAssessmentCommand(
            user_id=user_id,
            context=risk_context,
            assessment_type="behavioral_analysis",
            include_behavioral_analysis=True,
        )

        # Act
        result = await handler.handle(command)

        # Assert
        assert result.risk_level == RiskLevel.HIGH
        assert result.behavioral_anomaly_detected is True
        assert "location_anomaly" in result.risk_factors
        assert "require_mfa" in result.recommendations

    @pytest.mark.asyncio
    async def test_device_fingerprint_analysis(self, handler):
        """Test risk assessment with device fingerprint analysis."""
        # Arrange
        user_id = str(uuid4())

        device_context = {
            "fingerprint": "new_device_fingerprint",
            "browser": "Chrome",
            "os": "Windows 10",
            "screen_resolution": "1920x1080",
            "timezone": "UTC-5",
            "language": "en-US",
            "plugins": ["PDF Viewer", "Chrome PDF Plugin"],
        }

        risk_assessment = {
            "risk_level": RiskLevel.MEDIUM,
            "risk_score": 0.6,
            "factors": ["new_device", "fingerprint_mismatch"],
            "device_risk_score": 0.65,
            "recommendations": ["verify_device", "send_notification"],
        }

        handler.risk_analyzer.assess_device_risk = AsyncMock(
            return_value=risk_assessment
        )
        handler.security_service.apply_risk_policies = AsyncMock()

        command = RiskAssessmentCommand(
            user_id=user_id, context=device_context, assessment_type="device_analysis"
        )

        # Act
        result = await handler.handle(command)

        # Assert
        assert result.risk_level == RiskLevel.MEDIUM
        assert result.device_risk_score == 0.65
        assert "new_device" in result.risk_factors


class TestThreatDetectionCommandHandler:
    """Test threat detection command handler."""

    @pytest.fixture
    def handler(self):
        """Create handler with mocked dependencies."""
        mock_threat_detector = Mock()
        mock_security_service = Mock()
        mock_incident_service = Mock()
        mock_event_bus = Mock()
        mock_audit_logger = Mock()

        return ThreatDetectionCommandHandler(
            threat_detector=mock_threat_detector,
            security_service=mock_security_service,
            incident_service=mock_incident_service,
            event_bus=mock_event_bus,
            audit_logger=mock_audit_logger,
        )

    @pytest.mark.asyncio
    async def test_brute_force_attack_detection(self, handler):
        """Test detection of brute force attack."""
        # Arrange
        user_id = str(uuid4())
        ip_address = "203.0.113.100"

        attack_pattern = {
            "threat_type": ThreatType.BRUTE_FORCE,
            "severity": RiskLevel.HIGH,
            "confidence": 0.9,
            "details": {
                "failed_attempts": 25,
                "time_window": 300,  # 5 minutes
                "target_accounts": [user_id],
                "source_ip": ip_address,
            },
            "indicators": [
                "rapid_failed_logins",
                "multiple_usernames",
                "consistent_source",
            ],
        }

        response_actions = {
            "block_ip": True,
            "lock_accounts": [user_id],
            "alert_security_team": True,
            "increase_monitoring": True,
        }

        handler.threat_detector.analyze_login_patterns = AsyncMock(
            return_value=attack_pattern
        )
        handler.security_service.execute_threat_response = AsyncMock(
            return_value=response_actions
        )
        handler.incident_service.create_security_incident = AsyncMock()

        command = ThreatDetectionCommand(
            event_type="failed_login",
            source_ip=ip_address,
            target_user_id=user_id,
            context={"timestamp": datetime.now(UTC)},
            auto_respond=True,
        )

        # Act
        result = await handler.handle(command)

        # Assert
        assert result.threat_detected is True
        assert result.threat_type == ThreatType.BRUTE_FORCE
        assert result.severity == RiskLevel.HIGH
        assert result.confidence_score == 0.9
        assert result.actions_taken["block_ip"] is True
        assert result.actions_taken["lock_accounts"] == [user_id]
        handler.incident_service.create_security_incident.assert_called_once()

    @pytest.mark.asyncio
    async def test_credential_stuffing_detection(self, handler):
        """Test detection of credential stuffing attack."""
        # Arrange
        attack_pattern = {
            "threat_type": ThreatType.CREDENTIAL_STUFFING,
            "severity": RiskLevel.CRITICAL,
            "confidence": 0.95,
            "details": {
                "affected_accounts": 150,
                "success_rate": 0.02,  # 2% success rate typical of credential stuffing
                "sources": ["203.0.113.0/24", "198.51.100.0/24"],
                "time_window": 1800,  # 30 minutes
            },
            "indicators": [
                "low_success_rate",
                "multiple_sources",
                "high_volume",
                "distributed_attack",
            ],
        }

        response_actions = {
            "enable_captcha": True,
            "rate_limit_aggressive": True,
            "block_ip_ranges": ["203.0.113.0/24", "198.51.100.0/24"],
            "force_password_resets": [],  # Will be populated based on successful logins
            "alert_users": True,
        }

        handler.threat_detector.analyze_distributed_login_attempts = AsyncMock(
            return_value=attack_pattern
        )
        handler.security_service.execute_threat_response = AsyncMock(
            return_value=response_actions
        )
        handler.incident_service.create_security_incident = AsyncMock()

        command = ThreatDetectionCommand(
            event_type="distributed_login_pattern",
            context={"analysis_window": 1800, "pattern_threshold": 0.8},
            auto_respond=True,
        )

        # Act
        result = await handler.handle(command)

        # Assert
        assert result.threat_type == ThreatType.CREDENTIAL_STUFFING
        assert result.severity == RiskLevel.CRITICAL
        assert result.actions_taken["enable_captcha"] is True
        assert "203.0.113.0/24" in result.actions_taken["block_ip_ranges"]

    @pytest.mark.asyncio
    async def test_account_takeover_detection(self, handler):
        """Test detection of account takeover attempt."""
        # Arrange
        user_id = str(uuid4())

        takeover_indicators = {
            "threat_type": ThreatType.ACCOUNT_TAKEOVER,
            "severity": RiskLevel.CRITICAL,
            "confidence": 0.88,
            "details": {
                "user_id": user_id,
                "suspicious_activities": [
                    "password_changed",
                    "email_changed",
                    "login_from_new_location",
                    "unusual_access_patterns",
                ],
                "timeline": [
                    {
                        "activity": "successful_login",
                        "timestamp": "2023-12-01T10:00:00Z",
                        "ip": "203.0.113.50",
                    },
                    {
                        "activity": "password_change",
                        "timestamp": "2023-12-01T10:05:00Z",
                        "ip": "203.0.113.50",
                    },
                    {
                        "activity": "email_change_requested",
                        "timestamp": "2023-12-01T10:07:00Z",
                        "ip": "203.0.113.50",
                    },
                ],
            },
            "indicators": ["rapid_account_changes", "new_location", "bypassed_mfa"],
        }

        response_actions = {
            "lock_account": True,
            "revoke_all_sessions": True,
            "notify_user_urgently": True,
            "require_identity_verification": True,
            "escalate_to_security_team": True,
        }

        handler.threat_detector.analyze_account_activity = AsyncMock(
            return_value=takeover_indicators
        )
        handler.security_service.execute_threat_response = AsyncMock(
            return_value=response_actions
        )
        handler.incident_service.create_security_incident = AsyncMock()

        command = ThreatDetectionCommand(
            event_type="suspicious_account_activity",
            target_user_id=user_id,
            context={
                "activity_window": 300,  # 5 minutes
                "change_types": ["password", "email"],
            },
            auto_respond=True,
        )

        # Act
        result = await handler.handle(command)

        # Assert
        assert result.threat_type == ThreatType.ACCOUNT_TAKEOVER
        assert result.actions_taken["lock_account"] is True
        assert result.actions_taken["revoke_all_sessions"] is True
        assert result.escalated is True

    @pytest.mark.asyncio
    async def test_no_threat_detected(self, handler):
        """Test when no threat is detected."""
        # Arrange
        handler.threat_detector.analyze_login_patterns = AsyncMock(return_value=None)

        command = ThreatDetectionCommand(
            event_type="normal_login",
            source_ip="192.168.1.100",
            target_user_id=str(uuid4()),
        )

        # Act
        result = await handler.handle(command)

        # Assert
        assert result.threat_detected is False
        assert result.threat_type is None
        assert result.actions_taken == {}
        handler.security_service.execute_threat_response.assert_not_called()


class TestSecurityAuditCommandHandler:
    """Test security audit command handler."""

    @pytest.fixture
    def handler(self):
        """Create handler with mocked dependencies."""
        mock_audit_service = Mock()
        mock_compliance_service = Mock()
        mock_security_service = Mock()
        mock_event_bus = Mock()

        return SecurityAuditCommandHandler(
            audit_service=mock_audit_service,
            compliance_service=mock_compliance_service,
            security_service=mock_security_service,
            event_bus=mock_event_bus,
        )

    @pytest.mark.asyncio
    async def test_comprehensive_security_audit(self, handler):
        """Test comprehensive security audit."""
        # Arrange
        audit_scope = {
            "audit_type": "comprehensive",
            "time_range": {
                "start": datetime.now(UTC) - timedelta(days=30),
                "end": datetime.now(UTC),
            },
            "include_systems": [
                "authentication",
                "authorization",
                "session_management",
                "mfa",
            ],
            "compliance_frameworks": ["SOX", "GDPR", "SOC2"],
        }

        audit_results = {
            "audit_id": str(uuid4()),
            "findings": [
                {
                    "category": "authentication",
                    "severity": RiskLevel.MEDIUM,
                    "finding": "Weak password policy detected",
                    "affected_users": 45,
                    "recommendation": "Enforce stronger password requirements",
                },
                {
                    "category": "session_management",
                    "severity": RiskLevel.LOW,
                    "finding": "Some sessions exceed recommended timeout",
                    "affected_sessions": 12,
                    "recommendation": "Reduce session timeout to 2 hours",
                },
            ],
            "compliance_status": {
                "SOX": "compliant",
                "GDPR": "compliant_with_minor_issues",
                "SOC2": "compliant",
            },
            "security_score": 85,
            "recommendations": [
                "Implement stricter password policy",
                "Review session timeout settings",
                "Enable additional MFA methods",
            ],
        }

        handler.audit_service.conduct_security_audit = AsyncMock(
            return_value=audit_results
        )
        handler.compliance_service.validate_compliance = AsyncMock()

        command = SecurityAuditCommand(
            audit_scope=audit_scope, initiated_by=str(uuid4()), audit_type="scheduled"
        )

        # Act
        result = await handler.handle(command)

        # Assert
        assert result.success is True
        assert result.audit_id is not None
        assert len(result.findings) == 2
        assert result.security_score == 85
        assert "SOX" in result.compliance_status
        assert result.compliance_status["GDPR"] == "compliant_with_minor_issues"

    @pytest.mark.asyncio
    async def test_targeted_access_audit(self, handler):
        """Test targeted access control audit."""
        # Arrange
        audit_scope = {
            "audit_type": "access_control",
            "focus_areas": [
                "role_assignments",
                "permission_grants",
                "privilege_escalation",
            ],
            "user_subset": "high_privilege_users",
        }

        audit_results = {
            "audit_id": str(uuid4()),
            "findings": [
                {
                    "category": "privilege_escalation",
                    "severity": RiskLevel.HIGH,
                    "finding": "Admin role assigned without proper approval",
                    "affected_users": 3,
                    "details": {
                        "users": ["user1", "user2", "user3"],
                        "assigned_by": "system_admin",
                        "approval_missing": True,
                    },
                }
            ],
            "access_violations": 3,
            "orphaned_permissions": 15,
            "excessive_privileges": 8,
        }

        handler.audit_service.conduct_access_audit = AsyncMock(
            return_value=audit_results
        )

        command = SecurityAuditCommand(
            audit_scope=audit_scope,
            initiated_by=str(uuid4()),
            audit_type="access_control",
        )

        # Act
        result = await handler.handle(command)

        # Assert
        assert result.access_violations == 3
        assert result.orphaned_permissions == 15
        assert result.excessive_privileges == 8
        assert any(f["severity"] == RiskLevel.HIGH for f in result.findings)


class TestGetSecurityDashboardQueryHandler:
    """Test get security dashboard query handler."""

    @pytest.fixture
    def handler(self):
        """Create handler with mocked dependencies."""
        mock_security_service = Mock()
        mock_threat_service = Mock()
        mock_audit_service = Mock()
        mock_cache = Mock()

        return GetSecurityDashboardQueryHandler(
            security_service=mock_security_service,
            threat_service=mock_threat_service,
            audit_service=mock_audit_service,
            cache=mock_cache,
        )

    @pytest.mark.asyncio
    async def test_get_security_dashboard_comprehensive(self, handler):
        """Test getting comprehensive security dashboard."""
        # Arrange
        dashboard_data = {
            "security_overview": {
                "overall_risk_level": RiskLevel.MEDIUM,
                "security_score": 78,
                "active_threats": 2,
                "recent_incidents": 1,
                "compliance_status": "compliant",
            },
            "threat_summary": {
                "threats_detected_24h": 5,
                "threats_blocked_24h": 4,
                "top_threat_types": [
                    {"type": "brute_force", "count": 3},
                    {"type": "suspicious_login", "count": 2},
                ],
                "geographic_threats": [
                    {"country": "Unknown", "count": 3},
                    {"country": "CN", "count": 2},
                ],
            },
            "access_metrics": {
                "successful_logins_24h": 1250,
                "failed_logins_24h": 89,
                "mfa_challenges_24h": 456,
                "account_lockouts_24h": 3,
                "new_device_registrations_24h": 12,
            },
            "user_activity": {
                "active_users_24h": 245,
                "high_risk_sessions": 8,
                "privilege_escalations_24h": 2,
                "policy_violations_24h": 1,
            },
            "system_health": {
                "auth_service_status": "healthy",
                "mfa_service_status": "healthy",
                "audit_service_status": "degraded",
                "last_backup": datetime.now(UTC) - timedelta(hours=6),
            },
        }

        handler.cache.get = Mock(return_value=None)
        handler.security_service.get_security_overview = AsyncMock(
            return_value=dashboard_data["security_overview"]
        )
        handler.threat_service.get_threat_summary = AsyncMock(
            return_value=dashboard_data["threat_summary"]
        )
        handler.security_service.get_access_metrics = AsyncMock(
            return_value=dashboard_data["access_metrics"]
        )
        handler.security_service.get_user_activity = AsyncMock(
            return_value=dashboard_data["user_activity"]
        )
        handler.security_service.get_system_health = AsyncMock(
            return_value=dashboard_data["system_health"]
        )
        handler.cache.set = Mock()

        query = GetSecurityDashboardQuery(
            time_range="24h", include_detailed_metrics=True
        )

        # Act
        result = await handler.handle(query)

        # Assert
        assert result.overall_risk_level == RiskLevel.MEDIUM
        assert result.security_score == 78
        assert result.active_threats == 2
        assert result.threats_detected_24h == 5
        assert result.successful_logins_24h == 1250
        assert result.active_users_24h == 245
        assert result.system_health["auth_service_status"] == "healthy"

    @pytest.mark.asyncio
    async def test_get_security_dashboard_alerts_only(self, handler):
        """Test getting security dashboard with alerts only."""
        # Arrange
        alerts_data = {
            "critical_alerts": [
                {
                    "id": str(uuid4()),
                    "type": "account_takeover_detected",
                    "severity": RiskLevel.CRITICAL,
                    "user_id": str(uuid4()),
                    "timestamp": datetime.now(UTC) - timedelta(minutes=15),
                    "status": "active",
                }
            ],
            "high_priority_alerts": [
                {
                    "id": str(uuid4()),
                    "type": "brute_force_attack",
                    "severity": RiskLevel.HIGH,
                    "source_ip": "203.0.113.100",
                    "timestamp": datetime.now(UTC) - timedelta(hours=1),
                    "status": "investigating",
                }
            ],
            "alert_summary": {
                "total_active_alerts": 2,
                "critical_count": 1,
                "high_count": 1,
                "medium_count": 0,
                "low_count": 0,
            },
        }

        handler.cache.get = Mock(return_value=None)
        handler.security_service.get_active_alerts = AsyncMock(return_value=alerts_data)
        handler.cache.set = Mock()

        query = GetSecurityDashboardQuery(
            view_type="alerts_only",
            alert_severity_filter=[RiskLevel.CRITICAL, RiskLevel.HIGH],
        )

        # Act
        result = await handler.handle(query)

        # Assert
        assert len(result.critical_alerts) == 1
        assert len(result.high_priority_alerts) == 1
        assert result.alert_summary["total_active_alerts"] == 2
        assert result.critical_alerts[0]["type"] == "account_takeover_detected"


class TestGetThreatAnalysisQueryHandler:
    """Test get threat analysis query handler."""

    @pytest.fixture
    def handler(self):
        """Create handler with mocked dependencies."""
        mock_threat_service = Mock()
        mock_analytics_service = Mock()
        mock_intelligence_service = Mock()
        mock_cache = Mock()

        return GetThreatAnalysisQueryHandler(
            threat_service=mock_threat_service,
            analytics_service=mock_analytics_service,
            intelligence_service=mock_intelligence_service,
            cache=mock_cache,
        )

    @pytest.mark.asyncio
    async def test_get_threat_analysis_comprehensive(self, handler):
        """Test getting comprehensive threat analysis."""
        # Arrange
        analysis_data = {
            "analysis_period": {
                "start": datetime.now(UTC) - timedelta(days=7),
                "end": datetime.now(UTC),
            },
            "threat_statistics": {
                "total_threats_detected": 47,
                "threats_blocked": 44,
                "threats_allowed": 1,
                "false_positives": 2,
                "detection_accuracy": 95.7,
            },
            "threat_breakdown": {
                "brute_force": {"count": 25, "blocked": 25, "success_rate": 0.0},
                "credential_stuffing": {
                    "count": 12,
                    "blocked": 11,
                    "success_rate": 0.08,
                },
                "account_takeover": {"count": 3, "blocked": 2, "success_rate": 0.33},
                "suspicious_login": {"count": 7, "blocked": 6, "success_rate": 0.14},
            },
            "geographic_analysis": {
                "top_threat_countries": [
                    {"country": "CN", "threats": 15, "blocked": 15},
                    {"country": "RU", "threats": 12, "blocked": 11},
                    {"country": "Unknown", "threats": 8, "blocked": 7},
                ],
                "threat_distribution": {
                    "asia": 60,
                    "europe": 25,
                    "north_america": 10,
                    "unknown": 5,
                },
            },
            "attack_patterns": {
                "peak_hours": [2, 3, 4, 22, 23],  # UTC hours
                "common_user_agents": [
                    "curl/7.68.0",
                    "python-requests/2.25.1",
                    "Mozilla/5.0 (compatible; Googlebot/2.1)",
                ],
                "targeted_accounts": ["admin", "root", "administrator", "test"],
            },
            "threat_intelligence": {
                "known_bad_ips": 1247,
                "reputation_blocks": 89,
                "ioc_matches": 23,
                "intelligence_feeds_active": 5,
            },
        }

        handler.cache.get = Mock(return_value=None)
        handler.threat_service.get_threat_statistics = AsyncMock(
            return_value=analysis_data["threat_statistics"]
        )
        handler.analytics_service.analyze_threat_patterns = AsyncMock(
            return_value={
                "threat_breakdown": analysis_data["threat_breakdown"],
                "geographic_analysis": analysis_data["geographic_analysis"],
                "attack_patterns": analysis_data["attack_patterns"],
            }
        )
        handler.intelligence_service.get_threat_intelligence = AsyncMock(
            return_value=analysis_data["threat_intelligence"]
        )
        handler.cache.set = Mock()

        query = GetThreatAnalysisQuery(
            analysis_period="7d",
            include_geographic_data=True,
            include_attack_patterns=True,
            include_threat_intelligence=True,
        )

        # Act
        result = await handler.handle(query)

        # Assert
        assert result.total_threats_detected == 47
        assert result.detection_accuracy == 95.7
        assert result.threat_breakdown["brute_force"]["count"] == 25
        assert result.geographic_analysis["top_threat_countries"][0]["country"] == "CN"
        assert 2 in result.attack_patterns["peak_hours"]
        assert result.threat_intelligence["known_bad_ips"] == 1247

    @pytest.mark.asyncio
    async def test_get_threat_analysis_specific_threat_type(self, handler):
        """Test getting threat analysis for specific threat type."""
        # Arrange
        brute_force_analysis = {
            "threat_type": ThreatType.BRUTE_FORCE,
            "detection_count": 25,
            "success_rate": 0.0,
            "avg_attempts_per_attack": 147,
            "most_targeted_accounts": ["admin", "root", "test"],
            "attack_duration_avg": 285,  # seconds
            "source_analysis": {
                "unique_ips": 18,
                "repeat_offenders": 3,
                "geographic_spread": ["CN", "RU", "BR", "Unknown"],
            },
            "mitigation_effectiveness": {
                "rate_limiting": 85,
                "ip_blocking": 95,
                "account_lockout": 100,
            },
        }

        handler.cache.get = Mock(return_value=None)
        handler.threat_service.analyze_specific_threat = AsyncMock(
            return_value=brute_force_analysis
        )
        handler.cache.set = Mock()

        query = GetThreatAnalysisQuery(
            threat_type_filter=ThreatType.BRUTE_FORCE,
            analysis_period="7d",
            detailed_analysis=True,
        )

        # Act
        result = await handler.handle(query)

        # Assert
        assert result.threat_type == ThreatType.BRUTE_FORCE
        assert result.detection_count == 25
        assert result.success_rate == 0.0
        assert result.source_analysis["unique_ips"] == 18
        assert result.mitigation_effectiveness["ip_blocking"] == 95
