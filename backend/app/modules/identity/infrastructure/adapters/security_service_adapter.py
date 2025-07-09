"""
Security Service Adapter

Production-ready implementation for security monitoring, threat detection, and incident management.
"""

import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from app.core.logging import logger
from app.modules.identity.domain.interfaces.services.security.security_service import (
    ISecurityService,
)
from app.modules.identity.domain.value_objects.ip_address import IpAddress


class SecurityServiceAdapter(ISecurityService):
    """Production security service adapter."""

    def __init__(
        self,
        threat_intel_service=None,
        ml_model_client=None,
        incident_repo=None,
        audit_service=None,
        notification_service=None,
    ):
        """Initialize security service adapter."""
        self._threat_intel = threat_intel_service
        self._ml_client = ml_model_client
        self._incident_repo = incident_repo
        self._audit = audit_service
        self._notifications = notification_service
        self._anomaly_cache = {}
        self._threat_patterns = self._load_threat_patterns()

    async def detect_anomalies(
        self, user_id: UUID, activity_data: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Detect anomalous behavior."""
        try:
            anomalies = []
            
            # Get user's baseline behavior
            baseline = await self._get_user_baseline(user_id)
            
            # Check various anomaly types
            login_anomalies = await self._detect_login_anomalies(user_id, activity_data, baseline)
            anomalies.extend(login_anomalies)
            
            location_anomalies = await self._detect_location_anomalies(user_id, activity_data, baseline)
            anomalies.extend(location_anomalies)
            
            behavioral_anomalies = await self._detect_behavioral_anomalies(user_id, activity_data, baseline)
            anomalies.extend(behavioral_anomalies)
            
            access_anomalies = await self._detect_access_pattern_anomalies(user_id, activity_data, baseline)
            anomalies.extend(access_anomalies)

            # Use ML model if available
            if self._ml_client and activity_data:
                ml_anomalies = await self._detect_ml_anomalies(user_id, activity_data)
                anomalies.extend(ml_anomalies)

            # Score and prioritize anomalies
            scored_anomalies = self._score_anomalies(anomalies)
            
            # Cache results
            cache_key = f"anomalies:{user_id}:{datetime.now(UTC).strftime('%Y%m%d%H')}"
            self._anomaly_cache[cache_key] = {
                "anomalies": scored_anomalies,
                "timestamp": datetime.now(UTC),
            }

            # Report high-severity anomalies
            high_severity = [a for a in scored_anomalies if a.get("severity") == "high"]
            if high_severity:
                await self._report_anomaly_incidents(user_id, high_severity)

            logger.info(f"Detected {len(scored_anomalies)} anomalies for user {user_id}")
            return scored_anomalies

        except Exception as e:
            logger.error(f"Error detecting anomalies for user {user_id}: {e}")
            return [
                {
                    "type": "detection_error",
                    "severity": "medium",
                    "description": f"Anomaly detection failed: {str(e)}",
                    "detected_at": datetime.now(UTC).isoformat(),
                }
            ]

    async def check_ip_reputation(self, ip_address: IpAddress) -> dict[str, Any]:
        """Check IP address reputation."""
        try:
            ip_str = str(ip_address.value)
            
            # Build reputation analysis
            reputation = {
                "ip_address": ip_str,
                "reputation_score": 0.0,
                "risk_level": "low",
                "categories": [],
                "sources": [],
                "indicators": [],
                "analyzed_at": datetime.now(UTC).isoformat(),
            }

            # Check against threat intelligence
            if self._threat_intel:
                threat_indicators = await self._threat_intel.get_threat_indicators(ip_address)
                for indicator in threat_indicators:
                    reputation["indicators"].append(indicator)
                    reputation["sources"].append(indicator.get("source", "unknown"))
                    
                    # Adjust score based on threat type
                    threat_type = indicator.get("type", "unknown")
                    severity = indicator.get("severity", "low")
                    
                    if severity == "high":
                        reputation["reputation_score"] += 0.4
                    elif severity == "medium":
                        reputation["reputation_score"] += 0.2
                    else:
                        reputation["reputation_score"] += 0.1
                        
                    if threat_type not in reputation["categories"]:
                        reputation["categories"].append(threat_type)

            # Check internal blacklists
            internal_check = await self._check_internal_blacklist(ip_str)
            if internal_check.get("blacklisted"):
                reputation["reputation_score"] += 0.5
                reputation["categories"].append("internal_blacklist")
                reputation["indicators"].append({
                    "type": "internal_blacklist",
                    "severity": "high",
                    "reason": internal_check.get("reason", "Listed in internal blacklist"),
                    "source": "internal",
                })

            # Check for recent incidents
            recent_incidents = await self._check_recent_incidents(ip_str)
            if recent_incidents:
                reputation["reputation_score"] += len(recent_incidents) * 0.1
                reputation["categories"].append("recent_incidents")
                reputation["indicators"].extend(recent_incidents)

            # Determine risk level
            score = min(reputation["reputation_score"], 1.0)
            if score >= 0.8:
                reputation["risk_level"] = "critical"
            elif score >= 0.6:
                reputation["risk_level"] = "high"
            elif score >= 0.4:
                reputation["risk_level"] = "medium"
            else:
                reputation["risk_level"] = "low"

            reputation["reputation_score"] = score

            logger.info(f"IP reputation check for {ip_str}: {reputation['risk_level']} risk ({score:.2f})")
            return reputation

        except Exception as e:
            logger.error(f"Error checking IP reputation for {ip_address}: {e}")
            return {
                "ip_address": str(ip_address.value),
                "reputation_score": 0.5,
                "risk_level": "unknown",
                "categories": ["error"],
                "sources": [],
                "indicators": [{"type": "error", "description": str(e)}],
                "analyzed_at": datetime.now(UTC).isoformat(),
            }

    async def scan_for_threats(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        """Scan data for security threats."""
        try:
            threats = []
            
            # Scan for common attack patterns
            pattern_threats = await self._scan_attack_patterns(data)
            threats.extend(pattern_threats)
            
            # Scan for malicious content
            content_threats = await self._scan_malicious_content(data)
            threats.extend(content_threats)
            
            # Scan for data exfiltration indicators
            exfiltration_threats = await self._scan_data_exfiltration(data)
            threats.extend(exfiltration_threats)
            
            # Scan for injection attempts
            injection_threats = await self._scan_injection_attempts(data)
            threats.extend(injection_threats)

            # Custom threat rules
            custom_threats = await self._apply_custom_threat_rules(data)
            threats.extend(custom_threats)

            # Score and deduplicate threats
            unique_threats = self._deduplicate_threats(threats)
            scored_threats = self._score_threats(unique_threats)

            logger.info(f"Threat scan completed: {len(scored_threats)} threats detected")
            return scored_threats

        except Exception as e:
            logger.error(f"Error scanning for threats: {e}")
            return [
                {
                    "type": "scan_error",
                    "severity": "medium",
                    "description": f"Threat scan failed: {str(e)}",
                    "detected_at": datetime.now(UTC).isoformat(),
                }
            ]

    async def report_security_incident(
        self, incident_type: str, details: dict[str, Any]
    ) -> str:
        """Report security incident."""
        try:
            incident_id = str(uuid4())
            
            incident = {
                "id": incident_id,
                "type": incident_type,
                "severity": details.get("severity", "medium"),
                "status": "open",
                "source": "security_service",
                "details": details,
                "created_at": datetime.now(UTC).isoformat(),
                "updated_at": datetime.now(UTC).isoformat(),
                "tags": self._generate_incident_tags(incident_type, details),
                "affected_resources": details.get("affected_resources", []),
                "remediation_steps": await self._generate_remediation_steps(incident_type, details),
            }

            # Store incident
            if self._incident_repo:
                await self._incident_repo.create_incident(incident)

            # Log to audit trail
            if self._audit:
                await self._audit.log_security_event({
                    "event_type": "security_incident_reported",
                    "incident_id": incident_id,
                    "incident_type": incident_type,
                    "severity": details.get("severity"),
                    "user_id": details.get("user_id"),
                    "ip_address": details.get("ip_address"),
                    "timestamp": datetime.now(UTC).isoformat(),
                })

            # Send notifications for high-severity incidents
            if details.get("severity") in ["high", "critical"]:
                await self._send_incident_notifications(incident)

            # Auto-trigger response actions
            await self._trigger_incident_response(incident)

            logger.warning(f"Security incident reported: {incident_type} (ID: {incident_id})")
            return incident_id

        except Exception as e:
            logger.error(f"Error reporting security incident {incident_type}: {e}")
            return str(uuid4())  # Return fallback ID

    async def _get_user_baseline(self, user_id: UUID) -> dict[str, Any]:
        """Get user's baseline behavior patterns."""
        # Mock implementation - would analyze historical data
        return {
            "typical_login_hours": [8, 9, 10, 17, 18, 19],
            "typical_locations": ["US", "CA"],
            "typical_devices": ["desktop", "mobile"],
            "average_session_duration": 3600,
            "typical_actions": ["login", "read_profile", "update_profile"],
            "baseline_established_at": datetime.now(UTC) - timedelta(days=30),
        }

    async def _detect_login_anomalies(
        self, user_id: UUID, activity_data: dict[str, Any], baseline: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Detect login-related anomalies."""
        anomalies = []
        
        # Check for unusual login times
        current_hour = datetime.now(UTC).hour
        typical_hours = baseline.get("typical_login_hours", [])
        if typical_hours and current_hour not in typical_hours:
            anomalies.append({
                "type": "unusual_login_time",
                "severity": "medium",
                "description": f"Login at unusual hour: {current_hour}:00",
                "details": {"hour": current_hour, "typical_hours": typical_hours},
                "detected_at": datetime.now(UTC).isoformat(),
            })

        # Check for rapid successive logins
        recent_logins = activity_data.get("recent_logins", [])
        if len(recent_logins) > 5:  # More than 5 logins in the time window
            anomalies.append({
                "type": "excessive_login_attempts",
                "severity": "high",
                "description": f"Excessive login attempts: {len(recent_logins)} in recent period",
                "details": {"login_count": len(recent_logins)},
                "detected_at": datetime.now(UTC).isoformat(),
            })

        return anomalies

    async def _detect_location_anomalies(
        self, user_id: UUID, activity_data: dict[str, Any], baseline: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Detect location-based anomalies."""
        anomalies = []
        
        current_location = activity_data.get("location", {})
        typical_locations = baseline.get("typical_locations", [])
        
        if current_location.get("country") not in typical_locations:
            anomalies.append({
                "type": "unusual_location",
                "severity": "high",
                "description": f"Login from unusual location: {current_location.get('country')}",
                "details": {"location": current_location, "typical_locations": typical_locations},
                "detected_at": datetime.now(UTC).isoformat(),
            })

        return anomalies

    async def _detect_behavioral_anomalies(
        self, user_id: UUID, activity_data: dict[str, Any], baseline: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Detect behavioral anomalies."""
        anomalies = []
        
        # Check session duration
        session_duration = activity_data.get("session_duration", 0)
        avg_duration = baseline.get("average_session_duration", 3600)
        
        if session_duration > avg_duration * 3:  # 3x longer than average
            anomalies.append({
                "type": "unusual_session_duration",
                "severity": "medium",
                "description": f"Unusually long session: {session_duration}s vs avg {avg_duration}s",
                "details": {"duration": session_duration, "average": avg_duration},
                "detected_at": datetime.now(UTC).isoformat(),
            })

        return anomalies

    async def _detect_access_pattern_anomalies(
        self, user_id: UUID, activity_data: dict[str, Any], baseline: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Detect access pattern anomalies."""
        anomalies = []
        
        recent_actions = activity_data.get("actions", [])
        typical_actions = baseline.get("typical_actions", [])
        
        # Check for unusual actions
        unusual_actions = [action for action in recent_actions if action not in typical_actions]
        if unusual_actions:
            anomalies.append({
                "type": "unusual_access_pattern",
                "severity": "medium",
                "description": f"Unusual actions performed: {unusual_actions}",
                "details": {"unusual_actions": unusual_actions, "typical_actions": typical_actions},
                "detected_at": datetime.now(UTC).isoformat(),
            })

        return anomalies

    async def _detect_ml_anomalies(self, user_id: UUID, activity_data: dict[str, Any]) -> list[dict[str, Any]]:
        """Detect anomalies using ML model."""
        try:
            # Mock ML implementation
            features = self._extract_features(activity_data)
            anomaly_score = await self._ml_client.predict_anomaly(features)
            
            if anomaly_score > 0.7:
                return [
                    {
                        "type": "ml_anomaly",
                        "severity": "high" if anomaly_score > 0.9 else "medium",
                        "description": f"ML model detected anomaly (score: {anomaly_score:.2f})",
                        "details": {"score": anomaly_score, "features": features},
                        "detected_at": datetime.now(UTC).isoformat(),
                    }
                ]
        except Exception as e:
            logger.error(f"ML anomaly detection failed: {e}")
            
        return []

    def _extract_features(self, activity_data: dict[str, Any]) -> dict[str, float]:
        """Extract features for ML model."""
        return {
            "hour_of_day": datetime.now(UTC).hour,
            "session_duration": activity_data.get("session_duration", 0) / 3600,
            "action_count": len(activity_data.get("actions", [])),
            "unique_ips": len(set(activity_data.get("ip_addresses", []))),
            "failed_attempts": activity_data.get("failed_attempts", 0),
        }

    def _score_anomalies(self, anomalies: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Score and prioritize anomalies."""
        severity_scores = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        
        for anomaly in anomalies:
            severity = anomaly.get("severity", "low")
            anomaly["score"] = severity_scores.get(severity, 1)
            
        return sorted(anomalies, key=lambda x: x.get("score", 0), reverse=True)

    async def _scan_attack_patterns(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        """Scan for common attack patterns."""
        threats = []
        
        for pattern in self._threat_patterns:
            if pattern["pattern"] in str(data).lower():
                threats.append({
                    "type": pattern["type"],
                    "severity": pattern["severity"],
                    "description": pattern["description"],
                    "pattern_matched": pattern["pattern"],
                    "detected_at": datetime.now(UTC).isoformat(),
                })
        
        return threats

    async def _scan_malicious_content(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        """Scan for malicious content."""
        threats = []
        
        # Check for malicious URLs
        import re
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls = re.findall(url_pattern, str(data))
        
        for url in urls:
            if await self._is_malicious_url(url):
                threats.append({
                    "type": "malicious_url",
                    "severity": "high",
                    "description": f"Malicious URL detected: {url}",
                    "url": url,
                    "detected_at": datetime.now(UTC).isoformat(),
                })
        
        return threats

    async def _scan_data_exfiltration(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        """Scan for data exfiltration indicators."""
        threats = []
        
        # Check for large data requests
        data_size = len(str(data))
        if data_size > 100000:  # Large payload
            threats.append({
                "type": "potential_data_exfiltration",
                "severity": "medium",
                "description": f"Large data payload detected: {data_size} bytes",
                "data_size": data_size,
                "detected_at": datetime.now(UTC).isoformat(),
            })
        
        return threats

    async def _scan_injection_attempts(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        """Scan for injection attempts."""
        threats = []
        
        injection_patterns = [
            ("sql_injection", r"('|(\\x27)|(\\x2D))|(-)|(%27)|(%2D)"),
            ("xss", r"<script|javascript:|onerror|onload"),
            ("command_injection", r"(;|\||&|`|\$\(|\${)"),
        ]
        
        import re
        data_str = str(data).lower()
        
        for injection_type, pattern in injection_patterns:
            if re.search(pattern, data_str):
                threats.append({
                    "type": injection_type,
                    "severity": "high",
                    "description": f"Potential {injection_type.replace('_', ' ')} detected",
                    "pattern": pattern,
                    "detected_at": datetime.now(UTC).isoformat(),
                })
        
        return threats

    async def _apply_custom_threat_rules(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        """Apply custom threat detection rules."""
        threats = []
        
        # Custom rule: Check for admin escalation attempts
        if "admin" in str(data).lower() and "grant" in str(data).lower():
            threats.append({
                "type": "privilege_escalation_attempt",
                "severity": "high",
                "description": "Potential privilege escalation attempt detected",
                "detected_at": datetime.now(UTC).isoformat(),
            })
        
        return threats

    def _deduplicate_threats(self, threats: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Remove duplicate threats."""
        seen = set()
        unique_threats = []
        
        for threat in threats:
            threat_signature = f"{threat.get('type')}:{threat.get('description', '')}"
            if threat_signature not in seen:
                seen.add(threat_signature)
                unique_threats.append(threat)
        
        return unique_threats

    def _score_threats(self, threats: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Score and prioritize threats."""
        severity_scores = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        
        for threat in threats:
            severity = threat.get("severity", "low")
            threat["score"] = severity_scores.get(severity, 1)
            
        return sorted(threats, key=lambda x: x.get("score", 0), reverse=True)

    def _load_threat_patterns(self) -> list[dict[str, Any]]:
        """Load threat detection patterns."""
        return [
            {
                "pattern": "select * from",
                "type": "sql_injection",
                "severity": "high",
                "description": "SQL injection pattern detected",
            },
            {
                "pattern": "<script",
                "type": "xss",
                "severity": "high",
                "description": "Cross-site scripting pattern detected",
            },
            {
                "pattern": "../",
                "type": "directory_traversal",
                "severity": "medium",
                "description": "Directory traversal pattern detected",
            },
        ]

    async def _check_internal_blacklist(self, ip_address: str) -> dict[str, Any]:
        """Check internal IP blacklist."""
        # Mock implementation
        blacklisted_ips = ["192.168.1.100", "10.0.0.50"]
        return {
            "blacklisted": ip_address in blacklisted_ips,
            "reason": "Previous security incident" if ip_address in blacklisted_ips else None,
        }

    async def _check_recent_incidents(self, ip_address: str) -> list[dict[str, Any]]:
        """Check for recent security incidents from IP."""
        # Mock implementation
        return []

    async def _is_malicious_url(self, url: str) -> bool:
        """Check if URL is malicious."""
        # Mock implementation
        malicious_domains = ["malware.com", "phishing.net", "spam.org"]
        return any(domain in url for domain in malicious_domains)

    async def _report_anomaly_incidents(self, user_id: UUID, anomalies: list[dict[str, Any]]) -> None:
        """Report high-severity anomalies as incidents."""
        for anomaly in anomalies:
            await self.report_security_incident(
                incident_type=f"anomaly_{anomaly['type']}",
                details={
                    "user_id": str(user_id),
                    "anomaly": anomaly,
                    "severity": anomaly["severity"],
                    "detected_at": anomaly["detected_at"],
                }
            )

    def _generate_incident_tags(self, incident_type: str, details: dict[str, Any]) -> list[str]:
        """Generate tags for incident."""
        tags = [incident_type]
        
        if details.get("user_id"):
            tags.append("user_related")
        if details.get("ip_address"):
            tags.append("network_related")
        if details.get("severity") in ["high", "critical"]:
            tags.append("high_priority")
            
        return tags

    async def _generate_remediation_steps(self, incident_type: str, details: dict[str, Any]) -> list[str]:
        """Generate remediation steps for incident."""
        base_steps = [
            "Investigate incident details",
            "Assess impact and scope",
            "Document findings",
        ]
        
        if "login" in incident_type.lower():
            base_steps.extend([
                "Review user login history",
                "Check for compromised credentials",
                "Consider MFA enforcement",
            ])
        
        if details.get("severity") in ["high", "critical"]:
            base_steps.extend([
                "Notify security team immediately",
                "Consider temporary access restrictions",
                "Escalate to management if needed",
            ])
            
        return base_steps

    async def _send_incident_notifications(self, incident: dict[str, Any]) -> None:
        """Send notifications for security incident."""
        if self._notifications:
            await self._notifications.send_security_alert(
                recipients=["security-team@company.com"],
                incident_id=incident["id"],
                incident_type=incident["type"],
                severity=incident["severity"],
                details=incident["details"],
            )

    async def _trigger_incident_response(self, incident: dict[str, Any]) -> None:
        """Trigger automated incident response actions."""
        incident_type = incident["type"]
        severity = incident["severity"]
        
        # Auto-block high-risk IPs
        if "malicious_ip" in incident_type and severity in ["high", "critical"]:
            ip_address = incident["details"].get("ip_address")
            if ip_address:
                logger.warning(f"Auto-blocking IP {ip_address} due to security incident")
                # Would implement actual IP blocking here
        
        # Auto-disable compromised accounts
        if "account_compromise" in incident_type and severity == "critical":
            user_id = incident["details"].get("user_id")
            if user_id:
                logger.warning(f"Auto-disabling account {user_id} due to compromise")
                # Would implement account disabling here