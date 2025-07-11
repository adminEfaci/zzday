"""
Security Domain Service

Pure domain service for security monitoring and threat detection.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any
from uuid import UUID

from ...errors import ValidationError
from ...interfaces.repositories.user_repository import IUserRepository
from ...interfaces.services.security.security_service import ISecurityService
from ...value_objects.ip_address import IpAddress


class ThreatLevel(Enum):
    """Threat severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class SecurityThreat:
    """Domain value object for security threats."""
    threat_type: str
    severity: str
    description: str
    mitigation: str
    
    def is_critical(self) -> bool:
        """Check if threat is critical."""
        return self.severity == "critical"


@dataclass(frozen=True)
class AnomalyDetection:
    """Domain value object for anomaly detection."""
    anomaly_type: str
    severity: str
    description: str
    confidence: float
    data: dict[str, Any]
    
    def is_high_confidence(self) -> bool:
        """Check if detection has high confidence."""
        return self.confidence > 0.8


class SecurityService(ISecurityService):
    """Pure domain service for security business logic.
    
    Coordinates security monitoring using domain rules.
    No infrastructure concerns - only security logic.
    """
    
    def __init__(
        self,
        user_repository: IUserRepository
    ) -> None:
        self._user_repository = user_repository
        self._threat_patterns = self._initialize_threat_patterns()
    
    async def detect_anomalies(
        self, 
        user_id: UUID, 
        activity_data: dict[str, Any]
    ) -> list[dict[str, Any]]:
        """Detect anomalous behavior using domain rules."""
        
        # Get user aggregate
        user = await self._user_repository.get_by_id(user_id)
        if not user:
            return []
        
        anomalies = []
        
        # Use aggregate methods for anomaly detection
        login_anomaly = user.detect_login_frequency_anomaly(
            activity_data.get("login_frequency", 0)
        )
        if login_anomaly:
            anomalies.append({
                "type": "unusual_login_frequency",
                "severity": login_anomaly.severity,
                "description": login_anomaly.description,
                "confidence": login_anomaly.confidence,
                "data": login_anomaly.evidence
            })
        
        # Location anomaly detection
        location_anomaly = user.detect_location_anomaly(
            activity_data.get("location")
        )
        if location_anomaly:
            anomalies.append({
                "type": "unusual_location",
                "severity": location_anomaly.severity,
                "description": location_anomaly.description,
                "confidence": location_anomaly.confidence,
                "data": location_anomaly.evidence
            })
        
        # Time-based anomaly detection
        time_anomaly = user.detect_time_anomaly(
            activity_data.get("login_hour")
        )
        if time_anomaly:
            anomalies.append({
                "type": "unusual_time",
                "severity": time_anomaly.severity,
                "description": time_anomaly.description,
                "confidence": time_anomaly.confidence,
                "data": time_anomaly.evidence
            })
        
        # Device anomaly detection
        device_anomaly = user.detect_device_anomaly(
            activity_data.get("device_fingerprint")
        )
        if device_anomaly:
            anomalies.append({
                "type": "unknown_device",
                "severity": device_anomaly.severity,
                "description": device_anomaly.description,
                "confidence": device_anomaly.confidence,
                "data": device_anomaly.evidence
            })
        
        return anomalies
    
    async def check_ip_reputation(self, ip_address: IpAddress) -> dict[str, Any]:
        """Check IP reputation using domain logic."""
        
        reputation_score = 1.0  # Start with clean reputation
        is_blocklisted = False
        threat_categories = []
        
        # Use domain logic for IP reputation assessment
        if ip_address.is_tor():
            reputation_score -= 0.4
            threat_categories.append("tor_exit_node")
        
        if ip_address.is_vpn():
            reputation_score -= 0.2
            threat_categories.append("vpn_service")
        
        if ip_address.is_datacenter():
            reputation_score -= 0.3
            threat_categories.append("datacenter_ip")
        
        if ip_address.is_known_malicious():
            is_blocklisted = True
            reputation_score = 0.0
            threat_categories.append("known_malicious")
        
        # Normalize score
        reputation_score = max(0.0, min(1.0, reputation_score))
        
        return {
            "reputation_score": reputation_score,
            "is_blocklisted": is_blocklisted,
            "threat_categories": threat_categories,
            "last_seen_malicious": ip_address.last_seen_malicious()
        }
    
    async def scan_for_threats(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        """Scan data for security threats using domain patterns."""
        
        threats = []
        
        # SQL injection detection
        if self._detect_sql_injection(data):
            threats.append({
                "type": "sql_injection",
                "severity": "high",
                "description": "Potential SQL injection detected",
                "mitigation": "Sanitize and validate all input parameters"
            })
        
        # XSS detection
        if self._detect_xss(data):
            threats.append({
                "type": "xss_attempt",
                "severity": "medium", 
                "description": "Potential XSS payload detected",
                "mitigation": "Encode output and validate input"
            })
        
        # Command injection detection
        if self._detect_command_injection(data):
            threats.append({
                "type": "command_injection",
                "severity": "critical",
                "description": "Potential command injection detected",
                "mitigation": "Use parameterized commands and input validation"
            })
        
        # Sensitive data exposure detection
        if self._detect_sensitive_data_exposure(data):
            threats.append({
                "type": "sensitive_data_exposure",
                "severity": "medium",
                "description": "Potential sensitive data in request",
                "mitigation": "Ensure proper data handling and encryption"
            })
        
        return threats
    
    async def report_security_incident(
        self,
        incident_type: str,
        details: dict[str, Any]
    ) -> str:
        """Create security incident using domain logic."""
        
        # Generate incident ID using domain logic
        from app.core.security import generate_token
        incident_id = generate_token(16)
        
        # Validate incident using domain rules
        if not self._is_valid_incident_type(incident_type):
            raise ValidationError(f"Invalid incident type: {incident_type}")
        
        # Calculate severity using domain logic
        self._calculate_incident_severity(incident_type, details)
        
        # Domain incident creation (Application Service handles persistence)
        return incident_id
    
    # Pure domain helper methods
    
    def _detect_sql_injection(self, data: dict[str, Any]) -> bool:
        """Detect SQL injection patterns using domain rules."""
        sql_patterns = ["' OR '1'='1", "UNION SELECT", "DROP TABLE", "INSERT INTO"]
        
        for value in data.values():
            if isinstance(value, str):
                for pattern in sql_patterns:
                    if pattern.lower() in value.lower():
                        return True
        return False
    
    def _detect_xss(self, data: dict[str, Any]) -> bool:
        """Detect XSS patterns using domain rules."""
        xss_patterns = ["<script>", "javascript:", "onload=", "onerror="]
        
        for value in data.values():
            if isinstance(value, str):
                for pattern in xss_patterns:
                    if pattern.lower() in value.lower():
                        return True
        return False
    
    def _detect_command_injection(self, data: dict[str, Any]) -> bool:
        """Detect command injection patterns using domain rules."""
        cmd_patterns = ["; rm -rf", "&& rm", "| cat", "`whoami`"]
        
        for value in data.values():
            if isinstance(value, str):
                for pattern in cmd_patterns:
                    if pattern in value:
                        return True
        return False
    
    def _detect_sensitive_data_exposure(self, data: dict[str, Any]) -> bool:
        """Detect sensitive data patterns using domain rules."""
        import re
        
        # Credit card pattern
        cc_pattern = r'\b(?:\d{4}[-\s]?){3}\d{4}\b'
        # SSN pattern  
        ssn_pattern = r'\b\d{3}-\d{2}-\d{4}\b'
        
        for value in data.values():
            if isinstance(value, str):
                if re.search(cc_pattern, value) or re.search(ssn_pattern, value):
                    return True
        return False
    
    def _is_valid_incident_type(self, incident_type: str) -> bool:
        """Validate incident type using domain rules."""
        valid_types = [
            "data_breach", "unauthorized_access", "malware_detected",
            "phishing_attempt", "ddos_attack", "insider_threat"
        ]
        return incident_type in valid_types
    
    def _calculate_incident_severity(self, incident_type: str, details: dict[str, Any]) -> str:
        """Calculate incident severity using domain rules."""
        high_severity_types = ["data_breach", "unauthorized_access", "malware_detected"]
        
        if incident_type in high_severity_types:
            return "high"
        
        # Check for additional severity factors
        if details.get("user_count", 0) > 100:
            return "high"
        
        return "medium"
    
    def _initialize_threat_patterns(self) -> dict[str, Any]:
        """Initialize threat detection patterns."""
        return {
            "brute_force": {
                "threshold": 5,
                "window_minutes": 15
            },
            "credential_stuffing": {
                "threshold": 10, 
                "window_minutes": 5
            },
            "suspicious_location": {
                "distance_threshold_km": 1000,
                "time_threshold_hours": 2
            }
        }