"""
User Security Service

Domain service for risk assessment, security monitoring, and threat detection.
"""

from datetime import datetime, timedelta
from typing import Any

from ..entities.user.login_attempt import LoginAttempt, RiskIndicator
from ..enums import LoginFailureReason
from ..value_objects import Geolocation


class UserSecurityService:
    """Service for user security operations and risk assessment."""
    
    def assess_login_risk(
        self,
        attempt: LoginAttempt,
        historical_data: dict[str, Any] | None = None,
        recent_attempts: list[LoginAttempt] | None = None
    ) -> float:
        """Comprehensive risk assessment for login attempt."""
        risk_factors = {
            "base": self._calculate_base_risk(attempt),
            "indicators": self._calculate_indicator_risk(attempt),
            "behavioral": self._calculate_behavioral_risk(attempt, historical_data or {}),
            "trust": self._calculate_trust_risk(attempt),
            "velocity": self._calculate_velocity_risk(attempt, recent_attempts or [])
        }
        
        # Use ML score if available and confident
        if attempt.ml_risk_score is not None and attempt.ml_confidence and attempt.ml_confidence > 0.8:
            risk_factors["ml"] = attempt.ml_risk_score
        
        # Calculate weighted risk
        weights = {
            "base": 0.2,
            "indicators": 0.25,
            "behavioral": 0.2,
            "trust": 0.15,
            "velocity": 0.15,
            "ml": 0.05
        }
        
        weighted_risk = sum(
            risk_factors.get(factor, 0.0) * weight 
            for factor, weight in weights.items()
        )
        
        # Store breakdown in attempt
        attempt.risk_breakdown = {
            factor: round(score, 3) 
            for factor, score in risk_factors.items()
        }
        attempt.risk_breakdown["combined"] = round(weighted_risk, 3)
        
        # Update attempt with final score
        final_score = max(0.0, min(1.0, weighted_risk))
        attempt.risk_score = final_score
        
        return final_score
    
    def _calculate_base_risk(self, attempt: LoginAttempt) -> float:
        """Calculate base risk from attempt properties."""
        risk = 0.0
        
        # Failed attempt increases risk
        if not attempt.success:
            risk += 0.2
            
            # High-risk failure reasons
            high_risk_failures = [
                LoginFailureReason.ACCOUNT_LOCKED,
                LoginFailureReason.ACCOUNT_SUSPENDED,
                LoginFailureReason.SUSPICIOUS_ACTIVITY,
                LoginFailureReason.TOO_MANY_ATTEMPTS
            ]
            
            if attempt.failure_reason in high_risk_failures:
                risk += 0.3
        
        # Bot detection
        if attempt.is_bot_attempt():
            risk += 0.4
            attempt.risk_indicators.add(RiskIndicator.BOT_ACTIVITY)
        
        # IP risk assessment
        ip_risk = self._assess_ip_risk(attempt)
        risk += ip_risk
        
        return min(risk, 1.0)
    
    def _assess_ip_risk(self, attempt: LoginAttempt) -> float:
        """Assess risk based on IP characteristics."""
        risk = 0.0
        
        if attempt.ip_address.is_vpn:
            risk += 0.1
            attempt.risk_indicators.add(RiskIndicator.VPN_DETECTED)
        
        if attempt.ip_address.is_tor:
            risk += 0.3
            attempt.risk_indicators.add(RiskIndicator.TOR_EXIT_NODE)
        
        if attempt.ip_address.is_datacenter:
            risk += 0.2
            attempt.risk_indicators.add(RiskIndicator.DATACENTER_IP)
        
        # Geographic anomalies
        if attempt.ip_address.country in ['XX', 'T1']:  # Unknown or Tor
            risk += 0.2
            attempt.risk_indicators.add(RiskIndicator.SUSPICIOUS_IP)
        
        return risk
    
    def _calculate_indicator_risk(self, attempt: LoginAttempt) -> float:
        """Calculate risk from risk indicators."""
        if not attempt.risk_indicators:
            return 0.0
        
        # Weight for each indicator
        indicator_weights = {
            RiskIndicator.ACCOUNT_TAKEOVER: 0.9,
            RiskIndicator.IMPOSSIBLE_TRAVEL: 0.8,
            RiskIndicator.CREDENTIAL_STUFFING: 0.7,
            RiskIndicator.BRUTE_FORCE: 0.7,
            RiskIndicator.TOR_EXIT_NODE: 0.6,
            RiskIndicator.HIGH_VELOCITY: 0.5,
            RiskIndicator.DATACENTER_IP: 0.4,
            RiskIndicator.VPN_DETECTED: 0.3,
            RiskIndicator.NEW_DEVICE: 0.3,
            RiskIndicator.UNKNOWN_LOCATION: 0.3,
            RiskIndicator.UNCOMMON_TIME: 0.2,
            RiskIndicator.PATTERN_ANOMALY: 0.4,
            RiskIndicator.BOT_ACTIVITY: 0.6,
            RiskIndicator.SUSPICIOUS_IP: 0.5
        }
        
        # Get max weight from present indicators
        max_risk = 0.0
        for indicator in attempt.risk_indicators:
            weight = indicator_weights.get(indicator, 0.3)
            max_risk = max(max_risk, weight)
        
        # Add small amount for multiple indicators
        indicator_count_bonus = min(len(attempt.risk_indicators) * 0.05, 0.2)
        
        return min(max_risk + indicator_count_bonus, 1.0)
    
    def _calculate_behavioral_risk(self, attempt: LoginAttempt, historical_data: dict[str, Any]) -> float:
        """Calculate risk based on behavioral patterns."""
        risk = 0.0
        
        # High velocity of attempts
        if attempt.login_velocity > 10:
            risk += 0.3
            attempt.risk_indicators.add(RiskIndicator.HIGH_VELOCITY)
        elif attempt.login_velocity > 5:
            risk += 0.1
        
        # Multiple IPs in short time
        if attempt.unique_ips_used > 5:
            risk += 0.3
            attempt.risk_indicators.add(RiskIndicator.PATTERN_ANOMALY)
        elif attempt.unique_ips_used > 2:
            risk += 0.1
        
        # High failure rate
        if attempt.failed_attempts_24h > 20:
            risk += 0.4
            attempt.risk_indicators.add(RiskIndicator.BRUTE_FORCE)
        elif attempt.failed_attempts_24h > 10:
            risk += 0.2
        
        # Time-based anomalies
        typical_hours = historical_data.get("typical_login_hours", [])
        if typical_hours:
            current_hour = attempt.timestamp.hour
            if current_hour not in typical_hours:
                # Check if significantly outside normal hours
                hour_distance = min(
                    abs(current_hour - h) for h in typical_hours
                )
                if hour_distance > 6:
                    risk += 0.2
                    attempt.risk_indicators.add(RiskIndicator.UNCOMMON_TIME)
        
        # Credential stuffing patterns
        if attempt.credential_stuffing_score > 0.7:
            risk += 0.4
            attempt.risk_indicators.add(RiskIndicator.CREDENTIAL_STUFFING)
        
        return min(risk, 1.0)
    
    def _calculate_trust_risk(self, attempt: LoginAttempt) -> float:
        """Calculate risk based on device and location trust."""
        risk = 0.0
        
        # Unknown device
        if not attempt.is_known_device:
            risk += 0.2
            attempt.risk_indicators.add(RiskIndicator.NEW_DEVICE)
        
        # Low device trust
        if attempt.device_trust_score < 0.3:
            risk += 0.3
        elif attempt.device_trust_score < 0.5:
            risk += 0.1
        
        # Unknown location
        if not attempt.is_known_location:
            risk += 0.2
            attempt.risk_indicators.add(RiskIndicator.UNKNOWN_LOCATION)
        
        # Low location trust
        if attempt.location_trust_score < 0.3:
            risk += 0.3
        elif attempt.location_trust_score < 0.5:
            risk += 0.1
        
        return min(risk, 1.0)
    
    def _calculate_velocity_risk(self, attempt: LoginAttempt, recent_attempts: list[LoginAttempt]) -> float:
        """Calculate risk based on attempt velocity."""
        if not recent_attempts:
            return 0.0
        
        risk = 0.0
        now = attempt.timestamp
        
        # Count attempts in different time windows
        attempts_1h = sum(1 for a in recent_attempts if (now - a.timestamp) <= timedelta(hours=1))
        attempts_10m = sum(1 for a in recent_attempts if (now - a.timestamp) <= timedelta(minutes=10))
        
        # Update attempt velocity data
        attempt.login_velocity = attempts_1h
        
        # Detect high velocity
        if attempts_10m > 5:
            risk += 0.4
            attempt.risk_indicators.add(RiskIndicator.HIGH_VELOCITY)
        
        if attempts_1h > 20:
            risk += 0.5
            attempt.risk_indicators.add(RiskIndicator.BRUTE_FORCE)
        
        # Check for distributed attack pattern
        unique_ips = {a.ip_address.value for a in recent_attempts}
        if len(unique_ips) > 10 and attempts_1h > 30:
            attempt.is_distributed_attack = True
            attempt.attack_pattern = "distributed_brute_force"
            risk += 0.3
        
        return min(risk, 1.0)
    
    def check_impossible_travel(
        self,
        attempt: LoginAttempt,
        previous_location: Geolocation,
        previous_time: datetime
    ) -> bool:
        """Check for impossible travel between login attempts."""
        if not attempt.geolocation or not previous_location:
            return False
        
        # Calculate distance and time
        distance_km = attempt.geolocation.distance_to(previous_location, "kilometers")
        time_diff = (attempt.timestamp - previous_time).total_seconds() / 3600  # hours
        
        if time_diff <= 0:
            return False
        
        # Calculate required speed
        speed_kmh = distance_km / time_diff
        
        # Impossible if faster than commercial flight (~900 km/h)
        if speed_kmh > 900:
            attempt.risk_indicators.add(RiskIndicator.IMPOSSIBLE_TRAVEL)
            return True
        
        # Suspicious if faster than typical travel (>500 km/h)
        if speed_kmh > 500:
            attempt.risk_indicators.add(RiskIndicator.PATTERN_ANOMALY)
        
        return False
    
    def analyze_credential_stuffing(
        self,
        attempt: LoginAttempt,
        global_attempts: dict[str, int]
    ) -> float:
        """Analyze if this is part of credential stuffing attack."""
        score = 0.0
        
        # Same IP trying many different emails
        if attempt.ip_address.value in global_attempts:
            unique_emails = global_attempts[attempt.ip_address.value]
            if unique_emails > 50:
                score += 0.8
            elif unique_emails > 20:
                score += 0.5
            elif unique_emails > 10:
                score += 0.3
        
        # Datacenter IP + bot = likely automated
        if attempt.ip_address.is_datacenter and attempt.is_bot_attempt():
            score += 0.4
        
        # Failed login with non-existent email
        if attempt.failure_reason == LoginFailureReason.INVALID_EMAIL:
            score += 0.2
        
        # Rapid attempts
        if attempt.login_velocity > 5:
            score += 0.2
        
        score = min(score, 1.0)
        attempt.credential_stuffing_score = score
        
        if score > 0.7:
            attempt.risk_indicators.add(RiskIndicator.CREDENTIAL_STUFFING)
            attempt.attack_pattern = "credential_stuffing"
        
        return score
    
    def calculate_device_trust(
        self,
        attempt: LoginAttempt,
        device_history: list[dict[str, Any]]
    ) -> float:
        """Calculate device trust score based on history."""
        if not attempt.device_fingerprint:
            attempt.device_trust_score = 0.0
            return 0.0
        
        trust = 0.0
        device_seen_count = 0
        successful_logins = 0
        days_since_first_seen = 0
        
        for record in device_history:
            if record.get("fingerprint") == attempt.device_fingerprint:
                device_seen_count += 1
                if record.get("success"):
                    successful_logins += 1
                
                first_seen = record.get("first_seen")
                if first_seen:
                    days = (attempt.timestamp - first_seen).days
                    days_since_first_seen = max(days_since_first_seen, days)
        
        # Calculate trust based on history
        if device_seen_count > 0:
            attempt.is_known_device = True
            
            # Success rate
            success_rate = successful_logins / device_seen_count
            trust += success_rate * 0.3
            
            # Longevity
            if days_since_first_seen > 90:
                trust += 0.3
            elif days_since_first_seen > 30:
                trust += 0.2
            elif days_since_first_seen > 7:
                trust += 0.1
            
            # Frequency
            if device_seen_count > 50:
                trust += 0.2
            elif device_seen_count > 20:
                trust += 0.15
            elif device_seen_count > 5:
                trust += 0.1
            
            # Recent activity
            recent_successful = sum(1 for r in device_history[-30:] if r.get("success", False))
            if recent_successful > 5:
                trust += 0.2
        
        trust = min(trust, 1.0)
        attempt.device_trust_score = trust
        return trust
    
    def calculate_location_trust(
        self,
        attempt: LoginAttempt,
        location_history: list[dict[str, Any]]
    ) -> float:
        """Calculate location trust score based on history."""
        if not attempt.geolocation:
            attempt.location_trust_score = 0.0
            return 0.0
        
        trust = 0.0
        location_matches = 0
        successful_from_location = 0
        
        for record in location_history:
            record_geo = record.get("geolocation")
            if record_geo:
                # Check if within reasonable distance (50km)
                if attempt.geolocation.is_within_radius(record_geo, 50000):
                    location_matches += 1
                    if record.get("success"):
                        successful_from_location += 1
        
        # Calculate trust
        if location_matches > 0:
            attempt.is_known_location = True
            
            # Success rate from location
            success_rate = successful_from_location / location_matches
            trust += success_rate * 0.4
            
            # Frequency from location
            if location_matches > 20:
                trust += 0.3
            elif location_matches > 10:
                trust += 0.2
            elif location_matches > 3:
                trust += 0.1
            
            # Country trust
            trusted_countries = ['US', 'CA', 'GB', 'AU', 'NZ', 'DE', 'FR', 'JP', 'KR']
            if attempt.country in trusted_countries:
                trust += 0.2
            
            # Not datacenter/VPN
            if not attempt.ip_address.is_datacenter and not attempt.ip_address.is_vpn:
                trust += 0.1
        
        trust = min(trust, 1.0)
        attempt.location_trust_score = trust
        return trust
    
    def should_require_mfa(self, attempt: LoginAttempt) -> bool:
        """Determine if MFA should be required for this attempt."""
        # Always require MFA for high-risk attempts
        if attempt.risk_score > 0.6:
            return True
        
        # Require for unknown devices
        if not attempt.is_known_device:
            return True
        
        # Require for unknown locations
        if not attempt.is_known_location:
            return True
        
        # Require for specific risk indicators
        mfa_indicators = {
            RiskIndicator.IMPOSSIBLE_TRAVEL,
            RiskIndicator.SUSPICIOUS_IP,
            RiskIndicator.VPN_DETECTED,
            RiskIndicator.TOR_EXIT_NODE
        }
        
        return bool(attempt.risk_indicators & mfa_indicators)
    
    def should_block_attempt(self, attempt: LoginAttempt) -> bool:
        """Determine if attempt should be blocked."""
        # Block critical risk attempts
        if attempt.risk_score > 0.9:
            return True
        
        # Block specific attack patterns
        blocking_indicators = {
            RiskIndicator.ACCOUNT_TAKEOVER,
            RiskIndicator.BRUTE_FORCE,
            RiskIndicator.CREDENTIAL_STUFFING
        }
        
        return bool(attempt.risk_indicators & blocking_indicators)
    
    def get_security_recommendation(self, attempt: LoginAttempt) -> dict[str, Any]:
        """Get comprehensive security recommendation."""
        return {
            "action": attempt.get_recommended_action(),
            "require_mfa": self.should_require_mfa(attempt),
            "block_attempt": self.should_block_attempt(attempt),
            "risk_level": attempt.get_risk_level(),
            "key_concerns": [i.value for i in attempt.risk_indicators],
            "trust_factors": {
                "device_known": attempt.is_known_device,
                "location_known": attempt.is_known_location,
                "device_trust": round(attempt.device_trust_score, 3),
                "location_trust": round(attempt.location_trust_score, 3)
            }
        }