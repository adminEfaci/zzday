"""
Account Lockout Policy

Business rules for account lockout and brute force protection.
"""

from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any

from app.core.config import PolicyConfigManager

from .base import BusinessRule, PolicyViolation


class AccountLockoutPolicy(BusinessRule):
    """Account lockout policy validation."""
    
    def __init__(self, policy_config: dict[str, Any] | None = None):
        if policy_config:
            self.config = policy_config
        else:
            config_manager = PolicyConfigManager()
            lockout_config = config_manager.get_lockout_config()
            self.config = lockout_config.__dict__
    
    def validate(self, login_attempts: list[dict[str, Any]]) -> list[PolicyViolation]:
        """Validate login attempts against lockout policy."""
        violations = []
        
        if not login_attempts:
            return violations
        
        # Validate failed attempt threshold
        violations.extend(self._validate_failed_attempts(login_attempts))
        
        # Validate attempt velocity
        violations.extend(self._validate_attempt_velocity(login_attempts))
        
        # Validate IP-based limits
        violations.extend(self._validate_ip_limits(login_attempts))
        
        # Validate pattern-based threats
        violations.extend(self._validate_threat_patterns(login_attempts))
        
        return violations
    
    def is_compliant(self, login_attempts: list[dict[str, Any]]) -> bool:
        """Check if login attempts are compliant with policy."""
        violations = self.validate(login_attempts)
        return not self.has_blocking_violations(violations)
    
    def should_lock_account(self, login_attempts: list[dict[str, Any]]) -> bool:
        """Determine if account should be locked."""
        return not self.is_compliant(login_attempts)
    
    def _validate_failed_attempts(self, login_attempts: list[dict[str, Any]]) -> list[PolicyViolation]:
        """Validate failed attempt thresholds."""
        violations = []
        
        # Filter recent failed attempts within lockout window
        lockout_window = self.config["lockout_duration"]
        window_start = datetime.now(UTC) - lockout_window
        
        recent_failures = [
            attempt for attempt in login_attempts
            if not attempt.get("success", False) and
            attempt.get("timestamp", datetime.min) > window_start
        ]
        
        # Check basic threshold
        max_failures = self.config["max_failed_attempts"]
        if len(recent_failures) >= max_failures:
            violations.append(PolicyViolation(
                rule_name="max_failed_attempts",
                description="Maximum failed login attempts exceeded",
                severity="error",
                current_value=len(recent_failures),
                expected_value=max_failures - 1
            ))
        
        # Check progressive lockout
        if self.config.get("progressive_lockout", {}).get("enabled", False):
            violations.extend(self._validate_progressive_lockout(login_attempts))
        
        # Warning threshold (80% of max)
        warning_threshold = int(max_failures * 0.8)
        if warning_threshold < len(recent_failures) < max_failures:
            violations.append(PolicyViolation(
                rule_name="approaching_lockout",
                description="Approaching account lockout threshold",
                severity="warning",
                current_value=len(recent_failures),
                expected_value=warning_threshold
            ))
        
        return violations
    
    def _validate_progressive_lockout(self, login_attempts: list[dict[str, Any]]) -> list[PolicyViolation]:
        """Validate progressive lockout rules."""
        violations = []
        
        progressive_config = self.config.get("progressive_lockout", {})
        if not progressive_config.get("enabled", False):
            return violations
        
        # Count lockout occurrences
        lockout_count = sum(1 for attempt in login_attempts if attempt.get("caused_lockout", False))
        
        # Check if we need extended lockout
        thresholds = progressive_config.get("thresholds", [])
        for threshold in thresholds:
            if lockout_count >= threshold["lockout_count"]:
                extended_duration = timedelta(minutes=threshold["duration_minutes"])
                current_duration = self.config["lockout_duration"]
                
                if extended_duration > current_duration:
                    violations.append(PolicyViolation(
                        rule_name="progressive_lockout_triggered",
                        description=f"Extended lockout period required after {lockout_count} lockouts",
                        severity="error",
                        current_value=current_duration,
                        expected_value=extended_duration,
                        context={"lockout_count": lockout_count}
                    ))
        
        return violations
    
    def _validate_attempt_velocity(self, login_attempts: list[dict[str, Any]]) -> list[PolicyViolation]:
        """Validate login attempt velocity/rate."""
        violations = []
        
        # Check attempts in last minute
        one_minute_ago = datetime.now(UTC) - timedelta(minutes=1)
        recent_attempts = [
            attempt for attempt in login_attempts
            if attempt.get("timestamp", datetime.min) > one_minute_ago
        ]
        
        max_per_minute = self.config.get("max_attempts_per_minute", 10)
        if len(recent_attempts) > max_per_minute:
            violations.append(PolicyViolation(
                rule_name="excessive_attempt_velocity",
                description="Too many login attempts per minute",
                severity="error",
                current_value=len(recent_attempts),
                expected_value=max_per_minute
            ))
        
        # Check burst patterns
        burst_window = timedelta(seconds=10)
        burst_threshold = 5
        
        for i in range(len(login_attempts) - burst_threshold + 1):
            window_attempts = login_attempts[i:i + burst_threshold]
            if len(window_attempts) == burst_threshold:
                first_time = window_attempts[0].get("timestamp", datetime.min)
                last_time = window_attempts[-1].get("timestamp", datetime.max)
                
                if last_time - first_time < burst_window:
                    violations.append(PolicyViolation(
                        rule_name="burst_attack_detected",
                        description="Burst login attack pattern detected",
                        severity="critical",
                        current_value=f"{burst_threshold} attempts in {(last_time - first_time).total_seconds()}s",
                        expected_value=f"< {burst_threshold} attempts in {burst_window.total_seconds()}s"
                    ))
                    break
        
        return violations
    
    def _validate_ip_limits(self, login_attempts: list[dict[str, Any]]) -> list[PolicyViolation]:
        """Validate IP-based attempt limits."""
        violations = []
        
        # Group attempts by IP
        ip_attempts = defaultdict(list)
        for attempt in login_attempts:
            ip = attempt.get("ip_address")
            if ip:
                ip_attempts[ip].append(attempt)
        
        # Check per-IP limits
        max_per_ip = self.config.get("max_attempts_per_ip_per_hour", 20)
        time_window = timedelta(hours=self.config.get("ip_block_duration_hours", 24))
        window_start = datetime.now(UTC) - time_window
        
        for ip, attempts in ip_attempts.items():
            recent_failures = [
                a for a in attempts
                if not a.get("success", False) and
                a.get("timestamp", datetime.min) > window_start
            ]
            
            if len(recent_failures) >= max_per_ip:
                violations.append(PolicyViolation(
                    rule_name="ip_failed_attempts_exceeded",
                    description=f"Too many failed attempts from IP {ip}",
                    severity="error",
                    current_value=len(recent_failures),
                    expected_value=max_per_ip - 1,
                    context={"ip_address": ip}
                ))
        
        # Check distributed attack pattern
        if len(ip_attempts) > 10:
            total_failures = sum(
                1 for attempt in login_attempts
                if not attempt.get("success", False) and
                attempt.get("timestamp", datetime.min) > window_start
            )
            
            if total_failures > len(ip_attempts) * 2:
                violations.append(PolicyViolation(
                    rule_name="distributed_attack_pattern",
                    description="Possible distributed attack detected",
                    severity="critical",
                    current_value=f"{total_failures} failures from {len(ip_attempts)} IPs",
                    expected_value="Normal distribution pattern"
                ))
        
        return violations
    
    def _validate_threat_patterns(self, login_attempts: list[dict[str, Any]]) -> list[PolicyViolation]:
        """Validate against known threat patterns."""
        violations = []
        
        # Check for credential stuffing pattern
        violations.extend(self._check_credential_stuffing(login_attempts))
        
        # Check for timing attack pattern
        violations.extend(self._check_timing_attack(login_attempts))
        
        # Check for username enumeration
        violations.extend(self._check_username_enumeration(login_attempts))
        
        return violations
    
    def _check_credential_stuffing(self, login_attempts: list[dict[str, Any]]) -> list[PolicyViolation]:
        """Check for credential stuffing patterns."""
        violations = []
        
        # Look for rapid attempts with different credentials
        time_window = timedelta(minutes=5)
        window_start = datetime.now(UTC) - time_window
        
        recent_attempts = [
            a for a in login_attempts
            if a.get("timestamp", datetime.min) > window_start
        ]
        
        unique_passwords = len({a.get("password_hash", "") for a in recent_attempts if a.get("password_hash")})
        
        if unique_passwords > 10:
            violations.append(PolicyViolation(
                rule_name="credential_stuffing_suspected",
                description="Credential stuffing attack pattern detected",
                severity="critical",
                current_value=f"{unique_passwords} unique passwords tried",
                expected_value="< 10 unique passwords"
            ))
        
        return violations
    
    def _check_timing_attack(self, login_attempts: list[dict[str, Any]]) -> list[PolicyViolation]:
        """Check for timing attack patterns."""
        violations = []
        
        # Look for attempts with suspiciously regular intervals
        if len(login_attempts) < 5:
            return violations
        
        intervals = []
        for i in range(1, min(10, len(login_attempts))):
            t1 = login_attempts[i-1].get("timestamp")
            t2 = login_attempts[i].get("timestamp")
            if t1 and t2:
                intervals.append((t2 - t1).total_seconds())
        
        if intervals:
            avg_interval = sum(intervals) / len(intervals)
            variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
            
            # Low variance suggests automated/scripted attempts
            if variance < 1.0 and avg_interval < 10:  # Less than 1 second variance, fast attempts
                violations.append(PolicyViolation(
                    rule_name="automated_attack_pattern",
                    description="Automated attack pattern detected (regular intervals)",
                    severity="warning",
                    current_value=f"variance: {variance:.2f}s",
                    expected_value="variance > 1.0s"
                ))
        
        return violations
    
    def _check_username_enumeration(self, login_attempts: list[dict[str, Any]]) -> list[PolicyViolation]:
        """Check for username enumeration attempts."""
        violations = []
        
        # Look for many different usernames from same IP
        ip_usernames = defaultdict(set)
        for attempt in login_attempts:
            ip = attempt.get("ip_address")
            username = attempt.get("username")
            if ip and username:
                ip_usernames[ip].add(username)
        
        for ip, usernames in ip_usernames.items():
            if len(usernames) > 10:
                violations.append(PolicyViolation(
                    rule_name="username_enumeration_suspected",
                    description=f"Username enumeration from IP {ip}",
                    severity="warning",
                    current_value=f"{len(usernames)} different usernames",
                    expected_value="< 10 different usernames",
                    context={"ip_address": ip}
                ))
        
        return violations
    
    def calculate_lockout_duration(self, login_attempts: list[dict[str, Any]]) -> timedelta:
        """Calculate appropriate lockout duration based on attempts."""
        base_duration = self.config["lockout_duration"]
        
        # Check if progressive lockout is enabled
        progressive_config = self.config.get("progressive_lockout", {})
        if not progressive_config.get("enabled", False):
            return base_duration
        
        # Count previous lockouts
        lockout_count = sum(1 for attempt in login_attempts if attempt.get("caused_lockout", False))
        
        # Find appropriate duration from thresholds
        thresholds = progressive_config.get("thresholds", [])
        for threshold in sorted(thresholds, key=lambda x: x["lockout_count"], reverse=True):
            if lockout_count >= threshold["lockout_count"]:
                return timedelta(minutes=threshold["duration_minutes"])
        
        return base_duration
    
    def get_remaining_attempts(self, login_attempts: list[dict[str, Any]]) -> int:
        """Get number of remaining attempts before lockout."""
        lockout_window = self.config["lockout_duration"]
        window_start = datetime.now(UTC) - lockout_window
        
        recent_failures = len([
            attempt for attempt in login_attempts
            if not attempt.get("success", False) and
            attempt.get("timestamp", datetime.min) > window_start
        ])
        
        max_failures = self.config["max_failed_attempts"]
        remaining = max_failures - recent_failures
        
        return max(0, remaining)
