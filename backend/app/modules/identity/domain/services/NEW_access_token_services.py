"""
Access Token Service

Domain service for complex token refresh strategies and token family management.
"""

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from ..aggregates.access_token import (
    AccessToken,
    RefreshStrategy,
    TokenStatus,
)


class AccessTokenService:
    """Service for access token operations and refresh strategies."""
    
    def determine_refresh_strategy(
        self,
        user_id: UUID,
        client_type: str,
        security_level: str = "standard"
    ) -> RefreshStrategy:
        """Determine appropriate refresh strategy based on context."""
        # High-security contexts use family tracking
        if security_level in ["high", "critical"]:
            return RefreshStrategy.FAMILY
        
        # Mobile apps typically use rotation
        if client_type in ["mobile_app", "native_app"]:
            return RefreshStrategy.ROTATE
        
        # SPAs might use reuse for better UX
        if client_type == "spa":
            return RefreshStrategy.REUSE
        
        # Default to rotation
        return RefreshStrategy.ROTATE
    
    def validate_refresh_request(
        self,
        token: AccessToken,
        raw_refresh_token: str,
        client_security_context: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Validate refresh token request and detect security issues."""
        validation_result = {
            "valid": True,
            "security_score": 1.0,
            "warnings": [],
            "errors": [],
            "recommendations": []
        }
        
        # Basic token validation
        if not token.verify_refresh_token(raw_refresh_token):
            validation_result["valid"] = False
            validation_result["errors"].append("Invalid refresh token")
            return validation_result
        
        if not token.can_refresh():
            validation_result["valid"] = False
            validation_result["errors"].append("Token cannot be refreshed")
            return validation_result
        
        # Security analysis
        security_issues = self._analyze_refresh_security(token, client_security_context or {})
        validation_result.update(security_issues)
        
        return validation_result
    
    def _analyze_refresh_security(
        self,
        token: AccessToken,
        security_context: dict[str, Any]
    ) -> dict[str, Any]:
        """Analyze security aspects of refresh request."""
        analysis = {
            "security_score": 1.0,
            "warnings": [],
            "recommendations": []
        }
        
        # Check refresh frequency
        if token.last_refreshed_at:
            time_since_refresh = datetime.now(UTC) - token.last_refreshed_at
            if time_since_refresh < timedelta(minutes=1):
                analysis["security_score"] -= 0.3
                analysis["warnings"].append("Rapid refresh detected")
        
        # Check refresh count
        if token.refresh_count > token.max_refresh_count * 0.8:
            analysis["security_score"] -= 0.2
            analysis["warnings"].append("High refresh count")
            analysis["recommendations"].append("Consider token re-issuance")
        
        # Check family status
        if token.refresh_strategy == RefreshStrategy.FAMILY and token.token_family:
            if not token.token_family.is_active():
                analysis["security_score"] = 0.0
                analysis["warnings"].append("Token family compromised")
        
        # Check client context changes
        client_ip = security_context.get("ip_address")
        client_fingerprint = security_context.get("client_fingerprint")
        
        if client_ip and hasattr(token, 'last_client_ip'):
            if token.last_client_ip != client_ip:
                analysis["security_score"] -= 0.1
                analysis["warnings"].append("IP address changed")
        
        # Check suspicious activity score
        if token.suspicious_activity_score > 0.5:
            analysis["security_score"] -= token.suspicious_activity_score * 0.5
            analysis["warnings"].append("Suspicious activity detected")
        
        return analysis
    
    def execute_refresh_with_security_checks(
        self,
        token: AccessToken,
        raw_refresh_token: str,
        new_ttl: int = 3600,
        refresh_ttl: int | None = None,
        security_context: dict[str, Any] | None = None
    ) -> tuple[AccessToken, str, str | None]:
        """Execute token refresh with comprehensive security checks."""
        # Validate refresh request
        validation = self.validate_refresh_request(token, raw_refresh_token, security_context)
        
        if not validation["valid"]:
            raise ValueError(f"Refresh validation failed: {', '.join(validation['errors'])}")
        
        # Check if additional security measures needed
        if validation["security_score"] < 0.5:
            # Could trigger additional verification, logging, etc.
            self._handle_suspicious_refresh(token, validation["warnings"])
        
        # Execute refresh based on strategy
        new_token, access_token, refresh_token = token.refresh(new_ttl, refresh_ttl)
        
        # Update security context
        if security_context:
            self._update_token_security_context(new_token, security_context)
        
        return new_token, access_token, refresh_token
    
    def _handle_suspicious_refresh(self, token: AccessToken, warnings: list[str]) -> None:
        """Handle suspicious refresh patterns."""
        # Increase suspicious activity score
        token.suspicious_activity_score += 0.1
        
        # Log security event (would be handled by application layer)
    
    def _update_token_security_context(
        self,
        token: AccessToken,
        security_context: dict[str, Any]
    ) -> None:
        """Update token with security context information."""
        if "ip_address" in security_context:
            token.metadata["last_client_ip"] = security_context["ip_address"]
        
        if "client_fingerprint" in security_context:
            token.metadata["client_fingerprint"] = security_context["client_fingerprint"]
        
        if "user_agent" in security_context:
            token.metadata["user_agent"] = security_context["user_agent"]
    
    def manage_token_family(
        self,
        family_id: UUID,
        operation: str,
        **kwargs
    ) -> dict[str, Any]:
        """Manage token family operations."""
        result = {"success": False, "operation": operation}
        
        if operation == "revoke_family":
            reason = kwargs.get("reason", "security_incident")
            # Would revoke all tokens in family
            result.update({
                "success": True,
                "revoked_tokens": kwargs.get("token_count", 0),
                "reason": reason
            })
        
        elif operation == "family_health_check":
            # Analyze family health
            health_score = self._calculate_family_health(kwargs.get("family_data", {}))
            result.update({
                "success": True,
                "health_score": health_score,
                "recommendations": self._get_family_recommendations(health_score)
            })
        
        return result
    
    def _calculate_family_health(self, family_data: dict[str, Any]) -> float:
        """Calculate token family health score."""
        base_score = 1.0
        
        # Check refresh patterns
        refresh_velocity = family_data.get("refreshes_per_hour", 0)
        if refresh_velocity > 10:
            base_score -= 0.3
        
        # Check geographic distribution
        unique_locations = family_data.get("unique_locations", 0)
        if unique_locations > 5:
            base_score -= 0.2
        
        # Check member count vs time
        member_count = family_data.get("member_count", 0)
        family_age_hours = family_data.get("family_age_hours", 1)
        
        if member_count / max(family_age_hours, 1) > 2:  # More than 2 tokens per hour
            base_score -= 0.2
        
        return max(0.0, base_score)
    
    def _get_family_recommendations(self, health_score: float) -> list[str]:
        """Get recommendations based on family health."""
        recommendations = []
        
        if health_score < 0.3:
            recommendations.append("Consider revoking token family")
            recommendations.append("Investigate potential security breach")
        
        elif health_score < 0.6:
            recommendations.append("Monitor family closely")
            recommendations.append("Reduce refresh frequency if possible")
        
        elif health_score < 0.8:
            recommendations.append("Review refresh patterns")
        
        return recommendations
    
    def optimize_token_rotation_schedule(
        self,
        tokens: list[AccessToken],
        optimization_strategy: str = "balanced"
    ) -> dict[str, Any]:
        """Optimize token rotation schedules to reduce load and improve security."""
        optimization_result = {
            "strategy": optimization_strategy,
            "tokens_analyzed": len(tokens),
            "schedule_changes": 0,
            "estimated_load_reduction": 0.0
        }
        
        if optimization_strategy == "balanced":
            # Spread rotations evenly across time
            self._balance_rotation_schedule(tokens, optimization_result)
        
        elif optimization_strategy == "security_focused":
            # Prioritize security with more frequent rotations for high-risk tokens
            self._security_focused_schedule(tokens, optimization_result)
        
        elif optimization_strategy == "performance_focused":
            # Minimize rotations while maintaining security
            self._performance_focused_schedule(tokens, optimization_result)
        
        return optimization_result
    
    def _balance_rotation_schedule(
        self,
        tokens: list[AccessToken],
        result: dict[str, Any]
    ) -> None:
        """Balance rotation schedule across time windows."""
        if not tokens:
            return
        
        # Distribute rotations across 24-hour period
        time_slots = 24  # hourly slots
        tokens_per_slot = len(tokens) // time_slots
        
        for i, token in enumerate(tokens):
            if token.refresh_strategy == RefreshStrategy.ROTATE:
                # Calculate offset for this token
                slot = i % time_slots
                offset_hours = slot
                
                # Update rotation schedule
                new_rotation_time = token.expires_at - timedelta(
                    minutes=10 + (offset_hours * 60)
                )
                
                if new_rotation_time != token.next_rotation_at:
                    token.next_rotation_at = new_rotation_time
                    result["schedule_changes"] += 1
        
        # Estimate load reduction
        if result["schedule_changes"] > 0:
            result["estimated_load_reduction"] = min(0.3, result["schedule_changes"] / len(tokens))
    
    def _security_focused_schedule(
        self,
        tokens: list[AccessToken],
        result: dict[str, Any]
    ) -> None:
        """Apply security-focused rotation schedule."""
        for token in tokens:
            if token.suspicious_activity_score > 0.3:
                # More frequent rotation for suspicious tokens
                new_rotation_time = token.expires_at - timedelta(minutes=30)
                if token.next_rotation_at != new_rotation_time:
                    token.next_rotation_at = new_rotation_time
                    result["schedule_changes"] += 1
    
    def _performance_focused_schedule(
        self,
        tokens: list[AccessToken],
        result: dict[str, Any]
    ) -> None:
        """Apply performance-focused rotation schedule."""
        for token in tokens:
            if token.device_trust_score > 0.8 and token.suspicious_activity_score < 0.1:
                # Less frequent rotation for trusted tokens
                new_rotation_time = token.expires_at - timedelta(minutes=5)
                if token.next_rotation_at != new_rotation_time:
                    token.next_rotation_at = new_rotation_time
                    result["schedule_changes"] += 1
    
    def generate_token_analytics(
        self,
        tokens: list[AccessToken],
        time_window_days: int = 30
    ) -> dict[str, Any]:
        """Generate comprehensive token usage analytics."""
        analytics = {
            "summary": {
                "total_tokens": len(tokens),
                "active_tokens": 0,
                "total_refreshes": 0,
                "average_refresh_count": 0.0
            },
            "strategy_distribution": {},
            "security_metrics": {
                "suspicious_tokens": 0,
                "compromised_families": 0,
                "high_velocity_refreshes": 0
            },
            "usage_patterns": {
                "peak_refresh_hours": [],
                "geographic_distribution": {},
                "client_type_distribution": {}
            }
        }
        
        if not tokens:
            return analytics
        
        # Basic metrics
        active_count = 0
        total_refreshes = 0
        strategy_counts = {}
        
        for token in tokens:
            if token.status == TokenStatus.ACTIVE:
                active_count += 1
            
            total_refreshes += token.refresh_count
            
            strategy = token.refresh_strategy.value
            strategy_counts[strategy] = strategy_counts.get(strategy, 0) + 1
            
            # Security metrics
            if token.suspicious_activity_score > 0.5:
                analytics["security_metrics"]["suspicious_tokens"] += 1
            
            if token.refresh_count > 20:  # High velocity threshold
                analytics["security_metrics"]["high_velocity_refreshes"] += 1
        
        analytics["summary"]["active_tokens"] = active_count
        analytics["summary"]["total_refreshes"] = total_refreshes
        analytics["summary"]["average_refresh_count"] = total_refreshes / len(tokens) if tokens else 0
        analytics["strategy_distribution"] = strategy_counts
        
        return analytics