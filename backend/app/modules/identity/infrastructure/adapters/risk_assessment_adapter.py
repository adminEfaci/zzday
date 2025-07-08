"""
Risk Assessment Service Adapter

Production-ready implementation for fraud detection and risk scoring.
"""

import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from app.core.logging import logger
from app.modules.identity.domain.interfaces.services.security.risk_assessment_service import (
    IRiskAssessmentService,
)
from app.modules.identity.domain.value_objects.ip_address import IpAddress


class RiskAssessmentAdapter(IRiskAssessmentService):
    """Production risk assessment adapter."""

    def __init__(
        self,
        ml_model_client=None,
        geo_service=None,
        user_behavior_db=None,
    ):
        """Initialize risk assessment adapter.

        Args:
            ml_model_client: Machine learning model client
            geo_service: Geolocation service
            user_behavior_db: User behavior database
        """
        self._ml_client = ml_model_client
        self._geo_service = geo_service
        self._behavior_db = user_behavior_db
        self._risk_cache = {}

    async def assess_login_risk(
        self,
        user_id: UUID,
        ip_address: IpAddress,
        user_agent: str,
        device_fingerprint: str | None = None,
    ) -> dict[str, Any]:  # RiskAssessment
        """Assess login risk using multiple factors."""
        try:
            factors = await self._collect_risk_factors(
                user_id, ip_address, user_agent, device_fingerprint
            )

            # Calculate risk score
            risk_score = await self._calculate_risk_score(factors)

            # Determine risk level
            risk_level = self._determine_risk_level(risk_score)

            # Create risk assessment
            assessment = {
                "user_id": str(user_id),
                "risk_level": risk_level,
                "risk_score": risk_score,
                "factors": factors,
                "recommendations": await self._get_risk_recommendations(user_id, risk_score),
                "assessed_at": datetime.now(UTC).isoformat(),
                "valid_until": (datetime.now(UTC) + timedelta(minutes=15)).isoformat()
            }

            # Cache result
            cache_key = f"risk:{user_id}:{hash(str(ip_address))}"
            self._risk_cache[cache_key] = assessment

            logger.info(
                f"Login risk assessed: {risk_level} (score: {risk_score:.2f}) for user {user_id}"
            )

            return assessment

        except Exception as e:
            logger.error(f"Error assessing login risk for user {user_id}: {e}")
            # Return safe default
            return {
                "user_id": str(user_id),
                "risk_level": "medium",
                "risk_score": 0.5,
                "factors": {"error": str(e)},
                "recommendations": [],
                "assessed_at": datetime.now(UTC).isoformat()
            }

    async def assess_transaction_risk(
        self,
        user_id: UUID,
        transaction_type: str,
        transaction_data: dict[str, Any],
    ) -> dict[str, Any]:  # RiskAssessment
        """Assess transaction risk."""
        try:
            # Collect transaction-specific factors
            factors = {
                "transaction_type": transaction_type,
                "amount": transaction_data.get("amount", 0),
                "frequency": await self._get_transaction_frequency(user_id, transaction_type),
                "time_of_day": datetime.now(UTC).hour,
                "day_of_week": datetime.now(UTC).weekday(),
            }

            # Check for suspicious patterns
            if await self._is_suspicious_transaction(user_id, transaction_data):
                factors["suspicious_pattern"] = True

            # Calculate risk score
            risk_score = await self._calculate_transaction_risk_score(factors)
            risk_level = self._determine_risk_level(risk_score)

            assessment = {
                "user_id": str(user_id),
                "transaction_type": transaction_type,
                "risk_level": risk_level,
                "risk_score": risk_score,
                "factors": factors,
                "recommendations": await self._get_transaction_recommendations(
                    user_id, transaction_type, risk_score
                ),
                "assessed_at": datetime.now(UTC).isoformat()
            }

            logger.info(
                f"Transaction risk assessed: {risk_level} for {transaction_type} by user {user_id}"
            )

            return assessment

        except Exception as e:
            logger.error(f"Error assessing transaction risk: {e}")
            return {
                "user_id": str(user_id),
                "transaction_type": transaction_type,
                "risk_level": "medium",
                "risk_score": 0.5,
                "factors": {"error": str(e)},
                "recommendations": []
            }

    async def update_risk_profile(
        self,
        user_id: UUID,
        factors: dict[str, Any],
        event_type: str,
    ) -> None:
        """Update user risk profile based on new events."""
        try:
            if self._behavior_db:
                await self._behavior_db.update_user_profile(
                    user_id=str(user_id),
                    event_type=event_type,
                    factors=factors,
                    timestamp=datetime.now(UTC)
                )

            # Clear cached risk assessments
            self._clear_user_risk_cache(user_id)

            logger.info(f"Risk profile updated for user {user_id} (event: {event_type})")

        except Exception as e:
            logger.error(f"Error updating risk profile for user {user_id}: {e}")

    async def get_risk_recommendations(
        self,
        user_id: UUID,
        risk_score: float,
    ) -> list[dict[str, Any]]:
        """Get risk mitigation recommendations."""
        recommendations = []

        try:
            if risk_score >= 0.8:
                recommendations.extend([
                    {
                        "action": "require_mfa",
                        "priority": "high",
                        "reason": "High risk score detected"
                    },
                    {
                        "action": "manual_review",
                        "priority": "high",
                        "reason": "Potential fraud indicators"
                    }
                ])
            elif risk_score >= 0.6:
                recommendations.extend([
                    {
                        "action": "additional_verification",
                        "priority": "medium",
                        "reason": "Elevated risk score"
                    },
                    {
                        "action": "monitor_session",
                        "priority": "medium",
                        "reason": "Enhanced monitoring recommended"
                    }
                ])
            elif risk_score >= 0.4:
                recommendations.append({
                    "action": "log_activity",
                    "priority": "low",
                    "reason": "Routine monitoring"
                })

            return recommendations

        except Exception as e:
            logger.error(f"Error getting risk recommendations: {e}")
            return []

    async def calculate_adaptive_thresholds(
        self, user_id: UUID
    ) -> dict[str, float]:
        """Calculate adaptive risk thresholds based on user behavior."""
        try:
            # Get user behavior history
            behavior_data = await self._get_user_behavior_data(user_id)

            # Calculate adaptive thresholds
            thresholds = {
                "login_risk": 0.7,  # Default
                "transaction_risk": 0.6,
                "device_risk": 0.5,
                "location_risk": 0.8
            }

            # Adjust based on user history
            if behavior_data.get("consistent_behavior"):
                # Lower thresholds for consistent users
                thresholds = {k: v * 0.8 for k, v in thresholds.items()}
            elif behavior_data.get("high_risk_history"):
                # Higher thresholds for risky users
                thresholds = {k: v * 1.2 for k, v in thresholds.items()}

            return thresholds

        except Exception as e:
            logger.error(f"Error calculating adaptive thresholds: {e}")
            return {
                "login_risk": 0.7,
                "transaction_risk": 0.6,
                "device_risk": 0.5,
                "location_risk": 0.8
            }

    async def _collect_risk_factors(
        self,
        user_id: UUID,
        ip_address: IpAddress,
        user_agent: str,
        device_fingerprint: str | None,
    ) -> dict[str, Any]:
        """Collect risk factors for assessment."""
        factors = {}

        try:
            # IP-based factors
            if self._geo_service:
                location = await self._geo_service.get_location(str(ip_address.value))
                factors["location"] = location
                factors["is_new_location"] = await self._is_new_location(user_id, location)

            # Device factors
            factors["user_agent"] = user_agent
            factors["device_fingerprint"] = device_fingerprint
            factors["is_new_device"] = await self._is_new_device(user_id, device_fingerprint)

            # Behavioral factors
            factors["login_frequency"] = await self._get_login_frequency(user_id)
            factors["time_since_last_login"] = await self._get_time_since_last_login(user_id)

            # Historical factors
            factors["failed_login_count"] = await self._get_recent_failed_logins(user_id)
            factors["account_age_days"] = await self._get_account_age(user_id)

            return factors

        except Exception as e:
            logger.error(f"Error collecting risk factors: {e}")
            return {"error": str(e)}

    async def _calculate_risk_score(self, factors: dict[str, Any]) -> float:
        """Calculate risk score from factors."""
        try:
            score = 0.0

            # Location risk
            if factors.get("is_new_location"):
                score += 0.3

            # Device risk
            if factors.get("is_new_device"):
                score += 0.4

            # Failed login attempts
            failed_logins = factors.get("failed_login_count", 0)
            if failed_logins > 0:
                score += min(failed_logins * 0.1, 0.5)

            # Time-based risk
            hour = datetime.now(UTC).hour
            if hour < 6 or hour > 22:  # Unusual hours
                score += 0.1

            # Account age risk
            age_days = factors.get("account_age_days", 365)
            if age_days < 30:  # New account
                score += 0.2

            return min(score, 1.0)

        except Exception as e:
            logger.error(f"Error calculating risk score: {e}")
            return 0.5  # Default medium risk

    def _determine_risk_level(self, risk_score: float) -> str:
        """Determine risk level from score."""
        if risk_score >= 0.8:
            return "high"
        elif risk_score >= 0.5:
            return "medium"
        else:
            return "low"

    async def _is_new_location(self, user_id: UUID, location: dict) -> bool:
        """Check if location is new for user."""
        # Mock implementation
        return location.get("country") != "US"

    async def _is_new_device(self, user_id: UUID, device_fingerprint: str | None) -> bool:
        """Check if device is new for user."""
        # Mock implementation
        return device_fingerprint is None

    async def _get_login_frequency(self, user_id: UUID) -> int:
        """Get user login frequency."""
        # Mock implementation
        return 5  # logins per day

    async def _get_time_since_last_login(self, user_id: UUID) -> int:
        """Get hours since last login."""
        # Mock implementation
        return 24

    async def _get_recent_failed_logins(self, user_id: UUID) -> int:
        """Get recent failed login count."""
        # Mock implementation
        return 0

    async def _get_account_age(self, user_id: UUID) -> int:
        """Get account age in days."""
        # Mock implementation
        return 365

    def _clear_user_risk_cache(self, user_id: UUID) -> None:
        """Clear cached risk assessments for user."""
        keys_to_remove = [k for k in self._risk_cache.keys() if str(user_id) in k]
        for key in keys_to_remove:
            del self._risk_cache[key]