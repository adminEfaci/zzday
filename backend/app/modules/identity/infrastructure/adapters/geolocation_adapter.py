"""
Geolocation Service Adapter

Production-ready implementation for IP-based geolocation and location analysis.
"""

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from app.core.logging import logger
from app.modules.identity.domain.interfaces.services.security.geolocation_service import (
    IGeolocationService,
)
from app.modules.identity.domain.value_objects.ip_address import IpAddress


class GeolocationAdapter(IGeolocationService):
    """Production geolocation service adapter."""

    def __init__(
        self,
        ip_info_client=None,
        maxmind_client=None,
        google_maps_client=None,
        user_location_db=None,
    ):
<<<<<<< HEAD
        """Initialize geolocation adapter.

        Args:
            ip_info_client: IPInfo.io client
            maxmind_client: MaxMind GeoIP2 client
            google_maps_client: Google Maps API client
            user_location_db: User location database
        """
=======
        """Initialize geolocation adapter."""
>>>>>>> analysis/coordination
        self._ip_info = ip_info_client
        self._maxmind = maxmind_client
        self._google_maps = google_maps_client
        self._user_db = user_location_db
        self._location_cache = {}
        self._risk_cache = {}

    async def get_location_info(self, ip_address: IpAddress) -> dict[str, Any]:
        """Get location information for IP address."""
        try:
            ip_str = str(ip_address.value)
            
<<<<<<< HEAD
            # Check cache first
=======
>>>>>>> analysis/coordination
            if ip_str in self._location_cache:
                cached_info = self._location_cache[ip_str]
                if self._is_cache_valid(cached_info):
                    return cached_info["data"]

<<<<<<< HEAD
            # Get location data from multiple sources
            location_data = await self._get_location_from_sources(ip_str)
            
            # Enrich with additional data
            enriched_data = await self._enrich_location_data(location_data)
            
            # Create LocationInfo-like dict
=======
            location_data = await self._get_location_from_sources(ip_str)
            enriched_data = await self._enrich_location_data(location_data)
            
>>>>>>> analysis/coordination
            location_info = {
                "ip_address": ip_str,
                "country": enriched_data.get("country", "Unknown"),
                "country_code": enriched_data.get("country_code", "XX"),
                "region": enriched_data.get("region", "Unknown"),
                "city": enriched_data.get("city", "Unknown"),
                "latitude": enriched_data.get("latitude", 0.0),
                "longitude": enriched_data.get("longitude", 0.0),
                "timezone": enriched_data.get("timezone", "UTC"),
                "isp": enriched_data.get("isp", "Unknown"),
                "organization": enriched_data.get("organization", "Unknown"),
                "connection_type": enriched_data.get("connection_type", "Unknown"),
                "is_proxy": enriched_data.get("is_proxy", False),
                "is_tor": enriched_data.get("is_tor", False),
                "is_vpn": enriched_data.get("is_vpn", False),
                "is_hosting": enriched_data.get("is_hosting", False),
                "threat_types": enriched_data.get("threat_types", []),
                "accuracy_radius": enriched_data.get("accuracy_radius", 1000),
                "asn": enriched_data.get("asn", "Unknown"),
                "domain": enriched_data.get("domain", "Unknown"),
                "retrieved_at": datetime.now(UTC).isoformat(),
            }

<<<<<<< HEAD
            # Cache the result
=======
>>>>>>> analysis/coordination
            self._location_cache[ip_str] = {
                "data": location_info,
                "timestamp": datetime.now(UTC),
            }

            logger.info(f"Location info retrieved for IP {ip_str}: {location_info['city']}, {location_info['country']}")
            return location_info

        except Exception as e:
            logger.error(f"Error getting location info for IP {ip_address}: {e}")
<<<<<<< HEAD
            # Return safe default
=======
>>>>>>> analysis/coordination
            return {
                "ip_address": str(ip_address.value),
                "country": "Unknown",
                "country_code": "XX",
                "region": "Unknown",
                "city": "Unknown",
                "latitude": 0.0,
                "longitude": 0.0,
                "timezone": "UTC",
                "isp": "Unknown",
                "organization": "Unknown",
                "connection_type": "Unknown",
                "is_proxy": False,
                "is_tor": False,
                "is_vpn": False,
                "is_hosting": False,
                "threat_types": [],
                "accuracy_radius": 1000,
                "asn": "Unknown",
                "domain": "Unknown",
                "retrieved_at": datetime.now(UTC).isoformat(),
                "error": str(e),
            }

    async def is_suspicious_location(
        self, user_id: UUID, ip_address: IpAddress
    ) -> dict[str, Any]:
        """Check if location is suspicious for user."""
        try:
            ip_str = str(ip_address.value)
            cache_key = f"risk:{user_id}:{ip_str}"
            
<<<<<<< HEAD
            # Check cache first
=======
>>>>>>> analysis/coordination
            if cache_key in self._risk_cache:
                cached_risk = self._risk_cache[cache_key]
                if self._is_cache_valid(cached_risk):
                    return cached_risk["data"]

<<<<<<< HEAD
            # Get current location info
            location_info = await self.get_location_info(ip_address)
            
            # Get user's location history
            user_locations = await self._get_user_location_history(user_id)
            
            # Analyze risk factors
            risk_factors = await self._analyze_location_risk(
                user_id, location_info, user_locations
            )
            
            # Calculate risk score
            risk_score = self._calculate_location_risk_score(risk_factors)
            
            # Determine risk level
            risk_level = self._determine_risk_level(risk_score)
            
            # Create LocationRiskAssessment-like dict
=======
            location_info = await self.get_location_info(ip_address)
            user_locations = await self._get_user_location_history(user_id)
            risk_factors = await self._analyze_location_risk(user_id, location_info, user_locations)
            risk_score = self._calculate_location_risk_score(risk_factors)
            risk_level = self._determine_risk_level(risk_score)
            
>>>>>>> analysis/coordination
            risk_assessment = {
                "user_id": str(user_id),
                "ip_address": ip_str,
                "location_info": location_info,
                "risk_level": risk_level,
                "risk_score": risk_score,
                "risk_factors": risk_factors,
                "is_suspicious": risk_score >= 0.6,
                "recommendations": self._get_risk_recommendations(risk_level),
                "assessed_at": datetime.now(UTC).isoformat(),
                "valid_until": (datetime.now(UTC) + timedelta(minutes=30)).isoformat(),
            }

<<<<<<< HEAD
            # Cache the result
=======
>>>>>>> analysis/coordination
            self._risk_cache[cache_key] = {
                "data": risk_assessment,
                "timestamp": datetime.now(UTC),
            }

            logger.info(
                f"Location risk assessed for user {user_id} from {location_info['city']}, {location_info['country']}: {risk_level} ({risk_score:.2f})"
            )
            return risk_assessment

        except Exception as e:
            logger.error(f"Error assessing location risk for user {user_id}: {e}")
<<<<<<< HEAD
            # Return safe default
=======
>>>>>>> analysis/coordination
            return {
                "user_id": str(user_id),
                "ip_address": str(ip_address.value),
                "location_info": {},
                "risk_level": "medium",
                "risk_score": 0.5,
                "risk_factors": {"error": str(e)},
                "is_suspicious": True,
                "recommendations": ["require_mfa"],
                "assessed_at": datetime.now(UTC).isoformat(),
            }

    async def update_known_locations(
        self, user_id: UUID, location_info: dict[str, Any]
    ) -> None:
        """Update user's known locations."""
        try:
            if self._user_db:
                location_record = {
                    "user_id": str(user_id),
                    "ip_address": location_info.get("ip_address"),
                    "country": location_info.get("country"),
                    "country_code": location_info.get("country_code"),
                    "region": location_info.get("region"),
                    "city": location_info.get("city"),
                    "latitude": location_info.get("latitude"),
                    "longitude": location_info.get("longitude"),
                    "first_seen": datetime.now(UTC),
                    "last_seen": datetime.now(UTC),
                    "visit_count": 1,
                    "is_trusted": await self._is_trusted_location(user_id, location_info),
                }
                
                await self._user_db.update_user_location(user_id, location_record)

<<<<<<< HEAD
            # Clear risk cache for this user
            self._clear_user_risk_cache(user_id)

=======
            self._clear_user_risk_cache(user_id)
>>>>>>> analysis/coordination
            logger.info(f"Updated known locations for user {user_id}")

        except Exception as e:
            logger.error(f"Error updating known locations for user {user_id}: {e}")

    async def _get_location_from_sources(self, ip_address: str) -> dict[str, Any]:
        """Get location data from multiple sources."""
        location_data = {}
<<<<<<< HEAD
        
        # Try multiple sources in parallel
=======
>>>>>>> analysis/coordination
        tasks = []
        
        if self._ip_info:
            tasks.append(self._get_ipinfo_data(ip_address))
        
        if self._maxmind:
            tasks.append(self._get_maxmind_data(ip_address))
        
<<<<<<< HEAD
        # If no external clients, use mock data
=======
>>>>>>> analysis/coordination
        if not tasks:
            tasks.append(self._get_mock_location_data(ip_address))

        try:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
<<<<<<< HEAD
            # Merge results from all sources
=======
>>>>>>> analysis/coordination
            for result in results:
                if isinstance(result, dict):
                    location_data.update(result)
                    
        except Exception as e:
            logger.error(f"Error getting location data from sources: {e}")
            
        return location_data

    async def _get_ipinfo_data(self, ip_address: str) -> dict[str, Any]:
        """Get data from IPInfo.io."""
        try:
<<<<<<< HEAD
            # Mock implementation - replace with actual IPInfo.io API call
=======
>>>>>>> analysis/coordination
            return {
                "country": "United States",
                "country_code": "US",
                "region": "California",
                "city": "San Francisco",
                "latitude": 37.7749,
                "longitude": -122.4194,
                "timezone": "America/Los_Angeles",
                "isp": "Cloudflare",
                "organization": "Cloudflare Inc.",
                "asn": "AS13335",
                "domain": "cloudflare.com",
            }
        except Exception as e:
            logger.error(f"Error getting IPInfo data: {e}")
            return {}

    async def _get_maxmind_data(self, ip_address: str) -> dict[str, Any]:
        """Get data from MaxMind GeoIP2."""
        try:
<<<<<<< HEAD
            # Mock implementation - replace with actual MaxMind API call
=======
>>>>>>> analysis/coordination
            return {
                "accuracy_radius": 50,
                "connection_type": "corporate",
                "is_proxy": False,
                "is_hosting": False,
                "threat_types": [],
            }
        except Exception as e:
            logger.error(f"Error getting MaxMind data: {e}")
            return {}

    async def _get_mock_location_data(self, ip_address: str) -> dict[str, Any]:
        """Get mock location data for testing."""
<<<<<<< HEAD
        # Simple mock based on IP patterns
=======
>>>>>>> analysis/coordination
        if "192.168" in ip_address or "10." in ip_address:
            return {
                "country": "Unknown",
                "country_code": "XX",
                "region": "Private Network",
                "city": "Local",
                "latitude": 0.0,
                "longitude": 0.0,
                "timezone": "UTC",
                "isp": "Private",
                "organization": "Local Network",
                "connection_type": "private",
                "is_proxy": False,
                "is_vpn": False,
                "is_hosting": False,
                "threat_types": [],
            }
        else:
            return {
                "country": "United States",
                "country_code": "US",
                "region": "California",
                "city": "San Francisco",
                "latitude": 37.7749,
                "longitude": -122.4194,
                "timezone": "America/Los_Angeles",
                "isp": "Example ISP",
                "organization": "Example Organization",
                "connection_type": "residential",
                "is_proxy": False,
                "is_vpn": False,
                "is_hosting": False,
                "threat_types": [],
            }

    async def _enrich_location_data(self, location_data: dict[str, Any]) -> dict[str, Any]:
        """Enrich location data with additional analysis."""
        enriched = location_data.copy()
        
<<<<<<< HEAD
        # Add threat analysis
=======
>>>>>>> analysis/coordination
        if location_data.get("isp") and "vpn" in location_data["isp"].lower():
            enriched["is_vpn"] = True
            enriched["threat_types"] = enriched.get("threat_types", []) + ["vpn"]
        
<<<<<<< HEAD
        # Add proxy detection
=======
>>>>>>> analysis/coordination
        if location_data.get("organization") and "proxy" in location_data["organization"].lower():
            enriched["is_proxy"] = True
            enriched["threat_types"] = enriched.get("threat_types", []) + ["proxy"]
        
<<<<<<< HEAD
        # Add hosting detection
=======
>>>>>>> analysis/coordination
        if location_data.get("connection_type") == "hosting":
            enriched["is_hosting"] = True
            enriched["threat_types"] = enriched.get("threat_types", []) + ["hosting"]
        
        return enriched

    async def _get_user_location_history(self, user_id: UUID) -> list[dict[str, Any]]:
        """Get user's location history."""
        try:
            if self._user_db:
                return await self._user_db.get_user_location_history(user_id)
            
<<<<<<< HEAD
            # Mock implementation
=======
>>>>>>> analysis/coordination
            return [
                {
                    "country": "United States",
                    "region": "California",
                    "city": "San Francisco",
                    "visit_count": 50,
                    "is_trusted": True,
                    "last_seen": datetime.now(UTC) - timedelta(days=1),
                }
            ]
        except Exception as e:
            logger.error(f"Error getting user location history: {e}")
            return []

    async def _analyze_location_risk(
        self, user_id: UUID, location_info: dict[str, Any], user_locations: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """Analyze location risk factors."""
        factors = {}
        
<<<<<<< HEAD
        # Check if it's a new location
=======
>>>>>>> analysis/coordination
        is_new_location = not any(
            loc["country"] == location_info.get("country") and 
            loc["city"] == location_info.get("city")
            for loc in user_locations
        )
        factors["is_new_location"] = is_new_location
        
<<<<<<< HEAD
        # Check if it's a new country
=======
>>>>>>> analysis/coordination
        is_new_country = not any(
            loc["country"] == location_info.get("country")
            for loc in user_locations
        )
        factors["is_new_country"] = is_new_country
        
<<<<<<< HEAD
        # Check threat indicators
=======
>>>>>>> analysis/coordination
        factors["is_proxy"] = location_info.get("is_proxy", False)
        factors["is_vpn"] = location_info.get("is_vpn", False)
        factors["is_tor"] = location_info.get("is_tor", False)
        factors["is_hosting"] = location_info.get("is_hosting", False)
        
<<<<<<< HEAD
        # Check time zone difference
        factors["timezone_risk"] = await self._assess_timezone_risk(user_id, location_info)
        
        # Check travel feasibility
        factors["travel_feasibility"] = await self._assess_travel_feasibility(user_id, location_info)
        
        # Check location reputation
=======
        factors["timezone_risk"] = await self._assess_timezone_risk(user_id, location_info)
        factors["travel_feasibility"] = await self._assess_travel_feasibility(user_id, location_info)
>>>>>>> analysis/coordination
        factors["location_reputation"] = await self._assess_location_reputation(location_info)
        
        return factors

    def _calculate_location_risk_score(self, factors: dict[str, Any]) -> float:
        """Calculate location risk score."""
        score = 0.0
        
<<<<<<< HEAD
        # New location risk
        if factors.get("is_new_location"):
            score += 0.3
        
        # New country risk
        if factors.get("is_new_country"):
            score += 0.4
        
        # Proxy/VPN risk
=======
        if factors.get("is_new_location"):
            score += 0.3
        
        if factors.get("is_new_country"):
            score += 0.4
        
>>>>>>> analysis/coordination
        if factors.get("is_proxy"):
            score += 0.5
        if factors.get("is_vpn"):
            score += 0.3
        if factors.get("is_tor"):
            score += 0.8
        if factors.get("is_hosting"):
            score += 0.6
        
<<<<<<< HEAD
        # Time zone risk
        timezone_risk = factors.get("timezone_risk", 0.0)
        score += timezone_risk * 0.2
        
        # Travel feasibility
        travel_risk = factors.get("travel_feasibility", 0.0)
        score += travel_risk * 0.3
        
        # Location reputation
=======
        timezone_risk = factors.get("timezone_risk", 0.0)
        score += timezone_risk * 0.2
        
        travel_risk = factors.get("travel_feasibility", 0.0)
        score += travel_risk * 0.3
        
>>>>>>> analysis/coordination
        reputation_risk = factors.get("location_reputation", 0.0)
        score += reputation_risk * 0.2
        
        return min(score, 1.0)

    def _determine_risk_level(self, risk_score: float) -> str:
        """Determine risk level from score."""
        if risk_score >= 0.8:
            return "high"
        elif risk_score >= 0.6:
            return "medium"
        else:
            return "low"

    def _get_risk_recommendations(self, risk_level: str) -> list[str]:
        """Get risk mitigation recommendations."""
<<<<<<< HEAD
        recommendations = []
        
        if risk_level == "high":
            recommendations.extend([
                "require_mfa",
                "manual_review",
                "additional_verification",
                "restrict_sensitive_actions",
            ])
        elif risk_level == "medium":
            recommendations.extend([
                "require_mfa",
                "enhanced_monitoring",
                "verify_identity",
            ])
        else:
            recommendations.append("normal_monitoring")
        
        return recommendations

    async def _assess_timezone_risk(self, user_id: UUID, location_info: dict[str, Any]) -> float:
        """Assess timezone-based risk."""
        # Mock implementation
        user_timezone = "America/Los_Angeles"  # Would get from user profile
        location_timezone = location_info.get("timezone", "UTC")
        
        # Simple heuristic - different timezone adds risk
=======
        if risk_level == "high":
            return ["require_mfa", "manual_review", "additional_verification", "restrict_sensitive_actions"]
        elif risk_level == "medium":
            return ["require_mfa", "enhanced_monitoring", "verify_identity"]
        else:
            return ["normal_monitoring"]

    async def _assess_timezone_risk(self, user_id: UUID, location_info: dict[str, Any]) -> float:
        """Assess timezone-based risk."""
        user_timezone = "America/Los_Angeles"
        location_timezone = location_info.get("timezone", "UTC")
        
>>>>>>> analysis/coordination
        if user_timezone != location_timezone:
            return 0.3
        return 0.0

    async def _assess_travel_feasibility(self, user_id: UUID, location_info: dict[str, Any]) -> float:
        """Assess if travel to location is feasible."""
<<<<<<< HEAD
        # Mock implementation - check if user could have traveled to this location
        # based on their last known location and time elapsed
        return 0.0  # Would implement proper travel time calculation

    async def _assess_location_reputation(self, location_info: dict[str, Any]) -> float:
        """Assess location reputation."""
        # Mock implementation - check if location is known for fraud
=======
        return 0.0

    async def _assess_location_reputation(self, location_info: dict[str, Any]) -> float:
        """Assess location reputation."""
>>>>>>> analysis/coordination
        threat_types = location_info.get("threat_types", [])
        
        if "malware" in threat_types or "botnet" in threat_types:
            return 0.8
        elif "fraud" in threat_types:
            return 0.6
        elif "spam" in threat_types:
            return 0.3
        
        return 0.0

    async def _is_trusted_location(self, user_id: UUID, location_info: dict[str, Any]) -> bool:
        """Check if location should be trusted."""
<<<<<<< HEAD
        # Mock implementation - location becomes trusted after multiple visits
=======
>>>>>>> analysis/coordination
        return location_info.get("visit_count", 0) >= 5

    def _is_cache_valid(self, cached_item: dict[str, Any]) -> bool:
        """Check if cached item is still valid."""
        cached_time = cached_item.get("timestamp")
        if not cached_time:
            return False
        
<<<<<<< HEAD
        # Cache valid for 1 hour
=======
>>>>>>> analysis/coordination
        return datetime.now(UTC) - cached_time < timedelta(hours=1)

    def _clear_user_risk_cache(self, user_id: UUID) -> None:
        """Clear cached risk assessments for user."""
        keys_to_remove = [k for k in self._risk_cache.keys() if str(user_id) in k]
        for key in keys_to_remove:
            del self._risk_cache[key]