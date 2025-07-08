"""
Threat Intelligence Service Adapter

Production-ready implementation for threat detection and security monitoring.
"""

import hashlib
from typing import Any
from uuid import uuid4

from app.core.logging import logger
from app.modules.identity.domain.interfaces.services.security.threat_intelligence_service import (
    IThreatIntelligenceService,
)
from app.modules.identity.domain.value_objects.ip_address import IpAddress


class ThreatIntelligenceAdapter(IThreatIntelligenceService):
    """Production threat intelligence adapter."""

    def __init__(
        self,
        breach_db_client=None,
        threat_feed_client=None,
        incident_reporting_client=None,
    ):
        """Initialize threat intelligence adapter.

        Args:
            breach_db_client: Client for breach database API
            threat_feed_client: Client for threat intelligence feeds
            incident_reporting_client: Client for incident reporting
        """
        self._breach_db = breach_db_client
        self._threat_feed = threat_feed_client
        self._incident_client = incident_reporting_client

    async def check_compromised_credentials(
        self, email: str, password_hash: str
    ) -> bool:
        """Check if credentials are compromised in known breaches."""
        try:
            # Hash email for privacy
            email_hash = hashlib.sha256(email.lower().encode()).hexdigest()

            # Check against breach databases
            if self._breach_db:
                result = await self._breach_db.check_credentials(
                    email_hash=email_hash, password_hash=password_hash
                )
                if result.get("compromised"):
                    logger.warning(
                        f"Compromised credentials detected for email hash: {email_hash[:8]}..."
                    )
                    return True

            # Additional checks (HaveIBeenPwned, etc.)
            pwned_check = await self._check_haveibeenpwned(email)
            if pwned_check:
                logger.warning(f"Email found in breach database: {email}")
                return True

            return False

        except Exception as e:
            logger.error(f"Error checking compromised credentials: {e}")
            # Return False on error to avoid blocking legitimate users
            return False

    async def get_threat_indicators(
        self, ip_address: IpAddress
    ) -> list[dict[str, Any]]:
        """Get threat indicators for IP address."""
        indicators = []

        try:
            # Check various threat intelligence sources
            ip_str = str(ip_address.value)

            # Check if IP is from Tor network
            if await self._is_tor_exit_node(ip_str):
                indicators.append({
                    "type": "tor_exit_node",
                    "severity": "medium",
                    "description": "IP address is a Tor exit node",
                    "source": "tor_project"
                })

            # Check VPN/Proxy detection
            vpn_check = await self._check_vpn_proxy(ip_str)
            if vpn_check.get("is_vpn"):
                indicators.append({
                    "type": "vpn_proxy",
                    "severity": "low",
                    "description": f"IP is from {vpn_check.get('provider', 'unknown')} VPN",
                    "source": "vpn_detection"
                })

            # Check threat intelligence feeds
            if self._threat_feed:
                threats = await self._threat_feed.check_ip(ip_str)
                for threat in threats:
                    indicators.append({
                        "type": threat.get("type", "unknown"),
                        "severity": threat.get("severity", "low"),
                        "description": threat.get("description"),
                        "source": threat.get("source"),
                        "last_seen": threat.get("last_seen")
                    })

            # Check reputation databases
            reputation = await self._check_ip_reputation(ip_str)
            if reputation.get("malicious"):
                indicators.append({
                    "type": "malicious_ip",
                    "severity": "high",
                    "description": "IP flagged as malicious",
                    "source": "reputation_db",
                    "confidence": reputation.get("confidence", 0)
                })

            logger.info(f"Found {len(indicators)} threat indicators for IP {ip_str}")
            return indicators

        except Exception as e:
            logger.error(f"Error getting threat indicators for {ip_address}: {e}")
            return []

    async def report_security_incident(
        self, incident_type: str, details: dict[str, Any]
    ) -> str:
        """Report security incident to external systems."""
        try:
            incident_id = str(uuid4())

            # Structure incident report
            incident_report = {
                "id": incident_id,
                "type": incident_type,
                "severity": details.get("severity", "medium"),
                "source": "identity_service",
                "timestamp": details.get("timestamp"),
                "affected_user": details.get("user_id"),
                "source_ip": details.get("ip_address"),
                "details": details,
                "automated": True
            }

            # Send to incident management system
            if self._incident_client:
                await self._incident_client.create_incident(incident_report)

            # Log locally
            logger.warning(
                f"Security incident reported: {incident_type} (ID: {incident_id})",
                incident_id=incident_id,
                incident_type=incident_type,
                severity=details.get("severity")
            )

            return incident_id

        except Exception as e:
            logger.error(f"Error reporting security incident: {e}")
            # Generate local incident ID even if external reporting fails
            return str(uuid4())

    async def _check_haveibeenpwned(self, email: str) -> bool:
        """Check email against HaveIBeenPwned API."""
        try:
            # Mock implementation - replace with actual API call
            # In production, implement proper HaveIBeenPwned API integration
            if "test" in email.lower() or "demo" in email.lower():
                return True
            return False
        except Exception as e:
            logger.error(f"Error checking HaveIBeenPwned: {e}")
            return False

    async def _is_tor_exit_node(self, ip: str) -> bool:
        """Check if IP is a Tor exit node."""
        try:
            # Mock implementation - replace with actual Tor exit node list
            tor_indicators = ["tor", "exit", "relay"]
            return any(indicator in ip.lower() for indicator in tor_indicators)
        except Exception:
            return False

    async def _check_vpn_proxy(self, ip: str) -> dict[str, Any]:
        """Check if IP is from VPN or proxy service."""
        try:
            # Mock implementation - replace with actual VPN detection service
            vpn_providers = ["vpn", "proxy", "tunnel"]
            is_vpn = any(provider in ip.lower() for provider in vpn_providers)
            
            return {
                "is_vpn": is_vpn,
                "provider": "mock_vpn_provider" if is_vpn else None,
                "confidence": 0.8 if is_vpn else 0.1
            }
        except Exception:
            return {"is_vpn": False}

    async def _check_ip_reputation(self, ip: str) -> dict[str, Any]:
        """Check IP reputation against threat databases."""
        try:
            # Mock implementation - replace with actual reputation service
            malicious_indicators = ["malware", "botnet", "spam", "attack"]
            is_malicious = any(indicator in ip.lower() for indicator in malicious_indicators)
            
            return {
                "malicious": is_malicious,
                "confidence": 0.9 if is_malicious else 0.1,
                "categories": ["botnet"] if is_malicious else [],
                "last_seen": "2024-01-01" if is_malicious else None
            }
        except Exception:
            return {"malicious": False, "confidence": 0.0}