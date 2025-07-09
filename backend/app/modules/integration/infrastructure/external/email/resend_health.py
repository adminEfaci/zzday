"""
Resend Health Check and Monitoring Utilities

This module provides health check functionality for the Resend email service,
including API connectivity, rate limit monitoring, and service diagnostics.
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from app.modules.notification.domain.value_objects import ChannelConfig

from .resend_adapter import ResendEmailAdapter
from .resend_client import ResendAPIError

logger = logging.getLogger(__name__)


@dataclass
class HealthStatus:
    """Health check status result."""

    healthy: bool
    status: str
    timestamp: datetime
    response_time_ms: float | None = None
    details: dict[str, Any] | None = None
    error: str | None = None


class ResendHealthMonitor:
    """Health monitoring for Resend email service."""

    def __init__(self, config: ChannelConfig):
        """Initialize health monitor.

        Args:
            config: Resend configuration
        """
        self.config = config
        self.adapter = ResendEmailAdapter(config)
        self._last_check: datetime | None = None
        self._cached_status: HealthStatus | None = None
        self._check_interval = timedelta(minutes=5)

    async def check_health(self, force_refresh: bool = False) -> HealthStatus:
        """Perform comprehensive health check.

        Args:
            force_refresh: Force fresh check ignoring cache

        Returns:
            Health status result
        """
        now = datetime.utcnow()

        # Use cached result if recent and not forcing refresh
        if (
            not force_refresh
            and self._cached_status
            and self._last_check
            and (now - self._last_check) < self._check_interval
        ):
            return self._cached_status

        start_time = now

        try:
            # Test API connectivity
            client = await self.adapter._get_api_client()

            async with client:
                # Perform health check via API
                health_data = await client.health_check()

                # Check rate limits
                rate_limit_info = {
                    "remaining": getattr(client, "_rate_limit_remaining", None),
                    "reset_time": getattr(client, "_rate_limit_reset", None),
                    "last_request": getattr(client, "_last_request_time", None),
                }

                # Get quota information
                quota_info = await self.adapter.get_quota_info()

            response_time = (datetime.utcnow() - start_time).total_seconds() * 1000

            # Determine overall health
            api_healthy = health_data.get("status") != "unhealthy"
            rate_limit_healthy = self._check_rate_limits(rate_limit_info)

            overall_healthy = api_healthy and rate_limit_healthy

            status = HealthStatus(
                healthy=overall_healthy,
                status="healthy" if overall_healthy else "degraded",
                timestamp=now,
                response_time_ms=response_time,
                details={
                    "api": health_data,
                    "rate_limits": rate_limit_info,
                    "quota": quota_info,
                    "configuration": {
                        "provider": self.config.provider,
                        "from_email": self.config.settings.get("from_email"),
                        "webhook_configured": bool(
                            self.config.settings.get("webhook_secret")
                        ),
                        "analytics_enabled": self.config.settings.get(
                            "enable_analytics", True
                        ),
                        "rate_limit_per_second": self.config.settings.get(
                            "rate_limit_per_second", 10
                        ),
                    },
                },
            )

        except ResendAPIError as e:
            status = HealthStatus(
                healthy=False,
                status="unhealthy",
                timestamp=now,
                error=f"API Error: {e.message}",
                details={
                    "error_code": e.error_code,
                    "status_code": e.status_code,
                    "response": e.response_data,
                },
            )

        except Exception as e:
            status = HealthStatus(
                healthy=False,
                status="unhealthy",
                timestamp=now,
                error=f"Health check failed: {e!s}",
            )

        # Cache the result
        self._cached_status = status
        self._last_check = now

        return status

    def _check_rate_limits(self, rate_limit_info: dict[str, Any]) -> bool:
        """Check if rate limits are healthy.

        Args:
            rate_limit_info: Rate limit information

        Returns:
            True if rate limits are healthy
        """
        remaining = rate_limit_info.get("remaining")
        if remaining is None:
            return True  # No rate limit info available

        # Consider unhealthy if less than 10% remaining
        configured_limit = self.config.settings.get("rate_limit_per_second", 10)
        threshold = max(1, configured_limit * 0.1)

        return remaining >= threshold

    async def test_email_sending(
        self, test_email: str, dry_run: bool = True
    ) -> dict[str, Any]:
        """Test email sending capability.

        Args:
            test_email: Email address for testing
            dry_run: If True, only validate without sending

        Returns:
            Test result information
        """
        try:
            if dry_run:
                # Just validate the email address
                is_valid = await self.adapter.validate_address(test_email)
                return {
                    "test_type": "validation",
                    "success": is_valid,
                    "email": test_email,
                    "message": "Email validation successful"
                    if is_valid
                    else "Email validation failed",
                }
            # Actually send a test email (implement based on your notification structure)
            return {
                "test_type": "send",
                "success": False,
                "message": "Test sending not implemented - requires Notification object",
            }

        except Exception as e:
            return {
                "test_type": "validation" if dry_run else "send",
                "success": False,
                "error": str(e),
            }

    async def get_service_metrics(self) -> dict[str, Any]:
        """Get comprehensive service metrics.

        Returns:
            Service metrics and statistics
        """
        try:
            # Get analytics for the last 24 hours
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=1)

            analytics = await self.adapter.get_delivery_analytics(
                start_date=start_date, end_date=end_date
            )

            # Get suppression list info
            try:
                suppression_info = await self.adapter.manage_suppression_list("list")
                suppression_count = suppression_info.total_count
            except Exception:
                suppression_count = None

            # Get health status
            health = await self.check_health()

            return {
                "health": {
                    "status": health.status,
                    "healthy": health.healthy,
                    "last_check": health.timestamp.isoformat(),
                    "response_time_ms": health.response_time_ms,
                },
                "analytics": analytics,
                "suppression_list": {"total_suppressed": suppression_count},
                "configuration": {
                    "provider": "resend",
                    "features": health.details.get("quota", {}).get("features", [])
                    if health.details
                    else [],
                },
            }

        except Exception as e:
            logger.exception(f"Failed to get service metrics: {e}")
            return {"error": str(e), "timestamp": datetime.utcnow().isoformat()}


class ResendServiceDiagnostics:
    """Advanced diagnostics for Resend service issues."""

    def __init__(self, config: ChannelConfig):
        """Initialize diagnostics.

        Args:
            config: Resend configuration
        """
        self.config = config
        self.monitor = ResendHealthMonitor(config)

    async def run_full_diagnostics(self) -> dict[str, Any]:
        """Run comprehensive diagnostics.

        Returns:
            Complete diagnostic report
        """
        report = {
            "timestamp": datetime.utcnow().isoformat(),
            "service": "resend",
            "tests": {},
        }

        # Test 1: Basic connectivity
        try:
            health = await self.monitor.check_health(force_refresh=True)
            report["tests"]["connectivity"] = {
                "status": "pass" if health.healthy else "fail",
                "response_time_ms": health.response_time_ms,
                "details": health.details,
                "error": health.error,
            }
        except Exception as e:
            report["tests"]["connectivity"] = {"status": "fail", "error": str(e)}

        # Test 2: Configuration validation
        report["tests"]["configuration"] = self._validate_configuration()

        # Test 3: Domain verification (if applicable)
        report["tests"]["domain"] = await self._check_domain_verification()

        # Test 4: Webhook configuration
        report["tests"]["webhook"] = self._validate_webhook_config()

        # Test 5: Rate limit status
        report["tests"]["rate_limits"] = await self._check_rate_limit_status()

        # Overall assessment
        all_tests = report["tests"]
        failed_tests = [
            name for name, result in all_tests.items() if result.get("status") == "fail"
        ]

        report["summary"] = {
            "overall_status": "healthy" if not failed_tests else "unhealthy",
            "total_tests": len(all_tests),
            "passed_tests": len(all_tests) - len(failed_tests),
            "failed_tests": failed_tests,
        }

        return report

    def _validate_configuration(self) -> dict[str, Any]:
        """Validate Resend configuration."""
        issues = []

        # Check required settings
        required_settings = ["from_email", "from_name"]
        for setting in required_settings:
            if not self.config.settings.get(setting):
                issues.append(f"Missing required setting: {setting}")

        # Check API key
        if not self.config.credentials.get("api_key"):
            issues.append("Missing API key")
        elif not self.config.credentials["api_key"].startswith("re_"):
            issues.append("API key format appears invalid")

        # Check email format
        from_email = self.config.settings.get("from_email", "")
        if from_email and "@" not in from_email:
            issues.append("Invalid from_email format")

        # Check webhook secret if webhooks enabled
        webhook_secret = self.config.settings.get("webhook_secret")
        if webhook_secret and len(webhook_secret) < 16:
            issues.append("Webhook secret should be at least 16 characters")

        return {"status": "pass" if not issues else "fail", "issues": issues}

    async def _check_domain_verification(self) -> dict[str, Any]:
        """Check domain verification status."""
        try:
            from_email = self.config.settings.get("from_email", "")
            if not from_email:
                return {"status": "skip", "reason": "No from_email configured"}

            domain = from_email.split("@")[1]

            # This would require implementing domain verification check
            # For now, return placeholder
            return {
                "status": "skip",
                "domain": domain,
                "reason": "Domain verification check not implemented",
            }

        except Exception as e:
            return {"status": "fail", "error": str(e)}

    def _validate_webhook_config(self) -> dict[str, Any]:
        """Validate webhook configuration."""
        webhook_secret = self.config.settings.get("webhook_secret")

        if not webhook_secret:
            return {"status": "info", "message": "Webhooks not configured (optional)"}

        issues = []

        if len(webhook_secret) < 16:
            issues.append("Webhook secret too short (minimum 16 characters)")

        # Additional webhook validation could be added here

        return {"status": "pass" if not issues else "fail", "issues": issues}

    async def _check_rate_limit_status(self) -> dict[str, Any]:
        """Check current rate limit status."""
        try:
            health = await self.monitor.check_health()

            if not health.details:
                return {
                    "status": "fail",
                    "error": "No rate limit information available",
                }

            rate_limits = health.details.get("rate_limits", {})
            remaining = rate_limits.get("remaining")

            if remaining is None:
                return {
                    "status": "info",
                    "message": "Rate limit information not available",
                }

            configured_limit = self.config.settings.get("rate_limit_per_second", 10)
            utilization = ((configured_limit - remaining) / configured_limit) * 100

            status = "pass"
            if utilization > 90:
                status = "warn"
            elif utilization > 99:
                status = "fail"

            return {
                "status": status,
                "remaining": remaining,
                "configured_limit": configured_limit,
                "utilization_percent": round(utilization, 2),
            }

        except Exception as e:
            return {"status": "fail", "error": str(e)}
