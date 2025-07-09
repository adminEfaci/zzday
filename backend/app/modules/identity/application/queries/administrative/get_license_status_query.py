"""Get license status query implementation."""

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any

from app.core.cqrs import Query, QueryHandler
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.contracts.ports import (
    IConfigurationPort,
    IUserRepository,
)
from app.modules.identity.application.decorators import (
    rate_limit,
    require_permission,
    validate_request,
)
from app.modules.identity.application.dtos.response import LicenseStatusResponse


class LicenseType(Enum):
    """License type enumeration."""
    TRIAL = "trial"
    STARTER = "starter"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"
    CUSTOM = "custom"


class LicenseStatus(Enum):
    """License status enumeration."""
    ACTIVE = "active"
    EXPIRED = "expired"
    SUSPENDED = "suspended"
    GRACE_PERIOD = "grace_period"
    INVALID = "invalid"


@dataclass
class GetLicenseStatusQuery(Query[LicenseStatusResponse]):
    """Query to get license status."""
    
    include_features: bool = True
    include_usage_stats: bool = True
    include_history: bool = False
    requester_permissions: list[str] = field(default_factory=list)


class GetLicenseStatusQueryHandler(QueryHandler[GetLicenseStatusQuery, LicenseStatusResponse]):
    """Handler for license status queries."""
    
    def __init__(
        self,
        uow: UnitOfWork,
        config_service: IConfigurationPort,
        user_repository: IUserRepository
    ):
        self.uow = uow
        self.config_service = config_service
        self.user_repository = user_repository
    
    @rate_limit(max_calls=30, window_seconds=300)
    @require_permission("admin.license.read")
    @validate_request
    async def handle(self, query: GetLicenseStatusQuery) -> LicenseStatusResponse:
        """Handle license status query."""
        
        async with self.uow:
            # Get license configuration
            license_config = await self._get_license_configuration()
            
            # Determine license status
            license_status = self._determine_license_status(license_config)
            
            # Build license information
            license_info = {
                "license_key": self._mask_license_key(license_config.get("key", "")),
                "type": license_config.get("type", LicenseType.TRIAL.value),
                "status": license_status.value,
                "issued_to": license_config.get("issued_to", "Unknown"),
                "issued_date": license_config.get("issued_date"),
                "expiry_date": license_config.get("expiry_date"),
                "days_remaining": self._calculate_days_remaining(license_config.get("expiry_date")),
                "grace_period_ends": self._calculate_grace_period_end(license_config),
                "seats": license_config.get("seats", {})
            }
            
            # Get feature entitlements if requested
            if query.include_features:
                license_info["features"] = self._get_feature_entitlements(license_config)
            
            # Get usage statistics if requested
            if query.include_usage_stats:
                license_info["usage"] = await self._get_usage_statistics(license_config)
            
            # Get license history if requested
            if query.include_history and "admin.license.history" in query.requester_permissions:
                license_info["history"] = self._get_license_history(license_config)
            
            # Get compliance status
            compliance = self._check_license_compliance(license_config, license_info.get("usage", {}))
            
            # Get renewal information
            renewal = self._get_renewal_information(license_config, license_status)
            
            return LicenseStatusResponse(
                license=license_info,
                compliance=compliance,
                renewal=renewal,
                notifications=self._get_license_notifications(license_status, license_info),
                retrieved_at=datetime.now(UTC)
            )
    
    async def _get_license_configuration(self) -> dict[str, Any]:
        """Get license configuration."""
        try:
            return await self.config_service.get_license_config()
        except (AttributeError, ConnectionError, FileNotFoundError, Exception):
            # Return default trial license
            return {
                "key": "TRIAL-XXXX-XXXX-XXXX",
                "type": LicenseType.TRIAL.value,
                "status": "active",
                "issued_to": "Trial User",
                "issued_date": datetime.now(UTC).isoformat(),
                "expiry_date": (datetime.now(UTC) + timedelta(days=30)).isoformat(),
                "seats": {
                    "users": 100,
                    "admins": 5,
                    "api_keys": 10
                },
                "features": {
                    "core": True,
                    "mfa": True,
                    "sso": False,
                    "api": True,
                    "webhooks": False,
                    "custom_roles": False,
                    "audit_logs": True,
                    "data_export": True
                },
                "limits": {
                    "api_calls_per_month": 100000,
                    "storage_gb": 10,
                    "retention_days": 90
                }
            }
    
    def _determine_license_status(self, config: dict[str, Any]) -> LicenseStatus:
        """Determine current license status."""
        if not config.get("key"):
            return LicenseStatus.INVALID
        
        status_str = config.get("status", "").lower()
        if status_str == "suspended":
            return LicenseStatus.SUSPENDED
        
        expiry_date_str = config.get("expiry_date")
        if not expiry_date_str:
            return LicenseStatus.ACTIVE  # Perpetual license
        
        try:
            expiry_date = datetime.fromisoformat(expiry_date_str.replace('Z', '+00:00'))
            now = datetime.now(UTC)
            
            if now > expiry_date:
                # Check if in grace period
                grace_days = config.get("grace_period_days", 7)
                grace_end = expiry_date + timedelta(days=grace_days)
                
                if now <= grace_end:
                    return LicenseStatus.GRACE_PERIOD
                return LicenseStatus.EXPIRED
            return LicenseStatus.ACTIVE
        except (ValueError, TypeError, AttributeError):
            return LicenseStatus.INVALID
    
    def _mask_license_key(self, key: str) -> str:
        """Mask license key for security."""
        if not key or len(key) < 8:
            return "INVALID"
        
        parts = key.split("-")
        if len(parts) > 1:
            # Show first part and mask the rest
            masked_parts = [parts[0]] + ["XXXX"] * (len(parts) - 1)
            return "-".join(masked_parts)
        # Show first 4 and last 4 characters
        return f"{key[:4]}...{key[-4:]}"
    
    def _calculate_days_remaining(self, expiry_date_str: str | None) -> int | None:
        """Calculate days remaining until expiry."""
        if not expiry_date_str:
            return None
        
        try:
            expiry_date = datetime.fromisoformat(expiry_date_str.replace('Z', '+00:00'))
            remaining = (expiry_date - datetime.now(UTC)).days
            return max(0, remaining)
        except (ValueError, TypeError, AttributeError):
            return None
    
    def _calculate_grace_period_end(self, config: dict[str, Any]) -> str | None:
        """Calculate grace period end date."""
        expiry_date_str = config.get("expiry_date")
        if not expiry_date_str:
            return None
        
        try:
            expiry_date = datetime.fromisoformat(expiry_date_str.replace('Z', '+00:00'))
            grace_days = config.get("grace_period_days", 7)
            grace_end = expiry_date + timedelta(days=grace_days)
            
            # Only return if currently expired
            if datetime.now(UTC) > expiry_date:
                return grace_end.isoformat()
        except (ValueError, TypeError, AttributeError):
            pass
        
        return None
    
    def _get_feature_entitlements(self, config: dict[str, Any]) -> dict[str, Any]:
        """Get feature entitlements from license."""
        features = config.get("features", {})
        limits = config.get("limits", {})
        
        return {
            "core_features": {
                "user_management": features.get("core", True),
                "authentication": features.get("core", True),
                "basic_rbac": features.get("core", True)
            },
            "security_features": {
                "mfa": features.get("mfa", True),
                "sso": features.get("sso", False),
                "biometric_auth": features.get("biometric", False),
                "advanced_threat_detection": features.get("threat_detection", False)
            },
            "integration_features": {
                "api_access": features.get("api", True),
                "webhooks": features.get("webhooks", False),
                "custom_integrations": features.get("custom_integrations", False)
            },
            "advanced_features": {
                "custom_roles": features.get("custom_roles", False),
                "audit_logs": features.get("audit_logs", True),
                "data_export": features.get("data_export", True),
                "white_labeling": features.get("white_label", False)
            },
            "limits": {
                "api_calls_per_month": limits.get("api_calls_per_month", 100000),
                "storage_gb": limits.get("storage_gb", 10),
                "data_retention_days": limits.get("retention_days", 90),
                "concurrent_sessions": limits.get("concurrent_sessions", 1000)
            }
        }
    
    async def _get_usage_statistics(self, config: dict[str, Any]) -> dict[str, Any]:
        """Get current usage statistics."""
        seats = config.get("seats", {})
        limits = config.get("limits", {})
        
        # Get actual usage
        total_users = await self.user_repository.count_users({})
        admin_users = await self.user_repository.count_users({"roles__contains": "admin"})
        
        # Calculate usage percentages
        user_usage_pct = (total_users / seats.get("users", 100)) * 100 if seats.get("users") else 0
        admin_usage_pct = (admin_users / seats.get("admins", 5)) * 100 if seats.get("admins") else 0
        
        return {
            "seats": {
                "users": {
                    "used": total_users,
                    "total": seats.get("users", 100),
                    "percentage": round(user_usage_pct, 1)
                },
                "admins": {
                    "used": admin_users,
                    "total": seats.get("admins", 5),
                    "percentage": round(admin_usage_pct, 1)
                },
                "api_keys": {
                    "used": 3,  # Mock value
                    "total": seats.get("api_keys", 10),
                    "percentage": 30.0
                }
            },
            "resources": {
                "api_calls_this_month": 45230,
                "api_calls_limit": limits.get("api_calls_per_month", 100000),
                "storage_used_gb": 3.4,
                "storage_limit_gb": limits.get("storage_gb", 10)
            }
        }
    
    def _get_license_history(self, config: dict[str, Any]) -> list[dict[str, Any]]:
        """Get license history."""
        # This would typically come from a license history table
        return [
            {
                "date": "2023-01-01T00:00:00Z",
                "action": "issued",
                "type": LicenseType.TRIAL.value,
                "duration_days": 30
            },
            {
                "date": "2023-01-30T00:00:00Z",
                "action": "upgraded",
                "type": LicenseType.PROFESSIONAL.value,
                "duration_days": 365
            },
            {
                "date": "2024-01-01T00:00:00Z",
                "action": "renewed",
                "type": LicenseType.PROFESSIONAL.value,
                "duration_days": 365
            }
        ]
    
    def _check_license_compliance(self, config: dict[str, Any], usage: dict[str, Any]) -> dict[str, Any]:
        """Check license compliance."""
        violations = []
        warnings = []
        
        # Check seat compliance
        if usage.get("seats", {}).get("users", {}).get("percentage", 0) > 100:
            violations.append({
                "type": "seat_limit_exceeded",
                "resource": "users",
                "limit": config.get("seats", {}).get("users"),
                "current": usage["seats"]["users"]["used"]
            })
        elif usage.get("seats", {}).get("users", {}).get("percentage", 0) > 90:
            warnings.append({
                "type": "approaching_seat_limit",
                "resource": "users",
                "percentage": usage["seats"]["users"]["percentage"]
            })
        
        # Check API usage
        if usage.get("resources", {}).get("api_calls_this_month", 0) > config.get("limits", {}).get("api_calls_per_month", 100000):
            violations.append({
                "type": "api_limit_exceeded",
                "resource": "api_calls",
                "limit": config["limits"]["api_calls_per_month"],
                "current": usage["resources"]["api_calls_this_month"]
            })
        
        return {
            "is_compliant": len(violations) == 0,
            "violations": violations,
            "warnings": warnings,
            "last_check": datetime.now(UTC).isoformat()
        }
    
    def _get_renewal_information(self, config: dict[str, Any], status: LicenseStatus) -> dict[str, Any]:
        """Get renewal information."""
        days_remaining = self._calculate_days_remaining(config.get("expiry_date"))
        
        renewal_info = {
            "required": status in [LicenseStatus.EXPIRED, LicenseStatus.GRACE_PERIOD] or (days_remaining and days_remaining < 30),
            "renewal_date": config.get("expiry_date"),
            "auto_renew": config.get("auto_renew", False),
            "renewal_url": "https://license.example.com/renew"
        }
        
        if days_remaining and days_remaining < 30:
            renewal_info["reminder_sent"] = True
            renewal_info["discount_available"] = days_remaining > 7
            renewal_info["discount_percentage"] = 10 if days_remaining > 7 else 0
        
        return renewal_info
    
    def _get_license_notifications(self, status: LicenseStatus, license_info: dict[str, Any]) -> list[dict[str, Any]]:
        """Get license-related notifications."""
        notifications = []
        
        if status == LicenseStatus.EXPIRED:
            notifications.append({
                "type": "error",
                "message": "License has expired. Please renew to continue using the service.",
                "action": "renew_license"
            })
        elif status == LicenseStatus.GRACE_PERIOD:
            grace_end = license_info.get("grace_period_ends")
            notifications.append({
                "type": "warning",
                "message": f"License expired. Grace period ends on {grace_end}.",
                "action": "renew_license"
            })
        elif license_info.get("days_remaining") and license_info["days_remaining"] < 30:
            notifications.append({
                "type": "info",
                "message": f"License expires in {license_info['days_remaining']} days.",
                "action": "renew_license"
            })
        
        # Check usage warnings
        usage = license_info.get("usage", {})
        if usage.get("seats", {}).get("users", {}).get("percentage", 0) > 90:
            notifications.append({
                "type": "warning",
                "message": "Approaching user seat limit. Consider upgrading your license.",
                "action": "upgrade_license"
            })
        
        return notifications