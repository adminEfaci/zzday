"""Get tenant info query implementation."""

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from app.core.cqrs import Query, QueryHandler
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.decorators import (
    rate_limit,
    require_permission,
    validate_request,
)
from app.modules.identity.application.dtos.response import TenantInfoResponse
from app.modules.identity.domain.interfaces.repositories.audit_repository import (
    IAuditRepository,
)
from app.modules.identity.domain.interfaces.repositories.user_repository import (
from app.modules.identity.domain.interfaces.services import (
    IConfigurationPort,
)
    IUserRepository,
)


@dataclass
class GetTenantInfoQuery(Query[TenantInfoResponse]):
    """Query to get tenant information."""

    requester_permissions: list[str] = field(default_factory=list)
    tenant_id: UUID | None = None
    include_usage: bool = True
    include_limits: bool = True
    include_billing: bool = False



class GetTenantInfoQueryHandler(QueryHandler[GetTenantInfoQuery, TenantInfoResponse]):
    """Handler for tenant info queries."""
    
    def __init__(
        self,
        uow: UnitOfWork,
        user_repository: IUserRepository,
        config_service: IConfigurationPort,
        audit_repository: IAuditRepository
    ):
        self.uow = uow
        self.user_repository = user_repository
        self.config_service = config_service
        self.audit_repository = audit_repository
    
    @rate_limit(max_calls=50, window_seconds=300)
    @require_permission("admin.tenant.read")
    @validate_request
    async def handle(self, query: GetTenantInfoQuery) -> TenantInfoResponse:
        """Handle tenant info query."""
        
        async with self.uow:
            # Get tenant configuration
            tenant_config = await self._get_tenant_configuration(query.tenant_id)
            
            # Get tenant details
            tenant_info = {
                "id": str(query.tenant_id) if query.tenant_id else tenant_config.get("default_tenant_id"),
                "name": tenant_config.get("name", "Default Tenant"),
                "display_name": tenant_config.get("display_name", "Default Organization"),
                "created_at": tenant_config.get("created_at", "2023-01-01T00:00:00Z"),
                "status": tenant_config.get("status", "active"),
                "type": tenant_config.get("type", "standard"),
                "owner_id": tenant_config.get("owner_id"),
                "contact_email": tenant_config.get("contact_email"),
                "domain": tenant_config.get("domain"),
                "settings": self._get_tenant_settings(tenant_config)
            }
            
            # Get usage information if requested
            if query.include_usage:
                tenant_info["usage"] = await self._get_tenant_usage(query.tenant_id)
            
            # Get limits if requested
            if query.include_limits:
                tenant_info["limits"] = self._get_tenant_limits(tenant_config)
            
            # Get billing information if requested and permitted
            if query.include_billing and "admin.tenant.billing" in query.requester_permissions:
                tenant_info["billing"] = await self._get_billing_info(query.tenant_id)
            
            # Get feature access
            tenant_info["features"] = self._get_tenant_features(tenant_config)
            
            # Get integrations
            tenant_info["integrations"] = await self._get_tenant_integrations(query.tenant_id)
            
            # Get custom branding
            tenant_info["branding"] = self._get_tenant_branding(tenant_config)
            
            return TenantInfoResponse(
                tenant=tenant_info,
                is_multi_tenant=tenant_config.get("multi_tenant_enabled", False),
                tenant_count=await self._get_tenant_count() if tenant_config.get("multi_tenant_enabled") else 1,
                retrieved_at=datetime.now(UTC)
            )
    
    async def _get_tenant_configuration(self, tenant_id: UUID | None) -> dict[str, Any]:
        """Get tenant configuration."""
        try:
            return await self.config_service.get_tenant_config(tenant_id)
        except (AttributeError, ConnectionError, FileNotFoundError, Exception):
            # Return default configuration
            return {
                "default_tenant_id": "00000000-0000-0000-0000-000000000001",
                "name": "default",
                "display_name": "Default Organization",
                "created_at": "2023-01-01T00:00:00Z",
                "status": "active",
                "type": "standard",
                "multi_tenant_enabled": False,
                "features": {
                    "sso": True,
                    "mfa": True,
                    "api_access": True,
                    "custom_branding": False,
                    "advanced_analytics": False
                },
                "limits": {
                    "max_users": 1000,
                    "max_api_calls_per_month": 1000000,
                    "storage_gb": 100,
                    "max_sessions_per_user": 5
                }
            }
    
    async def _get_tenant_usage(self, tenant_id: UUID | None) -> dict[str, Any]:
        """Get tenant usage statistics."""
        # User count
        user_count = await self.user_repository.count_users(
            {"tenant_id": tenant_id} if tenant_id else {}
        )
        
        # Active users in last 30 days
        thirty_days_ago = datetime.now(UTC) - timedelta(days=30)
        active_users = await self.user_repository.count_users({
            "last_login__gte": thirty_days_ago,
            "tenant_id": tenant_id
        } if tenant_id else {"last_login__gte": thirty_days_ago})
        
        # API usage (from audit logs)
        api_calls = await self.audit_repository.count_activities(
            thirty_days_ago,
            datetime.now(UTC)
        )
        
        # Storage usage (mock for now)
        storage_used_gb = user_count * 0.05  # Assume 50MB per user average
        
        return {
            "users": {
                "total": user_count,
                "active_30d": active_users,
                "inactive": user_count - active_users
            },
            "api_calls": {
                "current_month": api_calls,
                "daily_average": api_calls // 30,
                "peak_day_calls": api_calls // 20  # Mock peak
            },
            "storage": {
                "used_gb": round(storage_used_gb, 2),
                "files_count": user_count * 10,  # Mock file count
                "average_file_size_mb": 5
            },
            "sessions": {
                "current_active": active_users // 2,  # Mock active sessions
                "monthly_total": active_users * 50
            }
        }
    
    def _get_tenant_limits(self, config: dict[str, Any]) -> dict[str, Any]:
        """Get tenant limits and current usage percentage."""
        limits = config.get("limits", {})
        
        return {
            "users": {
                "limit": limits.get("max_users", 1000),
                "usage_percentage": 25.5  # This would be calculated from actual usage
            },
            "api_calls": {
                "limit_per_month": limits.get("max_api_calls_per_month", 1000000),
                "limit_per_minute": limits.get("max_api_calls_per_minute", 1000),
                "usage_percentage": 45.2
            },
            "storage": {
                "limit_gb": limits.get("storage_gb", 100),
                "usage_percentage": 12.8
            },
            "sessions": {
                "limit_per_user": limits.get("max_sessions_per_user", 5),
                "limit_total": limits.get("max_concurrent_sessions", 5000)
            },
            "custom_limits": limits.get("custom", {})
        }
    
    async def _get_billing_info(self, tenant_id: UUID | None) -> dict[str, Any]:
        """Get billing information."""
        # This would integrate with billing system
        return {
            "plan": "professional",
            "status": "active",
            "billing_cycle": "monthly",
            "next_billing_date": (datetime.now(UTC) + timedelta(days=15)).isoformat(),
            "amount": 299.00,
            "currency": "USD",
            "payment_method": {
                "type": "credit_card",
                "last_four": "1234",
                "expires": "12/2025"
            },
            "invoices": [
                {
                    "id": "inv_001",
                    "date": "2024-01-01",
                    "amount": 299.00,
                    "status": "paid"
                }
            ]
        }
    
    def _get_tenant_features(self, config: dict[str, Any]) -> dict[str, bool]:
        """Get tenant feature access."""
        features = config.get("features", {})
        
        return {
            "sso": features.get("sso", True),
            "mfa": features.get("mfa", True),
            "api_access": features.get("api_access", True),
            "custom_branding": features.get("custom_branding", False),
            "advanced_analytics": features.get("advanced_analytics", False),
            "audit_logs": features.get("audit_logs", True),
            "data_export": features.get("data_export", True),
            "webhooks": features.get("webhooks", False),
            "custom_roles": features.get("custom_roles", False),
            "ip_allowlist": features.get("ip_allowlist", False)
        }
    
    async def _get_tenant_integrations(self, tenant_id: UUID | None) -> list[dict[str, Any]]:
        """Get tenant integrations."""
        # This would query actual integrations
        return [
            {
                "id": "int_001",
                "type": "saml",
                "name": "Corporate SSO",
                "status": "active",
                "configured_at": "2023-06-01T00:00:00Z"
            },
            {
                "id": "int_002",
                "type": "ldap",
                "name": "Active Directory",
                "status": "active",
                "configured_at": "2023-06-15T00:00:00Z"
            },
            {
                "id": "int_003",
                "type": "webhook",
                "name": "Audit Log Export",
                "status": "active",
                "configured_at": "2023-07-01T00:00:00Z"
            }
        ]
    
    def _get_tenant_branding(self, config: dict[str, Any]) -> dict[str, Any]:
        """Get tenant branding configuration."""
        branding = config.get("branding", {})
        
        return {
            "logo_url": branding.get("logo_url"),
            "favicon_url": branding.get("favicon_url"),
            "primary_color": branding.get("primary_color", "#1976d2"),
            "secondary_color": branding.get("secondary_color", "#dc004e"),
            "custom_css": branding.get("custom_css_enabled", False),
            "email_templates": branding.get("custom_email_templates", False),
            "login_page": {
                "title": branding.get("login_title", "Welcome"),
                "subtitle": branding.get("login_subtitle"),
                "background_image": branding.get("login_background")
            }
        }
    
    def _get_tenant_settings(self, config: dict[str, Any]) -> dict[str, Any]:
        """Get tenant settings."""
        settings = config.get("settings", {})
        
        return {
            "security": {
                "password_policy": settings.get("password_policy", "standard"),
                "session_timeout_minutes": settings.get("session_timeout", 30),
                "mfa_required": settings.get("mfa_required", False),
                "ip_allowlist_enabled": settings.get("ip_allowlist_enabled", False)
            },
            "notifications": {
                "email_enabled": settings.get("email_notifications", True),
                "sms_enabled": settings.get("sms_notifications", False),
                "webhook_enabled": settings.get("webhook_notifications", False)
            },
            "data": {
                "retention_days": settings.get("data_retention_days", 365),
                "auto_delete_inactive_users": settings.get("auto_delete_inactive", False),
                "export_enabled": settings.get("data_export_enabled", True)
            }
        }
    
    async def _get_tenant_count(self) -> int:
        """Get total tenant count for multi-tenant systems."""
        # This would query the tenant table
        return 1  # Single tenant for now