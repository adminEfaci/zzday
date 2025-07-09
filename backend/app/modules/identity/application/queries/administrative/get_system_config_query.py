"""Get system configuration query implementation."""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.core.cqrs import Query, QueryHandler
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.decorators import (
    rate_limit,
    require_permission,
    validate_request,
)
from app.modules.identity.application.dtos.response import SystemConfigResponse
from app.modules.identity.domain.interfaces.services import (
    IConfigurationPort,
)


@dataclass
class GetSystemConfigQuery(Query[SystemConfigResponse]):
    """Query to get system configuration."""
    
    config_category: str | None = None
    include_sensitive: bool = False
    requester_permissions: list[str] = field(default_factory=list)


class GetSystemConfigQueryHandler(QueryHandler[GetSystemConfigQuery, SystemConfigResponse]):
    """Handler for system configuration queries."""
    
    def __init__(self, uow: UnitOfWork, config_service: IConfigurationPort):
        self.uow = uow
        self.config_service = config_service
    
    @rate_limit(max_calls=100, window_seconds=3600)
    @require_permission("admin.config.read")
    @validate_request
    async def handle(self, query: GetSystemConfigQuery) -> SystemConfigResponse:
        """Handle system configuration query."""
        
        async with self.uow:
            # Get configuration based on category
            if query.config_category == "password":
                config_data = await self.config_service.get_password_policy()
            elif query.config_category == "session":
                config_data = await self.config_service.get_session_config()
            elif query.config_category == "mfa":
                config_data = await self.config_service.get_mfa_config()
            elif query.config_category == "compliance":
                config_data = await self.config_service.get_compliance_settings()
            else:
                # Get all configuration categories
                config_data = {
                    "password_policy": await self.config_service.get_password_policy(),
                    "session_config": await self.config_service.get_session_config(),
                    "mfa_config": await self.config_service.get_mfa_config(),
                    "compliance_settings": await self.config_service.get_compliance_settings()
                }
            
            # Remove sensitive data if not requested
            if not query.include_sensitive and "admin.config.sensitive" not in query.requester_permissions:
                config_data = self._remove_sensitive_config(config_data)
            
            return SystemConfigResponse(
                category=query.config_category or "all",
                configuration=config_data,
                is_complete=query.include_sensitive,
                retrieved_at=datetime.now(UTC)
            )
    
    def _remove_sensitive_config(self, config: dict[str, Any]) -> dict[str, Any]:
        """Remove sensitive configuration values."""
        sensitive_keys = [
            "secret", "password", "key", "token", "private",
            "credential", "certificate", "salt"
        ]
        
        def clean_dict(d: dict[str, Any]) -> dict[str, Any]:
            cleaned = {}
            for key, value in d.items():
                if any(sensitive in key.lower() for sensitive in sensitive_keys):
                    cleaned[key] = "***REDACTED***"
                elif isinstance(value, dict):
                    cleaned[key] = clean_dict(value)
                else:
                    cleaned[key] = value
            return cleaned
        
        return clean_dict(config)