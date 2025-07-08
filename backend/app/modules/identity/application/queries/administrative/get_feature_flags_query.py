"""Get feature flags query implementation."""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from app.core.cqrs import Query, QueryHandler
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.contracts.ports import IConfigurationPort
from app.modules.identity.application.decorators import (
    rate_limit,
    require_permission,
    validate_request,
)
from app.modules.identity.application.dtos.response import FeatureFlagsResponse


@dataclass
class GetFeatureFlagsQuery(Query[FeatureFlagsResponse]):
    """Query to get feature flags."""
    
    feature_names: list[str] | None = None
    user_id: UUID | None = None
    include_experiments: bool = True
    include_rollout_status: bool = True
    requester_permissions: list[str] = field(default_factory=list)


class GetFeatureFlagsQueryHandler(QueryHandler[GetFeatureFlagsQuery, FeatureFlagsResponse]):
    """Handler for feature flags queries."""
    
    def __init__(self, uow: UnitOfWork, config_service: IConfigurationPort):
        self.uow = uow
        self.config_service = config_service
    
    @rate_limit(max_calls=100, window_seconds=60)
    @require_permission("admin.features.read")
    @validate_request
    async def handle(self, query: GetFeatureFlagsQuery) -> FeatureFlagsResponse:
        """Handle feature flags query."""
        
        async with self.uow:
            # Get all feature flags
            all_features = await self._get_all_feature_flags()
            
            # Filter if specific features requested
            if query.feature_names:
                all_features = {
                    k: v for k, v in all_features.items()
                    if k in query.feature_names
                }
            
            # Process each feature flag
            feature_data = {}
            for feature_name, config in all_features.items():
                # Check if feature is enabled for specific user
                is_enabled = await self.config_service.is_feature_enabled(
                    feature_name,
                    query.user_id
                )
                
                feature_info = {
                    "name": feature_name,
                    "enabled": is_enabled,
                    "description": config.get("description", ""),
                    "type": config.get("type", "boolean"),
                    "default_value": config.get("default", False),
                    "created_at": config.get("created_at"),
                    "updated_at": config.get("updated_at")
                }
                
                # Add rollout status if requested
                if query.include_rollout_status:
                    feature_info["rollout"] = {
                        "percentage": config.get("rollout_percentage", 100),
                        "strategy": config.get("rollout_strategy", "all"),
                        "target_groups": config.get("target_groups", []),
                        "excluded_groups": config.get("excluded_groups", [])
                    }
                
                # Add experiment data if requested
                if query.include_experiments and config.get("experiment"):
                    feature_info["experiment"] = {
                        "id": config["experiment"].get("id"),
                        "name": config["experiment"].get("name"),
                        "variants": config["experiment"].get("variants", []),
                        "control_group": config["experiment"].get("control_group"),
                        "metrics": config["experiment"].get("metrics", [])
                    }
                
                feature_data[feature_name] = feature_info
            
            # Get feature categories
            categories = self._categorize_features(feature_data)
            
            # Calculate statistics
            statistics = {
                "total_features": len(feature_data),
                "enabled_count": sum(1 for f in feature_data.values() if f["enabled"]),
                "in_experiment": sum(1 for f in feature_data.values() if f.get("experiment")),
                "partial_rollout": sum(
                    1 for f in feature_data.values()
                    if f.get("rollout", {}).get("percentage", 100) < 100
                )
            }
            
            return FeatureFlagsResponse(
                features=feature_data,
                categories=categories,
                statistics=statistics,
                user_context={
                    "user_id": str(query.user_id) if query.user_id else None,
                    "evaluation_context": await self._get_user_context(query.user_id)
                },
                retrieved_at=datetime.now(UTC)
            )
    
    async def _get_all_feature_flags(self) -> dict[str, Any]:
        """Get all feature flags from configuration."""
        # This would typically come from a feature flag service
        # For now, return example flags
        return {
            "new_dashboard": {
                "description": "New admin dashboard UI",
                "type": "boolean",
                "default": False,
                "rollout_percentage": 50,
                "rollout_strategy": "percentage",
                "created_at": "2024-01-01T00:00:00Z",
                "updated_at": "2024-01-15T00:00:00Z"
            },
            "enhanced_mfa": {
                "description": "Enhanced multi-factor authentication",
                "type": "boolean",
                "default": True,
                "rollout_percentage": 100,
                "target_groups": ["beta_users", "admins"],
                "created_at": "2023-12-01T00:00:00Z"
            },
            "api_v2": {
                "description": "Version 2 of the API",
                "type": "boolean",
                "default": False,
                "rollout_percentage": 25,
                "rollout_strategy": "gradual",
                "experiment": {
                    "id": "api_v2_experiment",
                    "name": "API v2 Performance Test",
                    "variants": ["control", "v2_enabled"],
                    "control_group": "control",
                    "metrics": ["response_time", "error_rate"]
                }
            },
            "advanced_analytics": {
                "description": "Advanced analytics dashboard",
                "type": "boolean",
                "default": False,
                "rollout_percentage": 0,
                "rollout_strategy": "targeted",
                "target_groups": ["enterprise"],
                "created_at": "2024-01-10T00:00:00Z"
            },
            "rate_limit_override": {
                "description": "Custom rate limiting rules",
                "type": "json",
                "default": {"default": 100},
                "rollout_percentage": 100
            },
            "maintenance_mode": {
                "description": "System maintenance mode",
                "type": "boolean",
                "default": False,
                "rollout_percentage": 100,
                "rollout_strategy": "immediate"
            },
            "password_policy_v2": {
                "description": "Enhanced password policy",
                "type": "boolean",
                "default": True,
                "rollout_percentage": 90,
                "excluded_groups": ["legacy_users"]
            },
            "biometric_auth": {
                "description": "Biometric authentication support",
                "type": "boolean",
                "default": False,
                "rollout_percentage": 10,
                "rollout_strategy": "percentage",
                "target_groups": ["mobile_users"]
            }
        }
    
    def _categorize_features(self, features: dict[str, Any]) -> dict[str, list[str]]:
        """Categorize features by type/area."""
        categories = {
            "authentication": [],
            "ui": [],
            "api": [],
            "security": [],
            "experimental": [],
            "operational": []
        }
        
        for name, feature in features.items():
            # Categorize based on name and description
            if any(term in name.lower() for term in ["auth", "mfa", "login", "biometric"]):
                categories["authentication"].append(name)
            elif any(term in name.lower() for term in ["dashboard", "ui"]):
                categories["ui"].append(name)
            elif "api" in name.lower():
                categories["api"].append(name)
            elif any(term in name.lower() for term in ["security", "password", "rate_limit"]):
                categories["security"].append(name)
            elif "maintenance" in name.lower():
                categories["operational"].append(name)
            
            # Mark experimental features
            if feature.get("experiment") or feature.get("rollout", {}).get("percentage", 100) < 50:
                categories["experimental"].append(name)
        
        return {k: v for k, v in categories.items() if v}
    
    async def _get_user_context(self, user_id: UUID | None) -> dict[str, Any]:
        """Get user context for feature evaluation."""
        if not user_id:
            return {}
        
        # This would typically fetch user attributes for feature targeting
        return {
            "user_groups": ["authenticated"],
            "account_type": "standard",
            "registration_date": "2023-01-01",
            "activity_level": "high"
        }