"""
Configuration Service Adapter

Production-ready implementation for configuration management and feature flags.
"""

import json
import os
from typing import Any
from uuid import UUID

from app.core.logging import logger
from app.modules.identity.domain.interfaces.services.infrastructure.configuration_port import (
    IConfigurationPort,
)


class ConfigurationAdapter(IConfigurationPort):
    """Production configuration adapter."""

    def __init__(
        self,
        config_file_path="/etc/ezzday/config.json",
        feature_flags_service=None,
        vault_client=None,
        environment_prefix="EZZDAY_",
    ):
        """Initialize configuration adapter.

        Args:
            config_file_path: Path to configuration file
            feature_flags_service: Feature flags service (LaunchDarkly, etc.)
            vault_client: HashiCorp Vault client for secrets
            environment_prefix: Prefix for environment variables
        """
        self._config_file = config_file_path
        self._feature_flags = feature_flags_service
        self._vault = vault_client
        self._env_prefix = environment_prefix
        self._config_cache = {}
        self._feature_cache = {}

    async def get_password_policy(self) -> dict[str, Any]:
        """Get password policy configuration."""
        try:
            # Try to get from cache first
            if "password_policy" in self._config_cache:
                return self._config_cache["password_policy"]

            # Get from various sources
            policy = await self._get_config_value("password_policy", {
                "min_length": 8,
                "max_length": 128,
                "require_uppercase": True,
                "require_lowercase": True,
                "require_digits": True,
                "require_special_chars": True,
                "min_special_chars": 1,
                "forbidden_patterns": [
                    "password",
                    "123456",
                    "qwerty",
                    "admin",
                    "user",
                ],
                "max_age_days": 90,
                "history_count": 5,
                "complexity_score_min": 3,
                "allow_user_info": False,
                "allow_common_passwords": False,
                "require_mixed_case": True,
                "lockout_threshold": 5,
                "lockout_duration_minutes": 30,
                "reset_token_expiry_minutes": 30,
            })

            # Cache the result
            self._config_cache["password_policy"] = policy
            return policy

        except Exception as e:
            logger.error(f"Error getting password policy: {e}")
            # Return safe defaults
            return {
                "min_length": 8,
                "max_length": 128,
                "require_uppercase": True,
                "require_lowercase": True,
                "require_digits": True,
                "require_special_chars": True,
                "min_special_chars": 1,
                "forbidden_patterns": ["password", "123456", "qwerty"],
                "max_age_days": 90,
                "history_count": 5,
            }

    async def get_session_config(self) -> dict[str, Any]:
        """Get session configuration."""
        try:
            # Try to get from cache first
            if "session_config" in self._config_cache:
                return self._config_cache["session_config"]

            # Get from various sources
            config = await self._get_config_value("session_config", {
                "access_token_expiry_minutes": 15,
                "refresh_token_expiry_days": 30,
                "max_concurrent_sessions": 5,
                "idle_timeout_minutes": 30,
                "absolute_timeout_hours": 8,
                "require_fresh_auth_for_sensitive": True,
                "remember_me_duration_days": 30,
                "secure_cookies": True,
                "same_site_policy": "strict",
                "session_rotation_enabled": True,
                "session_rotation_threshold_minutes": 5,
                "cleanup_expired_sessions_interval_hours": 1,
                "track_session_activity": True,
                "log_session_events": True,
                "concurrent_session_strategy": "logout_oldest",
                "device_tracking_enabled": True,
                "location_tracking_enabled": True,
                "anomaly_detection_enabled": True,
            })

            # Cache the result
            self._config_cache["session_config"] = config
            return config

        except Exception as e:
            logger.error(f"Error getting session config: {e}")
            # Return safe defaults
            return {
                "access_token_expiry_minutes": 15,
                "refresh_token_expiry_days": 30,
                "max_concurrent_sessions": 5,
                "idle_timeout_minutes": 30,
                "absolute_timeout_hours": 8,
                "secure_cookies": True,
                "same_site_policy": "strict",
            }

    async def get_mfa_config(self) -> dict[str, Any]:
        """Get MFA configuration."""
        try:
            # Try to get from cache first
            if "mfa_config" in self._config_cache:
                return self._config_cache["mfa_config"]

            # Get from various sources
            config = await self._get_config_value("mfa_config", {
                "enabled": True,
                "required_for_new_users": False,
                "required_for_admin_users": True,
                "required_for_sensitive_actions": True,
                "grace_period_days": 7,
                "totp_enabled": True,
                "sms_enabled": True,
                "email_enabled": True,
                "backup_codes_enabled": True,
                "biometric_enabled": False,
                "hardware_keys_enabled": False,
                "totp_algorithm": "SHA1",
                "totp_digits": 6,
                "totp_period_seconds": 30,
                "totp_window": 1,
                "sms_code_length": 6,
                "sms_code_expiry_minutes": 5,
                "email_code_length": 6,
                "email_code_expiry_minutes": 5,
                "backup_codes_count": 10,
                "backup_codes_length": 8,
                "max_failed_attempts": 5,
                "lockout_duration_minutes": 30,
                "remember_device_enabled": True,
                "remember_device_duration_days": 30,
                "challenge_expiry_minutes": 5,
                "step_up_auth_enabled": True,
            })

            # Cache the result
            self._config_cache["mfa_config"] = config
            return config

        except Exception as e:
            logger.error(f"Error getting MFA config: {e}")
            # Return safe defaults
            return {
                "enabled": True,
                "required_for_admin_users": True,
                "totp_enabled": True,
                "sms_enabled": True,
                "email_enabled": True,
                "backup_codes_enabled": True,
                "totp_digits": 6,
                "totp_period_seconds": 30,
                "sms_code_length": 6,
                "sms_code_expiry_minutes": 5,
            }

    async def get_rate_limit_config(self, endpoint: str) -> dict[str, Any]:
        """Get rate limit configuration for endpoint."""
        try:
            # Try to get from cache first
            cache_key = f"rate_limit_{endpoint}"
            if cache_key in self._config_cache:
                return self._config_cache[cache_key]

            # Get rate limit configurations
            rate_limits = await self._get_config_value("rate_limits", {
                "login": {
                    "requests_per_minute": 10,
                    "requests_per_hour": 100,
                    "burst_limit": 20,
                    "lockout_duration_minutes": 15,
                },
                "register": {
                    "requests_per_minute": 5,
                    "requests_per_hour": 50,
                    "burst_limit": 10,
                    "lockout_duration_minutes": 30,
                },
                "password_reset": {
                    "requests_per_minute": 3,
                    "requests_per_hour": 20,
                    "burst_limit": 5,
                    "lockout_duration_minutes": 60,
                },
                "mfa_verify": {
                    "requests_per_minute": 5,
                    "requests_per_hour": 30,
                    "burst_limit": 10,
                    "lockout_duration_minutes": 15,
                },
                "profile_update": {
                    "requests_per_minute": 10,
                    "requests_per_hour": 100,
                    "burst_limit": 15,
                    "lockout_duration_minutes": 5,
                },
                "default": {
                    "requests_per_minute": 60,
                    "requests_per_hour": 1000,
                    "burst_limit": 100,
                    "lockout_duration_minutes": 5,
                },
            })

            # Get config for specific endpoint or default
            config = rate_limits.get(endpoint, rate_limits["default"])

            # Cache the result
            self._config_cache[cache_key] = config
            return config

        except Exception as e:
            logger.error(f"Error getting rate limit config for {endpoint}: {e}")
            # Return safe defaults
            return {
                "requests_per_minute": 60,
                "requests_per_hour": 1000,
                "burst_limit": 100,
                "lockout_duration_minutes": 5,
            }

    async def is_feature_enabled(
        self, feature: str, user_id: UUID | None = None
    ) -> bool:
        """Check if feature is enabled."""
        try:
            # Try to get from cache first
            cache_key = f"feature_{feature}_{user_id}" if user_id else f"feature_{feature}"
            if cache_key in self._feature_cache:
                return self._feature_cache[cache_key]

            # Check feature flags service first
            if self._feature_flags and user_id:
                result = await self._feature_flags.is_enabled(feature, str(user_id))
                self._feature_cache[cache_key] = result
                return result
            if self._feature_flags:
                result = await self._feature_flags.is_enabled(feature)
                self._feature_cache[cache_key] = result
                return result

            # Fall back to configuration
            feature_flags = await self._get_config_value("feature_flags", {
                "user_registration": True,
                "email_verification": True,
                "social_login": True,
                "password_recovery": True,
                "mfa_enforcement": True,
                "session_management": True,
                "profile_completion": True,
                "avatar_upload": True,
                "account_deletion": True,
                "admin_impersonation": False,
                "audit_logging": True,
                "security_monitoring": True,
                "compliance_reporting": True,
                "api_access": True,
                "mobile_app": True,
                "desktop_app": False,
                "beta_features": False,
                "maintenance_mode": False,
                "analytics_tracking": True,
                "performance_monitoring": True,
                "error_reporting": True,
                "feature_experimentation": False,
                "advanced_security": True,
                "biometric_auth": False,
                "hardware_keys": False,
                "risk_assessment": True,
                "threat_detection": True,
                "geolocation_tracking": True,
                "device_fingerprinting": True,
                "behavioral_analytics": True,
            })

            result = feature_flags.get(feature, False)
            self._feature_cache[cache_key] = result
            return result

        except Exception as e:
            logger.error(f"Error checking feature {feature}: {e}")
            # Return safe default
            return False

    async def get_compliance_settings(self) -> dict[str, Any]:
        """Get compliance settings."""
        try:
            # Try to get from cache first
            if "compliance_settings" in self._config_cache:
                return self._config_cache["compliance_settings"]

            # Get from various sources
            settings = await self._get_config_value("compliance_settings", {
                "gdpr_enabled": True,
                "ccpa_enabled": True,
                "hipaa_enabled": False,
                "pci_dss_enabled": False,
                "sox_enabled": False,
                "data_retention_days": 365,
                "audit_log_retention_days": 2555,  # 7 years
                "consent_management_enabled": True,
                "right_to_be_forgotten_enabled": True,
                "data_portability_enabled": True,
                "breach_notification_enabled": True,
                "privacy_by_design_enabled": True,
                "data_minimization_enabled": True,
                "purpose_limitation_enabled": True,
                "storage_limitation_enabled": True,
                "accuracy_maintenance_enabled": True,
                "security_measures_enabled": True,
                "accountability_measures_enabled": True,
                "third_party_sharing_restricted": True,
                "cross_border_transfer_restricted": True,
                "encryption_at_rest_required": True,
                "encryption_in_transit_required": True,
                "access_logging_required": True,
                "regular_security_assessments": True,
                "incident_response_plan_enabled": True,
                "staff_training_required": True,
                "vendor_management_enabled": True,
                "risk_assessment_required": True,
                "compliance_monitoring_enabled": True,
                "audit_trail_immutability": True,
                "data_classification_enabled": True,
                "sensitive_data_masking": True,
                "automated_compliance_checks": True,
                "compliance_reporting_enabled": True,
                "regulatory_change_monitoring": True,
            })

            # Cache the result
            self._config_cache["compliance_settings"] = settings
            return settings

        except Exception as e:
            logger.error(f"Error getting compliance settings: {e}")
            # Return safe defaults
            return {
                "gdpr_enabled": True,
                "ccpa_enabled": True,
                "data_retention_days": 365,
                "audit_log_retention_days": 2555,
                "consent_management_enabled": True,
                "right_to_be_forgotten_enabled": True,
                "data_portability_enabled": True,
                "breach_notification_enabled": True,
                "encryption_at_rest_required": True,
                "encryption_in_transit_required": True,
                "access_logging_required": True,
            }

    async def _get_config_value(self, key: str, default: Any = None) -> Any:
        """Get configuration value from various sources."""
        try:
            # 1. Try environment variable first
            env_key = f"{self._env_prefix}{key.upper()}"
            env_value = os.getenv(env_key)
            if env_value:
                # Try to parse as JSON
                try:
                    return json.loads(env_value)
                except json.JSONDecodeError:
                    return env_value

            # 2. Try Vault if available
            if self._vault:
                try:
                    vault_value = await self._vault.read(f"secret/ezzday/{key}")
                    if vault_value:
                        return vault_value["data"]
                except Exception as e:
                    logger.debug(f"Vault read failed for {key}: {e}")

            # 3. Try configuration file
            if os.path.exists(self._config_file):
                try:
                    with open(self._config_file) as f:
                        config_data = json.load(f)
                        if key in config_data:
                            return config_data[key]
                except Exception as e:
                    logger.debug(f"Config file read failed for {key}: {e}")

            # 4. Return default
            return default

        except Exception as e:
            logger.error(f"Error getting config value {key}: {e}")
            return default

    async def set_config_value(self, key: str, value: Any) -> bool:
        """Set configuration value (extension method)."""
        try:
            # Update cache
            self._config_cache[key] = value

            # Try to persist to Vault
            if self._vault:
                try:
                    await self._vault.write(f"secret/ezzday/{key}", {"data": value})
                    logger.info(f"Config value {key} saved to Vault")
                    return True
                except Exception as e:
                    logger.error(f"Failed to save config {key} to Vault: {e}")

            # Fall back to config file
            if os.path.exists(self._config_file):
                try:
                    with open(self._config_file) as f:
                        config_data = json.load(f)
                    
                    config_data[key] = value
                    
                    with open(self._config_file, 'w') as f:
                        json.dump(config_data, f, indent=2)
                    
                    logger.info(f"Config value {key} saved to file")
                    return True
                except Exception as e:
                    logger.error(f"Failed to save config {key} to file: {e}")

            return False

        except Exception as e:
            logger.error(f"Error setting config value {key}: {e}")
            return False

    async def reload_config(self) -> None:
        """Reload configuration from sources."""
        try:
            # Clear caches
            self._config_cache.clear()
            self._feature_cache.clear()

            logger.info("Configuration reloaded")

        except Exception as e:
            logger.error(f"Error reloading configuration: {e}")

    async def get_all_feature_flags(self) -> dict[str, bool]:
        """Get all feature flags."""
        try:
            if self._feature_flags:
                return await self._feature_flags.get_all_flags()
            
            # Fall back to configuration
            feature_flags = await self._get_config_value("feature_flags", {})
            return feature_flags

        except Exception as e:
            logger.error(f"Error getting all feature flags: {e}")
            return {}

    async def get_environment_info(self) -> dict[str, Any]:
        """Get environment information."""
        try:
            return {
                "environment": os.getenv("ENVIRONMENT", "development"),
                "version": os.getenv("APP_VERSION", "unknown"),
                "deployment_id": os.getenv("DEPLOYMENT_ID", "unknown"),
                "region": os.getenv("AWS_REGION", "unknown"),
                "hostname": os.getenv("HOSTNAME", "unknown"),
                "config_source": self._get_config_source(),
                "feature_flags_provider": self._get_feature_flags_provider(),
                "vault_enabled": self._vault is not None,
            }

        except Exception as e:
            logger.error(f"Error getting environment info: {e}")
            return {"error": str(e)}

    def _get_config_source(self) -> str:
        """Get the primary configuration source."""
        if self._vault:
            return "vault"
        if os.path.exists(self._config_file):
            return "file"
        return "environment"

    def _get_feature_flags_provider(self) -> str:
        """Get the feature flags provider."""
        if self._feature_flags:
            return "external_service"
        return "configuration"