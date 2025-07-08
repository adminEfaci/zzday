"""Factory for creating integration adapters."""

from enum import Enum
from typing import Any

from app.modules.notification.infrastructure.adapters.base import BaseChannelAdapter
from app.modules.notification.infrastructure.adapters.email.resend_adapter import (
    ResendEmailAdapter,
)
from app.modules.notification.infrastructure.adapters.email_adapter import (
    EmailChannelAdapter,
)
from app.modules.notification.infrastructure.adapters.sms_adapter import (
    SMSChannelAdapter,
)

from .fleet import BaseFleetAdapter, GeotabAdapter, SamsaraAdapter
from .mapping import BaseMappingAdapter, OSMAdapter


class AdapterType(Enum):
    """Types of adapters available."""

    EMAIL = "email"
    SMS = "sms"
    FLEET = "fleet"
    MAPPING = "mapping"


class AdapterFactory:
    """Factory for creating various integration adapters."""

    # Registry of available adapters
    _email_adapters = {
        "smtp": EmailChannelAdapter,
        "sendgrid": EmailChannelAdapter,
        "resend": ResendEmailAdapter,
    }

    _sms_adapters = {
        "twilio": SMSChannelAdapter,
    }

    _fleet_adapters = {
        "samsara": SamsaraAdapter,
        "geotab": GeotabAdapter,
    }

    _mapping_adapters = {
        "osm": OSMAdapter,
        "openstreetmap": OSMAdapter,
    }

    @classmethod
    def create_email_adapter(
        cls, provider: str, config: dict[str, Any]
    ) -> BaseChannelAdapter:
        """Create email adapter instance.

        Args:
            provider: Email provider name (smtp, sendgrid, resend)
            config: Adapter configuration

        Returns:
            Email adapter instance

        Raises:
            ValueError: If provider is not supported
        """
        if provider not in cls._email_adapters:
            raise ValueError(
                f"Unsupported email provider: {provider}. "
                f"Available: {list(cls._email_adapters.keys())}"
            )

        adapter_class = cls._email_adapters[provider]

        # Convert config to proper format for email adapters
        from app.modules.notification.domain.enums import NotificationChannel
        from app.modules.notification.domain.value_objects import ChannelConfig

        channel_config = ChannelConfig(
            channel=NotificationChannel.EMAIL,
            provider=provider,
            settings=config.get("settings", {}),
            credentials=config.get("credentials", {}),
            rate_limits=config.get("rate_limits", {}),
        )

        return adapter_class(channel_config)

    @classmethod
    def create_sms_adapter(
        cls, provider: str, config: dict[str, Any]
    ) -> BaseChannelAdapter:
        """Create SMS adapter instance.

        Args:
            provider: SMS provider name (twilio)
            config: Adapter configuration

        Returns:
            SMS adapter instance

        Raises:
            ValueError: If provider is not supported
        """
        if provider not in cls._sms_adapters:
            raise ValueError(
                f"Unsupported SMS provider: {provider}. "
                f"Available: {list(cls._sms_adapters.keys())}"
            )

        adapter_class = cls._sms_adapters[provider]

        # Convert config to proper format for SMS adapters
        from app.modules.notification.domain.enums import NotificationChannel
        from app.modules.notification.domain.value_objects import ChannelConfig

        channel_config = ChannelConfig(
            channel=NotificationChannel.SMS,
            provider=provider,
            settings=config.get("settings", {}),
            credentials=config.get("credentials", {}),
            rate_limits=config.get("rate_limits", {}),
        )

        return adapter_class(channel_config)

    @classmethod
    def create_fleet_adapter(
        cls, provider: str, config: dict[str, Any]
    ) -> BaseFleetAdapter:
        """Create fleet management adapter instance.

        Args:
            provider: Fleet provider name (samsara, geotab)
            config: Adapter configuration

        Returns:
            Fleet adapter instance

        Raises:
            ValueError: If provider is not supported
        """
        if provider not in cls._fleet_adapters:
            raise ValueError(
                f"Unsupported fleet provider: {provider}. "
                f"Available: {list(cls._fleet_adapters.keys())}"
            )

        adapter_class = cls._fleet_adapters[provider]
        return adapter_class(config)

    @classmethod
    def create_mapping_adapter(
        cls, provider: str, config: dict[str, Any]
    ) -> BaseMappingAdapter:
        """Create mapping/routing adapter instance.

        Args:
            provider: Mapping provider name (osm, openstreetmap)
            config: Adapter configuration

        Returns:
            Mapping adapter instance

        Raises:
            ValueError: If provider is not supported
        """
        if provider not in cls._mapping_adapters:
            raise ValueError(
                f"Unsupported mapping provider: {provider}. "
                f"Available: {list(cls._mapping_adapters.keys())}"
            )

        adapter_class = cls._mapping_adapters[provider]
        return adapter_class(config)

    @classmethod
    def create_adapter(
        cls, adapter_type: AdapterType, provider: str, config: dict[str, Any]
    ) -> BaseChannelAdapter | BaseFleetAdapter | BaseMappingAdapter:
        """Create adapter instance of specified type.

        Args:
            adapter_type: Type of adapter to create
            provider: Provider name
            config: Adapter configuration

        Returns:
            Adapter instance

        Raises:
            ValueError: If adapter type or provider is not supported
        """
        if adapter_type == AdapterType.EMAIL:
            return cls.create_email_adapter(provider, config)
        if adapter_type == AdapterType.SMS:
            return cls.create_sms_adapter(provider, config)
        if adapter_type == AdapterType.FLEET:
            return cls.create_fleet_adapter(provider, config)
        if adapter_type == AdapterType.MAPPING:
            return cls.create_mapping_adapter(provider, config)
        raise ValueError(f"Unsupported adapter type: {adapter_type}")

    @classmethod
    def get_supported_providers(cls, adapter_type: AdapterType) -> list:
        """Get list of supported providers for adapter type.

        Args:
            adapter_type: Type of adapter

        Returns:
            List of supported provider names
        """
        if adapter_type == AdapterType.EMAIL:
            return list(cls._email_adapters.keys())
        if adapter_type == AdapterType.SMS:
            return list(cls._sms_adapters.keys())
        if adapter_type == AdapterType.FLEET:
            return list(cls._fleet_adapters.keys())
        if adapter_type == AdapterType.MAPPING:
            return list(cls._mapping_adapters.keys())
        return []

    @classmethod
    def register_email_adapter(
        cls, provider: str, adapter_class: type[BaseChannelAdapter]
    ) -> None:
        """Register a new email adapter.

        Args:
            provider: Provider name
            adapter_class: Adapter class
        """
        cls._email_adapters[provider] = adapter_class

    @classmethod
    def register_sms_adapter(
        cls, provider: str, adapter_class: type[BaseChannelAdapter]
    ) -> None:
        """Register a new SMS adapter.

        Args:
            provider: Provider name
            adapter_class: Adapter class
        """
        cls._sms_adapters[provider] = adapter_class

    @classmethod
    def register_fleet_adapter(
        cls, provider: str, adapter_class: type[BaseFleetAdapter]
    ) -> None:
        """Register a new fleet adapter.

        Args:
            provider: Provider name
            adapter_class: Adapter class
        """
        cls._fleet_adapters[provider] = adapter_class

    @classmethod
    def register_mapping_adapter(
        cls, provider: str, adapter_class: type[BaseMappingAdapter]
    ) -> None:
        """Register a new mapping adapter.

        Args:
            provider: Provider name
            adapter_class: Adapter class
        """
        cls._mapping_adapters[provider] = adapter_class

    @classmethod
    def health_check_all(cls) -> dict[str, dict[str, Any]]:
        """Perform health check on all registered adapters.

        Returns:
            Dictionary with health status for each adapter type and provider
        """
        health_status = {}

        # This would require configuration to instantiate adapters
        # Implementation would depend on how configurations are managed
        # For now, return basic info about registered adapters

        health_status["email"] = {
            "providers": list(cls._email_adapters.keys()),
            "status": "registered",
        }

        health_status["sms"] = {
            "providers": list(cls._sms_adapters.keys()),
            "status": "registered",
        }

        health_status["fleet"] = {
            "providers": list(cls._fleet_adapters.keys()),
            "status": "registered",
        }

        health_status["mapping"] = {
            "providers": list(cls._mapping_adapters.keys()),
            "status": "registered",
        }

        return health_status
