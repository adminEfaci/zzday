"""Factory for creating mapping adapters with configuration and health monitoring."""

import asyncio
import contextlib
import logging
from datetime import datetime, timedelta
from enum import Enum
from typing import Any

from .google_maps_adapter import GoogleMapsAdapter
from .mapbox_adapter import MapboxAdapter
from .mapping_base_adapter import BaseMappingAdapter, MappingAdapterError
from .osm_adapter import OSMAdapter

logger = logging.getLogger(__name__)


class MappingProvider(str, Enum):
    """Available mapping providers."""

    OSM = "osm"
    MAPBOX = "mapbox"
    GOOGLE_MAPS = "google_maps"


class MappingAdapterStatus(str, Enum):
    """Adapter health status."""

    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"
    RATE_LIMITED = "rate_limited"


class MappingAdapterFactory:
    """Factory for creating and managing mapping adapters."""

    # Registry of adapter classes
    _adapters: dict[MappingProvider, type[BaseMappingAdapter]] = {
        MappingProvider.OSM: OSMAdapter,
        MappingProvider.MAPBOX: MapboxAdapter,
        MappingProvider.GOOGLE_MAPS: GoogleMapsAdapter,
    }

    def __init__(self, config: dict[str, Any]):
        """Initialize mapping adapter factory.

        Args:
            config: Configuration dictionary containing:
                - providers: Dict of provider configurations
                - fallback_order: List of providers in fallback order
                - health_check_interval: Health check interval in seconds
                - rate_limits: Global rate limiting configuration
        """
        self.config = config
        self.providers_config = config.get("providers", {})
        self.fallback_order = config.get("fallback_order", [MappingProvider.OSM])
        self.health_check_interval = config.get(
            "health_check_interval", 300
        )  # 5 minutes

        # Adapter instances and status tracking
        self._adapters_cache: dict[MappingProvider, BaseMappingAdapter] = {}
        self._adapter_status: dict[MappingProvider, MappingAdapterStatus] = {}
        self._last_health_check: dict[MappingProvider, datetime] = {}
        self._health_check_task: asyncio.Task | None = None

        # Rate limiting
        self._rate_limiters: dict[MappingProvider, dict[str, Any]] = {}

        logger.info(
            f"MappingAdapterFactory initialized with providers: {list(self.providers_config.keys())}"
        )

    async def get_adapter(
        self, provider: MappingProvider | None = None, fallback: bool = True
    ) -> BaseMappingAdapter:
        """Get mapping adapter with optional fallback.

        Args:
            provider: Specific provider to use (None for auto-selection)
            fallback: Whether to try fallback providers if primary fails

        Returns:
            Mapping adapter instance

        Raises:
            MappingAdapterError: If no healthy adapter is available
        """
        providers_to_try = []

        if provider:
            providers_to_try.append(provider)
            if fallback:
                providers_to_try.extend(
                    [p for p in self.fallback_order if p != provider]
                )
        else:
            providers_to_try = self.fallback_order.copy()

        for provider_name in providers_to_try:
            try:
                adapter = await self._get_adapter_instance(provider_name)

                # Check if adapter is healthy
                if await self._is_adapter_healthy(provider_name):
                    logger.debug(f"Using {provider_name} adapter")
                    return adapter
                logger.warning(f"Adapter {provider_name} is unhealthy, trying next")
                continue

            except Exception as e:
                logger.warning(f"Failed to get {provider_name} adapter: {e!s}")
                continue

        raise MappingAdapterError(
            "No healthy mapping adapter available",
            error_code="NO_HEALTHY_ADAPTER",
            is_retryable=True,
        )

    async def _get_adapter_instance(
        self, provider: MappingProvider
    ) -> BaseMappingAdapter:
        """Get or create adapter instance."""
        if provider not in self._adapters_cache:
            # Validate provider is configured
            if provider not in self.providers_config:
                raise MappingAdapterError(
                    f"Provider {provider} is not configured",
                    error_code="PROVIDER_NOT_CONFIGURED",
                    is_retryable=False,
                )

            # Get adapter class
            adapter_class = self._adapters.get(provider)
            if not adapter_class:
                raise MappingAdapterError(
                    f"Adapter class for {provider} not found",
                    error_code="ADAPTER_CLASS_NOT_FOUND",
                    is_retryable=False,
                )

            # Create adapter instance
            provider_config = self.providers_config[provider]
            adapter = adapter_class(provider_config)

            self._adapters_cache[provider] = adapter
            logger.info(f"Created {provider} adapter instance")

        return self._adapters_cache[provider]

    async def _is_adapter_healthy(self, provider: MappingProvider) -> bool:
        """Check if adapter is healthy."""
        # Check cached status first
        status = self._adapter_status.get(provider, MappingAdapterStatus.UNKNOWN)
        last_check = self._last_health_check.get(provider)

        # Return cached status if recent
        if last_check and datetime.utcnow() - last_check < timedelta(
            seconds=self.health_check_interval
        ):
            return status == MappingAdapterStatus.HEALTHY

        # Perform health check
        try:
            adapter = await self._get_adapter_instance(provider)
            health_result = await adapter.health_check()

            if health_result.get("status") == "healthy":
                self._adapter_status[provider] = MappingAdapterStatus.HEALTHY
                logger.debug(f"Health check passed for {provider}")
                return True
            self._adapter_status[provider] = MappingAdapterStatus.UNHEALTHY
            logger.warning(f"Health check failed for {provider}: {health_result}")
            return False

        except Exception as e:
            self._adapter_status[provider] = MappingAdapterStatus.UNHEALTHY
            logger.exception(f"Health check error for {provider}: {e!s}")
            return False
        finally:
            self._last_health_check[provider] = datetime.utcnow()

    async def get_all_adapters_status(self) -> dict[str, dict[str, Any]]:
        """Get status of all configured adapters."""
        status = {}

        for provider in self.providers_config:
            try:
                is_healthy = await self._is_adapter_healthy(MappingProvider(provider))
                adapter_status = self._adapter_status.get(
                    MappingProvider(provider), MappingAdapterStatus.UNKNOWN
                )
                last_check = self._last_health_check.get(MappingProvider(provider))

                status[provider] = {
                    "status": adapter_status.value,
                    "healthy": is_healthy,
                    "last_health_check": last_check.isoformat() if last_check else None,
                    "configured": True,
                }

            except Exception as e:
                status[provider] = {
                    "status": "error",
                    "healthy": False,
                    "error": str(e),
                    "configured": True,
                }

        return status

    async def start_background_health_checks(self):
        """Start background health monitoring."""
        if self._health_check_task is None or self._health_check_task.done():
            self._health_check_task = asyncio.create_task(
                self._background_health_check_loop()
            )
            logger.info("Started background health check monitoring")

    async def stop_background_health_checks(self):
        """Stop background health monitoring."""
        if self._health_check_task and not self._health_check_task.done():
            self._health_check_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._health_check_task
            logger.info("Stopped background health check monitoring")

    async def _background_health_check_loop(self):
        """Background task for periodic health checks."""
        while True:
            try:
                await asyncio.sleep(self.health_check_interval)

                # Check health of all configured providers
                tasks = []
                for provider in self.providers_config:
                    task = asyncio.create_task(
                        self._is_adapter_healthy(MappingProvider(provider))
                    )
                    tasks.append(task)

                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=True)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.exception(f"Background health check error: {e!s}")

    def register_adapter(
        self, provider: MappingProvider, adapter_class: type[BaseMappingAdapter]
    ):
        """Register a custom adapter class.

        Args:
            provider: Provider identifier
            adapter_class: Adapter class to register
        """
        self._adapters[provider] = adapter_class
        logger.info(f"Registered custom adapter for {provider}")

    async def close_all_adapters(self):
        """Close all adapter connections."""
        for provider, adapter in self._adapters_cache.items():
            try:
                if hasattr(adapter, "__aexit__"):
                    await adapter.__aexit__(None, None, None)
                logger.debug(f"Closed {provider} adapter")
            except Exception as e:
                logger.warning(f"Error closing {provider} adapter: {e!s}")

        self._adapters_cache.clear()
        await self.stop_background_health_checks()

    def get_provider_capabilities(self, provider: MappingProvider) -> dict[str, bool]:
        """Get provider capabilities.

        Args:
            provider: Provider to check

        Returns:
            Dictionary of capabilities and their availability
        """
        capabilities = {
            "geocoding": True,
            "reverse_geocoding": True,
            "routing": True,
            "route_optimization": True,
            "distance_matrix": True,
            "map_tiles": False,
            "traffic_data": False,
            "place_search": False,
            "place_details": False,
        }

        if provider == MappingProvider.OSM:
            # OSM has basic capabilities
            capabilities.update(
                {
                    "map_tiles": False,
                    "traffic_data": False,
                    "place_search": False,
                    "place_details": False,
                }
            )
        elif provider == MappingProvider.MAPBOX:
            # Mapbox has premium capabilities
            capabilities.update(
                {
                    "map_tiles": True,
                    "traffic_data": True,
                    "place_search": True,
                    "place_details": False,
                }
            )
        elif provider == MappingProvider.GOOGLE_MAPS:
            # Google Maps has full capabilities
            capabilities.update(
                {
                    "map_tiles": True,
                    "traffic_data": True,
                    "place_search": True,
                    "place_details": True,
                }
            )

        return capabilities

    def get_configuration_template(self, provider: MappingProvider) -> dict[str, Any]:
        """Get configuration template for a provider.

        Args:
            provider: Provider to get template for

        Returns:
            Configuration template
        """
        templates = {
            MappingProvider.OSM: {
                "credentials": {},
                "settings": {
                    "email": "your-email@domain.com",
                    "nominatim_url": "https://nominatim.openstreetmap.org",
                    "osrm_url": "https://router.project-osrm.org",
                    "connect_timeout": 10.0,
                    "read_timeout": 30.0,
                    "max_connections": 20,
                },
            },
            MappingProvider.MAPBOX: {
                "credentials": {"api_key": "pk.your_mapbox_api_key"},
                "settings": {
                    "connect_timeout": 10.0,
                    "read_timeout": 30.0,
                    "max_connections": 20,
                },
            },
            MappingProvider.GOOGLE_MAPS: {
                "credentials": {"api_key": "your_google_maps_api_key"},
                "settings": {
                    "connect_timeout": 10.0,
                    "read_timeout": 30.0,
                    "max_connections": 20,
                },
            },
        }

        return templates.get(provider, {})

    async def __aenter__(self):
        """Async context manager entry."""
        await self.start_background_health_checks()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close_all_adapters()


# Default factory configuration
DEFAULT_MAPPING_CONFIG = {
    "providers": {
        "osm": {
            "credentials": {},
            "settings": {
                "email": "integration@ezzday.com",
                "connect_timeout": 10.0,
                "read_timeout": 30.0,
                "max_connections": 20,
            },
        }
    },
    "fallback_order": [MappingProvider.OSM],
    "health_check_interval": 300,
    "rate_limits": {"requests_per_minute": 60, "requests_per_hour": 1000},
}


async def create_mapping_adapter_factory(
    config: dict[str, Any] | None = None
) -> MappingAdapterFactory:
    """Create and initialize mapping adapter factory.

    Args:
        config: Factory configuration (uses default if None)

    Returns:
        Initialized factory instance
    """
    factory_config = config or DEFAULT_MAPPING_CONFIG
    factory = MappingAdapterFactory(factory_config)
    await factory.start_background_health_checks()
    return factory
