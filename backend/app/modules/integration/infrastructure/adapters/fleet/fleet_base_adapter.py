"""Base adapter interface for fleet management systems."""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any

from .fleet_types import (
    Driver,
    DriverStatus,
    FleetAlert,
    FleetSummary,
    Location,
    Route,
    TelematicsData,
    Vehicle,
    VehicleStatus,
)


class FleetAdapterError(Exception):
    """Base exception for fleet adapter errors."""

    def __init__(
        self,
        message: str,
        error_code: str | None = None,
        is_retryable: bool = True,
        provider_response: dict[str, Any] | None = None,
    ):
        super().__init__(message)
        self.error_code = error_code
        self.is_retryable = is_retryable
        self.provider_response = provider_response


class BaseFleetAdapter(ABC):
    """Base class for fleet management adapters."""

    def __init__(self, config: dict[str, Any]):
        """Initialize fleet adapter.

        Args:
            config: Configuration dictionary containing:
                - credentials: API keys, tokens, etc.
                - settings: Provider-specific settings
                - rate_limits: Rate limiting configuration
        """
        self.config = config
        self.credentials = config.get("credentials", {})
        self.settings = config.get("settings", {})
        self.rate_limits = config.get("rate_limits", {})
        self._validate_config()

    @abstractmethod
    def _validate_config(self) -> None:
        """Validate configuration.

        Raises:
            ValueError: If configuration is invalid
        """

    # Vehicle Management
    @abstractmethod
    async def get_vehicles(
        self,
        status: VehicleStatus | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ) -> list[Vehicle]:
        """Get list of vehicles.

        Args:
            status: Filter by vehicle status
            limit: Maximum number of vehicles to return
            offset: Number of vehicles to skip

        Returns:
            List of vehicles
        """

    @abstractmethod
    async def get_vehicle(self, vehicle_id: str) -> Vehicle | None:
        """Get vehicle by ID.

        Args:
            vehicle_id: Vehicle identifier

        Returns:
            Vehicle if found, None otherwise
        """

    @abstractmethod
    async def get_vehicle_location(self, vehicle_id: str) -> Location | None:
        """Get current vehicle location.

        Args:
            vehicle_id: Vehicle identifier

        Returns:
            Current location if available
        """

    @abstractmethod
    async def get_vehicle_history(
        self, vehicle_id: str, start_time: datetime, end_time: datetime
    ) -> list[TelematicsData]:
        """Get vehicle telematics history.

        Args:
            vehicle_id: Vehicle identifier
            start_time: Start of time range
            end_time: End of time range

        Returns:
            List of telematics data points
        """

    # Driver Management
    @abstractmethod
    async def get_drivers(
        self,
        status: DriverStatus | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ) -> list[Driver]:
        """Get list of drivers.

        Args:
            status: Filter by driver status
            limit: Maximum number of drivers to return
            offset: Number of drivers to skip

        Returns:
            List of drivers
        """

    @abstractmethod
    async def get_driver(self, driver_id: str) -> Driver | None:
        """Get driver by ID.

        Args:
            driver_id: Driver identifier

        Returns:
            Driver if found, None otherwise
        """

    # Route Management
    @abstractmethod
    async def get_routes(
        self,
        vehicle_id: str | None = None,
        driver_id: str | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ) -> list[Route]:
        """Get list of routes.

        Args:
            vehicle_id: Filter by vehicle
            driver_id: Filter by driver
            limit: Maximum number of routes to return
            offset: Number of routes to skip

        Returns:
            List of routes
        """

    @abstractmethod
    async def create_route(self, route: Route) -> str:
        """Create a new route.

        Args:
            route: Route to create

        Returns:
            Created route ID
        """

    # Alert Management
    @abstractmethod
    async def get_alerts(
        self,
        vehicle_id: str | None = None,
        driver_id: str | None = None,
        unresolved_only: bool = True,
        limit: int | None = None,
        offset: int | None = None,
    ) -> list[FleetAlert]:
        """Get fleet alerts.

        Args:
            vehicle_id: Filter by vehicle
            driver_id: Filter by driver
            unresolved_only: Only return unresolved alerts
            limit: Maximum number of alerts to return
            offset: Number of alerts to skip

        Returns:
            List of alerts
        """

    @abstractmethod
    async def acknowledge_alert(self, alert_id: str) -> bool:
        """Acknowledge an alert.

        Args:
            alert_id: Alert identifier

        Returns:
            True if successful
        """

    # Analytics and Reporting
    @abstractmethod
    async def get_fleet_summary(self, date: datetime | None = None) -> FleetSummary:
        """Get fleet summary statistics.

        Args:
            date: Date for statistics (defaults to today)

        Returns:
            Fleet summary
        """

    @abstractmethod
    async def get_driver_performance(
        self, driver_id: str, start_date: datetime, end_date: datetime
    ) -> dict[str, Any]:
        """Get driver performance metrics.

        Args:
            driver_id: Driver identifier
            start_date: Start of period
            end_date: End of period

        Returns:
            Performance metrics dictionary
        """

    @abstractmethod
    async def get_vehicle_utilization(
        self, vehicle_id: str, start_date: datetime, end_date: datetime
    ) -> dict[str, Any]:
        """Get vehicle utilization metrics.

        Args:
            vehicle_id: Vehicle identifier
            start_date: Start of period
            end_date: End of period

        Returns:
            Utilization metrics dictionary
        """

    # Health Check
    async def health_check(self) -> dict[str, Any]:
        """Check adapter health status.

        Returns:
            Health status dictionary
        """
        try:
            # Try a simple API call to test connectivity
            vehicles = await self.get_vehicles(limit=1)

            return {
                "status": "healthy",
                "provider": self.__class__.__name__,
                "timestamp": datetime.utcnow().isoformat(),
                "test_result": "api_accessible",
                "vehicle_count": len(vehicles),
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "provider": self.__class__.__name__,
                "timestamp": datetime.utcnow().isoformat(),
                "error": str(e),
                "test_result": "api_error",
            }

    # Utility Methods
    def _handle_rate_limit(self, response_headers: dict[str, str]) -> None:
        """Handle rate limiting based on response headers.

        Args:
            response_headers: HTTP response headers
        """
        # Default implementation - can be overridden

    def _sanitize_response(self, response: dict[str, Any]) -> dict[str, Any]:
        """Sanitize response to remove sensitive data.

        Args:
            response: Raw API response

        Returns:
            Sanitized response
        """
        # Remove common sensitive fields
        sensitive_fields = [
            "api_key",
            "secret",
            "token",
            "password",
            "authorization",
            "x-api-key",
            "bearer",
        ]

        sanitized = response.copy()
        for field in sensitive_fields:
            if field in sanitized:
                sanitized[field] = "[REDACTED]"
            # Also check nested fields
            for key in list(sanitized.keys()):
                if isinstance(sanitized[key], dict):
                    sanitized[key] = self._sanitize_response(sanitized[key])

        return sanitized
