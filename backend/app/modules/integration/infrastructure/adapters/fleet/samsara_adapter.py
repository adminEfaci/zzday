"""Samsara fleet management API adapter implementation."""

import asyncio
from datetime import UTC, datetime
from typing import Any

import httpx

from .fleet_base_adapter import BaseFleetAdapter, FleetAdapterError
from .fleet_types import (
    AlertSeverity,
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


class SamsaraAdapter(BaseFleetAdapter):
    """Samsara fleet management API adapter.

    Provides comprehensive fleet management capabilities including:
    - Real-time vehicle tracking
    - Driver management and HOS compliance
    - Route optimization
    - Safety alerts and compliance monitoring
    - Advanced analytics and reporting
    """

    BASE_URL = "https://api.samsara.com"
    API_VERSION = "2024-12-01"

    def __init__(self, config: dict[str, Any]):
        """Initialize Samsara adapter."""
        super().__init__(config)
        self._client = None

    def _validate_config(self) -> None:
        """Validate Samsara configuration."""
        required_credentials = ["api_token"]
        for cred in required_credentials:
            if cred not in self.credentials:
                raise ValueError(f"Missing required credential: {cred}")

        # Validate API token format
        api_token = self.credentials["api_token"]
        if not api_token.startswith("samsara_api_"):
            raise ValueError("Invalid Samsara API token format")

    def _get_client(self) -> httpx.AsyncClient:
        """Get HTTP client with authentication."""
        if self._client is None:
            headers = {
                "Authorization": f"Bearer {self.credentials['api_token']}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "EzzDay-Backend/1.0",
                "X-API-Version": self.API_VERSION,
            }

            timeout = httpx.Timeout(
                connect=self.settings.get("connect_timeout", 10.0),
                read=self.settings.get("read_timeout", 30.0),
                write=self.settings.get("write_timeout", 10.0),
                pool=self.settings.get("pool_timeout", 10.0),
            )

            self._client = httpx.AsyncClient(
                base_url=self.BASE_URL,
                headers=headers,
                timeout=timeout,
                limits=httpx.Limits(
                    max_keepalive_connections=self.settings.get("max_connections", 20),
                    max_connections=self.settings.get("max_connections", 100),
                ),
            )

        return self._client

    # Vehicle Management
    async def get_vehicles(
        self,
        status: VehicleStatus | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ) -> list[Vehicle]:
        """Get list of vehicles from Samsara."""
        try:
            client = self._get_client()

            params = {}
            if limit:
                params["limit"] = min(limit, 1000)  # Samsara max limit
            if offset:
                params["after"] = str(offset)

            response = await client.get("/fleet/vehicles", params=params)

            if response.status_code == 200:
                data = response.json()
                vehicles = []

                for vehicle_data in data.get("data", []):
                    vehicle = self._parse_vehicle(vehicle_data)
                    if status is None or vehicle.status == status:
                        vehicles.append(vehicle)

                return vehicles
            await self._handle_error_response(response)

        except FleetAdapterError:
            raise
        except Exception as e:
            raise FleetAdapterError(f"Failed to get vehicles: {e!s}")

    async def get_vehicle(self, vehicle_id: str) -> Vehicle | None:
        """Get vehicle by ID from Samsara."""
        try:
            client = self._get_client()
            response = await client.get(f"/fleet/vehicles/{vehicle_id}")

            if response.status_code == 200:
                data = response.json()
                return self._parse_vehicle(data["data"])
            if response.status_code == 404:
                return None
            await self._handle_error_response(response)

        except FleetAdapterError:
            raise
        except Exception as e:
            raise FleetAdapterError(f"Failed to get vehicle {vehicle_id}: {e!s}")

    async def get_vehicle_location(self, vehicle_id: str) -> Location | None:
        """Get current vehicle location from Samsara."""
        try:
            client = self._get_client()
            response = await client.get(
                f"/fleet/vehicles/{vehicle_id}/locations/latest"
            )

            if response.status_code == 200:
                data = response.json()
                location_data = data.get("data", {})

                if location_data:
                    return Location(
                        latitude=location_data.get("latitude"),
                        longitude=location_data.get("longitude"),
                        address=location_data.get("address"),
                        timestamp=self._parse_timestamp(location_data.get("time")),
                        accuracy=location_data.get("accuracy"),
                    )
                return None
            if response.status_code == 404:
                return None
            await self._handle_error_response(response)

        except FleetAdapterError:
            raise
        except Exception as e:
            raise FleetAdapterError(
                f"Failed to get vehicle location {vehicle_id}: {e!s}"
            )

    async def get_vehicle_history(
        self, vehicle_id: str, start_time: datetime, end_time: datetime
    ) -> list[TelematicsData]:
        """Get vehicle telematics history from Samsara."""
        try:
            client = self._get_client()

            params = {
                "startTime": start_time.isoformat(),
                "endTime": end_time.isoformat(),
            }

            response = await client.get(
                f"/fleet/vehicles/{vehicle_id}/stats", params=params
            )

            if response.status_code == 200:
                data = response.json()
                telematics_data = []

                for point in data.get("data", []):
                    telematics_data.append(
                        self._parse_telematics_data(vehicle_id, point)
                    )

                return telematics_data
            await self._handle_error_response(response)

        except FleetAdapterError:
            raise
        except Exception as e:
            raise FleetAdapterError(
                f"Failed to get vehicle history {vehicle_id}: {e!s}"
            )

    # Driver Management
    async def get_drivers(
        self,
        status: DriverStatus | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ) -> list[Driver]:
        """Get list of drivers from Samsara."""
        try:
            client = self._get_client()

            params = {}
            if limit:
                params["limit"] = min(limit, 1000)
            if offset:
                params["after"] = str(offset)

            response = await client.get("/fleet/drivers", params=params)

            if response.status_code == 200:
                data = response.json()
                drivers = []

                for driver_data in data.get("data", []):
                    driver = self._parse_driver(driver_data)
                    if status is None or driver.status == status:
                        drivers.append(driver)

                return drivers
            await self._handle_error_response(response)

        except FleetAdapterError:
            raise
        except Exception as e:
            raise FleetAdapterError(f"Failed to get drivers: {e!s}")

    async def get_driver(self, driver_id: str) -> Driver | None:
        """Get driver by ID from Samsara."""
        try:
            client = self._get_client()
            response = await client.get(f"/fleet/drivers/{driver_id}")

            if response.status_code == 200:
                data = response.json()
                return self._parse_driver(data["data"])
            if response.status_code == 404:
                return None
            await self._handle_error_response(response)

        except FleetAdapterError:
            raise
        except Exception as e:
            raise FleetAdapterError(f"Failed to get driver {driver_id}: {e!s}")

    # Route Management
    async def get_routes(
        self,
        vehicle_id: str | None = None,
        driver_id: str | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ) -> list[Route]:
        """Get list of routes from Samsara."""
        try:
            client = self._get_client()

            params = {}
            if vehicle_id:
                params["vehicleId"] = vehicle_id
            if driver_id:
                params["driverId"] = driver_id
            if limit:
                params["limit"] = min(limit, 1000)
            if offset:
                params["after"] = str(offset)

            response = await client.get("/fleet/routes", params=params)

            if response.status_code == 200:
                data = response.json()
                routes = []

                for route_data in data.get("data", []):
                    routes.append(self._parse_route(route_data))

                return routes
            await self._handle_error_response(response)

        except FleetAdapterError:
            raise
        except Exception as e:
            raise FleetAdapterError(f"Failed to get routes: {e!s}")

    async def create_route(self, route: Route) -> str:
        """Create a new route in Samsara."""
        try:
            client = self._get_client()

            route_data = {
                "name": route.name,
                "startLocation": {
                    "latitude": route.start_location.latitude,
                    "longitude": route.start_location.longitude,
                },
                "endLocation": {
                    "latitude": route.end_location.latitude,
                    "longitude": route.end_location.longitude,
                },
                "waypoints": [
                    {"latitude": wp.latitude, "longitude": wp.longitude}
                    for wp in route.waypoints
                ],
                "vehicleId": route.vehicle_id,
                "driverId": route.driver_id,
            }

            response = await client.post("/fleet/routes", json=route_data)

            if response.status_code == 201:
                data = response.json()
                return data["data"]["id"]
            await self._handle_error_response(response)

        except FleetAdapterError:
            raise
        except Exception as e:
            raise FleetAdapterError(f"Failed to create route: {e!s}")

    # Alert Management
    async def get_alerts(
        self,
        vehicle_id: str | None = None,
        driver_id: str | None = None,
        unresolved_only: bool = True,
        limit: int | None = None,
        offset: int | None = None,
    ) -> list[FleetAlert]:
        """Get fleet alerts from Samsara."""
        try:
            client = self._get_client()

            params = {}
            if vehicle_id:
                params["vehicleId"] = vehicle_id
            if driver_id:
                params["driverId"] = driver_id
            if unresolved_only:
                params["resolved"] = "false"
            if limit:
                params["limit"] = min(limit, 1000)
            if offset:
                params["after"] = str(offset)

            response = await client.get("/safety/alerts", params=params)

            if response.status_code == 200:
                data = response.json()
                alerts = []

                for alert_data in data.get("data", []):
                    alerts.append(self._parse_alert(alert_data))

                return alerts
            await self._handle_error_response(response)

        except FleetAdapterError:
            raise
        except Exception as e:
            raise FleetAdapterError(f"Failed to get alerts: {e!s}")

    async def acknowledge_alert(self, alert_id: str) -> bool:
        """Acknowledge an alert in Samsara."""
        try:
            client = self._get_client()

            response = await client.patch(
                f"/safety/alerts/{alert_id}", json={"acknowledged": True}
            )

            return response.status_code == 200

        except Exception as e:
            raise FleetAdapterError(f"Failed to acknowledge alert {alert_id}: {e!s}")

    # Analytics and Reporting
    async def get_fleet_summary(self, date: datetime | None = None) -> FleetSummary:
        """Get fleet summary statistics from Samsara."""
        if date is None:
            date = datetime.now(UTC)

        try:
            client = self._get_client()

            # Get multiple endpoints in parallel
            start_date = date.replace(hour=0, minute=0, second=0, microsecond=0)
            end_date = date.replace(hour=23, minute=59, second=59, microsecond=999999)

            params = {
                "startTime": start_date.isoformat(),
                "endTime": end_date.isoformat(),
            }

            # Make parallel requests
            tasks = [
                client.get("/fleet/vehicles"),
                client.get("/fleet/drivers"),
                client.get("/fleet/stats", params=params),
                client.get("/safety/alerts", params={"resolved": "false"}),
            ]

            responses = await asyncio.gather(*tasks, return_exceptions=True)

            # Parse responses
            vehicles_data = (
                responses[0].json()
                if not isinstance(responses[0], Exception)
                else {"data": []}
            )
            drivers_data = (
                responses[1].json()
                if not isinstance(responses[1], Exception)
                else {"data": []}
            )
            stats_data = (
                responses[2].json()
                if not isinstance(responses[2], Exception)
                else {"data": {}}
            )
            alerts_data = (
                responses[3].json()
                if not isinstance(responses[3], Exception)
                else {"data": []}
            )

            vehicles = vehicles_data.get("data", [])
            drivers = drivers_data.get("data", [])
            stats = stats_data.get("data", {})
            alerts = alerts_data.get("data", [])

            # Count active vehicles and drivers
            active_vehicles = sum(1 for v in vehicles if v.get("status") == "active")
            active_drivers = sum(
                1
                for d in drivers
                if d.get("status") in ["available", "driving", "on_duty"]
            )

            return FleetSummary(
                total_vehicles=len(vehicles),
                active_vehicles=active_vehicles,
                total_drivers=len(drivers),
                active_drivers=active_drivers,
                total_distance_today=stats.get("totalDistance", 0.0),
                total_fuel_consumed_today=stats.get("fuelConsumed", 0.0),
                active_alerts=len(alerts),
                maintenance_due=stats.get("maintenanceDue", 0),
                timestamp=date,
            )

        except Exception as e:
            raise FleetAdapterError(f"Failed to get fleet summary: {e!s}")

    async def get_driver_performance(
        self, driver_id: str, start_date: datetime, end_date: datetime
    ) -> dict[str, Any]:
        """Get driver performance metrics from Samsara."""
        try:
            client = self._get_client()

            params = {
                "startTime": start_date.isoformat(),
                "endTime": end_date.isoformat(),
                "driverId": driver_id,
            }

            response = await client.get("/fleet/drivers/performance", params=params)

            if response.status_code == 200:
                return response.json().get("data", {})
            await self._handle_error_response(response)

        except FleetAdapterError:
            raise
        except Exception as e:
            raise FleetAdapterError(
                f"Failed to get driver performance {driver_id}: {e!s}"
            )

    async def get_vehicle_utilization(
        self, vehicle_id: str, start_date: datetime, end_date: datetime
    ) -> dict[str, Any]:
        """Get vehicle utilization metrics from Samsara."""
        try:
            client = self._get_client()

            params = {
                "startTime": start_date.isoformat(),
                "endTime": end_date.isoformat(),
                "vehicleId": vehicle_id,
            }

            response = await client.get("/fleet/vehicles/utilization", params=params)

            if response.status_code == 200:
                return response.json().get("data", {})
            await self._handle_error_response(response)

        except FleetAdapterError:
            raise
        except Exception as e:
            raise FleetAdapterError(
                f"Failed to get vehicle utilization {vehicle_id}: {e!s}"
            )

    # Helper Methods
    def _parse_vehicle(self, data: dict[str, Any]) -> Vehicle:
        """Parse Samsara vehicle data."""
        location = None
        if "location" in data:
            loc_data = data["location"]
            location = Location(
                latitude=loc_data.get("latitude"),
                longitude=loc_data.get("longitude"),
                address=loc_data.get("address"),
                timestamp=self._parse_timestamp(loc_data.get("time")),
            )

        return Vehicle(
            id=data["id"],
            name=data.get("name", ""),
            license_plate=data.get("licensePlate", ""),
            vin=data.get("vin"),
            make=data.get("make"),
            model=data.get("model"),
            year=data.get("year"),
            status=self._parse_vehicle_status(data.get("status")),
            current_location=location,
            odometer=data.get("odometer"),
            fuel_level=data.get("fuelLevel"),
            engine_hours=data.get("engineHours"),
            last_updated=self._parse_timestamp(data.get("lastUpdated")),
            metadata=data.get("metadata", {}),
        )

    def _parse_driver(self, data: dict[str, Any]) -> Driver:
        """Parse Samsara driver data."""
        location = None
        if "location" in data:
            loc_data = data["location"]
            location = Location(
                latitude=loc_data.get("latitude"),
                longitude=loc_data.get("longitude"),
                timestamp=self._parse_timestamp(loc_data.get("time")),
            )

        return Driver(
            id=data["id"],
            name=data.get("name", ""),
            license_number=data.get("licenseNumber"),
            phone=data.get("phone"),
            email=data.get("email"),
            status=self._parse_driver_status(data.get("status")),
            current_vehicle_id=data.get("currentVehicleId"),
            current_location=location,
            hours_this_week=data.get("hoursThisWeek"),
            last_updated=self._parse_timestamp(data.get("lastUpdated")),
            metadata=data.get("metadata", {}),
        )

    def _parse_route(self, data: dict[str, Any]) -> Route:
        """Parse Samsara route data."""
        start_loc = data.get("startLocation", {})
        end_loc = data.get("endLocation", {})
        waypoints_data = data.get("waypoints", [])

        return Route(
            id=data["id"],
            name=data.get("name", ""),
            start_location=Location(
                latitude=start_loc.get("latitude"), longitude=start_loc.get("longitude")
            ),
            end_location=Location(
                latitude=end_loc.get("latitude"), longitude=end_loc.get("longitude")
            ),
            waypoints=[
                Location(latitude=wp.get("latitude"), longitude=wp.get("longitude"))
                for wp in waypoints_data
            ],
            estimated_duration=data.get("estimatedDuration"),
            estimated_distance=data.get("estimatedDistance"),
            vehicle_id=data.get("vehicleId"),
            driver_id=data.get("driverId"),
            status=data.get("status", "planned"),
            created_at=self._parse_timestamp(data.get("createdAt")),
            metadata=data.get("metadata", {}),
        )

    def _parse_alert(self, data: dict[str, Any]) -> FleetAlert:
        """Parse Samsara alert data."""
        location = None
        if "location" in data:
            loc_data = data["location"]
            location = Location(
                latitude=loc_data.get("latitude"), longitude=loc_data.get("longitude")
            )

        return FleetAlert(
            id=data["id"],
            type=data.get("type", ""),
            severity=self._parse_alert_severity(data.get("severity")),
            message=data.get("message", ""),
            vehicle_id=data.get("vehicleId"),
            driver_id=data.get("driverId"),
            location=location,
            timestamp=self._parse_timestamp(data.get("timestamp")),
            acknowledged=data.get("acknowledged", False),
            resolved=data.get("resolved", False),
            metadata=data.get("metadata", {}),
        )

    def _parse_telematics_data(
        self, vehicle_id: str, data: dict[str, Any]
    ) -> TelematicsData:
        """Parse Samsara telematics data."""
        location = Location(
            latitude=data.get("latitude"), longitude=data.get("longitude")
        )

        return TelematicsData(
            vehicle_id=vehicle_id,
            timestamp=self._parse_timestamp(data.get("time")),
            location=location,
            speed=data.get("speed"),
            heading=data.get("heading"),
            rpm=data.get("rpm"),
            fuel_level=data.get("fuelLevel"),
            engine_temperature=data.get("engineTemperature"),
            odometer=data.get("odometer"),
            engine_hours=data.get("engineHours"),
            harsh_braking=data.get("harshBraking", False),
            harsh_acceleration=data.get("harshAcceleration", False),
            speeding=data.get("speeding", False),
            idle_time=data.get("idleTime"),
            metadata=data.get("metadata", {}),
        )

    def _parse_vehicle_status(self, status: str) -> VehicleStatus:
        """Parse vehicle status."""
        status_map = {
            "active": VehicleStatus.ACTIVE,
            "inactive": VehicleStatus.INACTIVE,
            "maintenance": VehicleStatus.MAINTENANCE,
            "out_of_service": VehicleStatus.OUT_OF_SERVICE,
        }
        return status_map.get(status, VehicleStatus.INACTIVE)

    def _parse_driver_status(self, status: str) -> DriverStatus:
        """Parse driver status."""
        status_map = {
            "available": DriverStatus.AVAILABLE,
            "driving": DriverStatus.DRIVING,
            "on_duty": DriverStatus.ON_DUTY,
            "off_duty": DriverStatus.OFF_DUTY,
            "break": DriverStatus.BREAK,
        }
        return status_map.get(status, DriverStatus.OFF_DUTY)

    def _parse_alert_severity(self, severity: str) -> AlertSeverity:
        """Parse alert severity."""
        severity_map = {
            "low": AlertSeverity.LOW,
            "medium": AlertSeverity.MEDIUM,
            "high": AlertSeverity.HIGH,
            "critical": AlertSeverity.CRITICAL,
        }
        return severity_map.get(severity, AlertSeverity.MEDIUM)

    def _parse_timestamp(self, timestamp: str | None) -> datetime | None:
        """Parse ISO timestamp string."""
        if not timestamp:
            return None

        try:
            return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError:
            return None

    async def _handle_error_response(self, response: httpx.Response) -> None:
        """Handle error responses from Samsara API."""
        try:
            error_data = response.json()
            error_message = error_data.get("message", "Unknown error")
            error_code = error_data.get("code", str(response.status_code))
        except (ValueError, AttributeError, TypeError):
            error_message = response.text or f"HTTP {response.status_code} error"
            error_code = str(response.status_code)

        # Determine if error is retryable
        is_retryable = True
        if response.status_code in [400, 401, 403, 404, 422]:
            is_retryable = False
        elif response.status_code == 429 or response.status_code >= 500:
            is_retryable = True

        raise FleetAdapterError(
            f"Samsara API error ({response.status_code}): {error_message}",
            error_code=error_code,
            is_retryable=is_retryable,
            provider_response=error_data if "error_data" in locals() else None,
        )

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self._client:
            await self._client.aclose()
            self._client = None
