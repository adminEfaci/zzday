"""Geotab vehicle tracking API adapter implementation."""

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


class GeotabAdapter(BaseFleetAdapter):
    """Geotab vehicle tracking API adapter.

    Provides comprehensive vehicle tracking and fleet management:
    - Real-time GPS tracking
    - Vehicle diagnostics and maintenance
    - Driver behavior monitoring
    - Fuel management
    - Hours of service compliance
    - Advanced reporting and analytics
    """

    BASE_URL = "https://my.geotab.com/apiv1"

    def __init__(self, config: dict[str, Any]):
        """Initialize Geotab adapter."""
        super().__init__(config)
        self._client = None
        self._session_id = None

    def _validate_config(self) -> None:
        """Validate Geotab configuration."""
        required_credentials = ["username", "password", "database"]
        for cred in required_credentials:
            if cred not in self.credentials:
                raise ValueError(f"Missing required credential: {cred}")

        # Validate database name format
        database = self.credentials["database"]
        if not database or len(database) < 3:
            raise ValueError("Invalid Geotab database name")

    def _get_client(self) -> httpx.AsyncClient:
        """Get HTTP client."""
        if self._client is None:
            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "EzzDay-Backend/1.0",
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

    async def _authenticate(self) -> str:
        """Authenticate with Geotab and get session ID."""
        if self._session_id:
            return self._session_id

        client = self._get_client()

        auth_data = {
            "method": "Authenticate",
            "params": {
                "userName": self.credentials["username"],
                "password": self.credentials["password"],
                "database": self.credentials["database"],
            },
        }

        try:
            response = await client.post("/", json=auth_data)

            if response.status_code == 200:
                result = response.json()
                if "result" in result:
                    credentials = result["result"]["credentials"]
                    self._session_id = credentials["sessionId"]
                    return self._session_id
                raise FleetAdapterError(
                    f"Authentication failed: {result.get('error', 'Unknown error')}",
                    is_retryable=False,
                )
            raise FleetAdapterError(
                f"Authentication request failed: HTTP {response.status_code}",
                is_retryable=True,
            )

        except httpx.RequestError as e:
            raise FleetAdapterError(
                f"Authentication request error: {e!s}", is_retryable=True
            )

    async def _api_call(
        self, method: str, params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Make authenticated API call to Geotab."""
        session_id = await self._authenticate()

        client = self._get_client()

        request_data = {
            "method": method,
            "params": {
                "credentials": {
                    "sessionId": session_id,
                    "database": self.credentials["database"],
                }
            },
        }

        if params:
            request_data["params"].update(params)

        try:
            response = await client.post("/", json=request_data)

            if response.status_code == 200:
                result = response.json()

                if "result" in result:
                    return result["result"]
                if "error" in result:
                    error = result["error"]
                    # Check if session expired
                    if "InvalidUserException" in str(error):
                        self._session_id = None  # Reset session
                        # Retry once
                        session_id = await self._authenticate()
                        request_data["params"]["credentials"]["sessionId"] = session_id

                        response = await client.post("/", json=request_data)
                        if response.status_code == 200:
                            result = response.json()
                            if "result" in result:
                                return result["result"]

                    raise FleetAdapterError(
                        f"Geotab API error: {error}", is_retryable=True
                    )
                raise FleetAdapterError(
                    "Invalid API response format", is_retryable=True
                )
            raise FleetAdapterError(
                f"API request failed: HTTP {response.status_code}", is_retryable=True
            )

        except httpx.RequestError as e:
            raise FleetAdapterError(f"API request error: {e!s}", is_retryable=True)

    # Vehicle Management
    async def get_vehicles(
        self,
        status: VehicleStatus | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ) -> list[Vehicle]:
        """Get list of vehicles from Geotab."""
        try:
            params = {}
            if limit:
                params["resultsLimit"] = min(limit, 50000)  # Geotab max limit

            result = await self._api_call("Get", {"typeName": "Device", **params})

            vehicles = []
            for device_data in result:
                vehicle = self._parse_vehicle(device_data)
                if status is None or vehicle.status == status:
                    vehicles.append(vehicle)

            # Apply offset manually since Geotab doesn't support it directly
            if offset:
                vehicles = vehicles[offset:]

            return vehicles

        except FleetAdapterError:
            raise
        except Exception as e:
            raise FleetAdapterError(f"Failed to get vehicles: {e!s}")

    async def get_vehicle(self, vehicle_id: str) -> Vehicle | None:
        """Get vehicle by ID from Geotab."""
        try:
            result = await self._api_call(
                "Get", {"typeName": "Device", "search": {"id": vehicle_id}}
            )

            if result:
                return self._parse_vehicle(result[0])
            return None

        except FleetAdapterError:
            raise
        except Exception as e:
            raise FleetAdapterError(f"Failed to get vehicle {vehicle_id}: {e!s}")

    async def get_vehicle_location(self, vehicle_id: str) -> Location | None:
        """Get current vehicle location from Geotab."""
        try:
            result = await self._api_call(
                "Get",
                {
                    "typeName": "DeviceStatusInfo",
                    "search": {"deviceSearch": {"id": vehicle_id}},
                },
            )

            if result:
                status_info = result[0]
                if "latitude" in status_info and "longitude" in status_info:
                    return Location(
                        latitude=status_info["latitude"],
                        longitude=status_info["longitude"],
                        timestamp=self._parse_timestamp(status_info.get("dateTime")),
                    )
            return None

        except FleetAdapterError:
            raise
        except Exception as e:
            raise FleetAdapterError(
                f"Failed to get vehicle location {vehicle_id}: {e!s}"
            )

    async def get_vehicle_history(
        self, vehicle_id: str, start_time: datetime, end_time: datetime
    ) -> list[TelematicsData]:
        """Get vehicle telematics history from Geotab."""
        try:
            # Get GPS data
            gps_result = await self._api_call(
                "Get",
                {
                    "typeName": "LogRecord",
                    "search": {
                        "deviceSearch": {"id": vehicle_id},
                        "fromDate": start_time.isoformat(),
                        "toDate": end_time.isoformat(),
                    },
                },
            )

            # Get status data
            status_result = await self._api_call(
                "Get",
                {
                    "typeName": "StatusData",
                    "search": {
                        "deviceSearch": {"id": vehicle_id},
                        "fromDate": start_time.isoformat(),
                        "toDate": end_time.isoformat(),
                    },
                },
            )

            telematics_data = []

            for gps_point in gps_result:
                telematics_data.append(
                    self._parse_telematics_data(vehicle_id, gps_point, status_result)
                )

            return sorted(telematics_data, key=lambda x: x.timestamp)

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
        """Get list of drivers from Geotab."""
        try:
            params = {}
            if limit:
                params["resultsLimit"] = min(limit, 50000)

            result = await self._api_call("Get", {"typeName": "User", **params})

            drivers = []
            for user_data in result:
                # Filter to only drivers (users with driver license)
                if user_data.get("licenseNumber"):
                    driver = self._parse_driver(user_data)
                    if status is None or driver.status == status:
                        drivers.append(driver)

            if offset:
                drivers = drivers[offset:]

            return drivers

        except FleetAdapterError:
            raise
        except Exception as e:
            raise FleetAdapterError(f"Failed to get drivers: {e!s}")

    async def get_driver(self, driver_id: str) -> Driver | None:
        """Get driver by ID from Geotab."""
        try:
            result = await self._api_call(
                "Get", {"typeName": "User", "search": {"id": driver_id}}
            )

            if result:
                return self._parse_driver(result[0])
            return None

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
        """Get list of routes from Geotab."""
        try:
            search = {}
            if vehicle_id:
                search["deviceSearch"] = {"id": vehicle_id}
            if driver_id:
                search["userSearch"] = {"id": driver_id}

            params = {}
            if limit:
                params["resultsLimit"] = min(limit, 50000)
            if search:
                params["search"] = search

            result = await self._api_call("Get", {"typeName": "Route", **params})

            routes = []
            for route_data in result:
                routes.append(self._parse_route(route_data))

            if offset:
                routes = routes[offset:]

            return routes

        except FleetAdapterError:
            raise
        except Exception as e:
            raise FleetAdapterError(f"Failed to get routes: {e!s}")

    async def create_route(self, route: Route) -> str:
        """Create a new route in Geotab."""
        try:
            route_data = {
                "name": route.name,
                "zones": [
                    {
                        "centrePoint": {
                            "x": route.start_location.longitude,
                            "y": route.start_location.latitude,
                        }
                    },
                    {
                        "centrePoint": {
                            "x": route.end_location.longitude,
                            "y": route.end_location.latitude,
                        }
                    },
                ],
            }

            # Add waypoints as additional zones
            for waypoint in route.waypoints:
                route_data["zones"].append(
                    {"centrePoint": {"x": waypoint.longitude, "y": waypoint.latitude}}
                )

            return await self._api_call(
                "Add", {"typeName": "Route", "entity": route_data}
            )

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
        """Get fleet alerts from Geotab."""
        try:
            search = {}
            if vehicle_id:
                search["deviceSearch"] = {"id": vehicle_id}
            if driver_id:
                search["userSearch"] = {"id": driver_id}

            params = {}
            if limit:
                params["resultsLimit"] = min(limit, 50000)
            if search:
                params["search"] = search

            # Get exceptions (Geotab's term for alerts)
            result = await self._api_call(
                "Get", {"typeName": "ExceptionEvent", **params}
            )

            alerts = []
            for exception_data in result:
                alert = self._parse_alert(exception_data)

                # Filter resolved alerts if requested
                if unresolved_only and alert.resolved:
                    continue

                alerts.append(alert)

            if offset:
                alerts = alerts[offset:]

            return alerts

        except FleetAdapterError:
            raise
        except Exception as e:
            raise FleetAdapterError(f"Failed to get alerts: {e!s}")

    async def acknowledge_alert(self, alert_id: str) -> bool:
        """Acknowledge an alert in Geotab."""
        try:
            # Geotab doesn't have direct acknowledgment, but we can add a comment
            result = await self._api_call(
                "Add",
                {
                    "typeName": "AnnotationLog",
                    "entity": {
                        "exceptionEvent": {"id": alert_id},
                        "comment": "Alert acknowledged via EzzDay integration",
                        "dateTime": datetime.utcnow().isoformat(),
                    },
                },
            )

            return bool(result)

        except Exception as e:
            raise FleetAdapterError(f"Failed to acknowledge alert {alert_id}: {e!s}")

    # Analytics and Reporting
    async def get_fleet_summary(self, date: datetime | None = None) -> FleetSummary:
        """Get fleet summary statistics from Geotab."""
        if date is None:
            date = datetime.now(UTC)

        try:
            # Get vehicles and drivers counts
            vehicles_task = self._api_call("Get", {"typeName": "Device"})
            drivers_task = self._api_call("Get", {"typeName": "User"})

            vehicles_result, drivers_result = await asyncio.gather(
                vehicles_task, drivers_task
            )

            # Filter drivers to only those with license numbers
            drivers = [d for d in drivers_result if d.get("licenseNumber")]

            # Count active vehicles (those with recent data)
            active_vehicles = len(
                [v for v in vehicles_result if not v.get("isArchived", False)]
            )

            # Count active drivers (simplified - all non-archived)
            active_drivers = len([d for d in drivers if not d.get("isArchived", False)])

            # Get alerts
            alerts_result = await self._api_call("Get", {"typeName": "ExceptionEvent"})
            active_alerts = len(
                [a for a in alerts_result if not a.get("isResolved", False)]
            )

            return FleetSummary(
                total_vehicles=len(vehicles_result),
                active_vehicles=active_vehicles,
                total_drivers=len(drivers),
                active_drivers=active_drivers,
                total_distance_today=0.0,  # Would need separate calculation
                total_fuel_consumed_today=0.0,  # Would need separate calculation
                active_alerts=active_alerts,
                maintenance_due=0,  # Would need separate calculation
                timestamp=date,
            )

        except Exception as e:
            raise FleetAdapterError(f"Failed to get fleet summary: {e!s}")

    async def get_driver_performance(
        self, driver_id: str, start_date: datetime, end_date: datetime
    ) -> dict[str, Any]:
        """Get driver performance metrics from Geotab."""
        try:
            # Get driver trips
            trips_result = await self._api_call(
                "Get",
                {
                    "typeName": "Trip",
                    "search": {
                        "driverSearch": {"id": driver_id},
                        "fromDate": start_date.isoformat(),
                        "toDate": end_date.isoformat(),
                    },
                },
            )

            # Get exception events
            exceptions_result = await self._api_call(
                "Get",
                {
                    "typeName": "ExceptionEvent",
                    "search": {
                        "userSearch": {"id": driver_id},
                        "fromDate": start_date.isoformat(),
                        "toDate": end_date.isoformat(),
                    },
                },
            )

            # Calculate performance metrics
            total_distance = sum(trip.get("distance", 0) for trip in trips_result)
            total_driving_time = sum(
                trip.get("drivingDuration", 0) for trip in trips_result
            )
            safety_events = len(exceptions_result)

            return {
                "driver_id": driver_id,
                "period_start": start_date.isoformat(),
                "period_end": end_date.isoformat(),
                "total_trips": len(trips_result),
                "total_distance": total_distance,
                "total_driving_time": total_driving_time,
                "safety_events": safety_events,
                "average_speed": total_distance / (total_driving_time / 3600)
                if total_driving_time > 0
                else 0,
            }

        except FleetAdapterError:
            raise
        except Exception as e:
            raise FleetAdapterError(
                f"Failed to get driver performance {driver_id}: {e!s}"
            )

    async def get_vehicle_utilization(
        self, vehicle_id: str, start_date: datetime, end_date: datetime
    ) -> dict[str, Any]:
        """Get vehicle utilization metrics from Geotab."""
        try:
            # Get vehicle trips
            trips_result = await self._api_call(
                "Get",
                {
                    "typeName": "Trip",
                    "search": {
                        "deviceSearch": {"id": vehicle_id},
                        "fromDate": start_date.isoformat(),
                        "toDate": end_date.isoformat(),
                    },
                },
            )

            # Calculate utilization metrics
            total_distance = sum(trip.get("distance", 0) for trip in trips_result)
            total_driving_time = sum(
                trip.get("drivingDuration", 0) for trip in trips_result
            )
            total_idle_time = sum(trip.get("idleDuration", 0) for trip in trips_result)

            period_duration = (end_date - start_date).total_seconds()
            utilization_percentage = (
                (total_driving_time / period_duration * 100)
                if period_duration > 0
                else 0
            )

            return {
                "vehicle_id": vehicle_id,
                "period_start": start_date.isoformat(),
                "period_end": end_date.isoformat(),
                "total_trips": len(trips_result),
                "total_distance": total_distance,
                "total_driving_time": total_driving_time,
                "total_idle_time": total_idle_time,
                "utilization_percentage": utilization_percentage,
            }

        except FleetAdapterError:
            raise
        except Exception as e:
            raise FleetAdapterError(
                f"Failed to get vehicle utilization {vehicle_id}: {e!s}"
            )

    # Helper Methods
    def _parse_vehicle(self, data: dict[str, Any]) -> Vehicle:
        """Parse Geotab device data to Vehicle."""
        return Vehicle(
            id=data["id"],
            name=data.get("name", ""),
            license_plate=data.get("licensePlate", ""),
            vin=data.get("vehicleIdentificationNumber"),
            make=data.get("make"),
            model=data.get("model"),
            year=data.get("modelYear"),
            status=VehicleStatus.ACTIVE
            if not data.get("isArchived", False)
            else VehicleStatus.INACTIVE,
            odometer=data.get("odometer"),
            last_updated=self._parse_timestamp(data.get("lastUpdated")),
            metadata={
                "serialNumber": data.get("serialNumber"),
                "workTime": data.get("workTime"),
                "comment": data.get("comment"),
            },
        )

    def _parse_driver(self, data: dict[str, Any]) -> Driver:
        """Parse Geotab user data to Driver."""
        return Driver(
            id=data["id"],
            name=data.get("name", ""),
            license_number=data.get("licenseNumber"),
            phone=data.get("phoneNumber"),
            email=data.get("emailAddress"),
            status=DriverStatus.AVAILABLE
            if data.get("isActive", True)
            else DriverStatus.OFF_DUTY,
            last_updated=self._parse_timestamp(data.get("lastAccessDate")),
            metadata={
                "employeeNo": data.get("employeeNo"),
                "comment": data.get("comment"),
                "isActive": data.get("isActive", True),
            },
        )

    def _parse_route(self, data: dict[str, Any]) -> Route:
        """Parse Geotab route data."""
        zones = data.get("zones", [])

        # Extract start and end locations from zones
        start_location = Location(latitude=0, longitude=0)
        end_location = Location(latitude=0, longitude=0)
        waypoints = []

        if zones:
            if len(zones) >= 1:
                start_point = zones[0].get("centrePoint", {})
                start_location = Location(
                    latitude=start_point.get("y", 0), longitude=start_point.get("x", 0)
                )

            if len(zones) >= 2:
                end_point = zones[-1].get("centrePoint", {})
                end_location = Location(
                    latitude=end_point.get("y", 0), longitude=end_point.get("x", 0)
                )

            # Middle zones are waypoints
            for zone in zones[1:-1]:
                point = zone.get("centrePoint", {})
                waypoints.append(
                    Location(latitude=point.get("y", 0), longitude=point.get("x", 0))
                )

        return Route(
            id=data["id"],
            name=data.get("name", ""),
            start_location=start_location,
            end_location=end_location,
            waypoints=waypoints,
            metadata={"comment": data.get("comment"), "zones": zones},
        )

    def _parse_alert(self, data: dict[str, Any]) -> FleetAlert:
        """Parse Geotab exception event to FleetAlert."""
        rule = data.get("rule", {})

        return FleetAlert(
            id=data["id"],
            type=rule.get("name", "Unknown"),
            severity=AlertSeverity.MEDIUM,  # Geotab doesn't provide severity directly
            message=data.get("comment", rule.get("name", "Alert")),
            vehicle_id=data.get("device", {}).get("id"),
            driver_id=data.get("driver", {}).get("id"),
            timestamp=self._parse_timestamp(data.get("dateTime")),
            resolved=data.get("isResolved", False),
            metadata={
                "rule": rule,
                "state": data.get("state"),
                "duration": data.get("duration"),
            },
        )

    def _parse_telematics_data(
        self,
        vehicle_id: str,
        gps_data: dict[str, Any],
        status_data: list[dict[str, Any]],
    ) -> TelematicsData:
        """Parse Geotab GPS and status data to TelematicsData."""
        timestamp = self._parse_timestamp(gps_data.get("dateTime"))

        # Find matching status data by timestamp
        matching_status = None
        if timestamp and status_data:
            for status in status_data:
                status_time = self._parse_timestamp(status.get("dateTime"))
                if status_time and abs((timestamp - status_time).total_seconds()) < 60:
                    matching_status = status
                    break

        location = Location(
            latitude=gps_data.get("latitude", 0),
            longitude=gps_data.get("longitude", 0),
            timestamp=timestamp,
        )

        return TelematicsData(
            vehicle_id=vehicle_id,
            timestamp=timestamp or datetime.utcnow(),
            location=location,
            speed=gps_data.get("speed"),
            heading=gps_data.get("bearing"),
            odometer=matching_status.get("odometer") if matching_status else None,
            metadata={"gps_data": gps_data, "status_data": matching_status},
        )

    def _parse_timestamp(self, timestamp: str | None) -> datetime | None:
        """Parse Geotab timestamp string."""
        if not timestamp:
            return None

        try:
            # Geotab uses .NET DateTime format
            if timestamp.endswith("Z"):
                return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            return datetime.fromisoformat(timestamp)
        except ValueError:
            return None

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self._client:
            await self._client.aclose()
            self._client = None
        self._session_id = None
