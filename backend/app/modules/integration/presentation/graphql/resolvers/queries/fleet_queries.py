"""
Fleet Management Queries for GraphQL API

This module provides comprehensive fleet management queries including
vehicle tracking, driver management, route optimization, and telemetry data.
"""

from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

import strawberry

from app.core.errors import ValidationError
from app.core.logging import get_logger
from app.core.middleware.auth import require_auth, require_permission
from app.modules.identity.presentation.graphql.decorators import (
    audit_operation,
    rate_limit,
    track_metrics,
)

from ...schemas.inputs.fleet_inputs import (
    DateRangeInput,
    FleetFilterInput,
    LocationFilterInput,
    TelemetryFilterInput,
    TripFilterInput,
    VehicleFilterInput,
)
from ...schemas.types.fleet_type import (
    Driver,
    FleetProvider,
    FleetStatistics,
    FuelData,
    MaintenanceRecord,
    SafetyEvent,
    TripSummary,
    Vehicle,
    VehicleLocation,
    VehicleTelemetry,
)

logger = get_logger(__name__)


@strawberry.type
class FleetQueries:
    """Fleet management GraphQL queries."""

    @strawberry.field(description="Get available fleet providers")
    @require_auth()
    @require_permission("fleet.providers.read")
    @audit_operation("fleet.get_providers")
    @rate_limit(requests=50, window=60)
    @track_metrics("get_fleet_providers")
    async def get_fleet_providers(
        self, info: strawberry.Info, include_inactive: bool = False
    ) -> list[FleetProvider]:
        """
        Get list of available fleet management providers.

        Args:
            include_inactive: Whether to include inactive providers

        Returns:
            List of fleet providers with capabilities
        """
        try:
            service = info.context["container"].resolve("FleetProviderService")
            result = await service.get_providers(include_inactive=include_inactive)

            mapper = info.context["container"].resolve("FleetMapper")
            return [
                mapper.provider_dto_to_graphql_type(provider) for provider in result
            ]

        except Exception as e:
            logger.exception("Error retrieving fleet providers", error=str(e))
            raise

    @strawberry.field(description="Get vehicles from fleet")
    @require_auth()
    @require_permission("fleet.vehicles.read")
    @audit_operation("fleet.get_vehicles")
    @rate_limit(requests=100, window=60)
    @track_metrics("get_fleet_vehicles")
    async def get_fleet_vehicles(
        self,
        info: strawberry.Info,
        integration_id: UUID,
        filters: VehicleFilterInput | None = None,
        pagination: PaginationInput | None = None,
    ) -> list[Vehicle]:
        """
        Get vehicles from a fleet management system.

        Args:
            integration_id: UUID of the fleet integration
            filters: Optional vehicle filtering criteria
            pagination: Optional pagination parameters

        Returns:
            List of vehicles
        """
        try:
            service = info.context["container"].resolve("FleetVehicleService")
            result = await service.get_vehicles(
                integration_id=integration_id,
                filters=filters,
                pagination=pagination or PaginationInput(page=1, page_size=50),
            )

            mapper = info.context["container"].resolve("FleetMapper")
            return [mapper.vehicle_dto_to_graphql_type(vehicle) for vehicle in result]

        except Exception as e:
            logger.exception(
                "Error retrieving fleet vehicles",
                integration_id=str(integration_id),
                error=str(e),
            )
            raise

    @strawberry.field(description="Get vehicle by ID")
    @require_auth()
    @require_permission("fleet.vehicle.read")
    @audit_operation("fleet.get_vehicle")
    @rate_limit(requests=150, window=60)
    @track_metrics("get_vehicle")
    async def get_vehicle(
        self, info: strawberry.Info, integration_id: UUID, vehicle_id: str
    ) -> Vehicle | None:
        """
        Get detailed vehicle information.

        Args:
            integration_id: UUID of the fleet integration
            vehicle_id: External vehicle identifier

        Returns:
            Vehicle details or None if not found
        """
        try:
            service = info.context["container"].resolve("FleetVehicleService")
            result = await service.get_vehicle(
                integration_id=integration_id, vehicle_id=vehicle_id
            )

            if not result:
                return None

            mapper = info.context["container"].resolve("FleetMapper")
            return mapper.vehicle_dto_to_graphql_type(result)

        except Exception as e:
            logger.exception(
                "Error retrieving vehicle",
                integration_id=str(integration_id),
                vehicle_id=vehicle_id,
                error=str(e),
            )
            raise

    @strawberry.field(description="Get real-time vehicle locations")
    @require_auth()
    @require_permission("fleet.locations.read")
    @audit_operation("fleet.get_vehicle_locations")
    @rate_limit(requests=200, window=60)
    @track_metrics("get_vehicle_locations")
    async def get_vehicle_locations(
        self,
        info: strawberry.Info,
        integration_id: UUID,
        vehicle_ids: list[str] | None = None,
        filters: LocationFilterInput | None = None,
    ) -> list[VehicleLocation]:
        """
        Get real-time vehicle locations.

        Args:
            integration_id: UUID of the fleet integration
            vehicle_ids: Optional specific vehicle IDs to filter
            filters: Optional location filtering criteria

        Returns:
            List of vehicle locations
        """
        try:
            if vehicle_ids and len(vehicle_ids) > 100:
                raise ValidationError("Maximum 100 vehicle IDs allowed")

            service = info.context["container"].resolve("FleetLocationService")
            result = await service.get_vehicle_locations(
                integration_id=integration_id, vehicle_ids=vehicle_ids, filters=filters
            )

            mapper = info.context["container"].resolve("FleetMapper")
            return [
                mapper.location_dto_to_graphql_type(location) for location in result
            ]

        except ValidationError:
            raise
        except Exception as e:
            logger.exception(
                "Error retrieving vehicle locations",
                integration_id=str(integration_id),
                error=str(e),
            )
            raise

    @strawberry.field(description="Get vehicle telemetry data")
    @require_auth()
    @require_permission("fleet.telemetry.read")
    @audit_operation("fleet.get_vehicle_telemetry")
    @rate_limit(requests=50, window=60)
    @track_metrics("get_vehicle_telemetry")
    async def get_vehicle_telemetry(
        self,
        info: strawberry.Info,
        integration_id: UUID,
        vehicle_id: str,
        filters: TelemetryFilterInput | None = None,
    ) -> list[VehicleTelemetry]:
        """
        Get telemetry data for a specific vehicle.

        Args:
            integration_id: UUID of the fleet integration
            vehicle_id: External vehicle identifier
            filters: Optional telemetry filtering criteria

        Returns:
            List of telemetry data points
        """
        try:
            service = info.context["container"].resolve("FleetTelemetryService")
            result = await service.get_vehicle_telemetry(
                integration_id=integration_id, vehicle_id=vehicle_id, filters=filters
            )

            mapper = info.context["container"].resolve("FleetMapper")
            return [
                mapper.telemetry_dto_to_graphql_type(telemetry) for telemetry in result
            ]

        except Exception as e:
            logger.exception(
                "Error retrieving vehicle telemetry",
                integration_id=str(integration_id),
                vehicle_id=vehicle_id,
                error=str(e),
            )
            raise

    @strawberry.field(description="Get fleet drivers")
    @require_auth()
    @require_permission("fleet.drivers.read")
    @audit_operation("fleet.get_drivers")
    @rate_limit(requests=80, window=60)
    @track_metrics("get_fleet_drivers")
    async def get_fleet_drivers(
        self,
        info: strawberry.Info,
        integration_id: UUID,
        filters: FleetFilterInput | None = None,
        pagination: PaginationInput | None = None,
    ) -> list[Driver]:
        """
        Get drivers from fleet management system.

        Args:
            integration_id: UUID of the fleet integration
            filters: Optional driver filtering criteria
            pagination: Optional pagination parameters

        Returns:
            List of drivers
        """
        try:
            service = info.context["container"].resolve("FleetDriverService")
            result = await service.get_drivers(
                integration_id=integration_id,
                filters=filters,
                pagination=pagination or PaginationInput(page=1, page_size=50),
            )

            mapper = info.context["container"].resolve("FleetMapper")
            return [mapper.driver_dto_to_graphql_type(driver) for driver in result]

        except Exception as e:
            logger.exception(
                "Error retrieving fleet drivers",
                integration_id=str(integration_id),
                error=str(e),
            )
            raise

    @strawberry.field(description="Get trip summaries")
    @require_auth()
    @require_permission("fleet.trips.read")
    @audit_operation("fleet.get_trip_summaries")
    @rate_limit(requests=60, window=60)
    @track_metrics("get_trip_summaries")
    async def get_trip_summaries(
        self,
        info: strawberry.Info,
        integration_id: UUID,
        filters: TripFilterInput | None = None,
        pagination: PaginationInput | None = None,
    ) -> list[TripSummary]:
        """
        Get trip summaries from fleet data.

        Args:
            integration_id: UUID of the fleet integration
            filters: Optional trip filtering criteria
            pagination: Optional pagination parameters

        Returns:
            List of trip summaries
        """
        try:
            service = info.context["container"].resolve("FleetTripService")
            result = await service.get_trip_summaries(
                integration_id=integration_id,
                filters=filters,
                pagination=pagination or PaginationInput(page=1, page_size=50),
            )

            mapper = info.context["container"].resolve("FleetMapper")
            return [mapper.trip_summary_dto_to_graphql_type(trip) for trip in result]

        except Exception as e:
            logger.exception(
                "Error retrieving trip summaries",
                integration_id=str(integration_id),
                error=str(e),
            )
            raise

    @strawberry.field(description="Get fleet statistics")
    @require_auth()
    @require_permission("fleet.statistics.read")
    @audit_operation("fleet.get_statistics")
    @rate_limit(requests=25, window=60)
    @track_metrics("get_fleet_statistics")
    async def get_fleet_statistics(
        self,
        info: strawberry.Info,
        integration_id: UUID,
        date_range: DateRangeInput | None = None,
    ) -> FleetStatistics:
        """
        Get comprehensive fleet statistics.

        Args:
            integration_id: UUID of the fleet integration
            date_range: Optional date range for statistics

        Returns:
            Fleet statistics data
        """
        try:
            # Default to last 30 days if no range provided
            if not date_range:
                end_date = datetime.now()
                start_date = end_date - timedelta(days=30)
                date_range = DateRangeInput(start_date=start_date, end_date=end_date)

            # Validate date range
            if date_range.end_date <= date_range.start_date:
                raise ValidationError("End date must be after start date")

            days_diff = (date_range.end_date - date_range.start_date).days
            if days_diff > 365:
                raise ValidationError("Date range cannot exceed 365 days")

            service = info.context["container"].resolve("FleetStatisticsService")
            result = await service.get_fleet_statistics(
                integration_id=integration_id, date_range=date_range
            )

            mapper = info.context["container"].resolve("FleetMapper")
            return mapper.statistics_dto_to_graphql_type(result)

        except ValidationError:
            raise
        except Exception as e:
            logger.exception(
                "Error retrieving fleet statistics",
                integration_id=str(integration_id),
                error=str(e),
            )
            raise

    @strawberry.field(description="Get vehicle maintenance records")
    @require_auth()
    @require_permission("fleet.maintenance.read")
    @audit_operation("fleet.get_maintenance_records")
    @rate_limit(requests=40, window=60)
    @track_metrics("get_maintenance_records")
    async def get_maintenance_records(
        self,
        info: strawberry.Info,
        integration_id: UUID,
        vehicle_id: str | None = None,
        date_range: DateRangeInput | None = None,
        pagination: PaginationInput | None = None,
    ) -> list[MaintenanceRecord]:
        """
        Get vehicle maintenance records.

        Args:
            integration_id: UUID of the fleet integration
            vehicle_id: Optional specific vehicle ID
            date_range: Optional date range filter
            pagination: Optional pagination parameters

        Returns:
            List of maintenance records
        """
        try:
            service = info.context["container"].resolve("FleetMaintenanceService")
            result = await service.get_maintenance_records(
                integration_id=integration_id,
                vehicle_id=vehicle_id,
                date_range=date_range,
                pagination=pagination or PaginationInput(page=1, page_size=50),
            )

            mapper = info.context["container"].resolve("FleetMapper")
            return [
                mapper.maintenance_record_dto_to_graphql_type(record)
                for record in result
            ]

        except Exception as e:
            logger.exception(
                "Error retrieving maintenance records",
                integration_id=str(integration_id),
                error=str(e),
            )
            raise

    @strawberry.field(description="Get safety events")
    @require_auth()
    @require_permission("fleet.safety.read")
    @audit_operation("fleet.get_safety_events")
    @rate_limit(requests=60, window=60)
    @track_metrics("get_safety_events")
    async def get_safety_events(
        self,
        info: strawberry.Info,
        integration_id: UUID,
        vehicle_id: str | None = None,
        driver_id: str | None = None,
        severity_levels: list[str] | None = None,
        date_range: DateRangeInput | None = None,
        pagination: PaginationInput | None = None,
    ) -> list[SafetyEvent]:
        """
        Get safety events and violations.

        Args:
            integration_id: UUID of the fleet integration
            vehicle_id: Optional specific vehicle ID
            driver_id: Optional specific driver ID
            severity_levels: Optional severity level filters
            date_range: Optional date range filter
            pagination: Optional pagination parameters

        Returns:
            List of safety events
        """
        try:
            service = info.context["container"].resolve("FleetSafetyService")
            result = await service.get_safety_events(
                integration_id=integration_id,
                vehicle_id=vehicle_id,
                driver_id=driver_id,
                severity_levels=severity_levels,
                date_range=date_range,
                pagination=pagination or PaginationInput(page=1, page_size=50),
            )

            mapper = info.context["container"].resolve("FleetMapper")
            return [mapper.safety_event_dto_to_graphql_type(event) for event in result]

        except Exception as e:
            logger.exception(
                "Error retrieving safety events",
                integration_id=str(integration_id),
                error=str(e),
            )
            raise

    @strawberry.field(description="Get fuel data")
    @require_auth()
    @require_permission("fleet.fuel.read")
    @audit_operation("fleet.get_fuel_data")
    @rate_limit(requests=40, window=60)
    @track_metrics("get_fuel_data")
    async def get_fuel_data(
        self,
        info: strawberry.Info,
        integration_id: UUID,
        vehicle_id: str | None = None,
        date_range: DateRangeInput | None = None,
        pagination: PaginationInput | None = None,
    ) -> list[FuelData]:
        """
        Get fuel consumption and cost data.

        Args:
            integration_id: UUID of the fleet integration
            vehicle_id: Optional specific vehicle ID
            date_range: Optional date range filter
            pagination: Optional pagination parameters

        Returns:
            List of fuel data records
        """
        try:
            service = info.context["container"].resolve("FleetFuelService")
            result = await service.get_fuel_data(
                integration_id=integration_id,
                vehicle_id=vehicle_id,
                date_range=date_range,
                pagination=pagination or PaginationInput(page=1, page_size=100),
            )

            mapper = info.context["container"].resolve("FleetMapper")
            return [mapper.fuel_data_dto_to_graphql_type(fuel) for fuel in result]

        except Exception as e:
            logger.exception(
                "Error retrieving fuel data",
                integration_id=str(integration_id),
                error=str(e),
            )
            raise

    @strawberry.field(description="Get vehicle route history")
    @require_auth()
    @require_permission("fleet.routes.read")
    @audit_operation("fleet.get_route_history")
    @rate_limit(requests=30, window=60)
    @track_metrics("get_vehicle_route_history")
    async def get_vehicle_route_history(
        self,
        info: strawberry.Info,
        integration_id: UUID,
        vehicle_id: str,
        date_range: DateRangeInput,
        include_stops: bool = True,
    ) -> dict[str, Any]:
        """
        Get historical route data for a vehicle.

        Args:
            integration_id: UUID of the fleet integration
            vehicle_id: External vehicle identifier
            date_range: Date range for route history
            include_stops: Whether to include stop information

        Returns:
            Route history data
        """
        try:
            # Validate date range
            if date_range.end_date <= date_range.start_date:
                raise ValidationError("End date must be after start date")

            days_diff = (date_range.end_date - date_range.start_date).days
            if days_diff > 7:
                raise ValidationError("Maximum date range is 7 days for route history")

            service = info.context["container"].resolve("FleetRouteHistoryService")
            result = await service.get_vehicle_route_history(
                integration_id=integration_id,
                vehicle_id=vehicle_id,
                date_range=date_range,
                include_stops=include_stops,
            )

            return {
                "vehicle_id": vehicle_id,
                "date_range": {
                    "start_date": date_range.start_date,
                    "end_date": date_range.end_date,
                },
                "total_distance_km": result.total_distance_km,
                "total_duration_minutes": result.total_duration_minutes,
                "average_speed_kmh": result.average_speed_kmh,
                "route_points": [
                    {
                        "timestamp": point.timestamp,
                        "latitude": point.latitude,
                        "longitude": point.longitude,
                        "speed_kmh": point.speed_kmh,
                        "heading": point.heading,
                        "altitude_m": point.altitude_m,
                    }
                    for point in result.route_points
                ],
                "stops": [
                    {
                        "stop_id": stop.stop_id,
                        "name": stop.name,
                        "address": stop.address,
                        "latitude": stop.latitude,
                        "longitude": stop.longitude,
                        "arrival_time": stop.arrival_time,
                        "departure_time": stop.departure_time,
                        "duration_minutes": stop.duration_minutes,
                        "stop_type": stop.stop_type,
                    }
                    for stop in result.stops
                ]
                if include_stops
                else [],
            }

        except ValidationError:
            raise
        except Exception as e:
            logger.exception(
                "Error retrieving vehicle route history",
                integration_id=str(integration_id),
                vehicle_id=vehicle_id,
                error=str(e),
            )
            raise


__all__ = ["FleetQueries"]
