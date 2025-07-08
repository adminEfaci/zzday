"""
Mapping Service Queries for GraphQL API

This module provides comprehensive mapping service queries including
geocoding, routing, mapping data, and location services.
"""

from decimal import Decimal
from typing import Any

import strawberry

from app.core.errors import ValidationError
from app.core.logging import get_logger
from app.core.middleware.auth import require_auth, require_permission
from app.modules.identity.presentation.graphql.decorators import (
    audit_operation,
    rate_limit,
    track_metrics,
)

from ...schemas.inputs.mapping_inputs import (
    DistanceMatrixInput,
    ElevationInput,
    GeocodingInput,
    PlaceSearchInput,
    RouteInput,
)
from ...schemas.types.mapping_type import (
    DistanceMatrix,
    ElevationData,
    GeocodingResult,
    MappingCapabilities,
    MappingProvider,
    PlaceDetails,
    RouteResult,
)

logger = get_logger(__name__)


@strawberry.type
class MappingQueries:
    """Mapping service GraphQL queries."""

    @strawberry.field(description="Get available mapping providers")
    @require_auth()
    @require_permission("mapping.providers.read")
    @audit_operation("mapping.get_providers")
    @rate_limit(requests=50, window=60)
    @track_metrics("get_mapping_providers")
    async def get_mapping_providers(
        self, info: strawberry.Info, include_inactive: bool = False
    ) -> list[MappingProvider]:
        """
        Get list of available mapping service providers.

        Args:
            include_inactive: Whether to include inactive providers

        Returns:
            List of mapping providers with capabilities
        """
        try:
            service = info.context["container"].resolve("MappingProviderService")
            result = await service.get_providers(include_inactive=include_inactive)

            mapper = info.context["container"].resolve("MappingMapper")
            return [
                mapper.provider_dto_to_graphql_type(provider) for provider in result
            ]

        except Exception as e:
            logger.exception("Error retrieving mapping providers", error=str(e))
            raise

    @strawberry.field(description="Geocode an address to coordinates")
    @require_auth()
    @require_permission("mapping.geocoding.forward")
    @audit_operation("mapping.geocode_address")
    @rate_limit(requests=100, window=60)
    @track_metrics("geocode_address")
    async def geocode_address(
        self, info: strawberry.Info, input: GeocodingInput
    ) -> list[GeocodingResult]:
        """
        Convert an address to geographic coordinates.

        Args:
            input: Geocoding input parameters

        Returns:
            List of geocoding results
        """
        try:
            # Validate input
            if not input.query or len(input.query.strip()) < 3:
                raise ValidationError("Address query must be at least 3 characters")

            service = info.context["container"].resolve("GeocodingService")
            result = await service.geocode_address(input)

            mapper = info.context["container"].resolve("MappingMapper")
            return [
                mapper.geocoding_result_dto_to_graphql_type(item) for item in result
            ]

        except ValidationError:
            raise
        except Exception as e:
            logger.exception("Error geocoding address", query=input.query, error=str(e))
            raise

    @strawberry.field(description="Reverse geocode coordinates to address")
    @require_auth()
    @require_permission("mapping.geocoding.reverse")
    @audit_operation("mapping.reverse_geocode")
    @rate_limit(requests=100, window=60)
    @track_metrics("reverse_geocode")
    async def reverse_geocode(
        self,
        info: strawberry.Info,
        latitude: Decimal,
        longitude: Decimal,
        provider: str | None = None,
    ) -> list[GeocodingResult]:
        """
        Convert geographic coordinates to address.

        Args:
            latitude: Latitude coordinate
            longitude: Longitude coordinate
            provider: Optional specific provider to use

        Returns:
            List of reverse geocoding results
        """
        try:
            # Validate coordinates
            if not (-90 <= latitude <= 90):
                raise ValidationError("Latitude must be between -90 and 90")

            if not (-180 <= longitude <= 180):
                raise ValidationError("Longitude must be between -180 and 180")

            service = info.context["container"].resolve("GeocodingService")
            result = await service.reverse_geocode(
                latitude=latitude, longitude=longitude, provider=provider
            )

            mapper = info.context["container"].resolve("MappingMapper")
            return [
                mapper.geocoding_result_dto_to_graphql_type(item) for item in result
            ]

        except ValidationError:
            raise
        except Exception as e:
            logger.exception(
                "Error reverse geocoding",
                latitude=str(latitude),
                longitude=str(longitude),
                error=str(e),
            )
            raise

    @strawberry.field(description="Calculate route between locations")
    @require_auth()
    @require_permission("mapping.routing.calculate")
    @audit_operation("mapping.calculate_route")
    @rate_limit(requests=50, window=60)
    @track_metrics("calculate_route")
    async def calculate_route(
        self, info: strawberry.Info, input: RouteInput
    ) -> RouteResult:
        """
        Calculate route between origin and destination.

        Args:
            input: Route calculation input parameters

        Returns:
            Route calculation result
        """
        try:
            # Validate waypoints
            if len(input.waypoints) < 2:
                raise ValidationError(
                    "At least 2 waypoints (origin and destination) are required"
                )

            if len(input.waypoints) > 25:
                raise ValidationError("Maximum 25 waypoints allowed")

            service = info.context["container"].resolve("RoutingService")
            result = await service.calculate_route(input)

            mapper = info.context["container"].resolve("MappingMapper")
            return mapper.route_result_dto_to_graphql_type(result)

        except ValidationError:
            raise
        except Exception as e:
            logger.exception("Error calculating route", error=str(e))
            raise

    @strawberry.field(description="Search for places")
    @require_auth()
    @require_permission("mapping.places.search")
    @audit_operation("mapping.search_places")
    @rate_limit(requests=80, window=60)
    @track_metrics("search_places")
    async def search_places(
        self, info: strawberry.Info, input: PlaceSearchInput
    ) -> list[PlaceDetails]:
        """
        Search for places by name, category, or location.

        Args:
            input: Place search input parameters

        Returns:
            List of place details
        """
        try:
            # Validate search query
            if not input.query or len(input.query.strip()) < 2:
                raise ValidationError("Search query must be at least 2 characters")

            # Validate limit
            if input.limit and input.limit > 50:
                raise ValidationError("Maximum 50 results allowed")

            service = info.context["container"].resolve("PlaceSearchService")
            result = await service.search_places(input)

            mapper = info.context["container"].resolve("MappingMapper")
            return [mapper.place_details_dto_to_graphql_type(place) for place in result]

        except ValidationError:
            raise
        except Exception as e:
            logger.exception("Error searching places", query=input.query, error=str(e))
            raise

    @strawberry.field(description="Get place details by ID")
    @require_auth()
    @require_permission("mapping.places.details")
    @audit_operation("mapping.get_place_details")
    @rate_limit(requests=100, window=60)
    @track_metrics("get_place_details")
    async def get_place_details(
        self, info: strawberry.Info, place_id: str, provider: str | None = None
    ) -> PlaceDetails | None:
        """
        Get detailed information about a specific place.

        Args:
            place_id: Unique identifier for the place
            provider: Optional specific provider to use

        Returns:
            Place details or None if not found
        """
        try:
            if not place_id or len(place_id.strip()) == 0:
                raise ValidationError("Place ID is required")

            service = info.context["container"].resolve("PlaceDetailsService")
            result = await service.get_place_details(
                place_id=place_id.strip(), provider=provider
            )

            if not result:
                return None

            mapper = info.context["container"].resolve("MappingMapper")
            return mapper.place_details_dto_to_graphql_type(result)

        except ValidationError:
            raise
        except Exception as e:
            logger.exception(
                "Error retrieving place details", place_id=place_id, error=str(e)
            )
            raise

    @strawberry.field(description="Calculate distance matrix")
    @require_auth()
    @require_permission("mapping.distance.matrix")
    @audit_operation("mapping.calculate_distance_matrix")
    @rate_limit(requests=20, window=60)
    @track_metrics("calculate_distance_matrix")
    async def calculate_distance_matrix(
        self, info: strawberry.Info, input: DistanceMatrixInput
    ) -> DistanceMatrix:
        """
        Calculate distances and travel times between multiple points.

        Args:
            input: Distance matrix calculation input

        Returns:
            Distance matrix results
        """
        try:
            # Validate origins and destinations
            if not input.origins or len(input.origins) == 0:
                raise ValidationError("At least one origin is required")

            if not input.destinations or len(input.destinations) == 0:
                raise ValidationError("At least one destination is required")

            if len(input.origins) > 25:
                raise ValidationError("Maximum 25 origins allowed")

            if len(input.destinations) > 25:
                raise ValidationError("Maximum 25 destinations allowed")

            # Check total combinations
            total_combinations = len(input.origins) * len(input.destinations)
            if total_combinations > 100:
                raise ValidationError(
                    "Maximum 100 origin-destination combinations allowed"
                )

            service = info.context["container"].resolve("DistanceMatrixService")
            result = await service.calculate_distance_matrix(input)

            mapper = info.context["container"].resolve("MappingMapper")
            return mapper.distance_matrix_dto_to_graphql_type(result)

        except ValidationError:
            raise
        except Exception as e:
            logger.exception("Error calculating distance matrix", error=str(e))
            raise

    @strawberry.field(description="Get elevation data for coordinates")
    @require_auth()
    @require_permission("mapping.elevation.get")
    @audit_operation("mapping.get_elevation")
    @rate_limit(requests=100, window=60)
    @track_metrics("get_elevation")
    async def get_elevation(
        self, info: strawberry.Info, input: ElevationInput
    ) -> list[ElevationData]:
        """
        Get elevation data for specified coordinates.

        Args:
            input: Elevation query input parameters

        Returns:
            List of elevation data points
        """
        try:
            # Validate locations
            if not input.locations or len(input.locations) == 0:
                raise ValidationError("At least one location is required")

            if len(input.locations) > 100:
                raise ValidationError("Maximum 100 locations allowed")

            # Validate coordinates
            for i, location in enumerate(input.locations):
                if not (-90 <= location.latitude <= 90):
                    raise ValidationError(
                        f"Location {i+1}: Latitude must be between -90 and 90"
                    )

                if not (-180 <= location.longitude <= 180):
                    raise ValidationError(
                        f"Location {i+1}: Longitude must be between -180 and 180"
                    )

            service = info.context["container"].resolve("ElevationService")
            result = await service.get_elevation(input)

            mapper = info.context["container"].resolve("MappingMapper")
            return [mapper.elevation_data_dto_to_graphql_type(item) for item in result]

        except ValidationError:
            raise
        except Exception as e:
            logger.exception("Error retrieving elevation data", error=str(e))
            raise

    @strawberry.field(description="Get mapping provider capabilities")
    @require_auth()
    @require_permission("mapping.capabilities.read")
    @audit_operation("mapping.get_capabilities")
    @rate_limit(requests=50, window=60)
    @track_metrics("get_mapping_capabilities")
    async def get_mapping_capabilities(
        self, info: strawberry.Info, provider: str | None = None
    ) -> list[MappingCapabilities]:
        """
        Get capabilities of mapping providers.

        Args:
            provider: Optional specific provider name

        Returns:
            List of provider capabilities
        """
        try:
            service = info.context["container"].resolve("MappingCapabilitiesService")
            result = await service.get_capabilities(provider=provider)

            mapper = info.context["container"].resolve("MappingMapper")
            return [mapper.capabilities_dto_to_graphql_type(cap) for cap in result]

        except Exception as e:
            logger.exception("Error retrieving mapping capabilities", error=str(e))
            raise

    @strawberry.field(description="Validate address format")
    @require_auth()
    @require_permission("mapping.address.validate")
    @audit_operation("mapping.validate_address")
    @rate_limit(requests=100, window=60)
    @track_metrics("validate_address")
    async def validate_address(
        self,
        info: strawberry.Info,
        address: str,
        country_code: str | None = None,
        provider: str | None = None,
    ) -> dict[str, Any]:
        """
        Validate and standardize an address.

        Args:
            address: Address to validate
            country_code: Optional country code for validation
            provider: Optional specific provider to use

        Returns:
            Address validation results
        """
        try:
            if not address or len(address.strip()) < 5:
                raise ValidationError("Address must be at least 5 characters")

            service = info.context["container"].resolve("AddressValidationService")
            result = await service.validate_address(
                address=address.strip(), country_code=country_code, provider=provider
            )

            return {
                "is_valid": result.is_valid,
                "confidence_score": result.confidence_score,
                "standardized_address": result.standardized_address,
                "components": {
                    "street_number": result.components.street_number,
                    "street_name": result.components.street_name,
                    "city": result.components.city,
                    "state": result.components.state,
                    "postal_code": result.components.postal_code,
                    "country": result.components.country,
                    "country_code": result.components.country_code,
                },
                "coordinates": {
                    "latitude": result.coordinates.latitude
                    if result.coordinates
                    else None,
                    "longitude": result.coordinates.longitude
                    if result.coordinates
                    else None,
                },
                "validation_notes": result.validation_notes,
                "suggestions": result.suggestions,
                "provider_used": result.provider_used,
                "validated_at": result.validated_at,
            }

        except ValidationError:
            raise
        except Exception as e:
            logger.exception("Error validating address", address=address, error=str(e))
            raise

    @strawberry.field(description="Get timezone for coordinates")
    @require_auth()
    @require_permission("mapping.timezone.get")
    @audit_operation("mapping.get_timezone")
    @rate_limit(requests=100, window=60)
    @track_metrics("get_timezone")
    async def get_timezone(
        self,
        info: strawberry.Info,
        latitude: Decimal,
        longitude: Decimal,
        timestamp: datetime | None = None,
    ) -> dict[str, Any]:
        """
        Get timezone information for geographic coordinates.

        Args:
            latitude: Latitude coordinate
            longitude: Longitude coordinate
            timestamp: Optional timestamp for historical timezone data

        Returns:
            Timezone information
        """
        try:
            # Validate coordinates
            if not (-90 <= latitude <= 90):
                raise ValidationError("Latitude must be between -90 and 90")

            if not (-180 <= longitude <= 180):
                raise ValidationError("Longitude must be between -180 and 180")

            service = info.context["container"].resolve("TimezoneService")
            result = await service.get_timezone(
                latitude=latitude, longitude=longitude, timestamp=timestamp
            )

            return {
                "timezone_id": result.timezone_id,
                "timezone_name": result.timezone_name,
                "utc_offset": result.utc_offset,
                "dst_offset": result.dst_offset,
                "raw_offset": result.raw_offset,
                "is_dst": result.is_dst,
                "abbreviation": result.abbreviation,
                "country_code": result.country_code,
                "coordinates": {"latitude": latitude, "longitude": longitude},
                "queried_at": result.queried_at,
            }

        except ValidationError:
            raise
        except Exception as e:
            logger.exception(
                "Error retrieving timezone",
                latitude=str(latitude),
                longitude=str(longitude),
                error=str(e),
            )
            raise


__all__ = ["MappingQueries"]
