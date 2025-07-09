"""OpenStreetMap (OSM) routing and geocoding adapter implementation."""

import asyncio
from datetime import datetime
from typing import Any

import httpx

from .mapping_base_adapter import BaseMappingAdapter, MappingAdapterError
from .mapping_types import (
    Address,
    Coordinate,
    DistanceMatrix,
    GeocodeResult,
    GeocodeType,
    OptimizedRoute,
    Route,
    RouteProfile,
    RouteSegment,
    RouteStep,
    TrafficCondition,
)


class OSMAdapter(BaseMappingAdapter):
    """OpenStreetMap adapter using Nominatim for geocoding and OSRM for routing.

    Provides free, open-source mapping services:
    - Nominatim for geocoding/reverse geocoding
    - OSRM for routing and optimization
    - Overpass API for advanced queries
    - No API key required (rate limited)
    """

    NOMINATIM_URL = "https://nominatim.openstreetmap.org"
    OSRM_URL = "https://router.project-osrm.org"

    def __init__(self, config: dict[str, Any]):
        """Initialize OSM adapter."""
        super().__init__(config)
        self._nominatim_client = None
        self._osrm_client = None

        # Use custom endpoints if configured
        self.nominatim_url = self.settings.get("nominatim_url", self.NOMINATIM_URL)
        self.osrm_url = self.settings.get("osrm_url", self.OSRM_URL)

    def _validate_config(self) -> None:
        """Validate OSM configuration."""
        # OSM services are generally free and don't require API keys
        # But validate custom endpoints if provided
        if "nominatim_url" in self.settings:
            url = self.settings["nominatim_url"]
            if not url.startswith(("http://", "https://")):
                raise ValueError("Invalid Nominatim URL format")

        if "osrm_url" in self.settings:
            url = self.settings["osrm_url"]
            if not url.startswith(("http://", "https://")):
                raise ValueError("Invalid OSRM URL format")

        # Validate email for Nominatim (required for identification)
        if "email" not in self.settings:
            self.settings["email"] = "integration@ezzday.com"  # Default email

    def _get_nominatim_client(self) -> httpx.AsyncClient:
        """Get HTTP client for Nominatim."""
        if self._nominatim_client is None:
            headers = {
                "User-Agent": f"EzzDay-Backend/1.0 ({self.settings['email']})",
                "Accept": "application/json",
            }

            timeout = httpx.Timeout(
                connect=self.settings.get("connect_timeout", 10.0),
                read=self.settings.get("read_timeout", 30.0),
                write=self.settings.get("write_timeout", 10.0),
                pool=self.settings.get("pool_timeout", 10.0),
            )

            self._nominatim_client = httpx.AsyncClient(
                base_url=self.nominatim_url,
                headers=headers,
                timeout=timeout,
                limits=httpx.Limits(
                    max_keepalive_connections=self.settings.get("max_connections", 10),
                    max_connections=self.settings.get("max_connections", 20),
                ),
            )

        return self._nominatim_client

    def _get_osrm_client(self) -> httpx.AsyncClient:
        """Get HTTP client for OSRM."""
        if self._osrm_client is None:
            headers = {"User-Agent": "EzzDay-Backend/1.0", "Accept": "application/json"}

            timeout = httpx.Timeout(
                connect=self.settings.get("connect_timeout", 10.0),
                read=self.settings.get("read_timeout", 30.0),
                write=self.settings.get("write_timeout", 10.0),
                pool=self.settings.get("pool_timeout", 10.0),
            )

            self._osrm_client = httpx.AsyncClient(
                base_url=self.osrm_url,
                headers=headers,
                timeout=timeout,
                limits=httpx.Limits(
                    max_keepalive_connections=self.settings.get("max_connections", 10),
                    max_connections=self.settings.get("max_connections", 20),
                ),
            )

        return self._osrm_client

    # Geocoding Implementation
    async def geocode(
        self, address: str, country: str | None = None, limit: int | None = None
    ) -> list[GeocodeResult]:
        """Geocode address using Nominatim."""
        try:
            client = self._get_nominatim_client()

            params = {
                "q": address,
                "format": "json",
                "addressdetails": "1",
                "extratags": "1",
                "limit": str(limit or 10),
            }

            if country:
                params["countrycodes"] = country.lower()

            # Rate limiting for Nominatim (1 request per second)
            await asyncio.sleep(1.0)

            response = await client.get("/search", params=params)

            if response.status_code == 200:
                data = response.json()
                return [self._parse_geocode_result(item) for item in data]
            await self._handle_nominatim_error(response)

        except MappingAdapterError:
            raise
        except Exception as e:
            raise MappingAdapterError(f"Geocoding failed: {e!s}")

    async def reverse_geocode(
        self, coordinate: Coordinate, language: str | None = None
    ) -> list[GeocodeResult]:
        """Reverse geocode using Nominatim."""
        try:
            client = self._get_nominatim_client()

            params = {
                "lat": str(coordinate.latitude),
                "lon": str(coordinate.longitude),
                "format": "json",
                "addressdetails": "1",
                "zoom": "18",
            }

            if language:
                params["accept-language"] = language

            # Rate limiting for Nominatim
            await asyncio.sleep(1.0)

            response = await client.get("/reverse", params=params)

            if response.status_code == 200:
                data = response.json()
                if data:
                    return [self._parse_geocode_result(data)]
                return []
            await self._handle_nominatim_error(response)

        except MappingAdapterError:
            raise
        except Exception as e:
            raise MappingAdapterError(f"Reverse geocoding failed: {e!s}")

    # Routing Implementation
    async def calculate_route(
        self,
        origin: Coordinate,
        destination: Coordinate,
        waypoints: list[Coordinate] | None = None,
        profile: RouteProfile = RouteProfile.DRIVING,
        departure_time: datetime | None = None,
        alternatives: bool = False,
    ) -> list[Route]:
        """Calculate route using OSRM."""
        try:
            client = self._get_osrm_client()

            # Build coordinate string
            coordinates = [origin]
            if waypoints:
                coordinates.extend(waypoints)
            coordinates.append(destination)

            coord_string = ";".join(f"{c.longitude},{c.latitude}" for c in coordinates)

            # Map profile to OSRM profile
            osrm_profile = self._map_profile_to_osrm(profile)

            params = {
                "geometries": "geojson",
                "overview": "full",
                "steps": "true",
                "annotations": "true",
            }

            if alternatives:
                params["alternatives"] = "true"
                params["number_of_alternatives"] = "3"

            url = f"/route/v1/{osrm_profile}/{coord_string}"
            response = await client.get(url, params=params)

            if response.status_code == 200:
                data = response.json()
                if data.get("code") == "Ok":
                    routes = []
                    for route_data in data.get("routes", []):
                        route = self._parse_osrm_route(
                            route_data, origin, destination, waypoints or [], profile
                        )
                        routes.append(route)
                    return routes
                raise MappingAdapterError(
                    f"OSRM error: {data.get('message', 'Unknown error')}"
                )
            await self._handle_osrm_error(response)

        except MappingAdapterError:
            raise
        except Exception as e:
            raise MappingAdapterError(f"Route calculation failed: {e!s}")

    async def optimize_route(
        self,
        origin: Coordinate,
        destinations: list[Coordinate],
        return_to_origin: bool = False,
        profile: RouteProfile = RouteProfile.DRIVING,
    ) -> OptimizedRoute:
        """Optimize route using OSRM."""
        try:
            client = self._get_osrm_client()

            # Build coordinate string (origin + destinations)
            coordinates = [origin, *destinations]
            if return_to_origin:
                coordinates.append(origin)

            coord_string = ";".join(f"{c.longitude},{c.latitude}" for c in coordinates)

            osrm_profile = self._map_profile_to_osrm(profile)

            params = {
                "geometries": "geojson",
                "overview": "full",
                "steps": "true",
                "source": "first",  # Start from first coordinate (origin)
            }

            if return_to_origin:
                params["destination"] = "last"  # End at last coordinate (origin again)

            start_time = datetime.utcnow()

            url = f"/trip/v1/{osrm_profile}/{coord_string}"
            response = await client.get(url, params=params)

            optimization_time = (datetime.utcnow() - start_time).total_seconds()

            if response.status_code == 200:
                data = response.json()
                if data.get("code") == "Ok":
                    trip_data = data["trips"][0]  # OSRM returns list of trips

                    # Parse optimized route
                    route = self._parse_osrm_route(
                        trip_data,
                        origin,
                        destinations[-1] if not return_to_origin else origin,
                        destinations,
                        profile,
                    )

                    # Get waypoint order
                    waypoints_data = data.get("waypoints", [])
                    optimized_order = [
                        wp.get("waypoint_index", i)
                        for i, wp in enumerate(waypoints_data[1:])
                    ]

                    # Calculate savings (simplified)
                    savings = {
                        "distance_saved": 0.0,  # Would need original route to calculate
                        "time_saved": 0.0,
                    }

                    return OptimizedRoute(
                        optimized_order=optimized_order,
                        route=route,
                        optimization_time=optimization_time,
                        savings=savings,
                    )
                raise MappingAdapterError(
                    f"OSRM optimization error: {data.get('message', 'Unknown error')}"
                )
            await self._handle_osrm_error(response)

        except MappingAdapterError:
            raise
        except Exception as e:
            raise MappingAdapterError(f"Route optimization failed: {e!s}")

    async def calculate_distance_matrix(
        self,
        origins: list[Coordinate],
        destinations: list[Coordinate],
        profile: RouteProfile = RouteProfile.DRIVING,
        departure_time: datetime | None = None,
    ) -> DistanceMatrix:
        """Calculate distance matrix using OSRM."""
        try:
            client = self._get_osrm_client()

            # Combine all coordinates
            all_coordinates = origins + destinations
            coord_string = ";".join(
                f"{c.longitude},{c.latitude}" for c in all_coordinates
            )

            osrm_profile = self._map_profile_to_osrm(profile)

            # Build source and destination indices
            sources = ";".join(str(i) for i in range(len(origins)))
            destinations_indices = ";".join(
                str(i) for i in range(len(origins), len(all_coordinates))
            )

            params = {"sources": sources, "destinations": destinations_indices}

            url = f"/table/v1/{osrm_profile}/{coord_string}"
            response = await client.get(url, params=params)

            if response.status_code == 200:
                data = response.json()
                if data.get("code") == "Ok":
                    durations = data.get("durations", [])
                    distances = data.get("distances", [])

                    # If distances not provided, estimate from durations
                    if not distances:
                        # Estimate distance assuming average speed
                        avg_speed = 50  # km/h for driving
                        if profile == RouteProfile.WALKING:
                            avg_speed = 5
                        elif profile == RouteProfile.CYCLING:
                            avg_speed = 20

                        distances = [
                            [
                                duration * avg_speed / 3.6 if duration else 0
                                for duration in row
                            ]
                            for row in durations
                        ]

                    return DistanceMatrix(
                        origins=origins,
                        destinations=destinations,
                        distances=distances,
                        durations=durations,
                        profile=profile,
                        timestamp=datetime.utcnow(),
                    )
                raise MappingAdapterError(
                    f"OSRM matrix error: {data.get('message', 'Unknown error')}"
                )
            await self._handle_osrm_error(response)

        except MappingAdapterError:
            raise
        except Exception as e:
            raise MappingAdapterError(f"Distance matrix calculation failed: {e!s}")

    # Helper Methods
    def _parse_geocode_result(self, data: dict[str, Any]) -> GeocodeResult:
        """Parse Nominatim geocoding result."""
        coordinate = Coordinate(
            latitude=float(data["lat"]), longitude=float(data["lon"])
        )

        # Parse address components
        address_data = data.get("address", {})
        address = Address(
            formatted_address=data.get("display_name", ""),
            street_number=address_data.get("house_number"),
            street_name=address_data.get("road"),
            city=address_data.get("city")
            or address_data.get("town")
            or address_data.get("village"),
            state=address_data.get("state"),
            postal_code=address_data.get("postcode"),
            country=address_data.get("country"),
            country_code=address_data.get("country_code"),
        )

        # Determine geocode type
        place_type = data.get("type", "unknown")
        geocode_type = self._map_osm_type_to_geocode_type(place_type)

        # Calculate confidence based on importance
        importance = float(data.get("importance", 0.5))
        confidence = min(importance * 2, 1.0)  # Scale to 0-1

        return GeocodeResult(
            coordinate=coordinate,
            address=address,
            confidence=confidence,
            type=geocode_type,
            place_id=str(data.get("place_id", "")),
            metadata={
                "osm_id": data.get("osm_id"),
                "osm_type": data.get("osm_type"),
                "class": data.get("class"),
                "type": data.get("type"),
                "importance": importance,
            },
        )

    def _parse_osrm_route(
        self,
        route_data: dict[str, Any],
        origin: Coordinate,
        destination: Coordinate,
        waypoints: list[Coordinate],
        profile: RouteProfile,
    ) -> Route:
        """Parse OSRM route response."""
        # Parse geometry
        geometry = route_data.get("geometry", {})
        coordinates = geometry.get("coordinates", [])
        overview_geometry = [
            Coordinate(lat=coord[1], longitude=coord[0]) for coord in coordinates
        ]

        # Parse legs (segments between waypoints)
        legs = route_data.get("legs", [])
        segments = []

        for leg in legs:
            steps = []
            leg_steps = leg.get("steps", [])

            for step_data in leg_steps:
                step = self._parse_osrm_step(step_data)
                steps.append(step)

            # Calculate segment coordinates
            segment_geometry = leg.get("geometry", {})
            if segment_geometry:
                seg_coords = segment_geometry.get("coordinates", [])
                if seg_coords:
                    start_coord = Coordinate(
                        latitude=seg_coords[0][1], longitude=seg_coords[0][0]
                    )
                    end_coord = Coordinate(
                        latitude=seg_coords[-1][1], longitude=seg_coords[-1][0]
                    )
                else:
                    start_coord = origin
                    end_coord = destination
            else:
                start_coord = origin
                end_coord = destination

            segment = RouteSegment(
                start_coordinate=start_coord,
                end_coordinate=end_coord,
                distance=leg.get("distance", 0),
                duration=int(leg.get("duration", 0)),
                steps=steps,
                traffic_condition=TrafficCondition.UNKNOWN,
            )
            segments.append(segment)

        return Route(
            origin=origin,
            destination=destination,
            waypoints=waypoints,
            segments=segments,
            total_distance=route_data.get("distance", 0),
            total_duration=int(route_data.get("duration", 0)),
            profile=profile,
            overview_geometry=overview_geometry,
            metadata={
                "osrm_weight": route_data.get("weight"),
                "osrm_weight_name": route_data.get("weight_name"),
            },
        )

    def _parse_osrm_step(self, step_data: dict[str, Any]) -> RouteStep:
        """Parse OSRM step data."""
        geometry = step_data.get("geometry", {})
        coordinates = geometry.get("coordinates", [])

        step_geometry = []
        if coordinates:
            step_geometry = [
                Coordinate(latitude=coord[1], longitude=coord[0])
                for coord in coordinates
            ]

        start_coord = step_geometry[0] if step_geometry else Coordinate(0, 0)
        end_coord = step_geometry[-1] if step_geometry else Coordinate(0, 0)

        maneuver = step_data.get("maneuver", {})

        return RouteStep(
            instruction=step_data.get("name", "") or "Continue",
            distance=step_data.get("distance", 0),
            duration=int(step_data.get("duration", 0)),
            start_coordinate=start_coord,
            end_coordinate=end_coord,
            maneuver=maneuver.get("type"),
            street_name=step_data.get("name"),
            geometry=step_geometry,
        )

    def _map_profile_to_osrm(self, profile: RouteProfile) -> str:
        """Map RouteProfile to OSRM profile."""
        profile_map = {
            RouteProfile.DRIVING: "driving",
            RouteProfile.DRIVING_TRAFFIC: "driving",  # OSRM doesn't distinguish
            RouteProfile.WALKING: "foot",
            RouteProfile.CYCLING: "bike",
            RouteProfile.TRUCK: "driving",  # Use driving for truck (limited support)
        }
        return profile_map.get(profile, "driving")

    def _map_osm_type_to_geocode_type(self, osm_type: str) -> GeocodeType:
        """Map OSM place type to GeocodeType."""
        type_map = {
            "house": GeocodeType.ADDRESS,
            "postcode": GeocodeType.POSTCODE,
            "amenity": GeocodeType.POI,
            "shop": GeocodeType.POI,
            "tourism": GeocodeType.POI,
            "leisure": GeocodeType.POI,
            "city": GeocodeType.LOCALITY,
            "town": GeocodeType.LOCALITY,
            "village": GeocodeType.LOCALITY,
        }
        return type_map.get(osm_type, GeocodeType.ADDRESS)

    async def _handle_nominatim_error(self, response: httpx.Response) -> None:
        """Handle Nominatim API errors."""
        error_message = f"Nominatim error: HTTP {response.status_code}"

        if response.status_code == 429:
            error_message += " - Rate limit exceeded"
            is_retryable = True
        elif response.status_code >= 500:
            error_message += " - Server error"
            is_retryable = True
        else:
            is_retryable = False

        raise MappingAdapterError(
            error_message,
            error_code=str(response.status_code),
            is_retryable=is_retryable,
        )

    async def _handle_osrm_error(self, response: httpx.Response) -> None:
        """Handle OSRM API errors."""
        try:
            data = response.json()
            error_message = (
                f"OSRM error: {data.get('message', f'HTTP {response.status_code}')}"
            )
        except (ValueError, TypeError, KeyError) as e:
            error_message = f"OSRM error: HTTP {response.status_code}"

        is_retryable = response.status_code >= 500

        raise MappingAdapterError(
            error_message,
            error_code=str(response.status_code),
            is_retryable=is_retryable,
        )

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self._nominatim_client:
            await self._nominatim_client.aclose()
            self._nominatim_client = None

        if self._osrm_client:
            await self._osrm_client.aclose()
            self._osrm_client = None
