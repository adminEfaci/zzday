"""Mapbox API adapter implementation for mapping and routing services."""

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
    MapTile,
    OptimizedRoute,
    PlaceInfo,
    Route,
    RouteProfile,
    RouteSegment,
    RouteStep,
    TrafficCondition,
    TrafficInfo,
)


class MapboxAdapter(BaseMappingAdapter):
    """Mapbox API adapter for premium mapping services.

    Provides high-quality mapping services:
    - Geocoding API for address resolution
    - Directions API for routing with traffic
    - Matrix API for distance calculations
    - Maps API for tile serving
    - Traffic API for real-time conditions
    """

    BASE_URL = "https://api.mapbox.com"

    def __init__(self, config: dict[str, Any]):
        """Initialize Mapbox adapter."""
        super().__init__(config)
        self._client = None

    def _validate_config(self) -> None:
        """Validate Mapbox configuration."""
        if "api_key" not in self.credentials:
            raise ValueError("Mapbox API key is required")

        api_key = self.credentials["api_key"]
        if not api_key or not api_key.startswith("pk."):
            raise ValueError("Invalid Mapbox API key format")

    def _get_client(self) -> httpx.AsyncClient:
        """Get HTTP client for Mapbox API."""
        if self._client is None:
            headers = {"User-Agent": "EzzDay-Backend/1.0", "Accept": "application/json"}

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
                    max_keepalive_connections=self.settings.get("max_connections", 10),
                    max_connections=self.settings.get("max_connections", 20),
                ),
            )

        return self._client

    # Geocoding Implementation
    async def geocode(
        self, address: str, country: str | None = None, limit: int | None = None
    ) -> list[GeocodeResult]:
        """Geocode address using Mapbox Geocoding API."""
        try:
            client = self._get_client()

            params = {
                "access_token": self.credentials["api_key"],
                "limit": limit or 10,
                "types": "address,poi,postcode,locality",
            }

            if country:
                params["country"] = country.lower()

            # URL encode the address
            import urllib.parse

            encoded_address = urllib.parse.quote(address)

            url = f"/geocoding/v5/mapbox.places/{encoded_address}.json"
            response = await client.get(url, params=params)

            if response.status_code == 200:
                data = response.json()
                features = data.get("features", [])
                return [
                    self._parse_mapbox_geocode_result(feature) for feature in features
                ]
            await self._handle_mapbox_error(response)

        except MappingAdapterError:
            raise
        except Exception as e:
            raise MappingAdapterError(f"Geocoding failed: {e!s}")

    async def reverse_geocode(
        self, coordinate: Coordinate, language: str | None = None
    ) -> list[GeocodeResult]:
        """Reverse geocode using Mapbox Geocoding API."""
        try:
            client = self._get_client()

            params = {
                "access_token": self.credentials["api_key"],
                "types": "address,poi,postcode,locality",
            }

            if language:
                params["language"] = language

            url = f"/geocoding/v5/mapbox.places/{coordinate.longitude},{coordinate.latitude}.json"
            response = await client.get(url, params=params)

            if response.status_code == 200:
                data = response.json()
                features = data.get("features", [])
                return [
                    self._parse_mapbox_geocode_result(feature) for feature in features
                ]
            await self._handle_mapbox_error(response)

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
        """Calculate route using Mapbox Directions API."""
        try:
            client = self._get_client()

            # Build coordinate string
            coordinates = [origin]
            if waypoints:
                coordinates.extend(waypoints)
            coordinates.append(destination)

            coord_string = ";".join(f"{c.longitude},{c.latitude}" for c in coordinates)

            # Map profile to Mapbox profile
            mapbox_profile = self._map_profile_to_mapbox(profile)

            params = {
                "access_token": self.credentials["api_key"],
                "geometries": "geojson",
                "overview": "full",
                "steps": "true",
                "annotations": "duration,distance,speed",
            }

            if alternatives:
                params["alternatives"] = "true"
                params["max_alternative_routes"] = "3"

            # Use traffic data if available and profile supports it
            if profile in [RouteProfile.DRIVING, RouteProfile.DRIVING_TRAFFIC]:
                params["annotations"] = "duration,distance,speed,congestion"

            if departure_time:
                params["depart_at"] = departure_time.isoformat()

            url = f"/directions/v5/mapbox/{mapbox_profile}/{coord_string}"
            response = await client.get(url, params=params)

            if response.status_code == 200:
                data = response.json()
                routes = data.get("routes", [])
                parsed_routes = []

                for route_data in routes:
                    route = self._parse_mapbox_route(
                        route_data, origin, destination, waypoints or [], profile
                    )
                    parsed_routes.append(route)

                return parsed_routes
            await self._handle_mapbox_error(response)

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
        """Optimize route using Mapbox Optimization API."""
        try:
            client = self._get_client()

            # Build coordinate string
            coordinates = [origin, *destinations]
            if return_to_origin:
                coordinates.append(origin)

            coord_string = ";".join(f"{c.longitude},{c.latitude}" for c in coordinates)

            mapbox_profile = self._map_profile_to_mapbox(profile)

            params = {
                "access_token": self.credentials["api_key"],
                "geometries": "geojson",
                "overview": "full",
                "steps": "true",
                "source": "first",
            }

            if return_to_origin:
                params["destination"] = "last"

            start_time = datetime.utcnow()

            url = f"/optimized-trips/v1/mapbox/{mapbox_profile}/{coord_string}"
            response = await client.get(url, params=params)

            optimization_time = (datetime.utcnow() - start_time).total_seconds()

            if response.status_code == 200:
                data = response.json()
                trips = data.get("trips", [])

                if trips:
                    trip_data = trips[0]

                    # Parse optimized route
                    route = self._parse_mapbox_route(
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
                    savings = {"distance_saved": 0.0, "time_saved": 0.0}

                    return OptimizedRoute(
                        optimized_order=optimized_order,
                        route=route,
                        optimization_time=optimization_time,
                        savings=savings,
                    )
                raise MappingAdapterError("No optimization results returned")
            await self._handle_mapbox_error(response)

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
        """Calculate distance matrix using Mapbox Matrix API."""
        try:
            client = self._get_client()

            # Combine all coordinates
            all_coordinates = origins + destinations
            coord_string = ";".join(
                f"{c.longitude},{c.latitude}" for c in all_coordinates
            )

            mapbox_profile = self._map_profile_to_mapbox(profile)

            # Build source and destination indices
            sources = ";".join(str(i) for i in range(len(origins)))
            destination_indices = ";".join(
                str(i) for i in range(len(origins), len(all_coordinates))
            )

            params = {
                "access_token": self.credentials["api_key"],
                "sources": sources,
                "destinations": destination_indices,
                "annotations": "duration,distance",
            }

            if departure_time:
                params["depart_at"] = departure_time.isoformat()

            url = f"/directions-matrix/v1/mapbox/{mapbox_profile}/{coord_string}"
            response = await client.get(url, params=params)

            if response.status_code == 200:
                data = response.json()
                durations = data.get("durations", [])
                distances = data.get("distances", [])

                return DistanceMatrix(
                    origins=origins,
                    destinations=destinations,
                    distances=distances,
                    durations=durations,
                    profile=profile,
                    timestamp=datetime.utcnow(),
                )
            await self._handle_mapbox_error(response)

        except MappingAdapterError:
            raise
        except Exception as e:
            raise MappingAdapterError(f"Distance matrix calculation failed: {e!s}")

    # Map Services
    async def get_map_tile(
        self,
        x: int,
        y: int,
        z: int,
        style: str = "streets-v11",
        format: str = "png",
        size: int = 512,
    ) -> MapTile | None:
        """Get map tile from Mapbox Static Images API."""
        try:
            # Mapbox tile URL format
            retina = "@2x" if size > 512 else ""
            tile_size = 256 if size <= 512 else 512

            url = f"https://api.mapbox.com/styles/v1/mapbox/{style}/tiles/{z}/{x}/{y}{retina}"

            params = {"access_token": self.credentials["api_key"]}

            return MapTile(
                x=x,
                y=y,
                z=z,
                format=format,
                url=f"{url}?{httpx.QueryParams(params)}",
                size=tile_size,
            )

        except Exception as e:
            raise MappingAdapterError(f"Map tile generation failed: {e!s}")

    # Traffic Services
    async def get_traffic_info(
        self, coordinates: list[Coordinate], radius: float | None = None
    ) -> list[TrafficInfo]:
        """Get traffic information using Mapbox Traffic API."""
        try:
            # Mapbox doesn't have a direct traffic info API
            # But we can get traffic data through routing with traffic annotations
            traffic_info = []

            for coord in coordinates:
                # Create a short route to get traffic data
                nearby_coord = Coordinate(
                    latitude=coord.latitude + 0.001, longitude=coord.longitude + 0.001
                )

                routes = await self.calculate_route(
                    coord, nearby_coord, profile=RouteProfile.DRIVING_TRAFFIC
                )

                if routes:
                    route = routes[0]
                    # Extract traffic condition from route metadata

                    # Estimate traffic based on route duration vs. free flow
                    if hasattr(route, "traffic_duration") and route.traffic_duration:
                        ratio = route.traffic_duration / route.total_duration
                        if ratio > 1.5 or ratio > 1.3 or ratio > 1.1:
                            pass
                        else:
                            pass

                    traffic_info.append(
                        TrafficInfo(
                            coordinate=coord,
                            speed=50.0,  # Default speed
                            free_flow_speed=60.0,  # Default free flow speed
                            current_travel_time=route.total_duration,
                            free_flow_travel_time=route.total_duration,
                            confidence=0.8,
                            last_updated=datetime.utcnow(),
                        )
                    )

            return traffic_info

        except Exception as e:
            raise MappingAdapterError(f"Traffic info retrieval failed: {e!s}")

    # Places
    async def search_places(
        self,
        query: str,
        coordinate: Coordinate | None = None,
        radius: float | None = None,
        category: str | None = None,
        limit: int | None = None,
    ) -> list[PlaceInfo]:
        """Search for places using Mapbox Geocoding API."""
        try:
            client = self._get_client()

            params = {
                "access_token": self.credentials["api_key"],
                "limit": limit or 10,
                "types": category or "poi",
            }

            if coordinate:
                params["proximity"] = f"{coordinate.longitude},{coordinate.latitude}"

            if radius and coordinate:
                # Convert radius to bbox (approximate)
                lat_offset = radius / 111000  # degrees per meter (latitude)
                lon_offset = radius / (
                    111000 * abs(coordinate.latitude)
                )  # degrees per meter (longitude)

                bbox = [
                    coordinate.longitude - lon_offset,
                    coordinate.latitude - lat_offset,
                    coordinate.longitude + lon_offset,
                    coordinate.latitude + lat_offset,
                ]
                params["bbox"] = ",".join(map(str, bbox))

            import urllib.parse

            encoded_query = urllib.parse.quote(query)

            url = f"/geocoding/v5/mapbox.places/{encoded_query}.json"
            response = await client.get(url, params=params)

            if response.status_code == 200:
                data = response.json()
                features = data.get("features", [])
                places = []

                for feature in features:
                    place = self._parse_mapbox_place(feature)
                    if coordinate:
                        place.distance = self.calculate_distance(
                            coordinate, place.coordinate
                        )
                    places.append(place)

                return places
            await self._handle_mapbox_error(response)

        except MappingAdapterError:
            raise
        except Exception as e:
            raise MappingAdapterError(f"Place search failed: {e!s}")

    # Helper Methods
    def _parse_mapbox_geocode_result(self, feature: dict[str, Any]) -> GeocodeResult:
        """Parse Mapbox geocoding result."""
        geometry = feature.get("geometry", {})
        coordinates = geometry.get("coordinates", [0, 0])

        coordinate = Coordinate(latitude=coordinates[1], longitude=coordinates[0])

        properties = feature.get("properties", {})
        context = feature.get("context", [])

        # Parse address from context
        address_components = {
            item["id"].split(".")[0]: item["text"] for item in context
        }

        address = Address(
            formatted_address=feature.get("place_name", ""),
            street_number=properties.get("address"),
            street_name=feature.get("text", ""),
            city=address_components.get("place"),
            state=address_components.get("region"),
            postal_code=address_components.get("postcode"),
            country=address_components.get("country"),
        )

        # Determine geocode type
        place_type = feature.get("place_type", ["unknown"])[0]
        geocode_type = self._map_mapbox_type_to_geocode_type(place_type)

        # Calculate confidence from relevance
        relevance = feature.get("relevance", 0.5)
        confidence = min(relevance, 1.0)

        return GeocodeResult(
            coordinate=coordinate,
            address=address,
            confidence=confidence,
            type=geocode_type,
            place_id=feature.get("id", ""),
            metadata={
                "place_type": place_type,
                "relevance": relevance,
                "properties": properties,
            },
        )

    def _parse_mapbox_route(
        self,
        route_data: dict[str, Any],
        origin: Coordinate,
        destination: Coordinate,
        waypoints: list[Coordinate],
        profile: RouteProfile,
    ) -> Route:
        """Parse Mapbox route response."""
        # Parse geometry
        geometry = route_data.get("geometry", {})
        coordinates = geometry.get("coordinates", [])
        overview_geometry = [
            Coordinate(latitude=coord[1], longitude=coord[0]) for coord in coordinates
        ]

        # Parse legs
        legs = route_data.get("legs", [])
        segments = []

        for leg in legs:
            steps = []
            leg_steps = leg.get("steps", [])

            for step_data in leg_steps:
                step = self._parse_mapbox_step(step_data)
                steps.append(step)

            # Get leg coordinates
            if steps:
                start_coord = steps[0].start_coordinate
                end_coord = steps[-1].end_coordinate
            else:
                start_coord = origin
                end_coord = destination

            # Determine traffic condition from annotations
            traffic_condition = TrafficCondition.UNKNOWN
            annotations = leg.get("annotation", {})
            if "congestion" in annotations:
                congestion_levels = annotations["congestion"]
                if congestion_levels:
                    avg_congestion = sum(
                        1 for level in congestion_levels if level in ["heavy", "severe"]
                    ) / len(congestion_levels)
                    if avg_congestion > 0.5:
                        traffic_condition = TrafficCondition.HEAVY
                    elif avg_congestion > 0.3:
                        traffic_condition = TrafficCondition.MODERATE
                    elif avg_congestion > 0.1:
                        traffic_condition = TrafficCondition.LIGHT
                    else:
                        traffic_condition = TrafficCondition.FREE_FLOW

            segment = RouteSegment(
                start_coordinate=start_coord,
                end_coordinate=end_coord,
                distance=leg.get("distance", 0),
                duration=int(leg.get("duration", 0)),
                steps=steps,
                traffic_condition=traffic_condition,
                traffic_duration=leg.get("duration_typical"),
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
            traffic_duration=route_data.get("duration_typical"),
            metadata={
                "mapbox_weight": route_data.get("weight"),
                "mapbox_weight_name": route_data.get("weight_name"),
            },
        )

    def _parse_mapbox_step(self, step_data: dict[str, Any]) -> RouteStep:
        """Parse Mapbox step data."""
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
            instruction=maneuver.get("instruction", "Continue"),
            distance=step_data.get("distance", 0),
            duration=int(step_data.get("duration", 0)),
            start_coordinate=start_coord,
            end_coordinate=end_coord,
            maneuver=maneuver.get("type"),
            street_name=step_data.get("name"),
            geometry=step_geometry,
        )

    def _parse_mapbox_place(self, feature: dict[str, Any]) -> PlaceInfo:
        """Parse Mapbox place result."""
        geometry = feature.get("geometry", {})
        coordinates = geometry.get("coordinates", [0, 0])

        coordinate = Coordinate(latitude=coordinates[1], longitude=coordinates[0])

        properties = feature.get("properties", {})
        context = feature.get("context", [])
        address_components = {
            item["id"].split(".")[0]: item["text"] for item in context
        }

        address = Address(
            formatted_address=feature.get("place_name", ""),
            city=address_components.get("place"),
            state=address_components.get("region"),
            postal_code=address_components.get("postcode"),
            country=address_components.get("country"),
        )

        return PlaceInfo(
            place_id=feature.get("id", ""),
            name=feature.get("text", ""),
            coordinate=coordinate,
            address=address,
            category=properties.get("category"),
            phone=properties.get("phone"),
            website=properties.get("website"),
            metadata=properties,
        )

    def _map_profile_to_mapbox(self, profile: RouteProfile) -> str:
        """Map RouteProfile to Mapbox profile."""
        profile_map = {
            RouteProfile.DRIVING: "driving",
            RouteProfile.DRIVING_TRAFFIC: "driving-traffic",
            RouteProfile.WALKING: "walking",
            RouteProfile.CYCLING: "cycling",
            RouteProfile.TRUCK: "driving",  # Use driving for truck
        }
        return profile_map.get(profile, "driving")

    def _map_mapbox_type_to_geocode_type(self, mapbox_type: str) -> GeocodeType:
        """Map Mapbox place type to GeocodeType."""
        type_map = {
            "address": GeocodeType.ADDRESS,
            "postcode": GeocodeType.POSTCODE,
            "poi": GeocodeType.POI,
            "locality": GeocodeType.LOCALITY,
            "place": GeocodeType.LOCALITY,
            "region": GeocodeType.LOCALITY,
            "country": GeocodeType.LOCALITY,
        }
        return type_map.get(mapbox_type, GeocodeType.ADDRESS)

    async def _handle_mapbox_error(self, response: httpx.Response) -> None:
        """Handle Mapbox API errors."""
        try:
            data = response.json()
            error_message = data.get(
                "message", f"Mapbox error: HTTP {response.status_code}"
            )
        except (ValueError, TypeError, KeyError) as e:
            error_message = f"Mapbox error: HTTP {response.status_code}"

        if response.status_code == 401:
            error_message += " - Invalid API key"
            is_retryable = False
        elif response.status_code == 429:
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

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self._client:
            await self._client.aclose()
            self._client = None
