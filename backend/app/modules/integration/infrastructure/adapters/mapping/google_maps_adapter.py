"""Google Maps Platform API adapter implementation for mapping and routing services."""

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
)


class GoogleMapsAdapter(BaseMappingAdapter):
    """Google Maps Platform adapter for enterprise mapping services.

    Provides comprehensive mapping services:
    - Geocoding API for address resolution
    - Directions API for routing and navigation
    - Distance Matrix API for multi-point calculations
    - Places API for POI search and details
    - Maps Static API for map tiles
    - Roads API for advanced routing
    """

    BASE_URL = "https://maps.googleapis.com"

    def __init__(self, config: dict[str, Any]):
        """Initialize Google Maps adapter."""
        super().__init__(config)
        self._client = None

    def _validate_config(self) -> None:
        """Validate Google Maps configuration."""
        if "api_key" not in self.credentials:
            raise ValueError("Google Maps API key is required")

        api_key = self.credentials["api_key"]
        if not api_key:
            raise ValueError("Invalid Google Maps API key")

    def _get_client(self) -> httpx.AsyncClient:
        """Get HTTP client for Google Maps API."""
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
        """Geocode address using Google Geocoding API."""
        try:
            client = self._get_client()

            params = {"address": address, "key": self.credentials["api_key"]}

            if country:
                params["components"] = f"country:{country.upper()}"

            url = "/maps/api/geocode/json"
            response = await client.get(url, params=params)

            if response.status_code == 200:
                data = response.json()
                status = data.get("status")

                if status == "OK":
                    results = data.get("results", [])
                    if limit:
                        results = results[:limit]
                    return [
                        self._parse_google_geocode_result(result) for result in results
                    ]
                if status == "ZERO_RESULTS":
                    return []
                raise MappingAdapterError(f"Google Geocoding error: {status}")
            await self._handle_google_error(response)

        except MappingAdapterError:
            raise
        except Exception as e:
            raise MappingAdapterError(f"Geocoding failed: {e!s}")

    async def reverse_geocode(
        self, coordinate: Coordinate, language: str | None = None
    ) -> list[GeocodeResult]:
        """Reverse geocode using Google Geocoding API."""
        try:
            client = self._get_client()

            params = {
                "latlng": f"{coordinate.latitude},{coordinate.longitude}",
                "key": self.credentials["api_key"],
            }

            if language:
                params["language"] = language

            url = "/maps/api/geocode/json"
            response = await client.get(url, params=params)

            if response.status_code == 200:
                data = response.json()
                status = data.get("status")

                if status == "OK":
                    results = data.get("results", [])
                    return [
                        self._parse_google_geocode_result(result) for result in results
                    ]
                if status == "ZERO_RESULTS":
                    return []
                raise MappingAdapterError(f"Google Reverse Geocoding error: {status}")
            await self._handle_google_error(response)

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
        """Calculate route using Google Directions API."""
        try:
            client = self._get_client()

            params = {
                "origin": f"{origin.latitude},{origin.longitude}",
                "destination": f"{destination.latitude},{destination.longitude}",
                "key": self.credentials["api_key"],
                "mode": self._map_profile_to_google(profile),
                "units": "metric",
            }

            if waypoints:
                waypoint_string = "|".join(
                    f"{wp.latitude},{wp.longitude}" for wp in waypoints
                )
                params["waypoints"] = waypoint_string

            if alternatives:
                params["alternatives"] = "true"

            if departure_time and profile in [
                RouteProfile.DRIVING,
                RouteProfile.DRIVING_TRAFFIC,
            ]:
                params["departure_time"] = str(int(departure_time.timestamp()))
                params["traffic_model"] = "best_guess"

            url = "/maps/api/directions/json"
            response = await client.get(url, params=params)

            if response.status_code == 200:
                data = response.json()
                status = data.get("status")

                if status == "OK":
                    routes_data = data.get("routes", [])
                    routes = []

                    for route_data in routes_data:
                        route = self._parse_google_route(
                            route_data, origin, destination, waypoints or [], profile
                        )
                        routes.append(route)

                    return routes
                if status == "ZERO_RESULTS":
                    return []
                raise MappingAdapterError(f"Google Directions error: {status}")
            await self._handle_google_error(response)

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
        """Optimize route using Google Directions API with waypoint optimization."""
        try:
            client = self._get_client()

            # Build waypoint string with optimization
            waypoint_coords = [
                f"{dest.latitude},{dest.longitude}" for dest in destinations
            ]
            waypoints_string = "optimize:true|" + "|".join(waypoint_coords)

            final_destination = (
                f"{origin.latitude},{origin.longitude}"
                if return_to_origin
                else f"{destinations[-1].latitude},{destinations[-1].longitude}"
            )

            params = {
                "origin": f"{origin.latitude},{origin.longitude}",
                "destination": final_destination,
                "waypoints": waypoints_string,
                "key": self.credentials["api_key"],
                "mode": self._map_profile_to_google(profile),
                "units": "metric",
            }

            start_time = datetime.utcnow()

            url = "/maps/api/directions/json"
            response = await client.get(url, params=params)

            optimization_time = (datetime.utcnow() - start_time).total_seconds()

            if response.status_code == 200:
                data = response.json()
                status = data.get("status")

                if status == "OK":
                    routes_data = data.get("routes", [])
                    if routes_data:
                        route_data = routes_data[0]

                        # Parse optimized route
                        route = self._parse_google_route(
                            route_data,
                            origin,
                            destinations[-1] if not return_to_origin else origin,
                            destinations,
                            profile,
                        )

                        # Get waypoint order from route
                        waypoint_order = route_data.get(
                            "waypoint_order", list(range(len(destinations)))
                        )

                        # Calculate savings (simplified)
                        savings = {"distance_saved": 0.0, "time_saved": 0.0}

                        return OptimizedRoute(
                            optimized_order=waypoint_order,
                            route=route,
                            optimization_time=optimization_time,
                            savings=savings,
                        )
                    raise MappingAdapterError("No optimization results returned")
                raise MappingAdapterError(
                    f"Google Directions optimization error: {status}"
                )
            await self._handle_google_error(response)

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
        """Calculate distance matrix using Google Distance Matrix API."""
        try:
            client = self._get_client()

            # Build origins and destinations strings
            origins_string = "|".join(
                f"{coord.latitude},{coord.longitude}" for coord in origins
            )
            destinations_string = "|".join(
                f"{coord.latitude},{coord.longitude}" for coord in destinations
            )

            params = {
                "origins": origins_string,
                "destinations": destinations_string,
                "key": self.credentials["api_key"],
                "mode": self._map_profile_to_google(profile),
                "units": "metric",
            }

            if departure_time and profile in [
                RouteProfile.DRIVING,
                RouteProfile.DRIVING_TRAFFIC,
            ]:
                params["departure_time"] = str(int(departure_time.timestamp()))
                params["traffic_model"] = "best_guess"

            url = "/maps/api/distancematrix/json"
            response = await client.get(url, params=params)

            if response.status_code == 200:
                data = response.json()
                status = data.get("status")

                if status == "OK":
                    rows = data.get("rows", [])
                    distances = []
                    durations = []

                    for row in rows:
                        distance_row = []
                        duration_row = []

                        for element in row.get("elements", []):
                            if element.get("status") == "OK":
                                distance_row.append(element["distance"]["value"])
                                duration_row.append(element["duration"]["value"])
                            else:
                                distance_row.append(0)
                                duration_row.append(0)

                        distances.append(distance_row)
                        durations.append(duration_row)

                    return DistanceMatrix(
                        origins=origins,
                        destinations=destinations,
                        distances=distances,
                        durations=durations,
                        profile=profile,
                        timestamp=datetime.utcnow(),
                    )
                raise MappingAdapterError(f"Google Distance Matrix error: {status}")
            await self._handle_google_error(response)

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
        style: str = "roadmap",
        format: str = "png",
        size: int = 512,
    ) -> MapTile | None:
        """Get map tile using Google Maps Static API."""
        try:
            # Google Maps Static API doesn't use tile coordinates directly
            # This is a simplified implementation
            center_lat, center_lon = self._tile_to_lat_lon(x, y, z)

            params = {
                "center": f"{center_lat},{center_lon}",
                "zoom": str(z),
                "size": f"{size}x{size}",
                "maptype": style,
                "format": format,
                "key": self.credentials["api_key"],
            }

            url = "https://maps.googleapis.com/maps/api/staticmap"

            return MapTile(
                x=x,
                y=y,
                z=z,
                format=format,
                url=f"{url}?{httpx.QueryParams(params)}",
                size=size,
            )

        except Exception as e:
            raise MappingAdapterError(f"Map tile generation failed: {e!s}")

    # Places
    async def search_places(
        self,
        query: str,
        coordinate: Coordinate | None = None,
        radius: float | None = None,
        category: str | None = None,
        limit: int | None = None,
    ) -> list[PlaceInfo]:
        """Search for places using Google Places API."""
        try:
            client = self._get_client()

            params = {"query": query, "key": self.credentials["api_key"]}

            if coordinate:
                params["location"] = f"{coordinate.latitude},{coordinate.longitude}"

            if radius:
                params["radius"] = str(int(radius))

            if category:
                params["type"] = category

            url = "/maps/api/place/textsearch/json"
            response = await client.get(url, params=params)

            if response.status_code == 200:
                data = response.json()
                status = data.get("status")

                if status == "OK":
                    results = data.get("results", [])
                    if limit:
                        results = results[:limit]

                    places = []
                    for result in results:
                        place = self._parse_google_place(result)
                        if coordinate:
                            place.distance = self.calculate_distance(
                                coordinate, place.coordinate
                            )
                        places.append(place)

                    return places
                if status == "ZERO_RESULTS":
                    return []
                raise MappingAdapterError(f"Google Places search error: {status}")
            await self._handle_google_error(response)

        except MappingAdapterError:
            raise
        except Exception as e:
            raise MappingAdapterError(f"Place search failed: {e!s}")

    async def get_place_details(self, place_id: str) -> PlaceInfo | None:
        """Get detailed information about a place using Google Places API."""
        try:
            client = self._get_client()

            params = {
                "place_id": place_id,
                "key": self.credentials["api_key"],
                "fields": "name,formatted_address,geometry,rating,formatted_phone_number,website,opening_hours,photos,reviews",
            }

            url = "/maps/api/place/details/json"
            response = await client.get(url, params=params)

            if response.status_code == 200:
                data = response.json()
                status = data.get("status")

                if status == "OK":
                    result = data.get("result", {})
                    return self._parse_google_place_details(result)
                if status == "NOT_FOUND":
                    return None
                raise MappingAdapterError(f"Google Place details error: {status}")
            await self._handle_google_error(response)

        except MappingAdapterError:
            raise
        except Exception as e:
            raise MappingAdapterError(f"Place details retrieval failed: {e!s}")

    # Helper Methods
    def _parse_google_geocode_result(self, result: dict[str, Any]) -> GeocodeResult:
        """Parse Google geocoding result."""
        geometry = result.get("geometry", {})
        location = geometry.get("location", {})

        coordinate = Coordinate(
            latitude=location.get("lat", 0), longitude=location.get("lng", 0)
        )

        # Parse address components
        components = result.get("address_components", [])
        address_data = {}

        for component in components:
            types = component.get("types", [])
            long_name = component.get("long_name", "")

            if "street_number" in types:
                address_data["street_number"] = long_name
            elif "route" in types:
                address_data["street_name"] = long_name
            elif "locality" in types:
                address_data["city"] = long_name
            elif "administrative_area_level_1" in types:
                address_data["state"] = long_name
            elif "postal_code" in types:
                address_data["postal_code"] = long_name
            elif "country" in types:
                address_data["country"] = long_name

        address = Address(
            formatted_address=result.get("formatted_address", ""), **address_data
        )

        # Determine geocode type
        types = result.get("types", [])
        geocode_type = self._map_google_types_to_geocode_type(types)

        # Calculate confidence (Google doesn't provide this directly)
        confidence = 0.9  # Default high confidence for Google results

        return GeocodeResult(
            coordinate=coordinate,
            address=address,
            confidence=confidence,
            type=geocode_type,
            place_id=result.get("place_id", ""),
            metadata={"types": types, "geometry": geometry},
        )

    def _parse_google_route(
        self,
        route_data: dict[str, Any],
        origin: Coordinate,
        destination: Coordinate,
        waypoints: list[Coordinate],
        profile: RouteProfile,
    ) -> Route:
        """Parse Google route response."""
        # Parse overview polyline
        overview_polyline = route_data.get("overview_polyline", {}).get("points", "")
        overview_geometry = (
            self._decode_polyline(overview_polyline) if overview_polyline else []
        )

        # Parse legs
        legs = route_data.get("legs", [])
        segments = []

        for leg in legs:
            steps = []
            leg_steps = leg.get("steps", [])

            for step_data in leg_steps:
                step = self._parse_google_step(step_data)
                steps.append(step)

            # Get leg coordinates
            start_location = leg.get("start_location", {})
            end_location = leg.get("end_location", {})

            start_coord = Coordinate(
                latitude=start_location.get("lat", 0),
                longitude=start_location.get("lng", 0),
            )
            end_coord = Coordinate(
                latitude=end_location.get("lat", 0),
                longitude=end_location.get("lng", 0),
            )

            # Determine traffic condition
            traffic_condition = TrafficCondition.UNKNOWN
            duration = leg.get("duration", {}).get("value", 0)
            duration_in_traffic = leg.get("duration_in_traffic", {}).get("value", 0)

            if duration_in_traffic and duration:
                ratio = duration_in_traffic / duration
                if ratio > 1.5:
                    traffic_condition = TrafficCondition.HEAVY
                elif ratio > 1.3:
                    traffic_condition = TrafficCondition.MODERATE
                elif ratio > 1.1:
                    traffic_condition = TrafficCondition.LIGHT
                else:
                    traffic_condition = TrafficCondition.FREE_FLOW

            segment = RouteSegment(
                start_coordinate=start_coord,
                end_coordinate=end_coord,
                distance=leg.get("distance", {}).get("value", 0),
                duration=duration,
                steps=steps,
                traffic_condition=traffic_condition,
                traffic_duration=duration_in_traffic,
            )
            segments.append(segment)

        # Calculate total values
        total_distance = sum(leg.get("distance", {}).get("value", 0) for leg in legs)
        total_duration = sum(leg.get("duration", {}).get("value", 0) for leg in legs)
        traffic_duration = (
            sum(leg.get("duration_in_traffic", {}).get("value", 0) for leg in legs)
            or None
        )

        return Route(
            origin=origin,
            destination=destination,
            waypoints=waypoints,
            segments=segments,
            total_distance=total_distance,
            total_duration=total_duration,
            profile=profile,
            overview_geometry=overview_geometry,
            traffic_duration=traffic_duration,
            metadata={
                "bounds": route_data.get("bounds"),
                "copyrights": route_data.get("copyrights"),
                "warnings": route_data.get("warnings", []),
            },
        )

    def _parse_google_step(self, step_data: dict[str, Any]) -> RouteStep:
        """Parse Google step data."""
        start_location = step_data.get("start_location", {})
        end_location = step_data.get("end_location", {})

        start_coord = Coordinate(
            latitude=start_location.get("lat", 0),
            longitude=start_location.get("lng", 0),
        )
        end_coord = Coordinate(
            latitude=end_location.get("lat", 0), longitude=end_location.get("lng", 0)
        )

        # Decode step polyline
        polyline = step_data.get("polyline", {}).get("points", "")
        geometry = self._decode_polyline(polyline) if polyline else []

        return RouteStep(
            instruction=step_data.get("html_instructions", "")
            .replace("<b>", "")
            .replace("</b>", ""),
            distance=step_data.get("distance", {}).get("value", 0),
            duration=step_data.get("duration", {}).get("value", 0),
            start_coordinate=start_coord,
            end_coordinate=end_coord,
            maneuver=step_data.get("maneuver"),
            geometry=geometry,
        )

    def _parse_google_place(self, result: dict[str, Any]) -> PlaceInfo:
        """Parse Google place result."""
        geometry = result.get("geometry", {})
        location = geometry.get("location", {})

        coordinate = Coordinate(
            latitude=location.get("lat", 0), longitude=location.get("lng", 0)
        )

        address = Address(formatted_address=result.get("formatted_address", ""))

        return PlaceInfo(
            place_id=result.get("place_id", ""),
            name=result.get("name", ""),
            coordinate=coordinate,
            address=address,
            category=result.get("types", [None])[0],
            rating=result.get("rating"),
            metadata=result,
        )

    def _parse_google_place_details(self, result: dict[str, Any]) -> PlaceInfo:
        """Parse Google place details result."""
        geometry = result.get("geometry", {})
        location = geometry.get("location", {})

        coordinate = Coordinate(
            latitude=location.get("lat", 0), longitude=location.get("lng", 0)
        )

        address = Address(formatted_address=result.get("formatted_address", ""))

        return PlaceInfo(
            place_id=result.get("place_id", ""),
            name=result.get("name", ""),
            coordinate=coordinate,
            address=address,
            phone=result.get("formatted_phone_number"),
            website=result.get("website"),
            rating=result.get("rating"),
            opening_hours=result.get("opening_hours", {}).get("weekday_text", []),
            metadata=result,
        )

    def _map_profile_to_google(self, profile: RouteProfile) -> str:
        """Map RouteProfile to Google mode."""
        profile_map = {
            RouteProfile.DRIVING: "driving",
            RouteProfile.DRIVING_TRAFFIC: "driving",
            RouteProfile.WALKING: "walking",
            RouteProfile.CYCLING: "bicycling",
            RouteProfile.TRUCK: "driving",
        }
        return profile_map.get(profile, "driving")

    def _map_google_types_to_geocode_type(self, types: list[str]) -> GeocodeType:
        """Map Google place types to GeocodeType."""
        for place_type in types:
            if place_type in ["street_address", "premise"]:
                return GeocodeType.ADDRESS
            if place_type == "postal_code":
                return GeocodeType.POSTCODE
            if place_type in ["point_of_interest", "establishment"]:
                return GeocodeType.POI
            if place_type in ["locality", "administrative_area_level_1", "country"]:
                return GeocodeType.LOCALITY
            if place_type == "intersection":
                return GeocodeType.INTERSECTION

        return GeocodeType.ADDRESS

    def _decode_polyline(self, polyline_str: str) -> list[Coordinate]:
        """Decode Google polyline string to coordinates."""
        coordinates = []
        index = lat = lng = 0

        while index < len(polyline_str):
            # Decode latitude
            shift = result = 0
            while True:
                byte = ord(polyline_str[index]) - 63
                index += 1
                result |= (byte & 0x1F) << shift
                shift += 5
                if byte < 0x20:
                    break

            dlat = ~(result >> 1) if result & 1 else result >> 1
            lat += dlat

            # Decode longitude
            shift = result = 0
            while True:
                byte = ord(polyline_str[index]) - 63
                index += 1
                result |= (byte & 0x1F) << shift
                shift += 5
                if byte < 0x20:
                    break

            dlng = ~(result >> 1) if result & 1 else result >> 1
            lng += dlng

            coordinates.append(Coordinate(latitude=lat / 1e5, longitude=lng / 1e5))

        return coordinates

    def _tile_to_lat_lon(self, x: int, y: int, z: int) -> tuple:
        """Convert tile coordinates to lat/lon."""
        import math

        n = 2.0**z
        lon_deg = x / n * 360.0 - 180.0
        lat_rad = math.atan(math.sinh(math.pi * (1 - 2 * y / n)))
        lat_deg = math.degrees(lat_rad)

        return lat_deg, lon_deg

    async def _handle_google_error(self, response: httpx.Response) -> None:
        """Handle Google Maps API errors."""
        try:
            data = response.json()
            status = data.get("status", "UNKNOWN_ERROR")
            error_message = data.get("error_message", f"Google Maps error: {status}")
        except (ValueError, TypeError, KeyError):
            error_message = f"Google Maps error: HTTP {response.status_code}"
            status = str(response.status_code)

        if status == "REQUEST_DENIED":
            error_message += " - Invalid API key or permissions"
            is_retryable = False
        elif status == "OVER_QUERY_LIMIT":
            error_message += " - Query limit exceeded"
            is_retryable = True
        elif response.status_code >= 500:
            error_message += " - Server error"
            is_retryable = True
        else:
            is_retryable = False

        raise MappingAdapterError(
            error_message, error_code=status, is_retryable=is_retryable
        )

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self._client:
            await self._client.aclose()
            self._client = None
