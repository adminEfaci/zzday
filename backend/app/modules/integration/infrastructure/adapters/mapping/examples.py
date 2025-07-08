"""Examples of using the mapping and routing adapter system."""

import asyncio

from . import (
    AddressUtils,
    Coordinate,
    GeoUtils,
    MappingProvider,
    RouteProfile,
    create_mapping_adapter_factory,
)


async def example_osm_usage():
    """Example of using OSM adapter for basic mapping operations."""

    # Configuration for OSM (free service)
    config = {
        "providers": {
            "osm": {
                "credentials": {},
                "settings": {
                    "email": "your-email@domain.com",  # Required for Nominatim
                    "connect_timeout": 10.0,
                    "read_timeout": 30.0,
                    "max_connections": 20,
                },
            }
        },
        "fallback_order": [MappingProvider.OSM],
        "health_check_interval": 300,
    }

    # Create factory
    async with await create_mapping_adapter_factory(config) as factory:
        # Get OSM adapter
        adapter = await factory.get_adapter(MappingProvider.OSM)

        print("=== OSM Adapter Examples ===")

        # 1. Geocoding
        print("\n1. Geocoding:")
        geocode_results = await adapter.geocode("Times Square, New York, NY")
        for result in geocode_results[:3]:  # Show first 3 results
            print(f"  - {result.address.formatted_address}")
            print(
                f"    Coordinates: {result.coordinate.latitude:.6f}, {result.coordinate.longitude:.6f}"
            )
            print(f"    Confidence: {result.confidence:.2f}")

        # 2. Reverse Geocoding
        print("\n2. Reverse Geocoding:")
        times_square = Coordinate(latitude=40.7580, longitude=-73.9855)
        reverse_results = await adapter.reverse_geocode(times_square)
        if reverse_results:
            result = reverse_results[0]
            print(f"  Address: {result.address.formatted_address}")

        # 3. Route Calculation
        print("\n3. Route Calculation:")
        origin = Coordinate(latitude=40.7580, longitude=-73.9855)  # Times Square
        destination = Coordinate(
            latitude=40.7505, longitude=-73.9934
        )  # Empire State Building

        routes = await adapter.calculate_route(
            origin=origin, destination=destination, profile=RouteProfile.WALKING
        )

        if routes:
            route = routes[0]
            print(f"  Distance: {route.total_distance / 1000:.2f} km")
            print(f"  Duration: {route.total_duration / 60:.1f} minutes")
            print(f"  Segments: {len(route.segments)}")

        # 4. Distance Matrix
        print("\n4. Distance Matrix:")
        origins = [
            Coordinate(latitude=40.7580, longitude=-73.9855),  # Times Square
            Coordinate(latitude=40.7505, longitude=-73.9934),  # Empire State Building
        ]
        destinations = [
            Coordinate(latitude=40.7614, longitude=-73.9776),  # Central Park
            Coordinate(latitude=40.7061, longitude=-74.0087),  # Brooklyn Bridge
        ]

        matrix = await adapter.calculate_distance_matrix(
            origins=origins, destinations=destinations, profile=RouteProfile.DRIVING
        )

        print(f"  Origins: {len(matrix.origins)}")
        print(f"  Destinations: {len(matrix.destinations)}")
        print("  Distance matrix (km):")
        for i, row in enumerate(matrix.distances):
            distances_km = [d / 1000.0 for d in row]
            print(f"    Origin {i+1}: {distances_km}")


async def example_multi_provider_usage():
    """Example of using multiple providers with fallback."""

    # Configuration with multiple providers
    config = {
        "providers": {
            "osm": {
                "credentials": {},
                "settings": {
                    "email": "your-email@domain.com",
                    "connect_timeout": 10.0,
                    "read_timeout": 30.0,
                },
            },
            "mapbox": {
                "credentials": {
                    "api_key": "pk.your_mapbox_api_key_here"  # Replace with real key
                },
                "settings": {"connect_timeout": 10.0, "read_timeout": 30.0},
            },
            "google_maps": {
                "credentials": {
                    "api_key": "your_google_maps_api_key_here"  # Replace with real key
                },
                "settings": {"connect_timeout": 10.0, "read_timeout": 30.0},
            },
        },
        "fallback_order": [
            MappingProvider.GOOGLE_MAPS,  # Preferred (most features)
            MappingProvider.MAPBOX,  # Fallback 1 (good features)
            MappingProvider.OSM,  # Fallback 2 (free, basic features)
        ],
        "health_check_interval": 300,
    }

    async with await create_mapping_adapter_factory(config) as factory:
        print("=== Multi-Provider Examples ===")

        # 1. Get adapter with fallback
        print("\n1. Getting adapter with automatic fallback:")
        adapter = await factory.get_adapter(fallback=True)
        print(f"  Using adapter: {adapter.__class__.__name__}")

        # 2. Check all providers status
        print("\n2. Provider Status:")
        status = await factory.get_all_adapters_status()
        for provider, provider_status in status.items():
            print(
                f"  {provider}: {provider_status['status']} (healthy: {provider_status['healthy']})"
            )

        # 3. Try specific provider
        try:
            print("\n3. Using specific provider (OSM):")
            osm_adapter = await factory.get_adapter(MappingProvider.OSM, fallback=False)

            # Geocode with OSM
            results = await osm_adapter.geocode("San Francisco, CA")
            if results:
                result = results[0]
                print(f"  OSM Result: {result.address.formatted_address}")
                print(
                    f"  Coordinates: {result.coordinate.latitude:.6f}, {result.coordinate.longitude:.6f}"
                )
        except Exception as e:
            print(f"  Error with OSM: {e!s}")

        # 4. Provider capabilities
        print("\n4. Provider Capabilities:")
        for provider in [
            MappingProvider.OSM,
            MappingProvider.MAPBOX,
            MappingProvider.GOOGLE_MAPS,
        ]:
            capabilities = factory.get_provider_capabilities(provider)
            print(f"  {provider.value}:")
            for capability, available in capabilities.items():
                status = "✓" if available else "✗"
                print(f"    {status} {capability}")


async def example_route_optimization():
    """Example of route optimization for multiple destinations."""

    config = {
        "providers": {
            "osm": {
                "credentials": {},
                "settings": {
                    "email": "delivery@company.com",
                    "connect_timeout": 10.0,
                    "read_timeout": 60.0,  # Longer timeout for optimization
                },
            }
        },
        "fallback_order": [MappingProvider.OSM],
    }

    async with await create_mapping_adapter_factory(config) as factory:
        adapter = await factory.get_adapter()

        print("=== Route Optimization Example ===")

        # Delivery scenario: Start from depot, visit multiple stops, return to depot
        depot = Coordinate(latitude=40.7580, longitude=-73.9855)  # Times Square (depot)

        delivery_stops = [
            Coordinate(latitude=40.7505, longitude=-73.9934),  # Empire State Building
            Coordinate(latitude=40.7614, longitude=-73.9776),  # Central Park
            Coordinate(latitude=40.7061, longitude=-74.0087),  # Brooklyn Bridge
            Coordinate(latitude=40.7282, longitude=-73.9942),  # Flatiron Building
        ]

        print(f"\nOptimizing route for {len(delivery_stops)} delivery stops...")

        try:
            optimized_route = await adapter.optimize_route(
                origin=depot,
                destinations=delivery_stops,
                return_to_origin=True,  # Return to depot
                profile=RouteProfile.DRIVING,
            )

            print("\nOptimization Results:")
            print(f"  Optimized order: {optimized_route.optimized_order}")
            print(
                f"  Total distance: {optimized_route.route.total_distance / 1000:.2f} km"
            )
            print(
                f"  Total duration: {optimized_route.route.total_duration / 60:.1f} minutes"
            )
            print(
                f"  Optimization time: {optimized_route.optimization_time:.2f} seconds"
            )

            # Show optimized stop order
            print("\n  Optimized delivery sequence:")
            print("    1. Start at depot (Times Square)")
            for i, stop_index in enumerate(optimized_route.optimized_order):
                stop_names = [
                    "Empire State Building",
                    "Central Park",
                    "Brooklyn Bridge",
                    "Flatiron Building",
                ]
                print(f"    {i+2}. Stop {stop_index + 1}: {stop_names[stop_index]}")
            print(f"    {len(optimized_route.optimized_order) + 2}. Return to depot")

        except Exception as e:
            print(f"  Route optimization failed: {e!s}")
            print("  Note: OSRM public server may have limitations for optimization")


async def example_utility_functions():
    """Example of using utility functions."""

    print("=== Utility Functions Examples ===")

    # 1. Geographic calculations
    print("\n1. Geographic Calculations:")
    coord1 = Coordinate(latitude=40.7580, longitude=-73.9855)  # Times Square
    coord2 = Coordinate(latitude=40.7505, longitude=-73.9934)  # Empire State Building

    distance = GeoUtils.calculate_distance(coord1, coord2)
    bearing = GeoUtils.calculate_bearing(coord1, coord2)

    print(f"  Distance between points: {distance:.0f} meters")
    print(f"  Bearing: {bearing:.1f} degrees")

    # 2. Address parsing
    print("\n2. Address Parsing:")
    address_string = "350 5th Ave, New York, NY 10118, USA"
    parsed_address = AddressUtils.parse_address(address_string)

    print(f"  Original: {address_string}")
    print(f"  Street Number: {parsed_address.street_number}")
    print(f"  Street Name: {parsed_address.street_name}")
    print(f"  City: {parsed_address.city}")
    print(f"  State: {parsed_address.state}")
    print(f"  Postal Code: {parsed_address.postal_code}")

    # 3. Coordinate formatting
    print("\n3. Coordinate Formatting:")
    from .mapping_utils import CoordinateConverter

    coord = Coordinate(latitude=40.7580, longitude=-73.9855)

    decimal_format = CoordinateConverter.format_coordinate(coord, "decimal")
    dms_format = CoordinateConverter.format_coordinate(coord, "dms")

    print(f"  Decimal: {decimal_format}")
    print(f"  DMS: {dms_format}")

    # 4. Bounding box creation
    print("\n4. Bounding Box:")
    center = Coordinate(latitude=40.7580, longitude=-73.9855)
    radius = 1000  # 1km radius

    bbox = GeoUtils.create_bounding_box_from_center(center, radius)
    print(f"  Center: {center.latitude:.6f}, {center.longitude:.6f}")
    print(f"  Radius: {radius} meters")
    print(f"  Southwest: {bbox.southwest.latitude:.6f}, {bbox.southwest.longitude:.6f}")
    print(f"  Northeast: {bbox.northeast.latitude:.6f}, {bbox.northeast.longitude:.6f}")


async def main():
    """Run all examples."""

    print("Running Mapping System Examples")
    print("=" * 50)

    try:
        # Basic OSM usage (free, no API key required)
        await example_osm_usage()

        print("\n" + "=" * 50)

        # Multi-provider setup (requires API keys for Mapbox/Google)
        # await example_multi_provider_usage()

        # Route optimization
        await example_route_optimization()

        print("\n" + "=" * 50)

        # Utility functions
        await example_utility_functions()

    except Exception as e:
        print(f"Example failed: {e!s}")
        import traceback

        traceback.print_exc()


def example_configuration_templates():
    """Show configuration templates for different providers."""

    print("=== Configuration Templates ===")

    from .mapping_factory import MappingAdapterFactory

    factory = MappingAdapterFactory({})

    print("\n1. OSM Configuration (Free):")
    osm_config = factory.get_configuration_template(MappingProvider.OSM)
    print(f"  {osm_config}")

    print("\n2. Mapbox Configuration:")
    mapbox_config = factory.get_configuration_template(MappingProvider.MAPBOX)
    print(f"  {mapbox_config}")

    print("\n3. Google Maps Configuration:")
    google_config = factory.get_configuration_template(MappingProvider.GOOGLE_MAPS)
    print(f"  {google_config}")

    print("\n4. Complete Multi-Provider Configuration:")
    complete_config = {
        "providers": {
            "osm": osm_config,
            "mapbox": mapbox_config,
            "google_maps": google_config,
        },
        "fallback_order": [
            MappingProvider.GOOGLE_MAPS,
            MappingProvider.MAPBOX,
            MappingProvider.OSM,
        ],
        "health_check_interval": 300,
        "rate_limits": {"requests_per_minute": 60, "requests_per_hour": 1000},
    }

    import json

    print(json.dumps(complete_config, indent=2))


if __name__ == "__main__":
    # Show configuration templates
    example_configuration_templates()

    print("\n" + "=" * 50)

    # Run async examples
    asyncio.run(main())
