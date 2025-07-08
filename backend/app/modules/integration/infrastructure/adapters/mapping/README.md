# Mapping and Routing Adapter System

A comprehensive mapping and routing integration system that provides unified access to multiple mapping service providers including OpenStreetMap (OSM), Mapbox, and Google Maps Platform.

## Features

### Core Capabilities
- **Geocoding**: Convert addresses to coordinates
- **Reverse Geocoding**: Convert coordinates to addresses  
- **Routing**: Calculate routes between points with multiple travel modes
- **Route Optimization**: Optimize multi-stop routes (traveling salesman problem)
- **Distance Matrix**: Calculate distances/durations between multiple points
- **Place Search**: Find points of interest
- **Map Tiles**: Generate map tile URLs
- **Traffic Data**: Access real-time traffic information

### Provider Support
- **OpenStreetMap (OSM)**: Free, open-source mapping using Nominatim and OSRM
- **Mapbox**: Premium mapping services with traffic and advanced features
- **Google Maps Platform**: Enterprise-grade mapping with comprehensive features

### Key Features
- **Multi-Provider Fallback**: Automatic failover between providers
- **Health Monitoring**: Continuous health checks for all providers
- **Rate Limiting**: Built-in rate limiting compliance
- **Caching**: Intelligent caching for performance optimization
- **Async/Await**: Full asynchronous support
- **Type Safety**: Complete type annotations and data models

## Quick Start

### Basic Usage (OSM - Free)

```python
import asyncio
from app.modules.integration.infrastructure.adapters.mapping import (
    create_mapping_adapter_factory,
    MappingProvider,
    Coordinate,
    RouteProfile
)

async def basic_example():
    # OSM configuration (no API key required)
    config = {
        'providers': {
            'osm': {
                'credentials': {},
                'settings': {
                    'email': 'your-email@domain.com'  # Required for Nominatim
                }
            }
        },
        'fallback_order': [MappingProvider.OSM]
    }
    
    # Create factory and get adapter
    async with await create_mapping_adapter_factory(config) as factory:
        adapter = await factory.get_adapter()
        
        # Geocoding
        results = await adapter.geocode("Times Square, New York, NY")
        if results:
            location = results[0].coordinate
            print(f"Coordinates: {location.latitude}, {location.longitude}")
        
        # Routing
        origin = Coordinate(latitude=40.7580, longitude=-73.9855)
        destination = Coordinate(latitude=40.7505, longitude=-73.9934)
        
        routes = await adapter.calculate_route(
            origin=origin,
            destination=destination,
            profile=RouteProfile.WALKING
        )
        
        if routes:
            route = routes[0]
            print(f"Distance: {route.total_distance / 1000:.2f} km")
            print(f"Duration: {route.total_duration / 60:.1f} minutes")

# Run the example
asyncio.run(basic_example())
```

### Multi-Provider Setup

```python
config = {
    'providers': {
        'osm': {
            'credentials': {},
            'settings': {'email': 'your-email@domain.com'}
        },
        'mapbox': {
            'credentials': {'api_key': 'pk.your_mapbox_key'},
            'settings': {}
        },
        'google_maps': {
            'credentials': {'api_key': 'your_google_maps_key'},
            'settings': {}
        }
    },
    'fallback_order': [
        MappingProvider.GOOGLE_MAPS,  # Primary
        MappingProvider.MAPBOX,       # Fallback 1
        MappingProvider.OSM           # Fallback 2 (free)
    ]
}
```

## Provider Comparison

| Feature | OSM | Mapbox | Google Maps |
|---------|-----|--------|-------------|
| **Cost** | Free | Paid | Paid |
| **Geocoding** | ✓ | ✓ | ✓ |
| **Reverse Geocoding** | ✓ | ✓ | ✓ |
| **Routing** | ✓ | ✓ | ✓ |
| **Route Optimization** | ✓ | ✓ | ✓ |
| **Distance Matrix** | ✓ | ✓ | ✓ |
| **Map Tiles** | ✗ | ✓ | ✓ |
| **Traffic Data** | ✗ | ✓ | ✓ |
| **Place Search** | ✗ | ✓ | ✓ |
| **Place Details** | ✗ | ✗ | ✓ |
| **API Key Required** | ✗ | ✓ | ✓ |
| **Rate Limits** | 1 req/sec | Varies | Varies |

## Detailed Usage Examples

### Geocoding

```python
# Forward geocoding
results = await adapter.geocode(
    address="1600 Amphitheatre Parkway, Mountain View, CA",
    country="US",  # Optional country filter
    limit=5        # Maximum results
)

for result in results:
    print(f"Address: {result.address.formatted_address}")
    print(f"Coordinates: {result.coordinate.latitude}, {result.coordinate.longitude}")
    print(f"Confidence: {result.confidence}")
    print(f"Type: {result.type}")

# Reverse geocoding
coordinate = Coordinate(latitude=37.4224764, longitude=-122.0842499)
results = await adapter.reverse_geocode(coordinate, language="en")
```

### Routing

```python
# Basic routing
origin = Coordinate(latitude=37.7749, longitude=-122.4194)  # San Francisco
destination = Coordinate(latitude=34.0522, longitude=-118.2437)  # Los Angeles

routes = await adapter.calculate_route(
    origin=origin,
    destination=destination,
    profile=RouteProfile.DRIVING,
    departure_time=datetime.now(),  # For traffic-aware routing
    alternatives=True  # Get alternative routes
)

for i, route in enumerate(routes):
    print(f"Route {i+1}:")
    print(f"  Distance: {route.total_distance / 1000:.2f} km")
    print(f"  Duration: {route.total_duration / 60:.1f} minutes")
    if route.traffic_duration:
        delay = (route.traffic_duration - route.total_duration) / 60
        print(f"  Traffic delay: {delay:.1f} minutes")
```

### Route Optimization

```python
# Multi-stop delivery optimization
depot = Coordinate(latitude=37.7749, longitude=-122.4194)
delivery_stops = [
    Coordinate(latitude=37.7849, longitude=-122.4094),
    Coordinate(latitude=37.7649, longitude=-122.4294),
    Coordinate(latitude=37.7549, longitude=-122.4394),
]

optimized = await adapter.optimize_route(
    origin=depot,
    destinations=delivery_stops,
    return_to_origin=True,  # Return to starting point
    profile=RouteProfile.DRIVING
)

print(f"Optimized order: {optimized.optimized_order}")
print(f"Total distance: {optimized.route.total_distance / 1000:.2f} km")
print(f"Optimization time: {optimized.optimization_time:.2f} seconds")
```

### Distance Matrix

```python
# Calculate distances between multiple points
origins = [
    Coordinate(latitude=37.7749, longitude=-122.4194),  # San Francisco
    Coordinate(latitude=34.0522, longitude=-118.2437),  # Los Angeles
]

destinations = [
    Coordinate(latitude=40.7128, longitude=-74.0060),   # New York
    Coordinate(latitude=41.8781, longitude=-87.6298),   # Chicago
]

matrix = await adapter.calculate_distance_matrix(
    origins=origins,
    destinations=destinations,
    profile=RouteProfile.DRIVING
)

print("Distance Matrix (km):")
for i, origin_row in enumerate(matrix.distances):
    for j, distance in enumerate(origin_row):
        print(f"Origin {i+1} → Destination {j+1}: {distance / 1000:.2f} km")
```

### Place Search (Mapbox/Google Maps)

```python
# Search for places near a location
center = Coordinate(latitude=37.7749, longitude=-122.4194)

places = await adapter.search_places(
    query="coffee shop",
    coordinate=center,
    radius=1000,  # 1km radius
    category="food",
    limit=10
)

for place in places:
    print(f"Name: {place.name}")
    print(f"Address: {place.address.formatted_address}")
    print(f"Distance: {place.distance:.0f} meters")
    if place.rating:
        print(f"Rating: {place.rating}")
```

## Utility Functions

The system includes comprehensive utility functions for geographic calculations:

```python
from app.modules.integration.infrastructure.adapters.mapping import (
    GeoUtils, AddressUtils, RouteUtils, CoordinateConverter
)

# Geographic calculations
coord1 = Coordinate(latitude=37.7749, longitude=-122.4194)
coord2 = Coordinate(latitude=34.0522, longitude=-118.2437)

distance = GeoUtils.calculate_distance(coord1, coord2)
bearing = GeoUtils.calculate_bearing(coord1, coord2)

# Address parsing and formatting
address = AddressUtils.parse_address("123 Main St, Anytown, CA 12345")
formatted = AddressUtils.format_address(address, style="short")

# Coordinate formatting
decimal = CoordinateConverter.format_coordinate(coord1, "decimal")
dms = CoordinateConverter.format_coordinate(coord1, "dms")

# Route analysis
metrics = RouteUtils.calculate_route_metrics(route)
fuel_consumption = RouteUtils.estimate_fuel_consumption(route)
```

## Configuration

### Environment Variables

For production deployments, use environment variables:

```bash
# Mapbox
MAPBOX_API_KEY=pk.your_mapbox_api_key

# Google Maps
GOOGLE_MAPS_API_KEY=your_google_maps_api_key

# OSM settings
OSM_EMAIL=your-email@domain.com
```

### Complete Configuration Example

```python
config = {
    'providers': {
        'osm': {
            'credentials': {},
            'settings': {
                'email': 'integration@ezzday.com',
                'nominatim_url': 'https://nominatim.openstreetmap.org',
                'osrm_url': 'https://router.project-osrm.org',
                'connect_timeout': 10.0,
                'read_timeout': 30.0,
                'max_connections': 20
            }
        },
        'mapbox': {
            'credentials': {
                'api_key': os.getenv('MAPBOX_API_KEY')
            },
            'settings': {
                'connect_timeout': 10.0,
                'read_timeout': 30.0,
                'max_connections': 20
            }
        },
        'google_maps': {
            'credentials': {
                'api_key': os.getenv('GOOGLE_MAPS_API_KEY')
            },
            'settings': {
                'connect_timeout': 10.0,
                'read_timeout': 30.0,
                'max_connections': 20
            }
        }
    },
    'fallback_order': [
        MappingProvider.GOOGLE_MAPS,
        MappingProvider.MAPBOX,
        MappingProvider.OSM
    ],
    'health_check_interval': 300,  # 5 minutes
    'rate_limits': {
        'requests_per_minute': 60,
        'requests_per_hour': 1000
    }
}
```

## Health Monitoring

The system includes automatic health monitoring:

```python
async with await create_mapping_adapter_factory(config) as factory:
    # Check health of all providers
    status = await factory.get_all_adapters_status()
    
    for provider, health in status.items():
        print(f"{provider}: {health['status']} (healthy: {health['healthy']})")
    
    # Get provider capabilities
    for provider in [MappingProvider.OSM, MappingProvider.MAPBOX, MappingProvider.GOOGLE_MAPS]:
        capabilities = factory.get_provider_capabilities(provider)
        print(f"{provider} capabilities: {capabilities}")
```

## Error Handling

The system provides comprehensive error handling:

```python
from app.modules.integration.infrastructure.adapters.mapping import MappingAdapterError

try:
    results = await adapter.geocode("invalid address")
except MappingAdapterError as e:
    print(f"Mapping error: {e}")
    print(f"Error code: {e.error_code}")
    print(f"Is retryable: {e.is_retryable}")
    
    if e.is_retryable:
        # Retry with exponential backoff
        await asyncio.sleep(2)
        results = await adapter.geocode("invalid address")
```

## Performance Optimization

### Caching

Use the built-in caching utilities:

```python
from app.modules.integration.infrastructure.adapters.mapping import MappingCache

# Create cache for expensive operations
cache = MappingCache(max_size=1000, ttl_seconds=3600)

# Cache geocoding results
cache_key = f"geocode:{address}"
results = cache.get(cache_key)

if results is None:
    results = await adapter.geocode(address)
    cache.set(cache_key, results)
```

### Coordinate Simplification

For routes with many points:

```python
from app.modules.integration.infrastructure.adapters.mapping import GeoUtils

# Simplify route geometry for storage/transmission
simplified_coords = GeoUtils.simplify_coordinates(
    route.overview_geometry,
    tolerance=0.0001  # Degrees tolerance
)
```

## Best Practices

1. **Use OSM for Development**: Start with OSM for development and testing (free, no API key)

2. **Configure Fallbacks**: Always configure multiple providers with OSM as final fallback

3. **Monitor API Usage**: Track API usage to avoid unexpected costs

4. **Cache Results**: Cache geocoding and routing results to reduce API calls

5. **Handle Rate Limits**: Implement proper retry logic with exponential backoff

6. **Use Appropriate Profiles**: Choose the right routing profile for your use case

7. **Validate Coordinates**: Always validate coordinate ranges before API calls

8. **Monitor Health**: Use built-in health monitoring for production systems

## API Reference

### Core Classes

- `MappingAdapterFactory`: Factory for creating and managing adapters
- `BaseMappingAdapter`: Base interface for all mapping adapters
- `OSMAdapter`: OpenStreetMap implementation
- `MapboxAdapter`: Mapbox API implementation
- `GoogleMapsAdapter`: Google Maps Platform implementation

### Data Models

- `Coordinate`: Geographic coordinate (lat/lon)
- `Address`: Structured address information
- `Route`: Complete route with segments and metadata
- `GeocodeResult`: Geocoding result with confidence score
- `DistanceMatrix`: Matrix of distances/durations between points

### Utility Classes

- `GeoUtils`: Geographic calculations and utilities
- `AddressUtils`: Address parsing and formatting
- `RouteUtils`: Route analysis and optimization
- `CoordinateConverter`: Coordinate format conversions
- `MappingCache`: Simple caching for mapping operations

## Integration Examples

See `examples.py` for complete working examples of all features.

## License

This mapping adapter system is part of the EzzDay backend and follows the project's licensing terms.