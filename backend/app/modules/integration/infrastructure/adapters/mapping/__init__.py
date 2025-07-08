"""Mapping and routing adapter implementations."""

from .google_maps_adapter import GoogleMapsAdapter
from .mapbox_adapter import MapboxAdapter
from .mapping_base_adapter import BaseMappingAdapter, MappingAdapterError
from .mapping_factory import (
    DEFAULT_MAPPING_CONFIG,
    MappingAdapterFactory,
    MappingAdapterStatus,
    MappingProvider,
    create_mapping_adapter_factory,
)
from .mapping_types import (
    Address,
    BoundingBox,
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
from .mapping_utils import (
    AddressUtils,
    CoordinateConverter,
    GeoUtils,
    MappingCache,
    RouteUtils,
)
from .osm_adapter import OSMAdapter

__all__ = [
    "DEFAULT_MAPPING_CONFIG",
    "Address",
    "AddressUtils",
    # Base classes
    "BaseMappingAdapter",
    "BoundingBox",
    # Types and data models
    "Coordinate",
    "CoordinateConverter",
    "DistanceMatrix",
    # Utilities
    "GeoUtils",
    "GeocodeResult",
    "GeocodeType",
    "GoogleMapsAdapter",
    "MapTile",
    "MapboxAdapter",
    "MappingAdapterError",
    # Factory
    "MappingAdapterFactory",
    "MappingAdapterStatus",
    "MappingCache",
    "MappingProvider",
    # Adapters
    "OSMAdapter",
    "OptimizedRoute",
    "PlaceInfo",
    "Route",
    "RouteProfile",
    "RouteSegment",
    "RouteStep",
    "RouteUtils",
    "TrafficCondition",
    "TrafficInfo",
    "create_mapping_adapter_factory",
]
