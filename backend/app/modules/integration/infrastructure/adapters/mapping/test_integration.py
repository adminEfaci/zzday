"""Basic integration test for the mapping adapter system."""

import asyncio

import pytest

from . import (
    DEFAULT_MAPPING_CONFIG,
    AddressUtils,
    Coordinate,
    CoordinateConverter,
    GeoUtils,
    MappingProvider,
    RouteProfile,
    create_mapping_adapter_factory,
)


class TestMappingSystemIntegration:
    """Integration tests for the mapping system."""

    @pytest.mark.asyncio
    async def test_osm_adapter_basic_functionality(self):
        """Test basic OSM adapter functionality."""

        # Use default OSM configuration
        config = DEFAULT_MAPPING_CONFIG.copy()

        async with await create_mapping_adapter_factory(config) as factory:
            adapter = await factory.get_adapter(MappingProvider.OSM)

            # Test geocoding
            results = await adapter.geocode("New York, NY", limit=1)
            assert len(results) > 0

            result = results[0]
            assert result.coordinate.latitude is not None
            assert result.coordinate.longitude is not None
            assert result.address.formatted_address is not None

            # Test reverse geocoding
            coord = Coordinate(latitude=40.7128, longitude=-74.0060)  # NYC
            reverse_results = await adapter.reverse_geocode(coord)
            assert len(reverse_results) > 0

            # Test routing
            origin = Coordinate(latitude=40.7580, longitude=-73.9855)
            destination = Coordinate(latitude=40.7505, longitude=-73.9934)

            routes = await adapter.calculate_route(
                origin=origin, destination=destination, profile=RouteProfile.WALKING
            )

            assert len(routes) > 0
            route = routes[0]
            assert route.total_distance > 0
            assert route.total_duration > 0
            assert len(route.segments) > 0

    @pytest.mark.asyncio
    async def test_factory_health_monitoring(self):
        """Test factory health monitoring functionality."""

        config = DEFAULT_MAPPING_CONFIG.copy()

        async with await create_mapping_adapter_factory(config) as factory:
            # Test health status
            status = await factory.get_all_adapters_status()
            assert "osm" in status
            assert status["osm"]["configured"] is True

            # Test provider capabilities
            capabilities = factory.get_provider_capabilities(MappingProvider.OSM)
            assert capabilities["geocoding"] is True
            assert capabilities["routing"] is True
            assert (
                capabilities["map_tiles"] is False
            )  # OSM doesn't provide tiles directly

    def test_geo_utils_calculations(self):
        """Test geographic utility calculations."""

        # Test distance calculation
        coord1 = Coordinate(latitude=40.7580, longitude=-73.9855)  # Times Square
        coord2 = Coordinate(
            latitude=40.7505, longitude=-73.9934
        )  # Empire State Building

        distance = GeoUtils.calculate_distance(coord1, coord2)
        assert distance > 0
        assert 800 < distance < 1200  # Approximately 1km

        # Test bearing calculation
        bearing = GeoUtils.calculate_bearing(coord1, coord2)
        assert 0 <= bearing < 360

        # Test point in circle
        center = coord1
        radius = 1000  # 1km

        assert GeoUtils.point_in_circle(center, coord1, radius)  # Same point
        assert GeoUtils.point_in_circle(center, coord2, radius)  # Within radius

        far_point = Coordinate(latitude=34.0522, longitude=-118.2437)  # LA
        assert not GeoUtils.point_in_circle(center, far_point, radius)  # Outside radius

    def test_address_utils_parsing(self):
        """Test address parsing utilities."""

        # Test address parsing
        address_string = "123 Main St, Anytown, CA 12345"
        parsed = AddressUtils.parse_address(address_string)

        assert parsed.street_number == "123"
        assert parsed.street_name == "Main St"
        assert parsed.city == "Anytown"
        assert parsed.state == "CA"
        assert parsed.postal_code == "12345"

        # Test address formatting
        formatted_short = AddressUtils.format_address(parsed, style="short")
        assert "Main St" in formatted_short
        assert "Anytown" in formatted_short

        # Test address normalization
        normalized = AddressUtils.normalize_address(parsed)
        assert normalized.street_name == "Main Street"  # Should expand "St" to "Street"

    def test_coordinate_converter(self):
        """Test coordinate conversion utilities."""

        coord = Coordinate(latitude=40.7580, longitude=-73.9855)

        # Test decimal format
        decimal_str = CoordinateConverter.format_coordinate(coord, "decimal")
        assert "40.758000" in decimal_str
        assert "-73.985500" in decimal_str

        # Test DMS format
        dms_str = CoordinateConverter.format_coordinate(coord, "dms")
        assert "°" in dms_str
        assert "'" in dms_str
        assert '"' in dms_str
        assert "N" in dms_str or "S" in dms_str
        assert "E" in dms_str or "W" in dms_str

        # Test DMS conversion
        degrees, minutes, seconds = CoordinateConverter.decimal_to_dms(40.7580)
        assert degrees == 40
        assert 0 <= minutes < 60
        assert 0 <= seconds < 60

        # Test reverse conversion
        decimal_back = CoordinateConverter.dms_to_decimal(degrees, minutes, seconds)
        assert abs(decimal_back - 40.7580) < 0.0001

    def test_configuration_templates(self):
        """Test configuration template generation."""

        from .mapping_factory import MappingAdapterFactory

        factory = MappingAdapterFactory({})

        # Test OSM template
        osm_template = factory.get_configuration_template(MappingProvider.OSM)
        assert "credentials" in osm_template
        assert "settings" in osm_template
        assert "email" in osm_template["settings"]

        # Test Mapbox template
        mapbox_template = factory.get_configuration_template(MappingProvider.MAPBOX)
        assert "credentials" in mapbox_template
        assert "api_key" in mapbox_template["credentials"]

        # Test Google Maps template
        google_template = factory.get_configuration_template(
            MappingProvider.GOOGLE_MAPS
        )
        assert "credentials" in google_template
        assert "api_key" in google_template["credentials"]

    def test_data_model_validation(self):
        """Test data model validation."""

        # Test coordinate validation
        valid_coord = Coordinate(latitude=40.7580, longitude=-73.9855)
        assert valid_coord.latitude == 40.7580
        assert valid_coord.longitude == -73.9855

        # Test invalid coordinates
        with pytest.raises(ValueError):
            Coordinate(latitude=91.0, longitude=0.0)  # Invalid latitude

        with pytest.raises(ValueError):
            Coordinate(latitude=0.0, longitude=181.0)  # Invalid longitude

        # Test coordinate methods
        coord_dict = valid_coord.to_dict()
        assert coord_dict["latitude"] == 40.7580
        assert coord_dict["longitude"] == -73.9855

        coord_list = valid_coord.to_list()
        assert coord_list == [-73.9855, 40.7580]  # GeoJSON format [lon, lat]


# Async test runner for pytest
async def run_async_tests():
    """Run async tests manually if not using pytest-asyncio."""

    test_instance = TestMappingSystemIntegration()

    print("Running OSM adapter test...")
    await test_instance.test_osm_adapter_basic_functionality()
    print("✓ OSM adapter test passed")

    print("Running factory health monitoring test...")
    await test_instance.test_factory_health_monitoring()
    print("✓ Factory health monitoring test passed")

    print("All async tests passed!")


def run_sync_tests():
    """Run synchronous tests."""

    test_instance = TestMappingSystemIntegration()

    print("Running geo utils test...")
    test_instance.test_geo_utils_calculations()
    print("✓ Geo utils test passed")

    print("Running address utils test...")
    test_instance.test_address_utils_parsing()
    print("✓ Address utils test passed")

    print("Running coordinate converter test...")
    test_instance.test_coordinate_converter()
    print("✓ Coordinate converter test passed")

    print("Running configuration templates test...")
    test_instance.test_configuration_templates()
    print("✓ Configuration templates test passed")

    print("Running data model validation test...")
    test_instance.test_data_model_validation()
    print("✓ Data model validation test passed")

    print("All sync tests passed!")


if __name__ == "__main__":
    print("Running Mapping System Integration Tests")
    print("=" * 50)

    # Run synchronous tests
    run_sync_tests()

    print("\n" + "=" * 50)

    # Run asynchronous tests
    print("Running async tests...")
    try:
        asyncio.run(run_async_tests())
    except Exception as e:
        print(f"Async test error: {e!s}")
        print("Note: Some tests may fail without proper network connectivity")

    print("\nIntegration tests completed!")
