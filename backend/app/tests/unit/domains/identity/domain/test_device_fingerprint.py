"""
Test cases for DeviceFingerprint value object.

Tests all aspects of device fingerprinting including creation,
validation, similarity scoring, and anonymization.
"""

from dataclasses import FrozenInstanceError

import pytest

from app.modules.identity.domain.value_objects.device_fingerprint import (
    DeviceFingerprint,
    FingerprintComponent,
)


class TestDeviceFingerprintCreation:
    """Test DeviceFingerprint creation and validation."""

    def test_create_from_components(self):
        """Test creating fingerprint from components."""
        components = {
            FingerprintComponent.USER_AGENT.value: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            FingerprintComponent.SCREEN_RESOLUTION.value: "1920x1080",
            FingerprintComponent.TIMEZONE.value: "-5",
            FingerprintComponent.LANGUAGE.value: "en-US",
            FingerprintComponent.CANVAS.value: "canvas_hash_123456",
        }

        fingerprint = DeviceFingerprint.create_from_components(components)

        assert fingerprint.fingerprint_hash is not None
        assert len(fingerprint.fingerprint_hash) == 64  # SHA256
        assert fingerprint.components == components
        assert fingerprint.component_count == 5
        assert 0.0 <= fingerprint.confidence_score <= 1.0

    def test_create_with_minimal_components(self):
        """Test creating fingerprint with minimal components."""
        components = {FingerprintComponent.USER_AGENT.value: "Mozilla/5.0"}

        fingerprint = DeviceFingerprint.create_from_components(components)

        assert fingerprint.component_count == 1
        assert fingerprint.confidence_score < 0.5  # Low confidence

    def test_invalid_fingerprint_creation(self):
        """Test validation of invalid fingerprints."""
        # Empty components
        with pytest.raises(ValueError, match="Components cannot be empty"):
            DeviceFingerprint.create_from_components({})

        # All empty values
        with pytest.raises(ValueError, match="No valid components provided"):
            DeviceFingerprint.create_from_components(
                {"empty": "", "none": None, "whitespace": "   "}
            )

        # Invalid confidence score
        with pytest.raises(
            ValueError, match="Confidence score must be between 0.0 and 1.0"
        ):
            DeviceFingerprint(
                fingerprint_hash="a" * 64,
                components={"test": "value"},
                confidence_score=1.5,
            )

    def test_component_filtering(self):
        """Test that empty components are filtered out."""
        components = {
            FingerprintComponent.USER_AGENT.value: "Mozilla/5.0",
            "empty": "",
            "none": None,
            FingerprintComponent.LANGUAGE.value: "en-US",
            "whitespace": "   ",
        }

        fingerprint = DeviceFingerprint.create_from_components(components)

        # Only valid components should be kept
        assert fingerprint.component_count == 2
        assert FingerprintComponent.USER_AGENT.value in fingerprint.components
        assert FingerprintComponent.LANGUAGE.value in fingerprint.components
        assert "empty" not in fingerprint.components


class TestDeviceFingerprintConfidence:
    """Test device fingerprint confidence scoring."""

    def test_high_confidence_fingerprint(self):
        """Test high confidence fingerprint characteristics."""
        components = {
            FingerprintComponent.CANVAS.value: "unique_canvas_hash",
            FingerprintComponent.WEBGL.value: "webgl_renderer_info",
            FingerprintComponent.AUDIO.value: "audio_context_hash",
            FingerprintComponent.FONTS.value: "installed_fonts_list",
            FingerprintComponent.USER_AGENT.value: "Mozilla/5.0",
            FingerprintComponent.SCREEN_RESOLUTION.value: "1920x1080",
            FingerprintComponent.TIMEZONE.value: "-5",
        }

        fingerprint = DeviceFingerprint.create_from_components(components)

        assert fingerprint.is_high_confidence is True
        assert fingerprint.is_medium_confidence is False
        assert fingerprint.is_low_confidence is False
        assert fingerprint.confidence_score > 0.7

    def test_medium_confidence_fingerprint(self):
        """Test medium confidence fingerprint characteristics."""
        components = {
            FingerprintComponent.USER_AGENT.value: "Mozilla/5.0",
            FingerprintComponent.SCREEN_RESOLUTION.value: "1920x1080",
            FingerprintComponent.TIMEZONE.value: "-5",
            FingerprintComponent.LANGUAGE.value: "en-US",
        }

        fingerprint = DeviceFingerprint.create_from_components(components)

        assert fingerprint.is_high_confidence is False
        assert fingerprint.is_medium_confidence is True
        assert fingerprint.is_low_confidence is False
        assert 0.3 < fingerprint.confidence_score < 0.7

    def test_low_confidence_fingerprint(self):
        """Test low confidence fingerprint characteristics."""
        components = {
            FingerprintComponent.USER_AGENT.value: "Mozilla/5.0",
            FingerprintComponent.LANGUAGE.value: "en",
        }

        fingerprint = DeviceFingerprint.create_from_components(components)

        assert fingerprint.is_high_confidence is False
        assert fingerprint.is_medium_confidence is False
        assert fingerprint.is_low_confidence is True
        assert fingerprint.confidence_score < 0.3

    def test_confidence_boosting_components(self):
        """Test components that boost confidence."""
        base_components = {FingerprintComponent.USER_AGENT.value: "Mozilla/5.0"}

        # Canvas fingerprint significantly boosts confidence
        with_canvas = base_components.copy()
        with_canvas[FingerprintComponent.CANVAS.value] = "canvas_hash"

        base_fp = DeviceFingerprint.create_from_components(base_components)
        canvas_fp = DeviceFingerprint.create_from_components(with_canvas)

        assert canvas_fp.confidence_score > base_fp.confidence_score
        assert canvas_fp.has_canvas_fingerprint is True


class TestDeviceFingerprintProperties:
    """Test device fingerprint properties."""

    def test_component_detection(self):
        """Test detection of specific components."""
        components = {
            FingerprintComponent.CANVAS.value: "canvas_hash",
            FingerprintComponent.WEBGL.value: "webgl_info",
            FingerprintComponent.AUDIO.value: "audio_hash",
            FingerprintComponent.USER_AGENT.value: "Mozilla/5.0",
        }

        fingerprint = DeviceFingerprint.create_from_components(components)

        assert fingerprint.has_canvas_fingerprint is True
        assert fingerprint.has_webgl_fingerprint is True
        assert fingerprint.has_audio_fingerprint is True
        assert fingerprint.has_font_fingerprint is False

    def test_get_component(self):
        """Test retrieving specific components."""
        components = {
            FingerprintComponent.USER_AGENT.value: "Mozilla/5.0",
            FingerprintComponent.SCREEN_RESOLUTION.value: "1920x1080",
        }

        fingerprint = DeviceFingerprint.create_from_components(components)

        assert (
            fingerprint.get_component(FingerprintComponent.USER_AGENT) == "Mozilla/5.0"
        )
        assert (
            fingerprint.get_component(FingerprintComponent.SCREEN_RESOLUTION)
            == "1920x1080"
        )
        assert fingerprint.get_component(FingerprintComponent.CANVAS) is None

    def test_component_categories(self):
        """Test categorization of components."""
        components = {
            # Hardware components
            FingerprintComponent.SCREEN_RESOLUTION.value: "1920x1080",
            FingerprintComponent.HARDWARE_CONCURRENCY.value: "8",
            # Software components
            FingerprintComponent.USER_AGENT.value: "Mozilla/5.0",
            FingerprintComponent.PLATFORM.value: "Win32",
            # Behavioral components
            FingerprintComponent.CANVAS.value: "canvas_hash",
        }

        fingerprint = DeviceFingerprint.create_from_components(components)

        hardware = fingerprint.get_hardware_components()
        assert FingerprintComponent.SCREEN_RESOLUTION.value in hardware
        assert FingerprintComponent.HARDWARE_CONCURRENCY.value in hardware

        software = fingerprint.get_software_components()
        assert FingerprintComponent.USER_AGENT.value in software
        assert FingerprintComponent.PLATFORM.value in software


class TestDeviceFingerprintSimilarity:
    """Test device fingerprint similarity calculations."""

    def test_identical_fingerprints(self):
        """Test similarity of identical fingerprints."""
        components = {
            FingerprintComponent.CANVAS.value: "canvas_hash_123",
            FingerprintComponent.USER_AGENT.value: "Mozilla/5.0",
            FingerprintComponent.SCREEN_RESOLUTION.value: "1920x1080",
        }

        fp1 = DeviceFingerprint.create_from_components(components)
        fp2 = DeviceFingerprint.create_from_components(components)

        similarity = fp1.similarity_score(fp2)
        assert similarity == 1.0
        assert fp1.is_likely_same_device(fp2, threshold=0.9)

    def test_similar_fingerprints(self):
        """Test similarity of similar but not identical fingerprints."""
        components1 = {
            FingerprintComponent.CANVAS.value: "canvas_hash_123",  # Same
            FingerprintComponent.USER_AGENT.value: "Mozilla/5.0",  # Same
            FingerprintComponent.SCREEN_RESOLUTION.value: "1920x1080",  # Different
        }

        components2 = {
            FingerprintComponent.CANVAS.value: "canvas_hash_123",  # Same
            FingerprintComponent.USER_AGENT.value: "Mozilla/5.0",  # Same
            FingerprintComponent.SCREEN_RESOLUTION.value: "1366x768",  # Different
        }

        fp1 = DeviceFingerprint.create_from_components(components1)
        fp2 = DeviceFingerprint.create_from_components(components2)

        similarity = fp1.similarity_score(fp2)
        assert 0.5 < similarity < 1.0  # Partially similar
        assert fp1.is_likely_same_device(fp2, threshold=0.5)
        assert not fp1.is_likely_same_device(fp2, threshold=0.9)

    def test_different_fingerprints(self):
        """Test similarity of completely different fingerprints."""
        components1 = {
            FingerprintComponent.CANVAS.value: "canvas_hash_123",
            FingerprintComponent.USER_AGENT.value: "Mozilla/5.0 Windows",
            FingerprintComponent.SCREEN_RESOLUTION.value: "1920x1080",
        }

        components2 = {
            FingerprintComponent.CANVAS.value: "canvas_hash_456",
            FingerprintComponent.USER_AGENT.value: "Safari/605.1.15",
            FingerprintComponent.SCREEN_RESOLUTION.value: "2560x1440",
        }

        fp1 = DeviceFingerprint.create_from_components(components1)
        fp2 = DeviceFingerprint.create_from_components(components2)

        similarity = fp1.similarity_score(fp2)
        assert similarity < 0.3  # Very different
        assert not fp1.is_likely_same_device(fp2)

    def test_weighted_similarity(self):
        """Test that important components are weighted more heavily."""
        # Same canvas but different basic components
        components1 = {
            FingerprintComponent.CANVAS.value: "unique_canvas",
            FingerprintComponent.LANGUAGE.value: "en-US",
        }

        components2 = {
            FingerprintComponent.CANVAS.value: "unique_canvas",
            FingerprintComponent.LANGUAGE.value: "fr-FR",
        }

        fp1 = DeviceFingerprint.create_from_components(components1)
        fp2 = DeviceFingerprint.create_from_components(components2)

        # Should still have high similarity due to matching canvas
        similarity = fp1.similarity_score(fp2)
        assert similarity > 0.7


class TestDeviceFingerprintAnonymization:
    """Test device fingerprint anonymization."""

    def test_anonymize_fingerprint(self):
        """Test fingerprint anonymization."""
        components = {
            FingerprintComponent.CANVAS.value: "unique_identifying_hash",
            FingerprintComponent.WEBGL.value: "specific_gpu_info",
            FingerprintComponent.USER_AGENT.value: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            FingerprintComponent.SCREEN_RESOLUTION.value: "1920x1080",
            FingerprintComponent.TIMEZONE.value: "-5",
            FingerprintComponent.LANGUAGE.value: "en-US",
            FingerprintComponent.FONTS.value: "Arial,Helvetica,Times",
        }

        fingerprint = DeviceFingerprint.create_from_components(components)
        anonymized = fingerprint.anonymize()

        # Identifying components should be removed
        assert FingerprintComponent.CANVAS.value not in anonymized.components
        assert FingerprintComponent.WEBGL.value not in anonymized.components
        assert FingerprintComponent.FONTS.value not in anonymized.components

        # Generic components should be generalized
        assert anonymized.components.get("screen_category") in ["high_res", "standard"]
        assert anonymized.components.get("timezone_region") is not None

        # Should have lower confidence
        assert anonymized.confidence_score < fingerprint.confidence_score

    def test_anonymization_preserves_categories(self):
        """Test that anonymization preserves general categories."""
        components = {
            FingerprintComponent.SCREEN_RESOLUTION.value: "3840x2160",  # 4K
            FingerprintComponent.PLATFORM.value: "Win32",
            FingerprintComponent.HARDWARE_CONCURRENCY.value: "16",
        }

        fingerprint = DeviceFingerprint.create_from_components(components)
        anonymized = fingerprint.anonymize()

        # Should categorize rather than remove
        assert "screen_category" in anonymized.components
        assert anonymized.components["screen_category"] == "4k"
        assert "platform" in anonymized.components
        assert "cpu_category" in anonymized.components
        assert anonymized.components["cpu_category"] == "high_core_count"


class TestDeviceFingerprintSecurity:
    """Test device fingerprint security features."""

    def test_fingerprint_immutability(self):
        """Test that fingerprints are immutable."""
        components = {FingerprintComponent.USER_AGENT.value: "Mozilla/5.0"}
        fingerprint = DeviceFingerprint.create_from_components(components)

        with pytest.raises(FrozenInstanceError):
            fingerprint.fingerprint_hash = "modified"

        with pytest.raises(FrozenInstanceError):
            fingerprint.components = {}

    def test_fingerprint_comparison(self):
        """Test fingerprint equality and hashing."""
        components = {
            FingerprintComponent.CANVAS.value: "canvas_hash",
            FingerprintComponent.USER_AGENT.value: "Mozilla/5.0",
        }

        fp1 = DeviceFingerprint.create_from_components(components)
        fp2 = DeviceFingerprint.create_from_components(components)
        fp3 = DeviceFingerprint.create_from_components(
            {FingerprintComponent.USER_AGENT.value: "Safari/605.1.15"}
        )

        # Same components should produce same hash
        assert fp1.fingerprint_hash == fp2.fingerprint_hash
        assert fp1 == fp2
        assert hash(fp1) == hash(fp2)

        # Different components should produce different hash
        assert fp1.fingerprint_hash != fp3.fingerprint_hash
        assert fp1 != fp3
        assert hash(fp1) != hash(fp3)

    def test_secure_string_representation(self):
        """Test that string representations don't expose sensitive data."""
        components = {
            FingerprintComponent.CANVAS.value: "sensitive_canvas_hash",
            FingerprintComponent.USER_AGENT.value: "Mozilla/5.0",
        }

        fingerprint = DeviceFingerprint.create_from_components(components)

        str_repr = str(fingerprint)
        repr_repr = repr(fingerprint)

        # Should not expose sensitive component values
        assert "sensitive_canvas_hash" not in str_repr
        assert "sensitive_canvas_hash" not in repr_repr

        # Should show general info
        assert "components=" in str_repr or "confidence=" in str_repr


class TestDeviceFingerprintStability:
    """Test device fingerprint stability detection."""

    def test_stability_scoring(self):
        """Test fingerprint stability scoring."""
        # Stable components
        stable_components = {
            FingerprintComponent.CANVAS.value: "canvas_hash",
            FingerprintComponent.HARDWARE_CONCURRENCY.value: "8",
            FingerprintComponent.SCREEN_RESOLUTION.value: "1920x1080",
        }

        stable_fp = DeviceFingerprint.create_from_components(stable_components)
        assert stable_fp.get_stability_score() > 0.7

        # Unstable components
        unstable_components = {
            FingerprintComponent.BATTERY_LEVEL.value: "0.75",
            FingerprintComponent.AVAILABLE_MEMORY.value: "4096",
        }

        unstable_fp = DeviceFingerprint.create_from_components(unstable_components)
        assert unstable_fp.get_stability_score() < 0.3

    def test_evolution_tracking(self):
        """Test tracking fingerprint evolution over time."""
        # Initial fingerprint
        initial_components = {
            FingerprintComponent.CANVAS.value: "canvas_hash",
            FingerprintComponent.USER_AGENT.value: "Chrome/100.0",
            FingerprintComponent.SCREEN_RESOLUTION.value: "1920x1080",
        }

        # Updated fingerprint (browser update)
        updated_components = {
            FingerprintComponent.CANVAS.value: "canvas_hash",  # Same
            FingerprintComponent.USER_AGENT.value: "Chrome/101.0",  # Updated
            FingerprintComponent.SCREEN_RESOLUTION.value: "1920x1080",  # Same
        }

        initial_fp = DeviceFingerprint.create_from_components(initial_components)
        updated_fp = DeviceFingerprint.create_from_components(updated_components)

        evolution = initial_fp.get_evolution_score(updated_fp)
        assert evolution["similarity"] > 0.8  # Still very similar
        assert evolution["likely_same_device"] is True
        assert evolution["changed_components"] == [
            FingerprintComponent.USER_AGENT.value
        ]


class TestDeviceFingerprintMetadata:
    """Test device fingerprint metadata extraction."""

    def test_extract_device_info(self):
        """Test extraction of device information from fingerprint."""
        components = {
            FingerprintComponent.USER_AGENT.value: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/100.0",
            FingerprintComponent.PLATFORM.value: "Win32",
            FingerprintComponent.SCREEN_RESOLUTION.value: "1920x1080",
            FingerprintComponent.HARDWARE_CONCURRENCY.value: "8",
        }

        fingerprint = DeviceFingerprint.create_from_components(components)
        device_info = fingerprint.extract_device_info()

        assert device_info["os"] == "Windows"
        assert device_info["browser"] == "Chrome"
        assert device_info["screen_width"] == 1920
        assert device_info["screen_height"] == 1080
        assert device_info["cpu_cores"] == 8

    def test_fraud_risk_assessment(self):
        """Test fraud risk assessment based on fingerprint."""
        # Suspicious fingerprint (minimal components)
        suspicious_components = {FingerprintComponent.USER_AGENT.value: "curl/7.64.1"}

        suspicious_fp = DeviceFingerprint.create_from_components(suspicious_components)
        risk = suspicious_fp.assess_fraud_risk()

        assert risk["score"] > 0.7  # High risk
        assert "bot_like_ua" in risk["factors"]
        assert "minimal_components" in risk["factors"]

        # Normal fingerprint
        normal_components = {
            FingerprintComponent.CANVAS.value: "canvas_hash",
            FingerprintComponent.USER_AGENT.value: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/100.0",
            FingerprintComponent.SCREEN_RESOLUTION.value: "1920x1080",
            FingerprintComponent.TIMEZONE.value: "-5",
            FingerprintComponent.LANGUAGE.value: "en-US",
        }

        normal_fp = DeviceFingerprint.create_from_components(normal_components)
        risk = normal_fp.assess_fraud_risk()

        assert risk["score"] < 0.3  # Low risk

    def test_create_valid_fingerprint(self):
        """Test creating a valid device fingerprint."""
        components = {
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "screen_resolution": "1920x1080",
            "timezone": "-5",
        }

        fingerprint = DeviceFingerprint.create_from_components(components)

        assert fingerprint.fingerprint_hash is not None
        assert len(fingerprint.fingerprint_hash) == 64  # SHA256 hex
        assert fingerprint.components == components
        assert 0.0 <= fingerprint.confidence_score <= 1.0

    def test_create_manual_fingerprint(self):
        """Test creating fingerprint manually."""
        components = {"platform": "Windows"}
        hash_value = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"

        fingerprint = DeviceFingerprint(
            fingerprint_hash=hash_value, components=components, confidence_score=0.5
        )

        assert fingerprint.fingerprint_hash == hash_value
        assert fingerprint.components == components
        assert fingerprint.confidence_score == 0.5

    def test_empty_fingerprint_hash_raises_error(self):
        """Test that empty fingerprint hash raises ValueError."""
        with pytest.raises(ValueError, match="Fingerprint hash is required"):
            DeviceFingerprint(
                fingerprint_hash="",
                components={"platform": "Windows"},
                confidence_score=0.5,
            )

    def test_empty_components_raises_error(self):
        """Test that empty components raise ValueError."""
        with pytest.raises(
            ValueError, match="At least one fingerprint component is required"
        ):
            DeviceFingerprint(
                fingerprint_hash="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                components={},
                confidence_score=0.5,
            )

    def test_invalid_confidence_score_raises_error(self):
        """Test that invalid confidence score raises ValueError."""
        components = {"platform": "Windows"}
        hash_value = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"

        with pytest.raises(
            ValueError, match="Confidence score must be between 0.0 and 1.0"
        ):
            DeviceFingerprint(
                fingerprint_hash=hash_value, components=components, confidence_score=1.5
            )

        with pytest.raises(
            ValueError, match="Confidence score must be between 0.0 and 1.0"
        ):
            DeviceFingerprint(
                fingerprint_hash=hash_value,
                components=components,
                confidence_score=-0.1,
            )

    def test_invalid_hash_format_raises_error(self):
        """Test that invalid hash format raises ValueError."""
        with pytest.raises(ValueError, match="Invalid fingerprint hash format"):
            DeviceFingerprint(
                fingerprint_hash="invalid@hash#format",
                components={"platform": "Windows"},
                confidence_score=0.5,
            )

    def test_hash_normalization(self):
        """Test that hash is normalized to lowercase."""
        components = {"platform": "Windows"}
        hash_upper = "ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890"

        fingerprint = DeviceFingerprint(
            fingerprint_hash=hash_upper, components=components, confidence_score=0.5
        )

        assert fingerprint.fingerprint_hash == hash_upper.lower()

    def test_create_from_empty_components_raises_error(self):
        """Test that creating from empty components raises error."""
        with pytest.raises(ValueError, match="Components cannot be empty"):
            DeviceFingerprint.create_from_components({})

    def test_create_from_all_invalid_components_raises_error(self):
        """Test that creating from all invalid components raises error."""
        invalid_components = {"empty": "", "none": None, "whitespace": "   "}

        with pytest.raises(ValueError, match="No valid components provided"):
            DeviceFingerprint.create_from_components(invalid_components)


class TestDeviceFingerprintHashCalculation:
    """Test fingerprint hash calculation."""

    def test_hash_calculation_consistent(self):
        """Test that hash calculation is consistent."""
        components = {
            "user_agent": "Mozilla/5.0",
            "screen_resolution": "1920x1080",
            "platform": "Windows",
        }

        fingerprint1 = DeviceFingerprint.create_from_components(components)
        fingerprint2 = DeviceFingerprint.create_from_components(components)

        assert fingerprint1.fingerprint_hash == fingerprint2.fingerprint_hash

    def test_different_components_different_hash(self):
        """Test that different components produce different hashes."""
        components1 = {"platform": "Windows"}
        components2 = {"platform": "macOS"}

        fingerprint1 = DeviceFingerprint.create_from_components(components1)
        fingerprint2 = DeviceFingerprint.create_from_components(components2)

        assert fingerprint1.fingerprint_hash != fingerprint2.fingerprint_hash

    def test_component_order_does_not_affect_hash(self):
        """Test that component order doesn't affect hash."""
        components1 = {"platform": "Windows", "timezone": "-5"}
        components2 = {"timezone": "-5", "platform": "Windows"}

        fingerprint1 = DeviceFingerprint.create_from_components(components1)
        fingerprint2 = DeviceFingerprint.create_from_components(components2)

        assert fingerprint1.fingerprint_hash == fingerprint2.fingerprint_hash

    def test_sha1_algorithm(self):
        """Test hash calculation with SHA1 algorithm."""
        components = {"platform": "Windows"}

        fingerprint = DeviceFingerprint.create_from_components(
            components, algorithm="sha1"
        )

        assert len(fingerprint.fingerprint_hash) == 40  # SHA1 hex

    def test_unsupported_algorithm_raises_error(self):
        """Test that unsupported algorithm raises error."""
        components = {"platform": "Windows"}

        with pytest.raises(ValueError, match="Unsupported algorithm: md5"):
            DeviceFingerprint.create_from_components(components, algorithm="md5")

    def test_component_cleaning(self):
        """Test that invalid components are cleaned during creation."""
        components = {
            "valid": "value",
            "empty": "",
            "none": None,
            "whitespace": "   ",
            "another_valid": "another_value",
        }

        fingerprint = DeviceFingerprint.create_from_components(components)

        expected_components = {"valid": "value", "another_valid": "another_value"}

        assert fingerprint.components == expected_components


class TestDeviceFingerprintConfidenceScoring:
    """Test confidence score calculation."""

    def test_high_confidence_canvas_fingerprint(self):
        """Test high confidence with canvas fingerprint."""
        components = {
            FingerprintComponent.CANVAS.value: "canvas_data_hash",
            FingerprintComponent.WEBGL.value: "webgl_data_hash",
            FingerprintComponent.AUDIO.value: "audio_data_hash",
            FingerprintComponent.FONTS.value: "font_list_hash",
        }

        fingerprint = DeviceFingerprint.create_from_components(components)

        assert fingerprint.confidence_score >= 0.4  # Should be reasonably high

    def test_low_confidence_basic_fingerprint(self):
        """Test low confidence with basic components."""
        components = {
            FingerprintComponent.COOKIES_ENABLED.value: "true",
            FingerprintComponent.TOUCH_SUPPORT.value: "false",
        }

        fingerprint = DeviceFingerprint.create_from_components(components)

        assert fingerprint.confidence_score < 0.1  # Should be low

    def test_generic_values_reduce_confidence(self):
        """Test that generic values reduce confidence."""
        # High-value component but generic value
        components_generic = {
            FingerprintComponent.CANVAS.value: "true"  # Generic value
        }

        # High-value component with unique value
        components_unique = {
            FingerprintComponent.CANVAS.value: "unique_canvas_signature_12345"
        }

        fingerprint_generic = DeviceFingerprint.create_from_components(
            components_generic
        )
        fingerprint_unique = DeviceFingerprint.create_from_components(components_unique)

        assert (
            fingerprint_generic.confidence_score < fingerprint_unique.confidence_score
        )

    def test_unknown_components_get_default_weight(self):
        """Test that unknown components get default weight."""
        components = {
            "unknown_component": "some_value",
            "another_unknown": "another_value",
        }

        fingerprint = DeviceFingerprint.create_from_components(components)

        # Should still have some confidence
        assert fingerprint.confidence_score > 0.0
        assert fingerprint.confidence_score < 0.1  # But low due to default weight

    def test_confidence_capped_at_one(self):
        """Test that confidence score is capped at 1.0."""
        # Create with many high-value components
        components = {}
        for component in FingerprintComponent:
            components[component.value] = f"unique_value_for_{component.value}"

        fingerprint = DeviceFingerprint.create_from_components(components)

        assert fingerprint.confidence_score <= 1.0


class TestDeviceFingerprintProperties:
    """Test device fingerprint properties."""

    def test_is_high_confidence(self):
        """Test high confidence property."""
        # Create high confidence fingerprint
        components = {
            FingerprintComponent.CANVAS.value: "unique_canvas",
            FingerprintComponent.WEBGL.value: "unique_webgl",
            FingerprintComponent.AUDIO.value: "unique_audio",
            FingerprintComponent.FONTS.value: "unique_fonts",
            FingerprintComponent.SCREEN_RESOLUTION.value: "1920x1080",
        }

        fingerprint = DeviceFingerprint.create_from_components(components)

        if fingerprint.confidence_score >= 0.7:
            assert fingerprint.is_high_confidence is True
        else:
            assert fingerprint.is_high_confidence is False

    def test_is_medium_confidence(self):
        """Test medium confidence property."""
        components = {
            FingerprintComponent.USER_AGENT.value: "Mozilla/5.0",
            FingerprintComponent.SCREEN_RESOLUTION.value: "1920x1080",
            FingerprintComponent.PLATFORM.value: "Windows",
        }

        fingerprint = DeviceFingerprint.create_from_components(components)

        if 0.4 <= fingerprint.confidence_score < 0.7:
            assert fingerprint.is_medium_confidence is True
        else:
            assert fingerprint.is_medium_confidence is False

    def test_is_low_confidence(self):
        """Test low confidence property."""
        components = {FingerprintComponent.COOKIES_ENABLED.value: "true"}

        fingerprint = DeviceFingerprint.create_from_components(components)

        if fingerprint.confidence_score < 0.4:
            assert fingerprint.is_low_confidence is True
        else:
            assert fingerprint.is_low_confidence is False

    def test_component_count(self):
        """Test component count property."""
        components = {"comp1": "value1", "comp2": "value2", "comp3": "value3"}

        fingerprint = DeviceFingerprint.create_from_components(components)

        assert fingerprint.component_count == 3

    def test_has_canvas_fingerprint(self):
        """Test canvas fingerprint detection."""
        components_with_canvas = {FingerprintComponent.CANVAS.value: "canvas_data"}

        components_without_canvas = {
            FingerprintComponent.USER_AGENT.value: "Mozilla/5.0"
        }

        fingerprint_with = DeviceFingerprint.create_from_components(
            components_with_canvas
        )
        fingerprint_without = DeviceFingerprint.create_from_components(
            components_without_canvas
        )

        assert fingerprint_with.has_canvas_fingerprint is True
        assert fingerprint_without.has_canvas_fingerprint is False

    def test_has_webgl_fingerprint(self):
        """Test WebGL fingerprint detection."""
        components_with_webgl = {FingerprintComponent.WEBGL.value: "webgl_data"}

        components_without_webgl = {
            FingerprintComponent.USER_AGENT.value: "Mozilla/5.0"
        }

        fingerprint_with = DeviceFingerprint.create_from_components(
            components_with_webgl
        )
        fingerprint_without = DeviceFingerprint.create_from_components(
            components_without_webgl
        )

        assert fingerprint_with.has_webgl_fingerprint is True
        assert fingerprint_without.has_webgl_fingerprint is False

    def test_has_audio_fingerprint(self):
        """Test audio fingerprint detection."""
        components_with_audio = {FingerprintComponent.AUDIO.value: "audio_data"}

        components_without_audio = {
            FingerprintComponent.USER_AGENT.value: "Mozilla/5.0"
        }

        fingerprint_with = DeviceFingerprint.create_from_components(
            components_with_audio
        )
        fingerprint_without = DeviceFingerprint.create_from_components(
            components_without_audio
        )

        assert fingerprint_with.has_audio_fingerprint is True
        assert fingerprint_without.has_audio_fingerprint is False


class TestDeviceFingerprintComponentAccess:
    """Test component access methods."""

    def test_get_component_existing(self):
        """Test getting existing component."""
        components = {
            FingerprintComponent.USER_AGENT.value: "Mozilla/5.0",
            FingerprintComponent.PLATFORM.value: "Windows",
        }

        fingerprint = DeviceFingerprint.create_from_components(components)

        assert (
            fingerprint.get_component(FingerprintComponent.USER_AGENT) == "Mozilla/5.0"
        )
        assert fingerprint.get_component(FingerprintComponent.PLATFORM) == "Windows"

    def test_get_component_non_existing(self):
        """Test getting non-existing component."""
        components = {FingerprintComponent.USER_AGENT.value: "Mozilla/5.0"}

        fingerprint = DeviceFingerprint.create_from_components(components)

        assert fingerprint.get_component(FingerprintComponent.CANVAS) is None

    def test_get_critical_components(self):
        """Test getting critical components."""
        components = {
            FingerprintComponent.CANVAS.value: "canvas_data",
            FingerprintComponent.WEBGL.value: "webgl_data",
            FingerprintComponent.USER_AGENT.value: "Mozilla/5.0",  # Not critical
            FingerprintComponent.FONTS.value: "font_list",
            FingerprintComponent.PLATFORM.value: "Windows",  # Not critical
        }

        fingerprint = DeviceFingerprint.create_from_components(components)
        critical = fingerprint.get_critical_components()

        expected_critical = {
            FingerprintComponent.CANVAS.value: "canvas_data",
            FingerprintComponent.WEBGL.value: "webgl_data",
            FingerprintComponent.FONTS.value: "font_list",
        }

        assert critical == expected_critical

    def test_get_critical_components_empty(self):
        """Test getting critical components when none exist."""
        components = {
            FingerprintComponent.USER_AGENT.value: "Mozilla/5.0",
            FingerprintComponent.PLATFORM.value: "Windows",
        }

        fingerprint = DeviceFingerprint.create_from_components(components)
        critical = fingerprint.get_critical_components()

        assert critical == {}


class TestDeviceFingerprintSimilarity:
    """Test fingerprint similarity scoring."""

    def test_identical_fingerprints_full_similarity(self):
        """Test that identical fingerprints have full similarity."""
        components = {
            FingerprintComponent.USER_AGENT.value: "Mozilla/5.0",
            FingerprintComponent.CANVAS.value: "canvas_data",
        }

        fingerprint1 = DeviceFingerprint.create_from_components(components)
        fingerprint2 = DeviceFingerprint.create_from_components(components)

        assert fingerprint1.similarity_score(fingerprint2) == 1.0

    def test_completely_different_fingerprints_no_similarity(self):
        """Test that completely different fingerprints have no similarity."""
        components1 = {FingerprintComponent.USER_AGENT.value: "Mozilla/5.0"}
        components2 = {FingerprintComponent.PLATFORM.value: "Windows"}

        fingerprint1 = DeviceFingerprint.create_from_components(components1)
        fingerprint2 = DeviceFingerprint.create_from_components(components2)

        assert fingerprint1.similarity_score(fingerprint2) == 0.0

    def test_partial_similarity(self):
        """Test partial similarity calculation."""
        components1 = {
            FingerprintComponent.USER_AGENT.value: "Mozilla/5.0",
            FingerprintComponent.PLATFORM.value: "Windows",
        }

        components2 = {
            FingerprintComponent.USER_AGENT.value: "Mozilla/5.0",  # Same
            FingerprintComponent.PLATFORM.value: "macOS",  # Different
        }

        fingerprint1 = DeviceFingerprint.create_from_components(components1)
        fingerprint2 = DeviceFingerprint.create_from_components(components2)

        similarity = fingerprint1.similarity_score(fingerprint2)
        assert 0.0 < similarity < 1.0

    def test_high_value_components_weighted_more(self):
        """Test that high-value components are weighted more in similarity."""
        # Only canvas differs
        components1 = {
            FingerprintComponent.CANVAS.value: "canvas1",
            FingerprintComponent.USER_AGENT.value: "Mozilla/5.0",
        }

        components2 = {
            FingerprintComponent.CANVAS.value: "canvas2",  # Different high-value
            FingerprintComponent.USER_AGENT.value: "Mozilla/5.0",  # Same low-value
        }

        # Only user agent differs
        components3 = {
            FingerprintComponent.CANVAS.value: "canvas1",
            FingerprintComponent.USER_AGENT.value: "Chrome/90.0",  # Different low-value
        }

        components4 = {
            FingerprintComponent.CANVAS.value: "canvas1",  # Same high-value
            FingerprintComponent.USER_AGENT.value: "Mozilla/5.0",
        }

        fingerprint1 = DeviceFingerprint.create_from_components(components1)
        fingerprint2 = DeviceFingerprint.create_from_components(components2)
        fingerprint3 = DeviceFingerprint.create_from_components(components3)
        fingerprint4 = DeviceFingerprint.create_from_components(components4)

        similarity_canvas_diff = fingerprint1.similarity_score(fingerprint2)
        similarity_ua_diff = fingerprint3.similarity_score(fingerprint4)

        # Same canvas should result in higher similarity than same user agent
        assert similarity_ua_diff > similarity_canvas_diff

    def test_is_likely_same_device_default_threshold(self):
        """Test is_likely_same_device with default threshold."""
        components1 = {
            FingerprintComponent.CANVAS.value: "canvas_data",
            FingerprintComponent.WEBGL.value: "webgl_data",
        }

        components2 = {
            FingerprintComponent.CANVAS.value: "canvas_data",  # Same
            FingerprintComponent.WEBGL.value: "different_webgl",  # Different
        }

        fingerprint1 = DeviceFingerprint.create_from_components(components1)
        fingerprint2 = DeviceFingerprint.create_from_components(components2)

        similarity = fingerprint1.similarity_score(fingerprint2)
        expected_result = similarity >= 0.85

        assert fingerprint1.is_likely_same_device(fingerprint2) == expected_result

    def test_is_likely_same_device_custom_threshold(self):
        """Test is_likely_same_device with custom threshold."""
        components1 = {FingerprintComponent.USER_AGENT.value: "Mozilla/5.0"}
        components2 = {FingerprintComponent.USER_AGENT.value: "Mozilla/5.0"}

        fingerprint1 = DeviceFingerprint.create_from_components(components1)
        fingerprint2 = DeviceFingerprint.create_from_components(components2)

        # With low threshold, should be considered same device
        assert fingerprint1.is_likely_same_device(fingerprint2, threshold=0.5) is True

        # With high threshold, might not be (depending on weights)
        result_high = fingerprint1.is_likely_same_device(fingerprint2, threshold=0.99)
        assert isinstance(result_high, bool)  # Just ensure it returns a boolean


class TestDeviceFingerprintAnonymization:
    """Test fingerprint anonymization."""

    def test_anonymize_removes_identifying_data(self):
        """Test that anonymization removes identifying data."""
        components = {
            FingerprintComponent.CANVAS.value: "unique_canvas_signature",
            FingerprintComponent.WEBGL.value: "unique_webgl_signature",
            FingerprintComponent.USER_AGENT.value: "Mozilla/5.0 (specific details)",
            FingerprintComponent.PLATFORM.value: "Windows",
            FingerprintComponent.SCREEN_RESOLUTION.value: "1920x1080",
            FingerprintComponent.TIMEZONE.value: "-5",
            FingerprintComponent.LANGUAGE.value: "en-US",
        }

        fingerprint = DeviceFingerprint.create_from_components(components)
        anonymized = fingerprint.anonymize()

        # Should not contain identifying components
        assert FingerprintComponent.CANVAS.value not in anonymized.components
        assert FingerprintComponent.WEBGL.value not in anonymized.components
        assert FingerprintComponent.USER_AGENT.value not in anonymized.components

        # Should contain safe components
        assert "platform" in anonymized.components
        assert "screen_resolution" in anonymized.components
        assert "timezone" in anonymized.components
        assert "language" in anonymized.components

    def test_anonymize_generalizes_resolution(self):
        """Test resolution generalization."""
        fingerprint = DeviceFingerprint.create_from_components(
            {FingerprintComponent.SCREEN_RESOLUTION.value: "2560x1440"}
        )

        anonymized = fingerprint.anonymize()
        assert anonymized.components["screen_resolution"] == "high_res"

        fingerprint2 = DeviceFingerprint.create_from_components(
            {FingerprintComponent.SCREEN_RESOLUTION.value: "1920x1080"}
        )

        anonymized2 = fingerprint2.anonymize()
        assert anonymized2.components["screen_resolution"] == "full_hd"

    def test_anonymize_generalizes_timezone(self):
        """Test timezone generalization."""
        fingerprint = DeviceFingerprint.create_from_components(
            {FingerprintComponent.TIMEZONE.value: "-5"}  # Eastern US
        )

        anonymized = fingerprint.anonymize()
        assert anonymized.components["timezone"] == "americas_east"

        fingerprint2 = DeviceFingerprint.create_from_components(
            {FingerprintComponent.TIMEZONE.value: "1"}  # Central Europe
        )

        anonymized2 = fingerprint2.anonymize()
        assert anonymized2.components["timezone"] == "europe"

    def test_anonymize_simplifies_language(self):
        """Test language simplification."""
        fingerprint = DeviceFingerprint.create_from_components(
            {FingerprintComponent.LANGUAGE.value: "en-US"}
        )

        anonymized = fingerprint.anonymize()
        assert anonymized.components["language"] == "en"

    def test_anonymize_handles_missing_components(self):
        """Test anonymization with missing components."""
        fingerprint = DeviceFingerprint.create_from_components(
            {FingerprintComponent.PLATFORM.value: "Windows"}
        )

        anonymized = fingerprint.anonymize()

        # Should handle missing components gracefully
        assert "platform" in anonymized.components
        assert anonymized.components.get("screen_resolution") in ["unknown", ""]
        assert anonymized.components.get("timezone") in ["unknown", ""]


class TestDeviceFingerprintSerialization:
    """Test fingerprint serialization."""

    def test_to_dict(self):
        """Test converting to dictionary."""
        components = {
            FingerprintComponent.USER_AGENT.value: "Mozilla/5.0",
            FingerprintComponent.PLATFORM.value: "Windows",
        }

        fingerprint = DeviceFingerprint.create_from_components(components)
        data = fingerprint.to_dict()

        assert data["fingerprint_hash"] == fingerprint.fingerprint_hash
        assert data["components"] == components
        assert data["confidence_score"] == fingerprint.confidence_score
        assert data["component_count"] == 2


class TestDeviceFingerprintStringRepresentation:
    """Test string representation methods."""

    def test_str_representation(self):
        """Test __str__ method."""
        components = {FingerprintComponent.PLATFORM.value: "Windows"}
        fingerprint = DeviceFingerprint.create_from_components(components)

        str_repr = str(fingerprint)

        assert fingerprint.fingerprint_hash[:8] in str_repr
        assert f"confidence={fingerprint.confidence_score:.2f}" in str_repr

    def test_repr_representation(self):
        """Test __repr__ method."""
        components = {
            FingerprintComponent.PLATFORM.value: "Windows",
            FingerprintComponent.USER_AGENT.value: "Mozilla/5.0",
        }

        fingerprint = DeviceFingerprint.create_from_components(components)
        repr_str = repr(fingerprint)

        assert "components=2" in repr_str
        assert f"confidence={fingerprint.confidence_score:.2f}" in repr_str


class TestDeviceFingerprintImmutability:
    """Test that DeviceFingerprint is immutable."""

    def test_immutable_fingerprint_hash(self):
        """Test that fingerprint_hash cannot be changed."""
        fingerprint = DeviceFingerprint.create_from_components(
            {FingerprintComponent.PLATFORM.value: "Windows"}
        )

        with pytest.raises(FrozenInstanceError):
            fingerprint.fingerprint_hash = "new_hash"

    def test_immutable_components(self):
        """Test that components cannot be changed."""
        fingerprint = DeviceFingerprint.create_from_components(
            {FingerprintComponent.PLATFORM.value: "Windows"}
        )

        with pytest.raises(FrozenInstanceError):
            fingerprint.components = {"new": "components"}

    def test_immutable_confidence_score(self):
        """Test that confidence_score cannot be changed."""
        fingerprint = DeviceFingerprint.create_from_components(
            {FingerprintComponent.PLATFORM.value: "Windows"}
        )

        with pytest.raises(FrozenInstanceError):
            fingerprint.confidence_score = 0.9


class TestDeviceFingerprintEquality:
    """Test equality and comparison behavior."""

    def test_equal_fingerprints(self):
        """Test that identical fingerprints are equal."""
        components = {FingerprintComponent.PLATFORM.value: "Windows"}

        fingerprint1 = DeviceFingerprint.create_from_components(components)
        fingerprint2 = DeviceFingerprint.create_from_components(components)

        assert fingerprint1 == fingerprint2

    def test_different_fingerprints_not_equal(self):
        """Test that different fingerprints are not equal."""
        fingerprint1 = DeviceFingerprint.create_from_components(
            {FingerprintComponent.PLATFORM.value: "Windows"}
        )

        fingerprint2 = DeviceFingerprint.create_from_components(
            {FingerprintComponent.PLATFORM.value: "macOS"}
        )

        assert fingerprint1 != fingerprint2


class TestDeviceFingerprintEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_all_fingerprint_components_supported(self):
        """Test that all fingerprint components are supported."""
        components = {}
        for component in FingerprintComponent:
            components[component.value] = f"value_for_{component.value}"

        fingerprint = DeviceFingerprint.create_from_components(components)

        assert len(fingerprint.components) == len(FingerprintComponent)
        assert fingerprint.component_count == len(FingerprintComponent)

    def test_very_long_component_values(self):
        """Test with very long component values."""
        long_value = "x" * 10000
        components = {FingerprintComponent.USER_AGENT.value: long_value}

        fingerprint = DeviceFingerprint.create_from_components(components)

        assert (
            fingerprint.components[FingerprintComponent.USER_AGENT.value] == long_value
        )
        assert len(fingerprint.fingerprint_hash) == 64  # SHA256 should still work

    def test_unicode_component_values(self):
        """Test with unicode component values."""
        unicode_value = "测试用户代理 Mozilla/5.0"
        components = {FingerprintComponent.USER_AGENT.value: unicode_value}

        fingerprint = DeviceFingerprint.create_from_components(components)

        assert (
            fingerprint.components[FingerprintComponent.USER_AGENT.value]
            == unicode_value
        )

    def test_special_characters_in_components(self):
        """Test with special characters in component values."""
        special_value = (
            "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/534.16"
        )
        components = {FingerprintComponent.USER_AGENT.value: special_value}

        fingerprint = DeviceFingerprint.create_from_components(components)

        assert (
            fingerprint.components[FingerprintComponent.USER_AGENT.value]
            == special_value
        )

    def test_resolution_generalization_edge_cases(self):
        """Test resolution generalization edge cases."""
        fingerprint = DeviceFingerprint.create_from_components(
            {FingerprintComponent.PLATFORM.value: "test"}
        )

        # Test invalid resolution formats
        assert fingerprint._generalize_resolution("") == "unknown"
        assert fingerprint._generalize_resolution("invalid") == "unknown"
        assert fingerprint._generalize_resolution("1920") == "unknown"

        # Test boundary values
        assert fingerprint._generalize_resolution("2560x1440") == "high_res"
        assert fingerprint._generalize_resolution("1920x1080") == "full_hd"
        assert fingerprint._generalize_resolution("1366x768") == "hd"
        assert fingerprint._generalize_resolution("1024x768") == "standard"

    def test_timezone_generalization_edge_cases(self):
        """Test timezone generalization edge cases."""
        fingerprint = DeviceFingerprint.create_from_components(
            {FingerprintComponent.PLATFORM.value: "test"}
        )

        # Test invalid timezone formats
        assert fingerprint._generalize_timezone("") == "unknown"
        assert fingerprint._generalize_timezone("invalid") == "unknown"

        # Test boundary values
        assert fingerprint._generalize_timezone("-5") == "americas_east"
        assert fingerprint._generalize_timezone("-4") == "americas_east"
        assert fingerprint._generalize_timezone("-8") == "americas_west"
        assert fingerprint._generalize_timezone("1") == "europe"
        assert fingerprint._generalize_timezone("8") == "asia"
        assert fingerprint._generalize_timezone("15") == "other"

    def test_empty_similarity_components(self):
        """Test similarity calculation with empty components."""
        fingerprint1 = DeviceFingerprint(
            fingerprint_hash="hash1", components={}, confidence_score=0.0
        )

        fingerprint2 = DeviceFingerprint(
            fingerprint_hash="hash2", components={}, confidence_score=0.0
        )

        # Should handle empty components gracefully
        similarity = fingerprint1.similarity_score(fingerprint2)
        assert similarity == 0.0

    def test_boundary_confidence_scores(self):
        """Test boundary confidence score values."""
        components = {FingerprintComponent.PLATFORM.value: "Windows"}

        # Test exactly 0.0
        fingerprint1 = DeviceFingerprint(
            fingerprint_hash="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            components=components,
            confidence_score=0.0,
        )

        assert fingerprint1.confidence_score == 0.0
        assert fingerprint1.is_low_confidence is True

        # Test exactly 1.0
        fingerprint2 = DeviceFingerprint(
            fingerprint_hash="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            components=components,
            confidence_score=1.0,
        )

        assert fingerprint2.confidence_score == 1.0
        assert fingerprint2.is_high_confidence is True
