"""
Device Fingerprint Value Object

Immutable representation of a device fingerprint for device identification and tracking.
"""

import hashlib
import json
from dataclasses import dataclass
from enum import Enum

from .base import ValueObject


class FingerprintComponent(Enum):
    """Components that make up a device fingerprint."""
    
    USER_AGENT = "user_agent"
    SCREEN_RESOLUTION = "screen_resolution"
    COLOR_DEPTH = "color_depth"
    TIMEZONE = "timezone"
    LANGUAGE = "language"
    PLATFORM = "platform"
    PLUGINS = "plugins"
    FONTS = "fonts"
    CANVAS = "canvas"
    WEBGL = "webgl"
    AUDIO = "audio"
    HARDWARE_CONCURRENCY = "hardware_concurrency"
    DEVICE_MEMORY = "device_memory"
    TOUCH_SUPPORT = "touch_support"
    COOKIES_ENABLED = "cookies_enabled"
    LOCAL_STORAGE = "local_storage"
    SESSION_STORAGE = "session_storage"
    INDEXED_DB = "indexed_db"


@dataclass(frozen=True)
class DeviceFingerprint(ValueObject):
    """
    Value object representing a device fingerprint.
    
    Combines multiple browser/device characteristics to create
    a unique identifier for device recognition.
    """
    
    fingerprint_hash: str
    components: dict[str, str]
    confidence_score: float  # 0.0 to 1.0
    
    def __post_init__(self):
        """Validate device fingerprint."""
        if not self.fingerprint_hash:
            raise ValueError("Fingerprint hash is required")
        
        if not self.components:
            raise ValueError("At least one fingerprint component is required")
        
        if not 0.0 <= self.confidence_score <= 1.0:
            raise ValueError("Confidence score must be between 0.0 and 1.0")
        
        # Validate hash format (should be hex)
        if not all(c in '0123456789abcdef' for c in self.fingerprint_hash.lower()):
            raise ValueError("Invalid fingerprint hash format")
        
        # Normalize hash to lowercase
        object.__setattr__(self, 'fingerprint_hash', self.fingerprint_hash.lower())
        
        # Ensure components is immutable
        object.__setattr__(self, 'components', dict(self.components))
    
    @classmethod
    def create_from_components(
        cls,
        components: dict[str, str],
        algorithm: str = 'sha256'
    ) -> 'DeviceFingerprint':
        """
        Create a device fingerprint from component data.
        
        Args:
            components: Dictionary of fingerprint components
            algorithm: Hashing algorithm to use
        """
        if not components:
            raise ValueError("Components cannot be empty")
        
        # Filter out None values and empty strings
        clean_components = {
            k: v for k, v in components.items() 
            if v is not None and str(v).strip()
        }
        
        if not clean_components:
            raise ValueError("No valid components provided")
        
        # Calculate fingerprint hash
        fingerprint_hash = cls._calculate_hash(clean_components, algorithm)
        
        # Calculate confidence score based on components
        confidence_score = cls._calculate_confidence(clean_components)
        
        return cls(
            fingerprint_hash=fingerprint_hash,
            components=clean_components,
            confidence_score=confidence_score
        )
    
    @staticmethod
    def _calculate_hash(components: dict[str, str], algorithm: str = 'sha256') -> str:
        """Calculate hash from components."""
        # Sort components for consistent hashing
        sorted_components = sorted(components.items())
        
        # Create a canonical string representation
        canonical = json.dumps(sorted_components, sort_keys=True, separators=(',', ':'))
        
        # Hash the canonical string
        if algorithm == 'sha256':
            return hashlib.sha256(canonical.encode()).hexdigest()
        if algorithm == 'sha1':
            return hashlib.sha1(canonical.encode()).hexdigest()
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    @staticmethod
    def _calculate_confidence(components: dict[str, str]) -> float:
        """
        Calculate confidence score based on available components.
        
        More components and more unique components increase confidence.
        """
        # Define component weights based on uniqueness
        component_weights = {
            FingerprintComponent.CANVAS.value: 0.15,
            FingerprintComponent.WEBGL.value: 0.15,
            FingerprintComponent.AUDIO.value: 0.10,
            FingerprintComponent.FONTS.value: 0.10,
            FingerprintComponent.PLUGINS.value: 0.08,
            FingerprintComponent.SCREEN_RESOLUTION.value: 0.08,
            FingerprintComponent.USER_AGENT.value: 0.06,
            FingerprintComponent.HARDWARE_CONCURRENCY.value: 0.06,
            FingerprintComponent.DEVICE_MEMORY.value: 0.05,
            FingerprintComponent.TIMEZONE.value: 0.05,
            FingerprintComponent.LANGUAGE.value: 0.04,
            FingerprintComponent.PLATFORM.value: 0.03,
            FingerprintComponent.COLOR_DEPTH.value: 0.02,
            FingerprintComponent.TOUCH_SUPPORT.value: 0.02,
            FingerprintComponent.COOKIES_ENABLED.value: 0.01
        }
        
        total_score = 0.0
        
        for component, value in components.items():
            weight = component_weights.get(component, 0.01)
            
            # Reduce weight if value seems generic
            if value in ['true', 'false', '1', '0', 'unknown', 'not available']:
                weight *= 0.5
            
            total_score += weight
        
        # Cap at 1.0
        return min(total_score, 1.0)
    
    @property
    def is_high_confidence(self) -> bool:
        """Check if fingerprint has high confidence."""
        return self.confidence_score >= 0.7
    
    @property
    def is_medium_confidence(self) -> bool:
        """Check if fingerprint has medium confidence."""
        return 0.4 <= self.confidence_score < 0.7
    
    @property
    def is_low_confidence(self) -> bool:
        """Check if fingerprint has low confidence."""
        return self.confidence_score < 0.4
    
    @property
    def component_count(self) -> int:
        """Get number of components in fingerprint."""
        return len(self.components)
    
    @property
    def has_canvas_fingerprint(self) -> bool:
        """Check if canvas fingerprinting is available."""
        return FingerprintComponent.CANVAS.value in self.components
    
    @property
    def has_webgl_fingerprint(self) -> bool:
        """Check if WebGL fingerprinting is available."""
        return FingerprintComponent.WEBGL.value in self.components
    
    @property
    def has_audio_fingerprint(self) -> bool:
        """Check if audio fingerprinting is available."""
        return FingerprintComponent.AUDIO.value in self.components
    
    def get_component(self, component: FingerprintComponent) -> str | None:
        """Get a specific component value."""
        return self.components.get(component.value)
    
    def get_critical_components(self) -> dict[str, str]:
        """Get only the most identifying components."""
        critical = [
            FingerprintComponent.CANVAS,
            FingerprintComponent.WEBGL,
            FingerprintComponent.AUDIO,
            FingerprintComponent.FONTS
        ]
        
        return {
            comp.value: self.components[comp.value]
            for comp in critical
            if comp.value in self.components
        }
    
    def similarity_score(self, other: 'DeviceFingerprint') -> float:
        """
        Calculate similarity score with another fingerprint.
        
        Returns a score between 0.0 (completely different) and 1.0 (identical).
        """
        if self.fingerprint_hash == other.fingerprint_hash:
            return 1.0
        
        # Compare components
        all_keys = set(self.components.keys()) | set(other.components.keys())
        if not all_keys:
            return 0.0
        
        matching_weight = 0.0
        total_weight = 0.0
        
        # Use component weights for similarity
        component_weights = {
            FingerprintComponent.CANVAS.value: 3.0,
            FingerprintComponent.WEBGL.value: 3.0,
            FingerprintComponent.AUDIO.value: 2.5,
            FingerprintComponent.FONTS.value: 2.0,
            FingerprintComponent.SCREEN_RESOLUTION.value: 1.5,
            FingerprintComponent.USER_AGENT.value: 1.0
        }
        
        for key in all_keys:
            weight = component_weights.get(key, 0.5)
            total_weight += weight
            
            if key in self.components and key in other.components:
                if self.components[key] == other.components[key]:
                    matching_weight += weight
        
        return matching_weight / total_weight if total_weight > 0 else 0.0
    
    def is_likely_same_device(self, other: 'DeviceFingerprint', threshold: float = 0.85) -> bool:
        """
        Check if another fingerprint likely represents the same device.
        
        Uses similarity scoring with a configurable threshold.
        """
        return self.similarity_score(other) >= threshold
    
    def anonymize(self) -> 'DeviceFingerprint':
        """Create an anonymized version suitable for analytics."""
        # Keep only non-identifying components
        safe_components = {}
        
        if 'platform' in self.components:
            safe_components['platform'] = self.components['platform']
        
        if 'screen_resolution' in self.components:
            safe_components['screen_resolution'] = self._generalize_resolution(
                self.components['screen_resolution']
            )
        
        if 'color_depth' in self.components:
            safe_components['color_depth'] = self.components['color_depth']
        
        if 'timezone' in self.components:
            safe_components['timezone'] = self._generalize_timezone(
                self.components['timezone']
            )
        
        if 'language' in self.components:
            # Just language, not locale
            language = self.components['language'].split('-')[0]
            safe_components['language'] = language
        
        return DeviceFingerprint.create_from_components(safe_components)
    
    def _generalize_resolution(self, resolution: str) -> str:
        """Generalize screen resolution to common categories."""
        if not resolution:
            return 'unknown'
        
        try:
            if 'x' not in resolution:
                return 'unknown'
            
            width, height = map(int, resolution.split('x'))
            
            # Categorize into common groups
            if width >= 2560:
                return 'high_res'
            if width >= 1920:
                return 'full_hd'
            if width >= 1366:
                return 'hd'
            return 'standard'
        except (ValueError, IndexError):
            return 'unknown'
    
    def _generalize_timezone(self, timezone: str) -> str:
        """Generalize timezone to region."""
        if not timezone:
            return 'unknown'
        
        # Map to general regions
        try:
            offset = int(timezone)
            if -5 <= offset <= -4:
                return 'americas_east'
            if -8 <= offset <= -6:
                return 'americas_west'
            if -1 <= offset <= 2:
                return 'europe'
            if 3 <= offset <= 5:
                return 'middle_east'
            if 6 <= offset <= 9:
                return 'asia'
            if 10 <= offset <= 12:
                return 'pacific'
            return 'other'
        except (ValueError, TypeError):
            return 'unknown'
    
    def to_dict(self) -> dict[str, any]:
        """Convert to dictionary for storage."""
        return {
            'fingerprint_hash': self.fingerprint_hash,
            'components': self.components,
            'confidence_score': self.confidence_score,
            'component_count': self.component_count
        }
    
    def __str__(self) -> str:
        """String representation."""
        return f"DeviceFingerprint(hash={self.fingerprint_hash[:8]}..., confidence={self.confidence_score:.2f})"
    
    def __repr__(self) -> str:
        """Debug representation."""
        return f"DeviceFingerprint(components={self.component_count}, confidence={self.confidence_score:.2f})"