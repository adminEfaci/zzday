"""Serialization utilities following DDD principles and hexagonal architecture.

This module provides framework-agnostic serialization utilities that follow Domain-Driven Design
principles. All serialization classes are pure Python that can be used across different layers
of the application without tight coupling to any specific framework.

Design Principles:
- Framework-agnostic (no FastAPI/Pydantic dependencies)
- Pure Python classes with clean __init__ validation
- Rich functionality with utility methods and properties
- Comprehensive error handling with clear ValidationError messages
- Static utility methods for convenience
- Proper class behavior (__eq__, __hash__, __repr__, __str__)
"""

import json
from datetime import date, datetime, time, timedelta
from decimal import Decimal
from enum import Enum
from typing import Any
from uuid import UUID

from pydantic import BaseModel

from app.core.errors import ValidationError

# =====================================================================================
# SERIALIZATION CLASSES
# =====================================================================================


class ExtendedJSONEncoder(json.JSONEncoder):
    """JSON encoder with support for additional types and rich functionality."""

    def __init__(self, *args, **kwargs):
        """
        Initialize extended JSON encoder.

        Args:
            **kwargs: Additional keyword arguments for JSONEncoder
        """
        super().__init__(*args, **kwargs)
        self.serialized_objects = []
        self.type_counts = {}

    def default(self, obj: Any) -> Any:
        """
        Convert objects to JSON-serializable format.

        Args:
            obj: Object to serialize

        Returns:
            JSON-serializable representation
        """
        obj_type = type(obj).__name__
        self.type_counts[obj_type] = self.type_counts.get(obj_type, 0) + 1

        if isinstance(obj, datetime | date | time):
            self.serialized_objects.append(("datetime", obj.isoformat()))
            return obj.isoformat()

        if isinstance(obj, timedelta):
            seconds = obj.total_seconds()
            self.serialized_objects.append(("timedelta", seconds))
            return seconds

        if isinstance(obj, UUID):
            uuid_str = str(obj)
            self.serialized_objects.append(("uuid", uuid_str))
            return uuid_str

        if isinstance(obj, Decimal):
            float_val = float(obj)
            self.serialized_objects.append(("decimal", float_val))
            return float_val

        if isinstance(obj, Enum):
            enum_val = obj.value
            self.serialized_objects.append(("enum", enum_val))
            return enum_val

        if isinstance(obj, BaseModel):
            model_dict = obj.model_dump()
            self.serialized_objects.append(("pydantic", model_dict))
            return model_dict

        if isinstance(obj, bytes):
            try:
                decoded = obj.decode("utf-8")
                self.serialized_objects.append(("bytes", decoded))
                return decoded
            except UnicodeDecodeError:
                # Fall back to base64 encoding for non-UTF8 bytes
                import base64

                encoded = base64.b64encode(obj).decode("ascii")
                self.serialized_objects.append(("bytes_base64", encoded))
                return {"__bytes_base64__": encoded}

        elif hasattr(obj, "__dict__"):
            obj_dict = obj.__dict__
            self.serialized_objects.append(("object", obj_dict))
            return obj_dict

        return super().default(obj)

    def get_serialization_stats(self) -> dict[str, Any]:
        """Get statistics about serialization process."""
        return {
            "total_objects": len(self.serialized_objects),
            "type_counts": self.type_counts,
            "unique_types": len(self.type_counts),
        }


class JSONSerializer:
    """JSON serialization with comprehensive type support and rich functionality."""

    def __init__(
        self,
        ensure_ascii: bool = False,
        indent: int | None = None,
        sort_keys: bool = False,
        separators: tuple | None = None,
    ):
        """
        Initialize JSON serializer.

        Args:
            ensure_ascii: Ensure ASCII output
            indent: Indentation level
            sort_keys: Sort dictionary keys
            separators: Custom separators tuple
        """
        self.ensure_ascii = ensure_ascii
        self.indent = indent
        self.sort_keys = sort_keys
        self.separators = separators

    def serialize(self, obj: Any) -> str:
        """
        Serialize object to JSON string.

        Args:
            obj: Object to serialize

        Returns:
            str: JSON string

        Raises:
            ValidationError: If serialization fails
        """
        try:
            return json.dumps(
                obj,
                cls=ExtendedJSONEncoder,
                ensure_ascii=self.ensure_ascii,
                indent=self.indent,
                sort_keys=self.sort_keys,
                separators=self.separators,
            )
        except (TypeError, ValueError) as e:
            raise ValidationError(f"JSON serialization failed: {e!s}")

    def deserialize(self, json_str: str) -> Any:
        """
        Deserialize JSON string to object.

        Args:
            json_str: JSON string to deserialize

        Returns:
            Deserialized object

        Raises:
            ValidationError: If deserialization fails
        """
        if not isinstance(json_str, str):
            raise ValidationError("Input must be a string")

        try:
            return json.loads(json_str)
        except (json.JSONDecodeError, ValueError) as e:
            raise ValidationError(f"JSON deserialization failed: {e!s}")

    @staticmethod
    def serialize_json(obj: Any, **kwargs) -> str:
        """
        Static method to serialize object to JSON.

        Args:
            obj: Object to serialize
            **kwargs: Additional arguments

        Returns:
            str: JSON string
        """
        try:
            serializer = JSONSerializer(**kwargs)
            return serializer.serialize(obj)
        except ValidationError:
            return json.dumps(obj, cls=ExtendedJSONEncoder)

    @staticmethod
    def deserialize_json(json_str: str) -> Any:
        """
        Static method to deserialize JSON string.

        Args:
            json_str: JSON string

        Returns:
            Deserialized object
        """
        try:
            serializer = JSONSerializer()
            return serializer.deserialize(json_str)
        except ValidationError:
            return None

    @staticmethod
    def is_valid_json(json_str: str) -> bool:
        """
        Check if string is valid JSON.

        Args:
            json_str: String to check

        Returns:
            bool: True if valid JSON
        """
        try:
            json.loads(json_str)
            return True
        except (json.JSONDecodeError, ValueError, TypeError):
            return False

    def serialize_pretty(self, obj: Any) -> str:
        """
        Serialize with pretty formatting.

        Args:
            obj: Object to serialize

        Returns:
            str: Pretty-formatted JSON string
        """
        original_indent = self.indent
        original_sort = self.sort_keys

        self.indent = 2
        self.sort_keys = True

        try:
            result = self.serialize(obj)
        finally:
            self.indent = original_indent
            self.sort_keys = original_sort

        return result

    def serialize_compact(self, obj: Any) -> str:
        """
        Serialize with compact formatting.

        Args:
            obj: Object to serialize

        Returns:
            str: Compact JSON string
        """
        original_separators = self.separators
        original_indent = self.indent

        self.separators = (",", ":")
        self.indent = None

        try:
            result = self.serialize(obj)
        finally:
            self.separators = original_separators
            self.indent = original_indent

        return result

    def __repr__(self) -> str:
        """Detailed string representation for debugging."""
        return f"JSONSerializer(indent={self.indent}, sort_keys={self.sort_keys})"


class CacheSerializer:
    """Serialization optimized for caching with rich functionality."""

    def __init__(self, compression: bool = False, model_class: type | None = None):
        """
        Initialize cache serializer.

        Args:
            compression: Whether to compress serialized data
            model_class: Default Pydantic model class for deserialization
        """
        self.compression = compression
        self.model_class = model_class
        self.serializer = JSONSerializer()

    def serialize_for_cache(self, obj: Any) -> str:
        """
        Serialize object for caching.

        Args:
            obj: Object to serialize

        Returns:
            str: Serialized string optimized for caching

        Raises:
            ValidationError: If serialization fails
        """
        # Convert Pydantic model to dict
        if isinstance(obj, BaseModel):
            obj = obj.model_dump()

        serialized = self.serializer.serialize_compact(obj)

        if self.compression:
            serialized = self._compress_data(serialized)

        return serialized

    def deserialize_from_cache(self, data: str) -> Any:
        """
        Deserialize from cache.

        Args:
            data: Cached data string

        Returns:
            Deserialized object

        Raises:
            ValidationError: If deserialization fails
        """
        if self.compression:
            data = self._decompress_data(data)

        obj = self.serializer.deserialize(data)

        # Convert back to Pydantic model if specified
        if self.model_class and isinstance(obj, dict):
            try:
                return self.model_class(**obj)
            except Exception as e:
                raise ValidationError(f"Model instantiation failed: {e!s}")

        return obj

    def _compress_data(self, data: str) -> str:
        """Compress serialized data."""
        try:
            import base64
            import gzip

            compressed = gzip.compress(data.encode("utf-8"))
            return base64.b64encode(compressed).decode("ascii")
        except Exception as e:
            raise ValidationError(f"Compression failed: {e!s}")

    def _decompress_data(self, data: str) -> str:
        """Decompress serialized data."""
        try:
            import base64
            import gzip

            compressed_bytes = base64.b64decode(data.encode("ascii"))
            return gzip.decompress(compressed_bytes).decode("utf-8")
        except Exception as e:
            raise ValidationError(f"Decompression failed: {e!s}")

    @staticmethod
    def serialize_for_cache_static(obj: Any, model_class: type | None = None) -> str:
        """
        Static method to serialize for cache.

        Args:
            obj: Object to serialize
            model_class: Model class hint

        Returns:
            str: Serialized string
        """
        try:
            serializer = CacheSerializer(model_class=model_class)
            return serializer.serialize_for_cache(obj)
        except ValidationError:
            return JSONSerializer.serialize_json(obj)

    @staticmethod
    def deserialize_from_cache_static(
        data: str, model_class: type | None = None
    ) -> Any:
        """
        Static method to deserialize from cache.

        Args:
            data: Cached data
            model_class: Model class for reconstruction

        Returns:
            Deserialized object
        """
        try:
            serializer = CacheSerializer(model_class=model_class)
            return serializer.deserialize_from_cache(data)
        except ValidationError:
            return JSONSerializer.deserialize_json(data)

    def __repr__(self) -> str:
        """Detailed string representation for debugging."""
        return (
            f"CacheSerializer(compression={self.compression}, model={self.model_class})"
        )


class DictProcessor:
    """Dictionary processing with merging, flattening and rich functionality."""

    def __init__(self, separator: str = ".", preserve_lists: bool = True):
        """
        Initialize dictionary processor.

        Args:
            separator: Separator for flattened keys
            preserve_lists: Whether to preserve list structures
        """
        self.separator = separator
        self.preserve_lists = preserve_lists

    def deep_merge(self, dict1: dict, dict2: dict) -> dict:
        """
        Deep merge two dictionaries.

        Args:
            dict1: First dictionary
            dict2: Second dictionary

        Returns:
            Dict: Merged dictionary

        Raises:
            ValidationError: If inputs are invalid
        """
        if not isinstance(dict1, dict) or not isinstance(dict2, dict):
            raise ValidationError("Both inputs must be dictionaries")

        result = dict1.copy()

        for key, value in dict2.items():
            if (
                key in result
                and isinstance(result[key], dict)
                and isinstance(value, dict)
            ):
                result[key] = self.deep_merge(result[key], value)
            else:
                result[key] = value

        return result

    def flatten_dict(self, nested_dict: dict, parent_key: str = "") -> dict:
        """
        Flatten nested dictionary.

        Args:
            nested_dict: Dictionary to flatten
            parent_key: Parent key prefix

        Returns:
            Dict: Flattened dictionary

        Raises:
            ValidationError: If input is invalid
        """
        if not isinstance(nested_dict, dict):
            raise ValidationError("Input must be a dictionary")

        items = []

        for key, value in nested_dict.items():
            new_key = f"{parent_key}{self.separator}{key}" if parent_key else key

            if isinstance(value, dict):
                items.extend(self.flatten_dict(value, new_key).items())
            elif isinstance(value, list) and not self.preserve_lists:
                # Flatten lists as indexed items
                for i, item in enumerate(value):
                    list_key = f"{new_key}{self.separator}{i}"
                    if isinstance(item, dict):
                        items.extend(self.flatten_dict(item, list_key).items())
                    else:
                        items.append((list_key, item))
            else:
                items.append((new_key, value))

        return dict(items)

    def unflatten_dict(self, flat_dict: dict) -> dict:
        """
        Unflatten dictionary.

        Args:
            flat_dict: Flattened dictionary

        Returns:
            Dict: Nested dictionary

        Raises:
            ValidationError: If input is invalid
        """
        if not isinstance(flat_dict, dict):
            raise ValidationError("Input must be a dictionary")

        result = {}

        for key, value in flat_dict.items():
            parts = key.split(self.separator)
            current = result

            for part in parts[:-1]:
                if part not in current:
                    current[part] = {}
                current = current[part]

            current[parts[-1]] = value

        return result

    def filter_dict(
        self,
        data: dict,
        include_keys: list[str] | None = None,
        exclude_keys: list[str] | None = None,
    ) -> dict:
        """
        Filter dictionary by keys.

        Args:
            data: Dictionary to filter
            include_keys: Keys to include (None = all)
            exclude_keys: Keys to exclude

        Returns:
            Dict: Filtered dictionary
        """
        if not isinstance(data, dict):
            raise ValidationError("Input must be a dictionary")

        result = {}

        for key, value in data.items():
            # Check inclusion criteria
            if include_keys and key not in include_keys:
                continue

            # Check exclusion criteria
            if exclude_keys and key in exclude_keys:
                continue

            result[key] = value

        return result

    def clean_dict(
        self, data: dict, remove_none: bool = True, remove_empty: bool = False
    ) -> dict:
        """
        Clean dictionary by removing unwanted values.

        Args:
            data: Dictionary to clean
            remove_none: Remove None values
            remove_empty: Remove empty containers

        Returns:
            Dict: Cleaned dictionary
        """
        if not isinstance(data, dict):
            raise ValidationError("Input must be a dictionary")

        result = {}

        for key, value in data.items():
            # Skip None values if requested
            if remove_none and value is None:
                continue

            # Skip empty containers if requested
            if remove_empty:
                if isinstance(value, list | dict | str) and len(value) == 0:
                    continue

            # Recursively clean nested dictionaries
            if isinstance(value, dict):
                cleaned_value = self.clean_dict(value, remove_none, remove_empty)
                if not remove_empty or cleaned_value:
                    result[key] = cleaned_value
            else:
                result[key] = value

        return result

    @staticmethod
    def deep_merge_static(dict1: dict, dict2: dict, separator: str = ".") -> dict:
        """
        Static method to deep merge dictionaries.

        Args:
            dict1: First dictionary
            dict2: Second dictionary
            separator: Key separator for processor

        Returns:
            Dict: Merged dictionary
        """
        try:
            processor = DictProcessor(separator)
            return processor.deep_merge(dict1, dict2)
        except ValidationError:
            # Fallback to simple merge
            result = dict1.copy()
            result.update(dict2)
            return result

    @staticmethod
    def flatten_dict_static(nested_dict: dict, separator: str = ".") -> dict:
        """
        Static method to flatten dictionary.

        Args:
            nested_dict: Dictionary to flatten
            separator: Key separator

        Returns:
            Dict: Flattened dictionary
        """
        try:
            processor = DictProcessor(separator)
            return processor.flatten_dict(nested_dict)
        except ValidationError:
            return nested_dict

    @staticmethod
    def unflatten_dict_static(flat_dict: dict, separator: str = ".") -> dict:
        """
        Static method to unflatten dictionary.

        Args:
            flat_dict: Flattened dictionary
            separator: Key separator

        Returns:
            Dict: Nested dictionary
        """
        try:
            processor = DictProcessor(separator)
            return processor.unflatten_dict(flat_dict)
        except ValidationError:
            return flat_dict

    def __repr__(self) -> str:
        """Detailed string representation for debugging."""
        return f"DictProcessor(separator='{self.separator}', preserve_lists={self.preserve_lists})"


# =====================================================================================
# BACKWARD COMPATIBILITY FUNCTIONS (Legacy API)
# =====================================================================================


def serialize_json(obj: Any, **kwargs) -> str:
    """Serialize object to JSON string."""
    return json.dumps(obj, cls=ExtendedJSONEncoder, **kwargs)


def deserialize_json(json_str: str) -> Any:
    """Deserialize JSON string."""
    return json.loads(json_str)


def serialize_for_cache(obj: Any) -> str:
    """Serialize object for caching."""
    # Convert to dict if Pydantic model
    if isinstance(obj, BaseModel):
        obj = obj.model_dump()

    return serialize_json(obj)


def deserialize_from_cache(
    json_str: str, model_class: type[BaseModel] | None = None
) -> Any:
    """Deserialize from cache."""
    data = deserialize_json(json_str)

    if model_class and isinstance(data, dict):
        return model_class(**data)

    return data


def deep_merge(dict1: dict, dict2: dict) -> dict:
    """Deep merge two dictionaries."""
    return DictProcessor.deep_merge_static(dict1, dict2)


def flatten_dict(nested_dict: dict, parent_key: str = "", separator: str = ".") -> dict:
    """Flatten nested dictionary."""
    items = []

    for key, value in nested_dict.items():
        new_key = f"{parent_key}{separator}{key}" if parent_key else key

        if isinstance(value, dict):
            items.extend(flatten_dict(value, new_key, separator=separator).items())
        else:
            items.append((new_key, value))

    return dict(items)


def unflatten_dict(flat_dict: dict, separator: str = ".") -> dict:
    """Unflatten dictionary."""
    result = {}

    for key, value in flat_dict.items():
        parts = key.split(separator)
        current = result

        for part in parts[:-1]:
            if part not in current:
                current[part] = {}
            current = current[part]

        current[parts[-1]] = value

    return result
