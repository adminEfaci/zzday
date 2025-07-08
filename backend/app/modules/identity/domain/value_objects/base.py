"""
Base Value Object

Provides common functionality for all value objects in the identity domain.
"""

from abc import ABC
from datetime import datetime
from enum import Enum
from typing import Any, Generic, TypeVar

T = TypeVar('T')


class ValueObject(ABC, Generic[T]):
    """
    Base class for all value objects.
    
    Ensures immutability, proper equality, and hashing behavior.
    """
    
    def __eq__(self, other: Any) -> bool:
        """Value objects are equal if all their attributes are equal."""
        if not isinstance(other, self.__class__):
            return False
        
        # Compare all attributes
        return self.__dict__ == other.__dict__
    
    def __ne__(self, other: Any) -> bool:
        """Not equal is the opposite of equal."""
        return not self.__eq__(other)
    
    def __hash__(self) -> int:
        """Hash based on all attributes for use in sets and dicts."""
        # Get all attribute values as a tuple for hashing
        values = []
        for value in self.__dict__.values():
            if isinstance(value, (list, tuple)):
                values.append(tuple(value))
            elif isinstance(value, dict):
                values.append(tuple(sorted(value.items())))
            elif isinstance(value, set):
                values.append(frozenset(value))
            elif hasattr(value, '__dict__'):
                # For complex objects, use their string representation
                values.append(str(value))
            else:
                values.append(value)
        
        return hash((self.__class__.__name__, tuple(values)))
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        result = {}
        for key, value in self.__dict__.items():
            if hasattr(value, 'to_dict'):
                result[key] = value.to_dict()
            elif isinstance(value, (list, tuple)):
                result[key] = [
                    item.to_dict() if hasattr(item, 'to_dict') 
                    else self._serialize_value(item)
                    for item in value
                ]
            elif isinstance(value, dict):
                result[key] = {
                    k: v.to_dict() if hasattr(v, 'to_dict') 
                    else self._serialize_value(v)
                    for k, v in value.items()
                }
            elif isinstance(value, set):
                result[key] = [
                    item.to_dict() if hasattr(item, 'to_dict')
                    else self._serialize_value(item)
                    for item in value
                ]
            else:
                result[key] = self._serialize_value(value)
        return result
    
    def _serialize_value(self, value: Any) -> Any:
        """Serialize a single value for dictionary representation."""
        if isinstance(value, datetime):
            return value.isoformat()
        elif isinstance(value, Enum):
            return value.value
        elif hasattr(value, '__dict__'):
            # For complex objects without to_dict, use their dict
            return {k: self._serialize_value(v) for k, v in value.__dict__.items()}
        else:
            return value
    
    def __repr__(self) -> str:
        """Debug representation showing class and key attributes."""
        attrs = ', '.join(f'{k}={v!r}' for k, v in self.__dict__.items())
        return f"{self.__class__.__name__}({attrs})"