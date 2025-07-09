"""
Core Infrastructure Adapters

Base classes and utilities for module internal adapters.
"""

from .base import InternalModuleAdapter
from .event_translator import EventTranslator

__all__ = [
    "InternalModuleAdapter",
    "EventTranslator",
]