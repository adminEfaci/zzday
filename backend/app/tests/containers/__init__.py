"""
Test containers for real integration testing.

Replaces mocked services with actual containerized infrastructure.
"""

from .test_container import TestContainer

__all__ = ["TestContainer"]