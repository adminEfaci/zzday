"""
Chaos engineering framework for testing system resilience.

Tests system behavior under failure conditions.
"""

from .chaos_monkey import ChaosMonkey

__all__ = ["ChaosMonkey"]