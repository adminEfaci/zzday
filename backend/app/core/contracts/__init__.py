"""
Core Contract System for Module Communication

This module provides the base infrastructure for module contracts,
enabling proper boundaries and communication between modules without
direct dependencies.
"""

from .base import ContractCommand, ContractEvent, ContractQuery, ModuleContract
from .registry import ContractRegistry, get_contract_registry

__all__ = [
    "ContractCommand",
    "ContractEvent",
    "ContractQuery",
    "ContractRegistry",
    "ModuleContract",
    "get_contract_registry",
]