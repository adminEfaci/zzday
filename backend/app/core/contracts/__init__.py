"""
Core Contract System for Module Communication

This module provides the base infrastructure for module contracts,
enabling proper boundaries and communication between modules without
direct dependencies.
"""

from .base import ModuleContract, ContractEvent, ContractCommand, ContractQuery
from .registry import ContractRegistry, get_contract_registry

__all__ = [
    "ModuleContract",
    "ContractEvent", 
    "ContractCommand",
    "ContractQuery",
    "ContractRegistry",
    "get_contract_registry",
]