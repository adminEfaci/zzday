"""Integration Application Layer.

This module provides the application layer for the Integration module,
implementing the CQRS pattern with commands, queries, DTOs, and services.

The application layer orchestrates domain operations and provides
clean interfaces for external consumers while maintaining separation
of concerns and following DDD principles.

Key Components:
- Commands: Write operations that change state
- Queries: Read operations that retrieve data
- DTOs: Data transfer objects for clean interfaces
- Services: Application services for complex workflows
- Event Handlers: Cross-module event integration

Architecture:
- Command/Query Separation (CQRS)
- Domain-Driven Design (DDD)
- Event-Driven Architecture
- Clean Architecture principles
"""

from . import commands, dto, events, queries, services

__all__ = [
    "commands",
    "dto",
    "events",
    "queries",
    "services",
]
