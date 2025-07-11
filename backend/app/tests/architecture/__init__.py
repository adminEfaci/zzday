"""Architecture Compliance Tests Package.

This package contains comprehensive tests to validate that the EzzDay backend
adheres to Domain-Driven Design (DDD) principles and clean architecture patterns.

Test Modules:
- test_architecture_compliance: Main architecture validation tests

These tests ensure:
- Proper DDD layer separation (domain/application/infrastructure)
- No circular dependencies between modules
- Consistent naming conventions
- Framework independence in domain layer
- Proper error handling patterns
- Configuration management compliance
- Performance and security compliance

Run with: pytest app/tests/architecture/ -v
"""

__all__ = [
    "test_architecture_compliance",
]
