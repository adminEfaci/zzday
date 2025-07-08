"""Notification module for managing multi-channel notifications and templates.

This module provides comprehensive notification management capabilities including:
- Multi-channel notification delivery (email, SMS, push, in-app)
- Template management with variable substitution
- Batch processing for bulk notifications
- Retry mechanisms for failed deliveries
- Delivery tracking and analytics
- Scheduled notifications

The module follows Domain-Driven Design principles with clear separation between:
- Domain layer: Core business logic and rules
- Application layer: Use cases and workflows
- Infrastructure layer: External integrations and persistence
- Interface layer: API endpoints and DTOs
"""

__version__ = "1.0.0"
