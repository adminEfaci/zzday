"""
Main GraphQL Schema - Combines all module schemas into unified API

This is the central GraphQL schema that combines queries, mutations, and subscriptions 
from all modules into a single, cohesive API endpoint. Each module contributes its own 
operations which are organized under module-specific namespaces.
"""

import logging
from typing import Any

import strawberry

logger = logging.getLogger(__name__)

# Safe imports with fallbacks for modules that might not have presentation layers yet

# Identity Module
try:
    from app.modules.identity.presentation.graphql.schema import (
        IdentityMutations,
        IdentityQueries,
    )

    identity_available = True
    # Check if Identity has subscriptions
    try:
        from app.modules.identity.presentation.graphql.resolvers import (
            AuthSubscriptions,
            SessionSubscriptions,
            UserSubscriptions,
        )

        @strawberry.type
        class IdentitySubscriptions:
            """Combined identity module subscriptions."""

            auth: AuthSubscriptions = strawberry.field(
                resolver=lambda: AuthSubscriptions()
            )
            session: SessionSubscriptions = strawberry.field(
                resolver=lambda: SessionSubscriptions()
            )
            user: UserSubscriptions = strawberry.field(
                resolver=lambda: UserSubscriptions()
            )

        identity_subscriptions_available = True
    except ImportError:
        identity_subscriptions_available = False

except ImportError as e:
    logger.warning(f"Identity GraphQL schema not available: {e}")
    identity_available = False
    identity_subscriptions_available = False

    @strawberry.type
    class IdentityQueries:
        placeholder: str = strawberry.field(
            resolver=lambda: "Identity module not available"
        )

    @strawberry.type
    class IdentityMutations:
        placeholder: str = strawberry.field(
            resolver=lambda: "Identity module not available"
        )


# Audit Module
try:
    from app.modules.audit.presentation.graphql.schema import (
        AuditMutations,
        AuditQueries,
        AuditSubscriptions,
    )

    audit_available = True
    audit_subscriptions_available = True
except ImportError as e:
    logger.warning(f"Audit GraphQL schema not available: {e}")
    audit_available = False
    audit_subscriptions_available = False

    @strawberry.type
    class AuditQueries:
        placeholder: str = strawberry.field(
            resolver=lambda: "Audit module not available"
        )

    @strawberry.type
    class AuditMutations:
        placeholder: str = strawberry.field(
            resolver=lambda: "Audit module not available"
        )

    @strawberry.type
    class AuditSubscriptions:
        placeholder: str = strawberry.field(
            resolver=lambda: "Audit module not available"
        )


# Notification Module
try:
    from app.modules.notification.presentation.graphql.schema import (
        NotificationMutations,
        NotificationQueries,
        NotificationSubscriptions,
    )

    notification_available = True
    notification_subscriptions_available = True
except ImportError as e:
    logger.warning(f"Notification GraphQL schema not available: {e}")
    notification_available = False
    notification_subscriptions_available = False

    @strawberry.type
    class NotificationQueries:
        placeholder: str = strawberry.field(
            resolver=lambda: "Notification module not available"
        )

    @strawberry.type
    class NotificationMutations:
        placeholder: str = strawberry.field(
            resolver=lambda: "Notification module not available"
        )

    @strawberry.type
    class NotificationSubscriptions:
        placeholder: str = strawberry.field(
            resolver=lambda: "Notification module not available"
        )


# Integration Module
try:
    from app.modules.integration.presentation.graphql.schema import (
        IntegrationMutation as IntegrationMutations,
    )
    from app.modules.integration.presentation.graphql.schema import (
        IntegrationQuery as IntegrationQueries,
    )
    from app.modules.integration.presentation.graphql.schema import (
        IntegrationSubscription as IntegrationSubscriptions,
    )

    integration_available = True
    integration_subscriptions_available = True
except ImportError as e:
    logger.warning(f"Integration GraphQL schema not available: {e}")
    integration_available = False
    integration_subscriptions_available = False

    @strawberry.type
    class IntegrationQueries:
        placeholder: str = strawberry.field(
            resolver=lambda: "Integration module not available"
        )

    @strawberry.type
    class IntegrationMutations:
        placeholder: str = strawberry.field(
            resolver=lambda: "Integration module not available"
        )

    @strawberry.type
    class IntegrationSubscriptions:
        placeholder: str = strawberry.field(
            resolver=lambda: "Integration module not available"
        )


@strawberry.type
class Query:
    """Root GraphQL query combining all module queries."""

    # Identity module queries
    identity: IdentityQueries = strawberry.field(
        resolver=lambda info: IdentityQueries(),
        description="Identity and user management queries",
    )

    # Audit module queries
    audit: AuditQueries = strawberry.field(
        resolver=lambda info: AuditQueries(),
        description="Audit trail and compliance queries",
    )

    # Notification module queries
    notification: NotificationQueries = strawberry.field(
        resolver=lambda info: NotificationQueries(),
        description="Notification and messaging queries",
    )

    # Integration module queries
    integration: IntegrationQueries = strawberry.field(
        resolver=lambda info: IntegrationQueries(),
        description="External system integration queries",
    )


@strawberry.type
class Mutation:
    """Root GraphQL mutation combining all module mutations."""

    # Identity module mutations
    identity: IdentityMutations = strawberry.field(
        resolver=lambda info: IdentityMutations(),
        description="Identity and user management mutations",
    )

    # Audit module mutations
    audit: AuditMutations = strawberry.field(
        resolver=lambda info: AuditMutations(),
        description="Audit trail and compliance mutations",
    )

    # Notification module mutations
    notification: NotificationMutations = strawberry.field(
        resolver=lambda info: NotificationMutations(),
        description="Notification and messaging mutations",
    )

    # Integration module mutations
    integration: IntegrationMutations = strawberry.field(
        resolver=lambda info: IntegrationMutations(),
        description="External system integration mutations",
    )


# Build subscription type dynamically based on available modules
def build_subscription_class():
    """Dynamically build subscription class based on available modules."""

    # If no subscriptions are available, create a minimal subscription type
    if not any(
        [
            identity_subscriptions_available,
            audit_subscriptions_available,
            notification_subscriptions_available,
            integration_subscriptions_available,
        ]
    ):

        @strawberry.type
        class Subscription:
            """Root GraphQL subscription - no subscriptions currently available."""

            placeholder: str = strawberry.field(
                resolver=lambda: "No subscriptions available",
                description="Placeholder for when no module subscriptions are available",
            )

        return Subscription

    # Build subscription class with available modules
    @strawberry.type
    class Subscription:
        """Root GraphQL subscription combining all module subscriptions."""

    # Add fields dynamically
    if identity_subscriptions_available:
        Subscription.identity = strawberry.field(
            resolver=lambda info: IdentitySubscriptions(),
            description="Identity and user management subscriptions",
        )

    if audit_subscriptions_available:
        Subscription.audit = strawberry.field(
            resolver=lambda info: AuditSubscriptions(),
            description="Audit trail and compliance subscriptions",
        )

    if notification_subscriptions_available:
        Subscription.notification = strawberry.field(
            resolver=lambda info: NotificationSubscriptions(),
            description="Notification and messaging subscriptions",
        )

    if integration_subscriptions_available:
        Subscription.integration = strawberry.field(
            resolver=lambda info: IntegrationSubscriptions(),
            description="External system integration subscriptions",
        )

    return Subscription


# Create the subscription type
Subscription = build_subscription_class()


def create_schema() -> strawberry.Schema:
    """
    Create the main GraphQL schema with all module schemas combined.

    Returns:
        strawberry.Schema: The complete application schema
    """
    logger.info("Creating main GraphQL schema with all modules")

    try:
        # Log which modules are available
        logger.info(
            f"Module availability - Identity: {identity_available}, "
            f"Audit: {audit_available}, Notification: {notification_available}, "
            f"Integration: {integration_available}"
        )

        # Create schema with subscription support
        schema = strawberry.Schema(
            query=Query,
            mutation=Mutation,
            subscription=Subscription,
        )

        logger.info("Main GraphQL schema created successfully")
        
    except Exception as e:
        logger.error(f"Failed to create GraphQL schema: {e}", exc_info=True)
        raise
    else:
        return schema


async def get_context(request: Any, response: Any = None) -> dict:
    """
    Create GraphQL context with authentication, DI container, and request info.

    This context is passed to all resolvers and provides access to:
    - Current user (if authenticated)
    - DI container for service injection
    - Request and response objects
    - Database session factory

    Args:
        request: The incoming request object
        response: The response object (optional)

    Returns:
        dict: Context dictionary for GraphQL resolvers
    """
    from app.core.database import get_session

    context = {
        "request": request,
        "response": response,
        "container": getattr(request.app.state, "container", None),
        "get_session": get_session,  # Pass the session factory, not an open session
    }

    # Add current user if authenticated
    if hasattr(request, "state") and hasattr(request.state, "user"):
        context["user"] = request.state.user
    else:
        context["user"] = None

    # Add any additional context needed by modules
    context["is_authenticated"] = context["user"] is not None

    return context


# Export for main.py
__all__ = ["Mutation", "Query", "Subscription", "create_schema", "get_context"]
