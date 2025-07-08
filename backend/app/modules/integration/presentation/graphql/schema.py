"""
Integration Module GraphQL Schema

This module provides the main GraphQL schema for the integration module,
combining all queries, mutations, and subscriptions into a unified interface.
"""

import strawberry

# Import all mutation classes
from .resolvers.mutations.integration_mutations import IntegrationMutations
from .resolvers.mutations.sync_mutations import SyncMutations
from .resolvers.mutations.webhook_mutations import WebhookMutations
from .resolvers.queries.email_queries import EmailQueries
from .resolvers.queries.fleet_queries import FleetQueries
from .resolvers.queries.health_queries import HealthQueries

# Import all query classes
from .resolvers.queries.integration_queries import IntegrationQueries
from .resolvers.queries.mapping_queries import MappingQueries
from .resolvers.queries.webhook_queries import WebhookQueries

# Import subscription classes
from .resolvers.subscriptions.health_subscriptions import HealthSubscriptions


@strawberry.type
class IntegrationQuery(
    IntegrationQueries,
    HealthQueries,
    MappingQueries,
    WebhookQueries,
    FleetQueries,
    EmailQueries,
):
    """
    Combined Integration module queries.

    This class inherits from all individual query classes to provide
    a unified GraphQL query interface for the integration module.
    """


@strawberry.type
class IntegrationMutation(IntegrationMutations, WebhookMutations, SyncMutations):
    """
    Combined Integration module mutations.

    This class inherits from all individual mutation classes to provide
    a unified GraphQL mutation interface for the integration module.
    """


@strawberry.type
class IntegrationSubscription(HealthSubscriptions):
    """
    Combined Integration module subscriptions.

    This class inherits from all individual subscription classes to provide
    a unified GraphQL subscription interface for the integration module.
    """


# Create the main integration schema
integration_schema = strawberry.Schema(
    query=IntegrationQuery,
    mutation=IntegrationMutation,
    subscription=IntegrationSubscription,
)


# Export the main classes for use in the main application schema
__all__ = [
    "IntegrationMutation",
    "IntegrationMutations",
    # Export with standard naming for main schema
    "IntegrationQueries",
    "IntegrationQuery",
    "IntegrationSubscription",
    "IntegrationSubscriptions",
    "integration_schema",
]

# Aliases for consistency with other modules
IntegrationQueries = IntegrationQuery
IntegrationMutations = IntegrationMutation
IntegrationSubscriptions = IntegrationSubscription
