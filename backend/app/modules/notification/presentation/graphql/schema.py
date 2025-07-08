"""Notification GraphQL schema.

This module defines the complete GraphQL schema for the notification system,
including queries, mutations, and subscriptions.
"""


import strawberry

from .resolvers.mutations.notification_mutations import NotificationMutations
from .resolvers.queries.notification_queries import NotificationQueries
from .resolvers.subscriptions.notification_subscriptions import (
    NotificationSubscriptions,
)


@strawberry.type
class Query(NotificationQueries):
    """Root query type for notification system."""


@strawberry.type
class Mutation(NotificationMutations):
    """Root mutation type for notification system."""


@strawberry.type
class Subscription(NotificationSubscriptions):
    """Root subscription type for notification system."""


# Export the main schema components for integration with main GraphQL schema
# Use the base classes directly to avoid naming confusion
__all__ = [
    "NotificationMutations",
    "NotificationQueries",
    "NotificationSubscriptions",
    "schema",
]

# Alias for main schema integration
NotificationQueries = Query
NotificationMutations = Mutation
NotificationSubscriptions = Subscription

# Create the schema (for standalone use)
schema = strawberry.Schema(
    query=Query,
    mutation=Mutation,
    subscription=Subscription,
)
