"""
GraphQL Presentation Layer

This module provides the unified GraphQL schema for the entire application,
combining schemas from all domain modules.
"""

from .context import GraphQLContext, authenticated, with_permission
from .context import get_context as get_graphql_context
from .schema import Mutation, Query, Subscription, create_schema, get_context

__all__ = [
    "GraphQLContext",
    "Mutation",
    "Query",
    "Subscription",
    "authenticated",
    "create_schema",
    "get_context",
    "get_graphql_context",
    "with_permission",
]
