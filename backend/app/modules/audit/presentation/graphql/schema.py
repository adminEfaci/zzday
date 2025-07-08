"""
Audit Module GraphQL Schema

This module provides the main GraphQL schema for the audit module,
combining all queries, mutations, and subscriptions into a unified interface.
"""

import strawberry

# Import mutation classes
from .resolvers.mutations.audit_mutations import (
    AuditMutations as AuditMutationResolvers,
)
from .resolvers.queries.analytics_queries import AnalyticsQueries

# Import query classes
from .resolvers.queries.audit_queries import AuditQueries as AuditQueryResolvers
from .resolvers.queries.report_queries import ReportQueries

# Import subscription classes
from .resolvers.subscriptions.audit_subscriptions import (
    AuditSubscriptions as AuditSubscriptionResolvers,
)


@strawberry.type
class AuditQueries:
    """
    Combined Audit module queries.

    This class combines all individual query classes to provide
    a unified GraphQL query interface for the audit module.
    """

    # Audit trail queries
    audit: AuditQueryResolvers = strawberry.field(
        resolver=lambda: AuditQueryResolvers(),
        description="Audit trail and log queries",
    )

    # Report queries
    report: ReportQueries = strawberry.field(
        resolver=lambda: ReportQueries(),
        description="Compliance and report generation queries",
    )

    # Analytics queries
    analytics: AnalyticsQueries = strawberry.field(
        resolver=lambda: AnalyticsQueries(),
        description="Audit analytics and insights queries",
    )


@strawberry.type
class AuditMutations:
    """
    Combined Audit module mutations.

    This class combines all individual mutation classes to provide
    a unified GraphQL mutation interface for the audit module.
    """

    # Audit mutations
    audit: AuditMutationResolvers = strawberry.field(
        resolver=lambda: AuditMutationResolvers(),
        description="Audit trail and log mutations",
    )


@strawberry.type
class AuditSubscriptions:
    """
    Combined Audit module subscriptions.

    This class combines all individual subscription classes to provide
    a unified GraphQL subscription interface for the audit module.
    """

    # Audit subscriptions
    audit: AuditSubscriptionResolvers = strawberry.field(
        resolver=lambda: AuditSubscriptionResolvers(),
        description="Real-time audit event subscriptions",
    )


# Create the main audit schema
audit_schema = strawberry.Schema(
    query=AuditQueries, mutation=AuditMutations, subscription=AuditSubscriptions
)


# Export the main classes for use in the main application schema
__all__ = ["AuditMutations", "AuditQueries", "AuditSubscriptions", "audit_schema"]
