"""
Identity Module GraphQL Schema

This module provides the main GraphQL schema for the identity module,
combining all queries, mutations, and subscriptions into a unified interface.
"""

import strawberry

# Import mutation classes
from .resolvers.mutations.admin_mutations import (
    AdminMutations as AdminMutationResolvers,
)
from .resolvers.mutations.auth_mutations import AuthMutations as AuthMutationResolvers
from .resolvers.mutations.role_mutations import RoleMutations as RoleMutationResolvers
from .resolvers.mutations.security_mutations import (
    SecurityMutations as SecurityMutationResolvers,
)
from .resolvers.mutations.user_mutations import UserMutations as UserMutationResolvers

# Import query classes
from .resolvers.queries.administrative_queries import AdministrativeQueries
from .resolvers.queries.permission_queries import PermissionQueries
from .resolvers.queries.role_queries import RoleQueries
from .resolvers.queries.security_queries import SecurityQueries
from .resolvers.queries.session_queries import SessionQueries
from .resolvers.queries.user_queries import UserQueries

# Import subscription classes
from .resolvers.subscriptions.administrative_subscriptions import (
    AdministrativeSubscriptions,
)
from .resolvers.subscriptions.audit_compliance_subscriptions import (
    AuditComplianceSubscriptions,
)
from .resolvers.subscriptions.security_event_subscriptions import (
    SecurityEventSubscriptions,
)
from .resolvers.subscriptions.session_management_subscriptions import (
    SessionManagementSubscriptions,
)
from .resolvers.subscriptions.user_status_subscriptions import UserStatusSubscriptions


@strawberry.type
class IdentityQueries:
    """
    Combined Identity module queries.

    This class combines all individual query classes to provide
    a unified GraphQL query interface for the identity module.
    """

    # User queries
    user: UserQueries = strawberry.field(
        resolver=lambda: UserQueries(),
        description="User management and profile queries",
    )

    # Administrative queries
    admin: AdministrativeQueries = strawberry.field(
        resolver=lambda: AdministrativeQueries(),
        description="Administrative and bulk operation queries",
    )

    # Role queries
    role: RoleQueries = strawberry.field(
        resolver=lambda: RoleQueries(),
        description="Role and permission management queries",
    )

    # Permission queries
    permission: PermissionQueries = strawberry.field(
        resolver=lambda: PermissionQueries(),
        description="Permission and access control queries",
    )

    # Security queries
    security: SecurityQueries = strawberry.field(
        resolver=lambda: SecurityQueries(),
        description="Security monitoring and threat detection queries",
    )

    # Session queries
    session: SessionQueries = strawberry.field(
        resolver=lambda: SessionQueries(),
        description="Session management and authentication queries",
    )


@strawberry.type
class IdentityMutations:
    """
    Combined Identity module mutations.

    This class combines all individual mutation classes to provide
    a unified GraphQL mutation interface for the identity module.
    """

    # Authentication mutations
    auth: AuthMutationResolvers = strawberry.field(
        resolver=lambda: AuthMutationResolvers(),
        description="Authentication and login mutations",
    )

    # User mutations
    user: UserMutationResolvers = strawberry.field(
        resolver=lambda: UserMutationResolvers(),
        description="User management and profile mutations",
    )

    # Administrative mutations
    admin: AdminMutationResolvers = strawberry.field(
        resolver=lambda: AdminMutationResolvers(),
        description="Administrative and bulk operation mutations",
    )

    # Role mutations
    role: RoleMutationResolvers = strawberry.field(
        resolver=lambda: RoleMutationResolvers(),
        description="Role and permission management mutations",
    )

    # Security mutations
    security: SecurityMutationResolvers = strawberry.field(
        resolver=lambda: SecurityMutationResolvers(),
        description="Security configuration and threat response mutations",
    )


@strawberry.type
class IdentitySubscriptions:
    """
    Combined Identity module subscriptions.

    This class combines all individual subscription classes to provide
    a unified GraphQL subscription interface for the identity module.
    """

    # Administrative subscriptions
    admin: AdministrativeSubscriptions = strawberry.field(
        resolver=lambda: AdministrativeSubscriptions(),
        description="Administrative event subscriptions",
    )

    # Security event subscriptions
    security: SecurityEventSubscriptions = strawberry.field(
        resolver=lambda: SecurityEventSubscriptions(),
        description="Security event and threat monitoring subscriptions",
    )

    # Session management subscriptions
    session: SessionManagementSubscriptions = strawberry.field(
        resolver=lambda: SessionManagementSubscriptions(),
        description="Session lifecycle and management subscriptions",
    )

    # User status subscriptions
    user: UserStatusSubscriptions = strawberry.field(
        resolver=lambda: UserStatusSubscriptions(),
        description="User status and activity subscriptions",
    )

    # Audit compliance subscriptions
    audit: AuditComplianceSubscriptions = strawberry.field(
        resolver=lambda: AuditComplianceSubscriptions(),
        description="Audit and compliance monitoring subscriptions",
    )


# Create the main identity schema
identity_schema = strawberry.Schema(
    query=IdentityQueries, 
    mutation=IdentityMutations, 
    subscription=IdentitySubscriptions
)


# Export the main classes for use in the main application schema
__all__ = ["IdentityMutations", "IdentityQueries", "IdentitySubscriptions", "identity_schema"]