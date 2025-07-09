"""
Identity Module GraphQL Resolvers

This module aggregates all GraphQL resolvers for the identity module,
providing a unified interface for importing queries, mutations, and subscriptions.
"""

# Import all query resolvers
from .queries.administrative_queries import AdministrativeQueries
from .queries.permission_queries import PermissionQueries
from .queries.role_queries import RoleQueries
from .queries.security_queries import SecurityQueries
from .queries.session_queries import SessionQueries
from .queries.user_queries import UserQueries

# Import all mutation resolvers
from .mutations.admin_mutations import AdminMutations
from .mutations.auth_mutations import AuthMutations
from .mutations.role_mutations import RoleMutations
from .mutations.security_mutations import SecurityMutations
from .mutations.user_mutations import UserMutations

# Import all subscription resolvers
from .subscriptions.administrative_subscriptions import AdministrativeSubscriptions
from .subscriptions.audit_compliance_subscriptions import AuditComplianceSubscriptions
from .subscriptions.security_event_subscriptions import SecurityEventSubscriptions
from .subscriptions.session_management_subscriptions import SessionManagementSubscriptions
from .subscriptions.user_status_subscriptions import UserStatusSubscriptions

# Legacy aliases for backwards compatibility with main schema
AuthSubscriptions = SecurityEventSubscriptions
SessionSubscriptions = SessionManagementSubscriptions
UserSubscriptions = UserStatusSubscriptions

__all__ = [
    # Query resolvers
    "AdministrativeQueries",
    "PermissionQueries", 
    "RoleQueries",
    "SecurityQueries",
    "SessionQueries",
    "UserQueries",
    
    # Mutation resolvers
    "AdminMutations",
    "AuthMutations",
    "RoleMutations",
    "SecurityMutations",
    "UserMutations",
    
    # Subscription resolvers
    "AdministrativeSubscriptions",
    "AuditComplianceSubscriptions",
    "SecurityEventSubscriptions",
    "SessionManagementSubscriptions", 
    "UserStatusSubscriptions",
    
    # Legacy aliases
    "AuthSubscriptions",
    "SessionSubscriptions",
    "UserSubscriptions",
]