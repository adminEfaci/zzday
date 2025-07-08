"""
GraphQL Query Resolvers for Identity Module

This package provides comprehensive query resolvers for the identity module,
supporting secure, efficient access to identity data with features like:
- Advanced filtering, pagination, and sorting
- Field-level authorization
- N+1 query prevention with DataLoader
- Comprehensive error handling
- Performance monitoring and caching
"""

from .administrative_queries import AdministrativeQueries
from .base_query_resolver import BaseQueryResolver
from .dataloaders import IdentityDataLoaders
from .field_resolvers import FieldResolverRegistry
from .permission_queries import PermissionQueries
from .query_resolver_factory import IdentityQueryResolvers, QueryResolverFactory
from .role_queries import RoleQueries
from .security_queries import SecurityQueries
from .session_queries import SessionQueries
from .user_queries import UserQueries

__all__ = [
    'AdministrativeQueries',
    'BaseQueryResolver',
    'FieldResolverRegistry',
    'IdentityDataLoaders',
    'IdentityQueryResolvers',
    'PermissionQueries',
    'QueryResolverFactory',
    'RoleQueries',
    'SecurityQueries',
    'SessionQueries',
    'UserQueries',
]