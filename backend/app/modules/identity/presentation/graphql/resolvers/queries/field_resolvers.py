"""
Field Resolvers

Advanced field-level resolvers with authorization, caching, and comprehensive error handling.
These resolvers handle nested field resolution with proper security and performance optimizations.
"""

import logging
import time
from typing import Any

from strawberry.types import Info

from .base_query_resolver import BaseQueryResolver
from .dataloaders import IdentityDataLoaders

logger = logging.getLogger(__name__)


class UserFieldResolvers:
    """Field resolvers for User type with field-level authorization."""
    
    def __init__(self, base_resolver: BaseQueryResolver, dataloaders: IdentityDataLoaders):
        self.base_resolver = base_resolver
        self.dataloaders = dataloaders
        self.logger = logging.getLogger(self.__class__.__name__)
    
    async def resolve_profile(self, user: dict, info: Info) -> dict | None:
        """
        Resolve user profile field.
        
        Requires either:
        - User accessing their own profile
        - 'user:profile:read' permission
        """
        try:
            context = await self.base_resolver.extract_context(info)
            
            # Check field-level authorization
            if context.user_id != user["id"] and "user:profile:read" not in context.permissions and not context.is_admin:
                    # Return None for unauthorized access instead of raising error
                    # This allows the query to continue for other fields
                    return None
            
            # Use DataLoader for efficient loading
            return await self.dataloaders.user_profile_loader.load(user["id"])
            
        except Exception as e:
            self.logger.exception(f"Error resolving user profile for {user.get('id')}: {e}")
            return None
    
    async def resolve_preferences(self, user: dict, info: Info) -> dict | None:
        """
        Resolve user preferences field.
        
        Requires either:
        - User accessing their own preferences
        - 'user:preferences:read' permission
        """
        try:
            context = await self.base_resolver.extract_context(info)
            
            # Check field-level authorization
            if context.user_id != user["id"] and "user:preferences:read" not in context.permissions and not context.is_admin:
                    return None
            
            # Use DataLoader for efficient loading
            return await self.dataloaders.user_preference_loader.load(user["id"])
            
        except Exception as e:
            self.logger.exception(f"Error resolving user preferences for {user.get('id')}: {e}")
            return None
    
    async def resolve_roles(self, user: dict, info: Info) -> list[dict]:
        """
        Resolve user roles field.
        
        Requires either:
        - User accessing their own roles
        - 'user:roles:read' permission
        """
        try:
            context = await self.base_resolver.extract_context(info)
            
            # Check field-level authorization
            if context.user_id != user["id"] and "user:roles:read" not in context.permissions and not context.is_admin:
                    return []
            
            # Use DataLoader for efficient loading
            roles = await self.dataloaders.user_roles_loader.load(user["id"])
            return roles or []
            
        except Exception as e:
            self.logger.exception(f"Error resolving user roles for {user.get('id')}: {e}")
            return []
    
    async def resolve_permissions(self, user: dict, info: Info) -> list[dict]:
        """
        Resolve user permissions field.
        
        Requires either:
        - User accessing their own permissions
        - 'user:permissions:read' permission
        """
        try:
            context = await self.base_resolver.extract_context(info)
            
            # Check field-level authorization
            if context.user_id != user["id"] and "user:permissions:read" not in context.permissions and not context.is_admin:
                    return []
            
            # Use DataLoader for efficient loading
            permissions = await self.dataloaders.user_permissions_loader.load(user["id"])
            return permissions or []
            
        except Exception as e:
            self.logger.exception(f"Error resolving user permissions for {user.get('id')}: {e}")
            return []
    
    async def resolve_sessions(self, user: dict, info: Info, limit: int = 10) -> list[dict]:
        """
        Resolve user sessions field.
        
        Requires either:
        - User accessing their own sessions
        - 'user:sessions:read' permission
        """
        try:
            context = await self.base_resolver.extract_context(info)
            
            # Check field-level authorization
            if context.user_id != user["id"] and "user:sessions:read" not in context.permissions and not context.is_admin:
                    return []
            
            # Use DataLoader for efficient loading
            all_sessions = await self.dataloaders.user_sessions_loader.load(user["id"])
            
            # Apply limit and return most recent sessions
            if all_sessions:
                sessions = sorted(
                    all_sessions,
                    key=lambda s: s.get("last_activity", s.get("created_at")),
                    reverse=True
                )
                return sessions[:limit]
            
            return []
            
        except Exception as e:
            self.logger.exception(f"Error resolving user sessions for {user.get('id')}: {e}")
            return []
    
    async def resolve_security_events(
        self,
        user: dict,
        info: Info,
        limit: int = 20
    ) -> list[dict]:
        """
        Resolve user security events field.
        
        Requires either:
        - User accessing their own security events
        - 'security:events:read' permission
        """
        try:
            context = await self.base_resolver.extract_context(info)
            
            # Check field-level authorization
            if context.user_id != user["id"] and "security:events:read" not in context.permissions and not context.is_admin:
                    return []
            
            # Use DataLoader for efficient loading
            all_events = await self.dataloaders.user_security_events_loader.load(user["id"])
            
            # Apply limit and return most recent events
            if all_events:
                events = sorted(
                    all_events,
                    key=lambda e: e.get("created_at"),
                    reverse=True
                )
                return events[:limit]
            
            return []
            
        except Exception as e:
            self.logger.exception(f"Error resolving user security events for {user.get('id')}: {e}")
            return []


class RoleFieldResolvers:
    """Field resolvers for Role type with field-level authorization."""
    
    def __init__(self, base_resolver: BaseQueryResolver, dataloaders: IdentityDataLoaders):
        self.base_resolver = base_resolver
        self.dataloaders = dataloaders
        self.logger = logging.getLogger(self.__class__.__name__)
    
    async def resolve_permissions(self, role: dict, info: Info) -> list[dict]:
        """
        Resolve role permissions field.
        
        Requires 'role:permissions:read' permission.
        """
        try:
            context = await self.base_resolver.extract_context(info)
            
            # Check field-level authorization
            if "role:permissions:read" not in context.permissions and not context.is_admin:
                return []
            
            # Use DataLoader for efficient loading
            permissions = await self.dataloaders.role_permissions_loader.load(role["id"])
            return permissions or []
            
        except Exception as e:
            self.logger.exception(f"Error resolving role permissions for {role.get('id')}: {e}")
            return []
    
    async def resolve_user_count(self, role: dict, info: Info) -> int:
        """
        Resolve role user count field.
        
        Requires 'role:users:count' permission.
        """
        try:
            context = await self.base_resolver.extract_context(info)
            
            # Check field-level authorization
            if "role:users:count" not in context.permissions and not context.is_admin:
                return 0
            
            # This would typically be cached or pre-computed
            # For now, we'll use a placeholder implementation
            return role.get("user_count", 0)
            
        except Exception as e:
            self.logger.exception(f"Error resolving user count for role {role.get('id')}: {e}")
            return 0


class SessionFieldResolvers:
    """Field resolvers for Session type with field-level authorization."""
    
    def __init__(self, base_resolver: BaseQueryResolver, dataloaders: IdentityDataLoaders):
        self.base_resolver = base_resolver
        self.dataloaders = dataloaders
        self.logger = logging.getLogger(self.__class__.__name__)
    
    async def resolve_user(self, session: dict, info: Info) -> dict | None:
        """
        Resolve session user field.
        
        Requires either:
        - User accessing their own session
        - 'session:user:read' permission
        """
        try:
            context = await self.base_resolver.extract_context(info)
            
            # Check field-level authorization
            if context.user_id != session["user_id"] and "session:user:read" not in context.permissions and not context.is_admin:
                    return None
            
            # Use DataLoader for efficient loading
            return await self.dataloaders.user_loader.load(session["user_id"])
            
        except Exception as e:
            self.logger.exception(f"Error resolving user for session {session.get('id')}: {e}")
            return None
    
    async def resolve_security_events(self, session: dict, info: Info) -> list[dict]:
        """
        Resolve session security events field.
        
        Requires 'security:events:read' permission.
        """
        try:
            context = await self.base_resolver.extract_context(info)
            
            # Check field-level authorization
            if "security:events:read" not in context.permissions and not context.is_admin:
                return []
            
            # Get security events for this session
            # This would typically be a separate query
            return []
            
        except Exception as e:
            self.logger.exception(f"Error resolving security events for session {session.get('id')}: {e}")
            return []


class FieldResolverRegistry:
    """Registry for all field resolvers with performance monitoring."""
    
    def __init__(self, base_resolver: BaseQueryResolver, dataloaders: IdentityDataLoaders):
        self.base_resolver = base_resolver
        self.dataloaders = dataloaders
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Initialize field resolvers
        self.user_resolvers = UserFieldResolvers(base_resolver, dataloaders)
        self.role_resolvers = RoleFieldResolvers(base_resolver, dataloaders)
        self.session_resolvers = SessionFieldResolvers(base_resolver, dataloaders)
        
        # Performance tracking
        self.field_execution_times = {}
    
    async def resolve_field_with_monitoring(
        self,
        resolver_func,
        entity: dict,
        info: Info,
        field_name: str,
        *args,
        **kwargs
    ) -> Any:
        """
        Resolve field with performance monitoring and error handling.
        """
        start_time = time.time()
        
        try:
            result = await resolver_func(entity, info, *args, **kwargs)
            
            # Track execution time
            execution_time = (time.time() - start_time) * 1000
            self._record_execution_time(field_name, execution_time)
            
            return result
            
        except Exception as e:
            execution_time = (time.time() - start_time) * 1000
            self.logger.exception(
                f"Error in field resolver {field_name}: {e}",
                extra={
                    "field_name": field_name,
                    "entity_id": entity.get("id"),
                    "execution_time_ms": execution_time
                }
            )
            
            # Return appropriate default value based on expected return type
            if "list" in str(type(resolver_func).__annotations__.get("return", "")):
                return []
            return None
    
    def _record_execution_time(self, field_name: str, execution_time: float):
        """Record field execution time for monitoring."""
        if field_name not in self.field_execution_times:
            self.field_execution_times[field_name] = []
        
        self.field_execution_times[field_name].append(execution_time)
        
        # Keep only recent measurements (last 100)
        if len(self.field_execution_times[field_name]) > 100:
            self.field_execution_times[field_name] = \
                self.field_execution_times[field_name][-100:]
    
    def get_field_performance_stats(self) -> dict[str, dict[str, float]]:
        """Get performance statistics for field resolvers."""
        stats = {}
        
        for field_name, times in self.field_execution_times.items():
            if times:
                stats[field_name] = {
                    "count": len(times),
                    "avg_ms": sum(times) / len(times),
                    "min_ms": min(times),
                    "max_ms": max(times),
                    "total_ms": sum(times)
                }
        
        return stats
    
    def clear_performance_stats(self):
        """Clear performance statistics."""
        self.field_execution_times.clear()