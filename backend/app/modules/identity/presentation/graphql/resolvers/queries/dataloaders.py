"""
DataLoaders for N+1 Query Prevention

Implements efficient data loading patterns to prevent N+1 queries
in GraphQL resolvers using batching and caching.
"""

import asyncio
import logging
from collections import defaultdict
from dataclasses import dataclass
from uuid import UUID

from app.modules.identity.domain.interfaces.repositories import (
    IPermissionRepository,
    IRoleRepository,
    ISecurityEventRepository,
    ISessionRepository,
    IUserPreferenceRepository,
    IUserProfileRepository,
    IUserRepository,
)

logger = logging.getLogger(__name__)


@dataclass
class DataLoaderRepositoryDependencies:
    """Repository dependencies for identity dataloaders."""
    user_repository: IUserRepository
    role_repository: IRoleRepository
    permission_repository: IPermissionRepository
    session_repository: ISessionRepository
    security_event_repository: ISecurityEventRepository
    user_profile_repository: IUserProfileRepository
    user_preference_repository: IUserPreferenceRepository


class DataLoader:
    """Base DataLoader implementation with batching and caching."""
    
    def __init__(self, batch_load_fn, max_batch_size: int = 100, cache_ttl: int = 300):
        self.batch_load_fn = batch_load_fn
        self.max_batch_size = max_batch_size
        self.cache_ttl = cache_ttl
        self._cache = {}
        self._batch_promises = {}
        self._batch_keys = []
        self._batch_timeout = None
    
    async def load(self, key):
        """Load a single item by key."""
        if key in self._cache:
            return self._cache[key]
        
        if key in self._batch_promises:
            return await self._batch_promises[key]
        
        future = asyncio.Future()
        self._batch_promises[key] = future
        self._batch_keys.append(key)
        
        if len(self._batch_keys) >= self.max_batch_size:
            await self._dispatch_batch()
        elif self._batch_timeout is None:
            self._batch_timeout = asyncio.create_task(self._schedule_batch())
        
        return await future
    
    async def load_many(self, keys: list):
        """Load multiple items by keys."""
        return await asyncio.gather(*[self.load(key) for key in keys])
    
    async def _schedule_batch(self):
        """Schedule batch execution after a short delay."""
        await asyncio.sleep(0.001)  # 1ms delay to collect more keys
        if self._batch_keys:
            await self._dispatch_batch()
    
    async def _dispatch_batch(self):
        """Dispatch the current batch for loading."""
        if not self._batch_keys:
            return
        
        batch_keys = self._batch_keys.copy()
        batch_promises = {k: v for k, v in self._batch_promises.items() if k in batch_keys}
        
        # Clear current batch
        self._batch_keys.clear()
        for key in batch_keys:
            del self._batch_promises[key]
        if self._batch_timeout:
            self._batch_timeout.cancel()
            self._batch_timeout = None
        
        try:
            # Execute batch load function
            results = await self.batch_load_fn(batch_keys)
            
            # Cache and resolve results
            for key, result in zip(batch_keys, results, strict=False):
                self._cache[key] = result
                if key in batch_promises:
                    batch_promises[key].set_result(result)
        
        except Exception as e:
            logger.exception(f"Batch load failed: {e}")
            # Reject all promises
            for promise in batch_promises.values():
                if not promise.done():
                    promise.set_exception(e)
    
    def clear_cache(self):
        """Clear the cache."""
        self._cache.clear()
    
    def prime(self, key, value):
        """Prime the cache with a known value."""
        self._cache[key] = value


class IdentityDataLoaders:
    """Collection of DataLoaders for identity domain entities."""
    
    def __init__(
        self,
        repositories: DataLoaderRepositoryDependencies,
    ):
        # Repository dependencies
        self.user_repository = repositories.user_repository
        self.role_repository = repositories.role_repository
        self.permission_repository = repositories.permission_repository
        self.session_repository = repositories.session_repository
        self.security_event_repository = repositories.security_event_repository
        self.user_profile_repository = repositories.user_profile_repository
        self.user_preference_repository = repositories.user_preference_repository
        
        # Initialize DataLoaders
        self.user_loader = DataLoader(self._batch_load_users)
        self.role_loader = DataLoader(self._batch_load_roles)
        self.permission_loader = DataLoader(self._batch_load_permissions)
        self.session_loader = DataLoader(self._batch_load_sessions)
        self.user_profile_loader = DataLoader(self._batch_load_user_profiles)
        self.user_preference_loader = DataLoader(self._batch_load_user_preferences)
        
        # Association DataLoaders
        self.user_roles_loader = DataLoader(self._batch_load_user_roles)
        self.user_permissions_loader = DataLoader(self._batch_load_user_permissions)
        self.user_sessions_loader = DataLoader(self._batch_load_user_sessions)
        self.role_permissions_loader = DataLoader(self._batch_load_role_permissions)
        self.user_security_events_loader = DataLoader(self._batch_load_user_security_events)
    
    async def _batch_load_users(self, user_ids: list[UUID]) -> list[dict | None]:
        """Batch load users by IDs."""
        try:
            result = await self.user_repository.find_by_ids(user_ids)
            if not result.is_success:
                logger.error(f"Failed to batch load users: {result.error}")
                return [None] * len(user_ids)
            
            users_by_id = {user.id: user for user in result.value}
            return [users_by_id.get(user_id) for user_id in user_ids]
        
        except Exception as e:
            logger.exception(f"Exception in batch load users: {e}")
            return [None] * len(user_ids)
    
    async def _batch_load_roles(self, role_ids: list[UUID]) -> list[dict | None]:
        """Batch load roles by IDs."""
        try:
            result = await self.role_repository.find_by_ids(role_ids)
            if not result.is_success:
                logger.error(f"Failed to batch load roles: {result.error}")
                return [None] * len(role_ids)
            
            roles_by_id = {role.id: role for role in result.value}
            return [roles_by_id.get(role_id) for role_id in role_ids]
        
        except Exception as e:
            logger.exception(f"Exception in batch load roles: {e}")
            return [None] * len(role_ids)
    
    async def _batch_load_permissions(self, permission_ids: list[UUID]) -> list[dict | None]:
        """Batch load permissions by IDs."""
        try:
            result = await self.permission_repository.find_by_ids(permission_ids)
            if not result.is_success:
                logger.error(f"Failed to batch load permissions: {result.error}")
                return [None] * len(permission_ids)
            
            permissions_by_id = {perm.id: perm for perm in result.value}
            return [permissions_by_id.get(perm_id) for perm_id in permission_ids]
        
        except Exception as e:
            logger.exception(f"Exception in batch load permissions: {e}")
            return [None] * len(permission_ids)
    
    async def _batch_load_sessions(self, session_ids: list[UUID]) -> list[dict | None]:
        """Batch load sessions by IDs."""
        try:
            result = await self.session_repository.find_by_ids(session_ids)
            if not result.is_success:
                logger.error(f"Failed to batch load sessions: {result.error}")
                return [None] * len(session_ids)
            
            sessions_by_id = {session.id: session for session in result.value}
            return [sessions_by_id.get(session_id) for session_id in session_ids]
        
        except Exception as e:
            logger.exception(f"Exception in batch load sessions: {e}")
            return [None] * len(session_ids)
    
    async def _batch_load_user_profiles(self, user_ids: list[UUID]) -> list[dict | None]:
        """Batch load user profiles by user IDs."""
        try:
            result = await self.user_profile_repository.find_by_user_ids(user_ids)
            if not result.is_success:
                logger.error(f"Failed to batch load user profiles: {result.error}")
                return [None] * len(user_ids)
            
            profiles_by_user_id = {profile.user_id: profile for profile in result.value}
            return [profiles_by_user_id.get(user_id) for user_id in user_ids]
        
        except Exception as e:
            logger.exception(f"Exception in batch load user profiles: {e}")
            return [None] * len(user_ids)
    
    async def _batch_load_user_preferences(self, user_ids: list[UUID]) -> list[dict | None]:
        """Batch load user preferences by user IDs."""
        try:
            result = await self.user_preference_repository.find_by_user_ids(user_ids)
            if not result.is_success:
                logger.error(f"Failed to batch load user preferences: {result.error}")
                return [None] * len(user_ids)
            
            preferences_by_user_id = {pref.user_id: pref for pref in result.value}
            return [preferences_by_user_id.get(user_id) for user_id in user_ids]
        
        except Exception as e:
            logger.exception(f"Exception in batch load user preferences: {e}")
            return [None] * len(user_ids)
    
    async def _batch_load_user_roles(self, user_ids: list[UUID]) -> list[list[dict]]:
        """Batch load user roles by user IDs."""
        try:
            result = await self.role_repository.find_by_user_ids(user_ids)
            if not result.is_success:
                logger.error(f"Failed to batch load user roles: {result.error}")
                return [[] for _ in user_ids]
            
            # Group roles by user ID
            roles_by_user_id = defaultdict(list)
            for role in result.value:
                roles_by_user_id[role.user_id].append(role)
            
            return [roles_by_user_id.get(user_id, []) for user_id in user_ids]
        
        except Exception as e:
            logger.exception(f"Exception in batch load user roles: {e}")
            return [[] for _ in user_ids]
    
    async def _batch_load_user_permissions(self, user_ids: list[UUID]) -> list[list[dict]]:
        """Batch load user permissions by user IDs."""
        try:
            # First get user roles
            roles_result = await self.role_repository.find_by_user_ids(user_ids)
            if not roles_result.is_success:
                return [[] for _ in user_ids]
            
            # Get all role IDs
            role_ids = [role.id for role in roles_result.value]
            if not role_ids:
                return [[] for _ in user_ids]
            
            # Get permissions for all roles
            permissions_result = await self.permission_repository.find_by_role_ids(role_ids)
            if not permissions_result.is_success:
                return [[] for _ in user_ids]
            
            # Build user -> roles -> permissions mapping
            user_roles = defaultdict(list)
            for role in roles_result.value:
                user_roles[role.user_id].append(role.id)
            
            role_permissions = defaultdict(list)
            for permission in permissions_result.value:
                role_permissions[permission.role_id].append(permission)
            
            # Combine user permissions
            user_permissions = []
            for user_id in user_ids:
                permissions = set()
                for role_id in user_roles.get(user_id, []):
                    permissions.update(role_permissions.get(role_id, []))
                user_permissions.append(list(permissions))
            
            return user_permissions
        
        except Exception as e:
            logger.exception(f"Exception in batch load user permissions: {e}")
            return [[] for _ in user_ids]
    
    async def _batch_load_user_sessions(self, user_ids: list[UUID]) -> list[list[dict]]:
        """Batch load user sessions by user IDs."""
        try:
            result = await self.session_repository.find_by_user_ids(user_ids)
            if not result.is_success:
                logger.error(f"Failed to batch load user sessions: {result.error}")
                return [[] for _ in user_ids]
            
            sessions_by_user_id = defaultdict(list)
            for session in result.value:
                sessions_by_user_id[session.user_id].append(session)
            
            return [sessions_by_user_id.get(user_id, []) for user_id in user_ids]
        
        except Exception as e:
            logger.exception(f"Exception in batch load user sessions: {e}")
            return [[] for _ in user_ids]
    
    async def _batch_load_role_permissions(self, role_ids: list[UUID]) -> list[list[dict]]:
        """Batch load role permissions by role IDs."""
        try:
            result = await self.permission_repository.find_by_role_ids(role_ids)
            if not result.is_success:
                logger.error(f"Failed to batch load role permissions: {result.error}")
                return [[] for _ in role_ids]
            
            permissions_by_role_id = defaultdict(list)
            for permission in result.value:
                permissions_by_role_id[permission.role_id].append(permission)
            
            return [permissions_by_role_id.get(role_id, []) for role_id in role_ids]
        
        except Exception as e:
            logger.exception(f"Exception in batch load role permissions: {e}")
            return [[] for _ in role_ids]
    
    async def _batch_load_user_security_events(self, user_ids: list[UUID]) -> list[list[dict]]:
        """Batch load user security events by user IDs."""
        try:
            result = await self.security_event_repository.find_by_user_ids(user_ids)
            if not result.is_success:
                logger.error(f"Failed to batch load user security events: {result.error}")
                return [[] for _ in user_ids]
            
            events_by_user_id = defaultdict(list)
            for event in result.value:
                events_by_user_id[event.user_id].append(event)
            
            return [events_by_user_id.get(user_id, []) for user_id in user_ids]
        
        except Exception as e:
            logger.exception(f"Exception in batch load user security events: {e}")
            return [[] for _ in user_ids]
    
    def clear_all_caches(self):
        """Clear all DataLoader caches."""
        loaders = [
            self.user_loader,
            self.role_loader,
            self.permission_loader,
            self.session_loader,
            self.user_profile_loader,
            self.user_preference_loader,
            self.user_roles_loader,
            self.user_permissions_loader,
            self.user_sessions_loader,
            self.role_permissions_loader,
            self.user_security_events_loader,
        ]
        
        for loader in loaders:
            loader.clear_cache()
    
    def prime_user(self, user):
        """Prime user cache with a known user."""
        self.user_loader.prime(user.id, user)
    
    def prime_role(self, role):
        """Prime role cache with a known role."""
        self.role_loader.prime(role.id, role)
    
    def prime_permission(self, permission):
        """Prime permission cache with a known permission."""
        self.permission_loader.prime(permission.id, permission)
    
    def prime_session(self, session):
        """Prime session cache with a known session."""
        self.session_loader.prime(session.id, session)