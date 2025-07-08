"""
Query Resolver Factory

Factory for creating and configuring GraphQL query resolvers with proper dependency injection,
DataLoader setup, and comprehensive error handling.
"""

import logging
from dataclasses import dataclass
from typing import Any

from app.modules.identity.domain.interfaces.repositories import (
    IAccessTokenRepository,
    IEmergencyContactRepository,
    ILoginAttemptRepository,
    IMFARepository,
    INotificationSettingRepository,
    IPasswordHistoryRepository,
    IPermissionRepository,
    IRoleRepository,
    ISecurityEventRepository,
    ISessionRepository,
    IUserPreferenceRepository,
    IUserProfileRepository,
    IUserRepository,
)

from .administrative_queries import AdministrativeQueries
from .dataloaders import IdentityDataLoaders
from .permission_queries import PermissionQueries
from .role_queries import RoleQueries
from .security_queries import SecurityQueries
from .session_queries import SessionQueries
from .user_queries import UserQueries

logger = logging.getLogger(__name__)


@dataclass
class CoreRepositoryDependencies:
    """Core repository dependencies for query factory."""
    user_repository: IUserRepository
    role_repository: IRoleRepository
    permission_repository: IPermissionRepository
    session_repository: ISessionRepository
    security_event_repository: ISecurityEventRepository


@dataclass
class ExtendedRepositoryDependencies:
    """Extended repository dependencies for query factory."""
    user_profile_repository: IUserProfileRepository
    user_preference_repository: IUserPreferenceRepository
    access_token_repository: IAccessTokenRepository
    emergency_contact_repository: IEmergencyContactRepository
    login_attempt_repository: ILoginAttemptRepository
    mfa_repository: IMFARepository
    notification_setting_repository: INotificationSettingRepository
    password_history_repository: IPasswordHistoryRepository


class QueryResolverFactory:
    """Factory for creating and configuring query resolvers."""
    
    def __init__(
        self,
        core_repositories: CoreRepositoryDependencies,
        extended_repositories: ExtendedRepositoryDependencies,
    ):
        # Core repositories
        self.user_repository = core_repositories.user_repository
        self.role_repository = core_repositories.role_repository
        self.permission_repository = core_repositories.permission_repository
        self.session_repository = core_repositories.session_repository
        self.security_event_repository = core_repositories.security_event_repository
        
        # Extended repositories
        self.user_profile_repository = extended_repositories.user_profile_repository
        self.user_preference_repository = extended_repositories.user_preference_repository
        self.access_token_repository = extended_repositories.access_token_repository
        self.emergency_contact_repository = extended_repositories.emergency_contact_repository
        self.login_attempt_repository = extended_repositories.login_attempt_repository
        self.mfa_repository = extended_repositories.mfa_repository
        self.notification_setting_repository = extended_repositories.notification_setting_repository
        self.password_history_repository = extended_repositories.password_history_repository
        
        # Initialize DataLoaders
        from .dataloaders import DataLoaderRepositoryDependencies
        dataloader_repos = DataLoaderRepositoryDependencies(
            user_repository=self.user_repository,
            role_repository=self.role_repository,
            permission_repository=self.permission_repository,
            session_repository=self.session_repository,
            security_event_repository=self.security_event_repository,
            user_profile_repository=self.user_profile_repository,
            user_preference_repository=self.user_preference_repository,
        )
        self.dataloaders = IdentityDataLoaders(repositories=dataloader_repos)
        
        # Initialize query resolvers
        self._setup_resolvers()
    
    def _setup_resolvers(self):
        """Setup and configure all query resolvers."""
        # User queries
        self.user_queries = UserQueries(
            user_repository=self.user_repository,
            role_repository=self.role_repository,
            permission_repository=self.permission_repository,
            session_repository=self.session_repository,
            security_event_repository=self.security_event_repository,
        )
        self.user_queries.set_dataloaders(self.dataloaders)
        
        # Role queries
        self.role_queries = RoleQueries(
            user_repository=self.user_repository,
            role_repository=self.role_repository,
            permission_repository=self.permission_repository,
            session_repository=self.session_repository,
            security_event_repository=self.security_event_repository,
        )
        self.role_queries.set_dataloaders(self.dataloaders)
        
        # Permission queries
        self.permission_queries = PermissionQueries(
            user_repository=self.user_repository,
            role_repository=self.role_repository,
            permission_repository=self.permission_repository,
            session_repository=self.session_repository,
            security_event_repository=self.security_event_repository,
        )
        self.permission_queries.set_dataloaders(self.dataloaders)
        
        # Session queries
        self.session_queries = SessionQueries(
            user_repository=self.user_repository,
            role_repository=self.role_repository,
            permission_repository=self.permission_repository,
            session_repository=self.session_repository,
            security_event_repository=self.security_event_repository,
        )
        self.session_queries.set_dataloaders(self.dataloaders)
        
        # Security queries
        self.security_queries = SecurityQueries(
            user_repository=self.user_repository,
            role_repository=self.role_repository,
            permission_repository=self.permission_repository,
            session_repository=self.session_repository,
            security_event_repository=self.security_event_repository,
        )
        self.security_queries.set_dataloaders(self.dataloaders)
        
        # Administrative queries
        self.administrative_queries = AdministrativeQueries(
            user_repository=self.user_repository,
            role_repository=self.role_repository,
            permission_repository=self.permission_repository,
            session_repository=self.session_repository,
            security_event_repository=self.security_event_repository,
        )
        self.administrative_queries.set_dataloaders(self.dataloaders)
    
    def get_user_queries(self) -> UserQueries:
        """Get configured user query resolver."""
        return self.user_queries
    
    def get_role_queries(self) -> RoleQueries:
        """Get configured role query resolver."""
        return self.role_queries
    
    def get_permission_queries(self) -> PermissionQueries:
        """Get configured permission query resolver."""
        return self.permission_queries
    
    def get_session_queries(self) -> SessionQueries:
        """Get configured session query resolver."""
        return self.session_queries
    
    def get_security_queries(self) -> SecurityQueries:
        """Get configured security query resolver."""
        return self.security_queries
    
    def get_administrative_queries(self) -> AdministrativeQueries:
        """Get configured administrative query resolver."""
        return self.administrative_queries
    
    def get_dataloaders(self) -> IdentityDataLoaders:
        """Get DataLoaders instance."""
        return self.dataloaders
    
    def clear_caches(self):
        """Clear all DataLoader caches."""
        self.dataloaders.clear_all_caches()
        logger.debug("DataLoader caches cleared")
    
    async def prime_cache(self, entity_type: str, entity: Any):
        """Prime DataLoader cache with known entity."""
        try:
            if entity_type == "user":
                self.dataloaders.prime_user(entity)
            elif entity_type == "role":
                self.dataloaders.prime_role(entity)
            elif entity_type == "permission":
                self.dataloaders.prime_permission(entity)
            elif entity_type == "session":
                self.dataloaders.prime_session(entity)
            else:
                logger.warning(f"Unknown entity type for cache priming: {entity_type}")
        except Exception as e:
            logger.exception(f"Failed to prime cache for {entity_type}: {e}")


class IdentityQueryResolvers:
    """Main query resolver class that consolidates all identity query operations."""
    
    def __init__(self, factory: QueryResolverFactory):
        self.factory = factory
        self.user_queries = factory.get_user_queries()
        self.role_queries = factory.get_role_queries()
        self.permission_queries = factory.get_permission_queries()
        self.session_queries = factory.get_session_queries()
        self.security_queries = factory.get_security_queries()
        self.administrative_queries = factory.get_administrative_queries()
    
    # User queries
    async def user(self, info, id):
        return await self.user_queries.user(info, id)
    
    async def users(self, info, filter=None, sort=None, pagination=None):
        return await self.user_queries.users(info, filter, sort, pagination)
    
    async def me(self, info):
        return await self.user_queries.me(info)
    
    async def user_profile(self, info, user_id):
        return await self.user_queries.user_profile(info, user_id)
    
    async def user_preferences(self, info, user_id):
        return await self.user_queries.user_preferences(info, user_id)
    
    async def user_sessions(self, info, user_id):
        return await self.user_queries.user_sessions(info, user_id)
    
    async def user_roles(self, info, user_id):
        return await self.user_queries.user_roles(info, user_id)
    
    async def user_permissions(self, info, user_id):
        return await self.user_queries.user_permissions(info, user_id)
    
    async def user_audit_log(self, info, user_id, pagination=None):
        return await self.user_queries.user_audit_log(info, user_id, pagination)
    
    async def user_statistics(self, info):
        return await self.user_queries.user_statistics(info)
    
    # Role queries
    async def role(self, info, id):
        return await self.role_queries.role(info, id)
    
    async def roles(self, info, filter=None, sort=None, pagination=None):
        return await self.role_queries.roles(info, filter, sort, pagination)
    
    async def role_permissions(self, info, role_id):
        return await self.role_queries.role_permissions(info, role_id)
    
    async def user_role_assignments(self, info, user_id, pagination=None):
        return await self.role_queries.user_role_assignments(info, user_id, pagination)
    
    # Permission queries
    async def permission(self, info, id):
        return await self.permission_queries.permission(info, id)
    
    async def permissions(self, info, filter=None, sort=None, pagination=None):
        return await self.permission_queries.permissions(info, filter, sort, pagination)
    
    async def permission_check(self, info, user_id, resource, action):
        return await self.permission_queries.permission_check(info, user_id, resource, action)
    
    # Session queries
    async def session(self, info, id):
        return await self.session_queries.session(info, id)
    
    async def sessions(self, info, filter=None, sort=None, pagination=None):
        return await self.session_queries.sessions(info, filter, sort, pagination)
    
    async def active_sessions(self, info, user_id=None, pagination=None):
        return await self.session_queries.active_sessions(info, user_id, pagination)
    
    async def session_history(self, info, user_id, days=30, pagination=None):
        return await self.session_queries.session_history(info, user_id, days, pagination)
    
    async def suspicious_sessions(self, info, severity_threshold=0.7, pagination=None):
        return await self.session_queries.suspicious_sessions(info, severity_threshold, pagination)
    
    # Security queries
    async def security_event(self, info, id):
        return await self.security_queries.security_event(info, id)
    
    async def security_events(self, info, filter=None, sort=None, pagination=None):
        return await self.security_queries.security_events(info, filter, sort, pagination)
    
    async def audit_log(self, info, filter=None, sort=None, pagination=None):
        return await self.security_queries.audit_log(info, filter, sort, pagination)
    
    async def login_attempts(self, info, filter=None, sort=None, pagination=None):
        return await self.security_queries.login_attempts(info, filter, sort, pagination)
    
    async def security_statistics(self, info, days=30):
        return await self.security_queries.security_statistics(info, days)
    
    # Administrative queries
    async def system_health(self, info):
        return await self.administrative_queries.system_health(info)
    
    async def system_statistics(self, info):
        return await self.administrative_queries.system_statistics(info)
    
    async def configuration_settings(self, info, category=None, include_sensitive=False):
        return await self.administrative_queries.configuration_settings(
            info, category, include_sensitive
        )
    
    async def maintenance_status(self, info):
        return await self.administrative_queries.maintenance_status(info)