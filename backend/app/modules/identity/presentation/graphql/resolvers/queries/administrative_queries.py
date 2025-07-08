"""
Administrative Query Resolvers

GraphQL query resolvers for administrative operations including:
- System health monitoring
- System statistics and analytics
- Configuration settings
- Maintenance status and operations
"""

import time
from dataclasses import dataclass
from datetime import UTC, datetime

import strawberry
from strawberry.types import Info

from .base_query_resolver import BaseQueryResolver
from .dataloaders import IdentityDataLoaders


@dataclass
class SystemHealth:
    """System health information."""
    status: str
    uptime_seconds: int
    memory_usage_mb: float
    cpu_usage_percent: float
    database_status: str
    cache_status: str
    queue_status: str
    error_rate_percent: float
    response_time_ms: float
    active_connections: int
    last_check: datetime


@strawberry.type
class SystemHealthType:
    """GraphQL type for system health."""
    status: str
    uptime_seconds: int
    memory_usage_mb: float
    cpu_usage_percent: float
    database_status: str
    cache_status: str
    queue_status: str
    error_rate_percent: float
    response_time_ms: float
    active_connections: int
    last_check: datetime


@dataclass
class SystemStatistics:
    """System statistics information."""
    total_requests_today: int
    average_response_time_ms: float
    error_count_today: int
    active_users_count: int
    peak_concurrent_users: int
    database_query_count: int
    cache_hit_rate_percent: float
    storage_used_gb: float
    bandwidth_used_gb: float
    uptime_percentage: float


@strawberry.type
class SystemStatisticsType:
    """GraphQL type for system statistics."""
    total_requests_today: int
    average_response_time_ms: float
    error_count_today: int
    active_users_count: int
    peak_concurrent_users: int
    database_query_count: int
    cache_hit_rate_percent: float
    storage_used_gb: float
    bandwidth_used_gb: float
    uptime_percentage: float


@dataclass
class ConfigurationSetting:
    """Configuration setting information."""
    key: str
    value: str
    category: str
    description: str
    is_sensitive: bool
    last_modified: datetime
    modified_by: str


@strawberry.type
class ConfigurationSettingType:
    """GraphQL type for configuration settings."""
    key: str
    value: str
    category: str
    description: str
    is_sensitive: bool
    last_modified: datetime
    modified_by: str


@dataclass
class MaintenanceStatus:
    """Maintenance status information."""
    is_maintenance_mode: bool
    maintenance_message: str | None
    scheduled_start: datetime | None
    scheduled_end: datetime | None
    affected_services: list[str]
    maintenance_type: str
    last_updated: datetime


@strawberry.type
class MaintenanceStatusType:
    """GraphQL type for maintenance status."""
    is_maintenance_mode: bool
    maintenance_message: str | None
    scheduled_start: datetime | None
    scheduled_end: datetime | None
    affected_services: list[str]
    maintenance_type: str
    last_updated: datetime


class AdministrativeQueries(BaseQueryResolver):
    """GraphQL query resolvers for administrative operations."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.dataloaders: IdentityDataLoaders | None = None

    def set_dataloaders(self, dataloaders: IdentityDataLoaders):
        """Set DataLoaders for this resolver."""
        self.dataloaders = dataloaders

    async def system_health(self, info: Info) -> SystemHealthType:
        """
        Get system health status.

        Requires 'admin:system:health' permission.
        """
        start_time = time.time()
        context = await self.extract_context(info)

        try:
            # Check authorization
            self.require_permission(context, "admin:system:health")

            # Get system health metrics
            # This would typically integrate with monitoring services
            health_data = await self._get_system_health_data()

            health = SystemHealthType(
                status=health_data.status,
                uptime_seconds=health_data.uptime_seconds,
                memory_usage_mb=health_data.memory_usage_mb,
                cpu_usage_percent=health_data.cpu_usage_percent,
                database_status=health_data.database_status,
                cache_status=health_data.cache_status,
                queue_status=health_data.queue_status,
                error_rate_percent=health_data.error_rate_percent,
                response_time_ms=health_data.response_time_ms,
                active_connections=health_data.active_connections,
                last_check=health_data.last_check
            )

            # Log query execution
            execution_time = (time.time() - start_time) * 1000
            await self.log_query_execution(
                context, "systemHealth", {}, execution_time
            )

            return health

        except Exception as e:
            self.logger.exception(f"Error in systemHealth query: {e}")
            raise

    async def system_statistics(self, info: Info) -> SystemStatisticsType:
        """
        Get system statistics.

        Requires 'admin:system:statistics' permission.
        """
        start_time = time.time()
        context = await self.extract_context(info)

        try:
            # Check authorization
            self.require_permission(context, "admin:system:statistics")

            # Get system statistics
            stats_data = await self._get_system_statistics_data()

            statistics = SystemStatisticsType(
                total_requests_today=stats_data.total_requests_today,
                average_response_time_ms=stats_data.average_response_time_ms,
                error_count_today=stats_data.error_count_today,
                active_users_count=stats_data.active_users_count,
                peak_concurrent_users=stats_data.peak_concurrent_users,
                database_query_count=stats_data.database_query_count,
                cache_hit_rate_percent=stats_data.cache_hit_rate_percent,
                storage_used_gb=stats_data.storage_used_gb,
                bandwidth_used_gb=stats_data.bandwidth_used_gb,
                uptime_percentage=stats_data.uptime_percentage
            )

            # Log query execution
            execution_time = (time.time() - start_time) * 1000
            await self.log_query_execution(
                context, "systemStatistics", {}, execution_time
            )

            return statistics

        except Exception as e:
            self.logger.exception(f"Error in systemStatistics query: {e}")
            raise

    async def configuration_settings(
        self,
        info: Info,
        category: str | None = None,
        include_sensitive: bool = False
    ) -> list[ConfigurationSettingType]:
        """
        Get configuration settings.

        Requires 'admin:config:read' permission.
        For sensitive settings, requires 'admin:config:sensitive' permission.
        """
        start_time = time.time()
        context = await self.extract_context(info)

        try:
            # Check authorization
            self.require_permission(context, "admin:config:read")

            if include_sensitive:
                self.require_permission(context, "admin:config:sensitive")

            # Get configuration settings
            settings_data = await self._get_configuration_settings(
                category=category,
                include_sensitive=include_sensitive
            )

            settings = [
                ConfigurationSettingType(
                    key=setting.key,
                    value=setting.value if not setting.is_sensitive or include_sensitive else "***",
                    category=setting.category,
                    description=setting.description,
                    is_sensitive=setting.is_sensitive,
                    last_modified=setting.last_modified,
                    modified_by=setting.modified_by
                )
                for setting in settings_data
            ]

            # Log query execution
            execution_time = (time.time() - start_time) * 1000
            await self.log_query_execution(
                context, "configurationSettings", {
                    "category": category,
                    "include_sensitive": include_sensitive,
                    "result_count": len(settings)
                }, execution_time
            )

            return settings

        except Exception as e:
            self.logger.exception(f"Error in configurationSettings query: {e}")
            raise

    async def maintenance_status(self, info: Info) -> MaintenanceStatusType:
        """
        Get maintenance status.

        Requires 'admin:maintenance:read' permission.
        """
        start_time = time.time()
        context = await self.extract_context(info)

        try:
            # Check authorization
            self.require_permission(context, "admin:maintenance:read")

            # Get maintenance status
            status_data = await self._get_maintenance_status()

            status = MaintenanceStatusType(
                is_maintenance_mode=status_data.is_maintenance_mode,
                maintenance_message=status_data.maintenance_message,
                scheduled_start=status_data.scheduled_start,
                scheduled_end=status_data.scheduled_end,
                affected_services=status_data.affected_services,
                maintenance_type=status_data.maintenance_type,
                last_updated=status_data.last_updated
            )

            # Log query execution
            execution_time = (time.time() - start_time) * 1000
            await self.log_query_execution(
                context, "maintenanceStatus", {}, execution_time
            )

            return status

        except Exception as e:
            self.logger.exception(f"Error in maintenanceStatus query: {e}")
            raise

    async def _get_system_health_data(self) -> SystemHealth:
        """Get system health data from monitoring services."""
        # This would integrate with actual monitoring services
        # For now, return mock data

        import psutil

        try:
            # Get actual system metrics where possible
            memory = psutil.virtual_memory()
            cpu_percent = psutil.cpu_percent(interval=1)
            uptime = time.time() - psutil.boot_time()

            return SystemHealth(
                status="healthy",
                uptime_seconds=int(uptime),
                memory_usage_mb=memory.used / (1024 * 1024),
                cpu_usage_percent=cpu_percent,
                database_status="connected",
                cache_status="operational",
                queue_status="operational",
                error_rate_percent=0.1,
                response_time_ms=25.5,
                active_connections=150,
                last_check=datetime.now(UTC)
            )
        except ImportError:
            # Fallback if psutil is not available
            return SystemHealth(
                status="healthy",
                uptime_seconds=86400,  # 1 day
                memory_usage_mb=2048.0,
                cpu_usage_percent=15.5,
                database_status="connected",
                cache_status="operational",
                queue_status="operational",
                error_rate_percent=0.1,
                response_time_ms=25.5,
                active_connections=150,
                last_check=datetime.now(UTC)
            )

    async def _get_system_statistics_data(self) -> SystemStatistics:
        """Get system statistics data."""
        # This would integrate with analytics services
        # For now, return mock data
        return SystemStatistics(
            total_requests_today=15420,
            average_response_time_ms=185.2,
            error_count_today=23,
            active_users_count=1250,
            peak_concurrent_users=2100,
            database_query_count=45230,
            cache_hit_rate_percent=92.5,
            storage_used_gb=245.8,
            bandwidth_used_gb=12.4,
            uptime_percentage=99.95
        )

    async def _get_configuration_settings(
        self,
        category: str | None = None,
        include_sensitive: bool = False
    ) -> list[ConfigurationSetting]:
        """Get configuration settings."""
        # This would integrate with configuration management
        # For now, return mock data
        settings = [
            ConfigurationSetting(
                key="auth.session_timeout",
                value="3600",
                category="authentication",
                description="Session timeout in seconds",
                is_sensitive=False,
                last_modified=datetime.now(UTC),
                modified_by="admin"
            ),
            ConfigurationSetting(
                key="auth.max_login_attempts",
                value="5",
                category="authentication",
                description="Maximum login attempts before lockout",
                is_sensitive=False,
                last_modified=datetime.now(UTC),
                modified_by="admin"
            ),
            ConfigurationSetting(
                key="email.smtp_password",
                value="secret_password",
                category="email",
                description="SMTP server password",
                is_sensitive=True,
                last_modified=datetime.now(UTC),
                modified_by="admin"
            ),
        ]

        # Filter by category if provided
        if category:
            settings = [s for s in settings if s.category == category]

        # Filter sensitive settings if not requested
        if not include_sensitive:
            settings = [s for s in settings if not s.is_sensitive]

        return settings

    async def _get_maintenance_status(self) -> MaintenanceStatus:
        """Get maintenance status."""
        # This would integrate with maintenance management
        # For now, return mock data
        return MaintenanceStatus(
            is_maintenance_mode=False,
            maintenance_message=None,
            scheduled_start=None,
            scheduled_end=None,
            affected_services=[],
            maintenance_type="none",
            last_updated=datetime.now(UTC)
        )