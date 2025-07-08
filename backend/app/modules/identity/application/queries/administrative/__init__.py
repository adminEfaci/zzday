"""Administrative query handlers."""

from .get_admin_dashboard_query import (
    GetAdminDashboardQuery,
    GetAdminDashboardQueryHandler,
)
from .get_backup_status_query import GetBackupStatusQuery, GetBackupStatusQueryHandler
from .get_feature_flags_query import GetFeatureFlagsQuery, GetFeatureFlagsQueryHandler
from .get_license_status_query import (
    GetLicenseStatusQuery,
    GetLicenseStatusQueryHandler,
)
from .get_maintenance_status_query import (
    GetMaintenanceStatusQuery,
    GetMaintenanceStatusQueryHandler,
)
from .get_system_config_query import GetSystemConfigQuery, GetSystemConfigQueryHandler
from .get_system_health_query import GetSystemHealthQuery, GetSystemHealthQueryHandler
from .get_system_logs_query import GetSystemLogsQuery, GetSystemLogsQueryHandler
from .get_system_metrics_query import (
    GetSystemMetricsQuery,
    GetSystemMetricsQueryHandler,
)
from .get_tenant_info_query import GetTenantInfoQuery, GetTenantInfoQueryHandler

__all__ = [
    # Dashboard
    "GetAdminDashboardQuery",
    "GetAdminDashboardQueryHandler",
    # Backup Status
    "GetBackupStatusQuery",
    "GetBackupStatusQueryHandler",
    # Feature Flags
    "GetFeatureFlagsQuery",
    "GetFeatureFlagsQueryHandler",
    # License
    "GetLicenseStatusQuery",
    "GetLicenseStatusQueryHandler",
    # Maintenance
    "GetMaintenanceStatusQuery",
    "GetMaintenanceStatusQueryHandler",
    # System Configuration
    "GetSystemConfigQuery",
    "GetSystemConfigQueryHandler",
    # System Health
    "GetSystemHealthQuery",
    "GetSystemHealthQueryHandler",
    # Logs
    "GetSystemLogsQuery",
    "GetSystemLogsQueryHandler",
    # Metrics
    "GetSystemMetricsQuery",
    "GetSystemMetricsQueryHandler",
    # Tenant
    "GetTenantInfoQuery",
    "GetTenantInfoQueryHandler"
]