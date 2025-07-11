"""Get maintenance status query implementation."""

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any

from app.core.cqrs import Query, QueryHandler
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.decorators import (
    rate_limit,
    require_permission,
    validate_request,
)
from app.modules.identity.application.dtos.response import MaintenanceStatusResponse
from app.modules.identity.domain.interfaces.services import (
    ICachePort,
    IConfigurationPort,
)


class MaintenanceMode(Enum):
    """Maintenance mode types."""
    OFF = "off"
    SCHEDULED = "scheduled"
    ACTIVE = "active"
    EMERGENCY = "emergency"


@dataclass
class GetMaintenanceStatusQuery(Query[MaintenanceStatusResponse]):
    """Query to get maintenance status."""
    
    include_history: bool = True
    days_ahead: int = 30
    requester_permissions: list[str] = field(default_factory=list)


class GetMaintenanceStatusQueryHandler(QueryHandler[GetMaintenanceStatusQuery, MaintenanceStatusResponse]):
    """Handler for maintenance status queries."""
    
    def __init__(
        self,
        uow: UnitOfWork,
        config_service: IConfigurationPort,
        cache_service: ICachePort
    ):
        self.uow = uow
        self.config_service = config_service
        self.cache_service = cache_service
    
    @rate_limit(max_calls=100, window_seconds=60)
    @require_permission("admin.maintenance.read")
    @validate_request
    async def handle(self, query: GetMaintenanceStatusQuery) -> MaintenanceStatusResponse:
        """Handle maintenance status query."""
        
        async with self.uow:
            # Get current maintenance status from cache
            current_mode = await self._get_current_maintenance_mode()
            
            # Get maintenance configuration
            maintenance_config = await self._get_maintenance_configuration()
            
            # Get scheduled maintenance windows
            scheduled_windows = await self._get_scheduled_maintenance(query.days_ahead)
            
            # Get active maintenance details if in maintenance mode
            active_maintenance = None
            if current_mode in [MaintenanceMode.ACTIVE, MaintenanceMode.EMERGENCY]:
                active_maintenance = await self._get_active_maintenance_details()
            
            # Get maintenance history if requested
            history = []
            if query.include_history:
                history = await self._get_maintenance_history()
            
            # Determine next scheduled maintenance
            next_maintenance = self._find_next_maintenance(scheduled_windows)
            
            # Check if currently in maintenance window
            self._is_in_maintenance_window(scheduled_windows)
            
            return MaintenanceStatusResponse(
                mode=current_mode.value,
                is_active=current_mode in [MaintenanceMode.ACTIVE, MaintenanceMode.EMERGENCY],
                active_maintenance=active_maintenance,
                scheduled_windows=scheduled_windows,
                next_maintenance=next_maintenance,
                configuration=maintenance_config,
                history=history,
                affected_services=self._get_affected_services(current_mode, active_maintenance),
                estimated_duration_minutes=self._estimate_duration(active_maintenance),
                notifications_sent=await self._check_notifications_sent(),
                retrieved_at=datetime.now(UTC)
            )
    
    async def _get_current_maintenance_mode(self) -> MaintenanceMode:
        """Get current maintenance mode from cache."""
        mode = await self.cache_service.get_user_cache(None, "maintenance_mode")
        if not mode:
            return MaintenanceMode.OFF
        try:
            return MaintenanceMode(mode)
        except ValueError:
            return MaintenanceMode.OFF
    
    async def _get_maintenance_configuration(self) -> dict[str, Any]:
        """Get maintenance configuration."""
        try:
            return await self.config_service.get_maintenance_config()
        except (AttributeError, ConnectionError, FileNotFoundError, Exception):
            # Return default configuration
            return {
                "enabled": True,
                "allowed_actions_during_maintenance": [
                    "auth.login",
                    "auth.logout",
                    "admin.maintenance.read"
                ],
                "notification_lead_time_hours": 24,
                "auto_enable_on_schedule": True,
                "require_confirmation": True,
                "max_duration_hours": 4,
                "grace_period_minutes": 5
            }
    
    async def _get_scheduled_maintenance(self, days_ahead: int) -> list[dict[str, Any]]:
        """Get scheduled maintenance windows."""
        # This would typically query a maintenance schedule table
        # For now, return from cache or empty list
        windows = await self.cache_service.get_user_cache(None, "scheduled_maintenance")
        if not windows:
            windows = []
        
        # Filter to requested time period
        cutoff_date = datetime.now(UTC) + timedelta(days=days_ahead)
        filtered_windows = []
        
        for window in windows:
            start_time = window.get("start_time")
            if isinstance(start_time, str):
                start_time = datetime.fromisoformat(start_time)
            
            if start_time <= cutoff_date:
                filtered_windows.append(window)
        
        return filtered_windows
    
    async def _get_active_maintenance_details(self) -> dict[str, Any] | None:
        """Get details of active maintenance."""
        details = await self.cache_service.get_user_cache(None, "active_maintenance_details")
        if details:
            return {
                "started_at": details.get("started_at"),
                "started_by": details.get("started_by"),
                "reason": details.get("reason"),
                "expected_end_time": details.get("expected_end_time"),
                "progress_percentage": details.get("progress_percentage", 0),
                "current_task": details.get("current_task"),
                "tasks_completed": details.get("tasks_completed", []),
                "tasks_remaining": details.get("tasks_remaining", [])
            }
        return None
    
    async def _get_maintenance_history(self) -> list[dict[str, Any]]:
        """Get maintenance history."""
        # This would typically query audit logs for maintenance events
        history = await self.cache_service.get_user_cache(None, "maintenance_history")
        return history or []
    
    def _find_next_maintenance(self, windows: list[dict[str, Any]]) -> dict[str, Any] | None:
        """Find next scheduled maintenance window."""
        now = datetime.now(UTC)
        future_windows = []
        
        for window in windows:
            start_time = window.get("start_time")
            if isinstance(start_time, str):
                start_time = datetime.fromisoformat(start_time)
            
            if start_time > now:
                future_windows.append(window)
        
        if future_windows:
            # Sort by start time and return the earliest
            future_windows.sort(key=lambda w: w["start_time"])
            return future_windows[0]
        
        return None
    
    def _is_in_maintenance_window(self, windows: list[dict[str, Any]]) -> bool:
        """Check if currently in a scheduled maintenance window."""
        now = datetime.now(UTC)
        
        for window in windows:
            start_time = window.get("start_time")
            end_time = window.get("end_time")
            
            if isinstance(start_time, str):
                start_time = datetime.fromisoformat(start_time)
            if isinstance(end_time, str):
                end_time = datetime.fromisoformat(end_time)
            
            if start_time <= now <= end_time:
                return True
        
        return False
    
    def _get_affected_services(
        self,
        mode: MaintenanceMode,
        active_details: dict[str, Any] | None
    ) -> list[str]:
        """Get list of affected services."""
        if mode == MaintenanceMode.OFF:
            return []
        
        if active_details and "affected_services" in active_details:
            return active_details["affected_services"]
        
        # Default affected services during maintenance
        if mode == MaintenanceMode.EMERGENCY:
            return ["all"]
        return [
            "user_registration",
            "profile_updates", 
            "password_changes",
            "mfa_setup",
            "api_integrations"
        ]
    
    def _estimate_duration(self, active_details: dict[str, Any] | None) -> int | None:
        """Estimate remaining duration in minutes."""
        if not active_details:
            return None
        
        expected_end = active_details.get("expected_end_time")
        if not expected_end:
            return None
        
        if isinstance(expected_end, str):
            expected_end = datetime.fromisoformat(expected_end)
        
        remaining = (expected_end - datetime.now(UTC)).total_seconds() / 60
        return max(0, int(remaining))
    
    async def _check_notifications_sent(self) -> bool:
        """Check if maintenance notifications were sent."""
        return await self.cache_service.get_user_cache(
            None,
            "maintenance_notifications_sent"
        ) or False