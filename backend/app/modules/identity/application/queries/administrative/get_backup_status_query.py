"""Get backup status query implementation."""

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from app.core.cqrs import Query, QueryHandler
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.contracts.ports import (
    IAuditRepository,
    IConfigurationPort,
)
from app.modules.identity.application.decorators import (
    rate_limit,
    require_permission,
    validate_request,
)
from app.modules.identity.application.dtos.response import BackupStatusResponse


@dataclass
class GetBackupStatusQuery(Query[BackupStatusResponse]):
    """Query to get backup status and history."""
    
    backup_type: str | None = None  # full, incremental, differential
    days_back: int = 7
    include_details: bool = True
    requester_permissions: list[str] = field(default_factory=list)


class GetBackupStatusQueryHandler(QueryHandler[GetBackupStatusQuery, BackupStatusResponse]):
    """Handler for backup status queries."""
    
    def __init__(
        self,
        uow: UnitOfWork,
        audit_repository: IAuditRepository,
        config_service: IConfigurationPort
    ):
        self.uow = uow
        self.audit_repository = audit_repository
        self.config_service = config_service
    
    @rate_limit(max_calls=50, window_seconds=3600)
    @require_permission("admin.backup.read")
    @validate_request
    async def handle(self, query: GetBackupStatusQuery) -> BackupStatusResponse:
        """Handle backup status query."""
        
        async with self.uow:
            # Get backup history from audit logs
            start_date = datetime.now(UTC) - timedelta(days=query.days_back)
            
            backup_events = await self.audit_repository.search_logs({
                "action": ["backup.started", "backup.completed", "backup.failed"],
                "resource_type": "system",
                "start_date": start_date,
                "end_date": datetime.now(UTC)
            }, page=1, page_size=100)
            
            # Process backup events
            backups = []
            last_successful_backup = None
            failed_backups = 0
            
            for event in backup_events.items:
                backup_info = {
                    "id": str(event.id),
                    "type": event.details.get("backup_type", "full"),
                    "status": self._get_backup_status(event.action),
                    "started_at": event.created_at,
                    "size_bytes": event.details.get("size_bytes"),
                    "duration_seconds": event.details.get("duration_seconds"),
                    "location": event.details.get("location")
                }
                
                if query.backup_type is None or backup_info["type"] == query.backup_type:
                    backups.append(backup_info)
                
                if event.action == "backup.completed" and last_successful_backup is None:
                    last_successful_backup = backup_info
                elif event.action == "backup.failed":
                    failed_backups += 1
            
            # Get backup configuration
            backup_config = await self._get_backup_configuration()
            
            # Calculate next scheduled backup
            next_backup = self._calculate_next_backup(
                last_successful_backup,
                backup_config.get("schedule", {})
            )
            
            # Determine overall status
            overall_status = self._determine_overall_status(
                last_successful_backup,
                failed_backups,
                backup_config
            )
            
            return BackupStatusResponse(
                status=overall_status,
                last_backup=last_successful_backup,
                next_scheduled_backup=next_backup,
                backup_history=backups if query.include_details else [],
                failed_count=failed_backups,
                configuration=backup_config if query.include_details else {},
                storage_usage={
                    "total_size_bytes": sum(b.get("size_bytes", 0) for b in backups if b.get("size_bytes")),
                    "backup_count": len(backups)
                },
                retrieved_at=datetime.now(UTC)
            )
    
    def _get_backup_status(self, action: str) -> str:
        """Convert audit action to backup status."""
        status_map = {
            "backup.started": "in_progress",
            "backup.completed": "success",
            "backup.failed": "failed"
        }
        return status_map.get(action, "unknown")
    
    async def _get_backup_configuration(self) -> dict[str, Any]:
        """Get backup configuration."""
        try:
            return await self.config_service.get_backup_config()
        except (AttributeError, ConnectionError, FileNotFoundError, Exception):
            # Return default configuration if not available
            return {
                "enabled": True,
                "schedule": {
                    "full_backup": {"frequency": "daily", "time": "02:00"},
                    "incremental_backup": {"frequency": "hourly"}
                },
                "retention": {
                    "daily": 7,
                    "weekly": 4,
                    "monthly": 12
                },
                "storage": {
                    "type": "s3",
                    "encrypted": True
                }
            }
    
    def _calculate_next_backup(
        self,
        last_backup: dict[str, Any] | None,
        schedule: dict[str, Any]
    ) -> datetime | None:
        """Calculate next scheduled backup time."""
        if not schedule or not schedule.get("full_backup"):
            return None
        
        frequency = schedule["full_backup"].get("frequency", "daily")
        scheduled_time = schedule["full_backup"].get("time", "02:00")
        
        # Parse scheduled time
        hour, minute = map(int, scheduled_time.split(":"))
        
        # Calculate next occurrence
        now = datetime.now(UTC)
        next_backup = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
        
        if frequency == "daily":
            if next_backup <= now:
                next_backup += timedelta(days=1)
        elif frequency == "weekly":
            days_ahead = 7 - now.weekday()
            if days_ahead <= 0:
                days_ahead += 7
            next_backup += timedelta(days=days_ahead)
        
        return next_backup
    
    def _determine_overall_status(
        self,
        last_backup: dict[str, Any] | None,
        failed_count: int,
        config: dict[str, Any]
    ) -> str:
        """Determine overall backup status."""
        if not config.get("enabled", True):
            return "disabled"
        
        if not last_backup:
            return "no_backups"
        
        # Check if last backup is recent
        last_backup_time = last_backup.get("started_at")
        if isinstance(last_backup_time, str):
            last_backup_time = datetime.fromisoformat(last_backup_time)
        
        hours_since_backup = (datetime.now(UTC) - last_backup_time).total_seconds() / 3600
        
        if hours_since_backup > 48:
            return "outdated"
        if failed_count > 3:
            return "degraded"
        return "healthy"