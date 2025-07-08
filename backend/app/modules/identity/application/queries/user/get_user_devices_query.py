"""
Get user devices query implementation.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID

from app.core.cqrs import Query, QueryHandler
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.contracts.ports import IDeviceRepository
from app.modules.identity.application.decorators import (
    rate_limit,
    require_permission,
    validate_request,
)
from app.modules.identity.application.dtos.response import UserDevicesResponse


@dataclass
class GetUserDevicesQuery(Query[UserDevicesResponse]):
    """Query to retrieve user devices."""
    
    user_id: UUID
    requester_id: UUID
    include_inactive: bool = False
    device_type: str | None = None
    days_back: int = 90
    requester_permissions: list[str] = field(default_factory=list)


class GetUserDevicesQueryHandler(
    QueryHandler[GetUserDevicesQuery, UserDevicesResponse]
):
    """Handler for user devices queries."""
    
    def __init__(self, uow: UnitOfWork, device_repository: IDeviceRepository):
        self.uow = uow
        self.device_repository = device_repository
    
    @rate_limit(max_calls=100, window_seconds=3600)
    @require_permission("user.devices.read")
    @validate_request
    async def handle(self, query: GetUserDevicesQuery) -> UserDevicesResponse:
        """Handle user devices query."""
        
        async with self.uow:
            devices = await self.device_repository.get_user_devices(
                query.user_id,
                include_inactive=query.include_inactive,
                device_type=query.device_type,
                days_back=query.days_back
            )
            
            return UserDevicesResponse(
                user_id=query.user_id,
                devices=devices,
                total_count=len(devices),
                retrieved_at=datetime.now(UTC)
            )