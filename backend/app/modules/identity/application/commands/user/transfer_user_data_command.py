"""
Transfer user data command implementation.

Handles transferring ownership of user data between accounts.
"""

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.domain.interfaces.repositories.audit_repository import IAuditRepository
from app.modules.identity.domain.interfaces.services.infrastructure.cache_port import ICachePort as ICacheService
from app.modules.identity.domain.interfaces.services.communication.notification_service import IEmailService
from app.modules.identity.domain.interfaces.repositories.user_repository import IUserRepository
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    require_auth,
    require_permission,
    validate_request,
)
from app.modules.identity.application.dtos.internal import (
    DataTransferItem,
    EmailContext,
)
from app.modules.identity.application.dtos.request import TransferUserDataRequest
from app.modules.identity.application.dtos.response import DataTransferResponse
from app.modules.identity.domain.entities import User
from app.modules.identity.domain.enums import AuditAction, DataCategory, TransferStatus
from app.modules.identity.domain.events import UserDataTransferred
from app.modules.identity.domain.exceptions import (
    InvalidOperationError,
    UnauthorizedError,
    UserNotFoundError,
)
from app.modules.identity.domain.services import (
    AuthorizationService,
    DataMigrationService,
    SecurityService,
)


class TransferUserDataCommand(Command[DataTransferResponse]):
    """Command to transfer user data ownership."""
    
    def __init__(
        self,
        source_user_id: UUID,
        target_user_id: UUID,
        data_categories: list[DataCategory],
        transfer_mode: str = 'move',  # move, copy, or share
        preserve_access: bool = False,
        require_approval: bool = True,
        metadata: dict[str, Any] | None = None,
        initiated_by: UUID | None = None,
        reason: str | None = None
    ):
        self.source_user_id = source_user_id
        self.target_user_id = target_user_id
        self.data_categories = data_categories
        self.transfer_mode = transfer_mode
        self.preserve_access = preserve_access
        self.require_approval = require_approval
        self.metadata = metadata or {}
        self.initiated_by = initiated_by
        self.reason = reason


class TransferUserDataCommandHandler(CommandHandler[TransferUserDataCommand, DataTransferResponse]):
    """Handler for user data transfer."""
    
    def __init__(
        self,
        user_repository: IUserRepository,
        data_ownership_repository: IDataOwnershipRepository,
        audit_repository: IAuditRepository,
        security_service: SecurityService,
        data_migration_service: DataMigrationService,
        authorization_service: AuthorizationService,
        email_service: IEmailService,
        cache_service: ICacheService,
        event_bus: EventBus,
        unit_of_work: UnitOfWork
    ):
        self._user_repository = user_repository
        self._data_ownership_repository = data_ownership_repository
        self._audit_repository = audit_repository
        self._security_service = security_service
        self._data_migration_service = data_migration_service
        self._authorization_service = authorization_service
        self._email_service = email_service
        self._cache_service = cache_service
        self._event_bus = event_bus
        self._unit_of_work = unit_of_work
    
    @audit_action(
        action=AuditAction.DATA_TRANSFERRED,
        resource_type="user",
        resource_id_attr="source_user_id",
        include_request=True
    )
    @require_auth
    @require_permission(
        permission="users.transfer_data",
        resource_type="system"
    )
    @validate_request(TransferUserDataRequest)
    @rate_limit(
        max_requests=5,
        window_seconds=3600,
        strategy='user'
    )
    async def handle(self, command: TransferUserDataCommand) -> DataTransferResponse:
        """
        Transfer user data between accounts.
        
        Process:
        1. Validate both users exist
        2. Check transfer permissions
        3. Validate data categories
        4. Create transfer request
        5. Get approval if required
        6. Execute data transfer
        7. Update ownership records
        8. Send notifications
        9. Clear caches
        10. Publish event
        
        Returns:
            DataTransferResponse with transfer details
            
        Raises:
            UserNotFoundError: If either user not found
            UnauthorizedError: If not authorized
            InvalidOperationError: If transfer not allowed
        """
        async with self._unit_of_work:
            # 1. Load both users
            source_user = await self._user_repository.find_by_id(command.source_user_id)
            target_user = await self._user_repository.find_by_id(command.target_user_id)
            
            if not source_user:
                raise UserNotFoundError(f"Source user {command.source_user_id} not found")
            
            if not target_user:
                raise UserNotFoundError(f"Target user {command.target_user_id} not found")
            
            # 2. Check transfer permissions
            await self._check_transfer_permissions(
                source_user=source_user,
                target_user=target_user,
                initiated_by=command.initiated_by or source_user.id
            )
            
            # 3. Validate transfer mode
            if command.transfer_mode not in ['move', 'copy', 'share']:
                raise InvalidOperationError(
                    f"Invalid transfer mode: {command.transfer_mode}"
                )
            
            # 4. Check data ownership
            owned_data = await self._get_owned_data(
                user_id=source_user.id,
                categories=command.data_categories
            )
            
            if not owned_data:
                return DataTransferResponse(
                    transfer_id=UUID(),
                    status=TransferStatus.COMPLETED,
                    items_transferred=[],
                    summary={},
                    success=True,
                    message="No data to transfer"
                )
            
            # 5. Create transfer request
            transfer_id = UUID()
            transfer_request = await self._create_transfer_request(
                transfer_id=transfer_id,
                source_user=source_user,
                target_user=target_user,
                owned_data=owned_data,
                command=command
            )
            
            # 6. Get approval if required
            if command.require_approval:
                approval_token = await self._request_approval(
                    transfer_request=transfer_request,
                    target_user=target_user
                )
                
                # Store pending transfer
                await self._store_pending_transfer(
                    transfer_id=transfer_id,
                    transfer_request=transfer_request,
                    approval_token=approval_token
                )
                
                return DataTransferResponse(
                    transfer_id=transfer_id,
                    status=TransferStatus.PENDING_APPROVAL,
                    items_transferred=[],
                    approval_required=True,
                    approval_token=approval_token,
                    summary={
                        'items_to_transfer': len(owned_data),
                        'categories': [cat.value for cat in command.data_categories]
                    },
                    success=True,
                    message="Transfer pending approval from target user"
                )
            
            # 7. Execute transfer
            transfer_result = await self._execute_transfer(
                transfer_id=transfer_id,
                source_user=source_user,
                target_user=target_user,
                owned_data=owned_data,
                command=command
            )
            
            # 8. Update ownership records
            await self._update_ownership_records(
                transfer_result=transfer_result,
                command=command
            )
            
            # 9. Handle access preservation
            if command.preserve_access and command.transfer_mode == 'move':
                await self._grant_access_to_source(
                    source_user=source_user,
                    transferred_items=transfer_result['items']
                )
            
            # 10. Send notifications
            await self._send_transfer_notifications(
                source_user=source_user,
                target_user=target_user,
                transfer_result=transfer_result
            )
            
            # 11. Clear caches
            await self._clear_data_caches(source_user.id)
            await self._clear_data_caches(target_user.id)
            
            # 12. Log transfer details
            await self._log_transfer_details(
                transfer_id=transfer_id,
                source_user=source_user,
                target_user=target_user,
                transfer_result=transfer_result,
                command=command
            )
            
            # 13. Publish event
            await self._event_bus.publish(
                UserDataTransferred(
                    aggregate_id=source_user.id,
                    transfer_id=transfer_id,
                    source_user_id=source_user.id,
                    target_user_id=target_user.id,
                    data_categories=[cat.value for cat in command.data_categories],
                    transfer_mode=command.transfer_mode,
                    items_transferred=len(transfer_result['items']),
                    initiated_by=command.initiated_by
                )
            )
            
            # 14. Commit transaction
            await self._unit_of_work.commit()
            
            return DataTransferResponse(
                transfer_id=transfer_id,
                status=TransferStatus.COMPLETED,
                items_transferred=transfer_result['items'],
                summary=transfer_result['summary'],
                completion_timestamp=datetime.now(UTC),
                success=True,
                message=f"Successfully transferred {len(transfer_result['items'])} items"
            )
    
    async def _check_transfer_permissions(
        self,
        source_user: User,
        target_user: User,
        initiated_by: UUID
    ) -> None:
        """Check if transfer is allowed."""
        # Check if initiator owns the source data or has admin rights
        if initiated_by == source_user.id:
            # User transferring their own data
            pass
        elif await self._authorization_service.has_permission(
            user_id=initiated_by,
            permission="users.transfer_any_data"
        ):
            # Admin transferring data
            pass
        else:
            # Check if user has specific permission
            can_transfer = await self._authorization_service.has_permission(
                user_id=initiated_by,
                permission="users.transfer_data",
                resource_type="user",
                resource_id=str(source_user.id)
            )
            
            if not can_transfer:
                raise UnauthorizedError(
                    "Not authorized to transfer this user's data"
                )
        
        # Validate target user can receive data
        if target_user.is_deleted or target_user.is_suspended:
            raise InvalidOperationError(
                "Cannot transfer data to inactive user"
            )
    
    async def _get_owned_data(
        self,
        user_id: UUID,
        categories: list[DataCategory]
    ) -> list[DataTransferItem]:
        """Get data owned by user in specified categories."""
        owned_items = []
        
        for category in categories:
            items = await self._data_ownership_repository.get_owned_items(
                owner_id=user_id,
                category=category
            )
            
            for item in items:
                owned_items.append(
                    DataTransferItem(
                        item_id=item.id,
                        item_type=item.type,
                        category=category,
                        size=item.size,
                        created_at=item.created_at,
                        metadata=item.metadata
                    )
                )
        
        return owned_items
    
    async def _create_transfer_request(
        self,
        transfer_id: UUID,
        source_user: User,
        target_user: User,
        owned_data: list[DataTransferItem],
        command: TransferUserDataCommand
    ) -> dict[str, Any]:
        """Create transfer request details."""
        return {
            'transfer_id': transfer_id,
            'source_user': {
                'id': source_user.id,
                'username': source_user.username,
                'email': source_user.email
            },
            'target_user': {
                'id': target_user.id,
                'username': target_user.username,
                'email': target_user.email
            },
            'data_summary': {
                'total_items': len(owned_data),
                'categories': [cat.value for cat in command.data_categories],
                'total_size': sum(item.size for item in owned_data if item.size)
            },
            'transfer_mode': command.transfer_mode,
            'preserve_access': command.preserve_access,
            'initiated_by': command.initiated_by,
            'reason': command.reason,
            'created_at': datetime.now(UTC)
        }
    
    async def _request_approval(
        self,
        transfer_request: dict[str, Any],
        target_user: User
    ) -> str:
        """Request approval from target user."""
        # Generate approval token
        approval_token = await self._security_service.generate_secure_token()
        
        # Send approval request email
        await self._email_service.send_email(
            EmailContext(
                recipient=target_user.email,
                template="data_transfer_approval",
                subject="Data transfer approval required",
                variables={
                    "target_username": target_user.username,
                    "source_username": transfer_request['source_user']['username'],
                    "item_count": transfer_request['data_summary']['total_items'],
                    "categories": ', '.join(transfer_request['data_summary']['categories']),
                    "approval_link": f"https://app.example.com/approve-transfer?token={approval_token}",
                    "reason": transfer_request['reason'] or "No reason provided"
                },
                priority="high"
            )
        )
        
        return approval_token
    
    async def _store_pending_transfer(
        self,
        transfer_id: UUID,
        transfer_request: dict[str, Any],
        approval_token: str
    ) -> None:
        """Store pending transfer for later approval."""
        await self._cache_service.set(
            key=f"pending_transfer:{transfer_id}",
            value={
                'request': transfer_request,
                'approval_token': approval_token,
                'expires_at': (datetime.now(UTC) + timedelta(days=7)).isoformat()
            },
            ttl=604800  # 7 days
        )
    
    async def _execute_transfer(
        self,
        transfer_id: UUID,
        source_user: User,
        target_user: User,
        owned_data: list[DataTransferItem],
        command: TransferUserDataCommand
    ) -> dict[str, Any]:
        """Execute the data transfer."""
        transferred_items = []
        errors = []
        
        for item in owned_data:
            try:
                # Transfer based on mode
                if command.transfer_mode == 'move':
                    await self._data_migration_service.transfer_ownership(
                        item_id=item.item_id,
                        from_user_id=source_user.id,
                        to_user_id=target_user.id
                    )
                elif command.transfer_mode == 'copy':
                    await self._data_migration_service.copy_ownership(
                        item_id=item.item_id,
                        from_user_id=source_user.id,
                        to_user_id=target_user.id
                    )
                elif command.transfer_mode == 'share':
                    await self._data_migration_service.share_ownership(
                        item_id=item.item_id,
                        owner_id=source_user.id,
                        shared_with_id=target_user.id
                    )
                
                transferred_items.append(item)
                
            except Exception as e:
                errors.append({
                    'item_id': str(item.item_id),
                    'error': str(e)
                })
        
        return {
            'items': transferred_items,
            'errors': errors,
            'summary': {
                'total_items': len(owned_data),
                'transferred': len(transferred_items),
                'failed': len(errors),
                'transfer_mode': command.transfer_mode
            }
        }
    
    async def _update_ownership_records(
        self,
        transfer_result: dict[str, Any],
        command: TransferUserDataCommand
    ) -> None:
        """Update ownership records after transfer."""
        for item in transfer_result['items']:
            await self._data_ownership_repository.record_transfer(
                item_id=item.item_id,
                from_user_id=command.source_user_id,
                to_user_id=command.target_user_id,
                transfer_mode=command.transfer_mode,
                transferred_at=datetime.now(UTC)
            )
    
    async def _grant_access_to_source(
        self,
        source_user: User,
        transferred_items: list[DataTransferItem]
    ) -> None:
        """Grant read access to source user for transferred items."""
        for item in transferred_items:
            await self._authorization_service.grant_permission(
                user_id=source_user.id,
                permission=f"data.read.{item.category.value}",
                resource_type="data_item",
                resource_id=str(item.item_id),
                granted_by="system",
                reason="Access preserved after data transfer"
            )
    
    async def _send_transfer_notifications(
        self,
        source_user: User,
        target_user: User,
        transfer_result: dict[str, Any]
    ) -> None:
        """Send notifications about completed transfer."""
        summary = transfer_result['summary']
        
        # Notify source user
        await self._email_service.send_email(
            EmailContext(
                recipient=source_user.email,
                template="data_transfer_completed_source",
                subject="Your data has been transferred",
                variables={
                    "username": source_user.username,
                    "target_username": target_user.username,
                    "items_transferred": summary['transferred'],
                    "transfer_mode": summary['transfer_mode']
                },
                priority="high"
            )
        )
        
        # Notify target user
        await self._email_service.send_email(
            EmailContext(
                recipient=target_user.email,
                template="data_transfer_completed_target",
                subject="You have received transferred data",
                variables={
                    "username": target_user.username,
                    "source_username": source_user.username,
                    "items_received": summary['transferred'],
                    "transfer_mode": summary['transfer_mode']
                },
                priority="high"
            )
        )
    
    async def _clear_data_caches(self, user_id: UUID) -> None:
        """Clear data-related caches for user."""
        patterns = [
            f"user_data:{user_id}:*",
            f"data_ownership:{user_id}:*",
            f"data_permissions:{user_id}:*"
        ]
        
        for pattern in patterns:
            await self._cache_service.delete_pattern(pattern)
    
    async def _log_transfer_details(
        self,
        transfer_id: UUID,
        source_user: User,
        target_user: User,
        transfer_result: dict[str, Any],
        command: TransferUserDataCommand
    ) -> None:
        """Log detailed transfer information."""
        await self._security_service.log_security_event(
            user_id=source_user.id,
            event_type="data_ownership_transferred",
            details={
                "transfer_id": str(transfer_id),
                "source_user_id": str(source_user.id),
                "target_user_id": str(target_user.id),
                "categories": [cat.value for cat in command.data_categories],
                "transfer_mode": command.transfer_mode,
                "items_transferred": transfer_result['summary']['transferred'],
                "errors": len(transfer_result['errors']),
                "initiated_by": str(command.initiated_by) if command.initiated_by else None,
                "reason": command.reason
            }
        )