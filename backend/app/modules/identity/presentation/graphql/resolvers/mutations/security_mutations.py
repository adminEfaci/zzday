"""
Security mutation resolvers for GraphQL.

This module implements comprehensive security-related mutations including
security event management, user blocking/unblocking, blacklist management,
session invalidation, and security monitoring with audit logging.
"""

import uuid
from datetime import datetime, timedelta
from typing import Any

from strawberry import mutation
from strawberry.types import Info

from app.core.cache import get_cache
from app.core.database import get_db_context
from app.core.enums import BlockReason, EventType, SecurityLevel, UserStatus
from app.core.errors import (
    AuthorizationError,
    BusinessRuleError,
    ConflictError,
    NotFoundError,
    ValidationError,
)
from app.core.logging import get_logger
from app.modules.identity.domain.entities import SecurityEvent, Session, User
from app.modules.identity.domain.interfaces import (
    IBlacklistRepository,
    INotificationService,
    ISecurityEventRepository,
    ISecurityService,
    ISessionRepository,
    IUserBlockRepository,
    IUserRepository,
)
from app.modules.identity.presentation.graphql.types import (
    BlacklistCreateInput,
    BlacklistResponse,
    SecurityEventCreateInput,
    SecurityEventResponse,
)

logger = get_logger(__name__)


class SecurityMutations:
    """Security-related GraphQL mutations."""

    def __init__(
        self,
        security_event_repository: ISecurityEventRepository,
        user_block_repository: IUserBlockRepository,
        blacklist_repository: IBlacklistRepository,
        session_repository: ISessionRepository,
        user_repository: IUserRepository,
        security_service: ISecurityService,
        notification_service: INotificationService
    ):
        self.security_event_repository = security_event_repository
        self.user_block_repository = user_block_repository
        self.blacklist_repository = blacklist_repository
        self.session_repository = session_repository
        self.user_repository = user_repository
        self.security_service = security_service
        self.notification_service = notification_service
        self.cache = get_cache()
        self.logger = logger

    @mutation
    async def create_security_event(
        self,
        info: Info,
        input: SecurityEventCreateInput
    ) -> SecurityEventResponse:
        """
        Create security event for monitoring and audit purposes.
        
        Args:
            input: Security event data
            
        Returns:
            SecurityEventResponse with created event
            
        Raises:
            ValidationError: Invalid input data
            AuthorizationError: Insufficient permissions
        """
        async with get_db_context() as db:
            try:
                # Check authorization
                current_user = info.context.get("current_user")
                if not current_user or not self._has_security_event_create_permission(current_user):
                    raise AuthorizationError("Insufficient permissions to create security events")

                # Validate input
                await self._validate_security_event_input(input)

                # Create security event
                event_data = await self._prepare_security_event_data(input, current_user, info)
                event = await self.security_event_repository.create(event_data)

                # Check for automated security responses
                await self._process_security_event_triggers(event)

                # Log event creation
                self.logger.info(
                    f"Security event created: {event.event_type} by user {current_user.id}",
                    extra={
                        "event_id": event.id,
                        "event_type": event.event_type,
                        "user_id": current_user.id
                    }
                )

                await db.commit()

                return SecurityEventResponse(event=event)

            except Exception as e:
                await db.rollback()
                self.logger.exception(f"Security event creation failed: {e!s}")
                raise

    @mutation
    async def resolve_security_event(
        self,
        info: Info,
        id: str,
        resolution: str
    ) -> bool:
        """
        Resolve security event with resolution details.
        
        Args:
            id: Security event ID
            resolution: Resolution description
            
        Returns:
            True if event resolved successfully
        """
        async with get_db_context() as db:
            try:
                # Check authorization
                current_user = info.context.get("current_user")
                if not current_user or not self._has_security_event_resolve_permission(current_user):
                    raise AuthorizationError("Insufficient permissions to resolve security events")

                # Find security event
                event = await self.security_event_repository.find_by_id(id)
                if not event:
                    raise NotFoundError("Security event not found")

                # Check if already resolved
                if event.is_resolved:
                    raise BusinessRuleError("Security event is already resolved")

                # Update event
                event.is_resolved = True
                event.resolved_at = datetime.utcnow()
                event.resolved_by = current_user.id
                event.resolution = resolution

                await self.security_event_repository.update(event)

                # Log resolution
                await self._log_security_event(
                    current_user.id,
                    EventType.SECURITY_EVENT_RESOLVED,
                    f"Security event resolved: {event.id}",
                    info,
                    metadata={
                        "event_id": event.id,
                        "event_type": event.event_type,
                        "resolution": resolution
                    }
                )

                await db.commit()
                return True

            except Exception as e:
                await db.rollback()
                self.logger.exception(f"Security event resolution failed: {e!s}")
                raise

    @mutation
    async def block_user(
        self,
        info: Info,
        id: str,
        reason: str
    ) -> bool:
        """
        Block user account for security reasons.
        
        Args:
            id: User ID
            reason: Block reason
            
        Returns:
            True if user blocked successfully
        """
        async with get_db_context() as db:
            try:
                # Check authorization
                current_user = info.context.get("current_user")
                if not current_user or not self._has_user_block_permission(current_user):
                    raise AuthorizationError("Insufficient permissions to block users")

                # Find user
                user = await self.user_repository.find_by_id(id)
                if not user:
                    raise NotFoundError("User not found")

                # Check if user can be blocked
                if user.id == current_user.id:
                    raise BusinessRuleError("Cannot block your own account")

                if user.is_system_user:
                    raise BusinessRuleError("Cannot block system user")

                # Check if already blocked
                existing_block = await self.user_block_repository.find_active_block_by_user_id(id)
                if existing_block:
                    raise ConflictError("User is already blocked")

                # Create user block
                block_data = {
                    "id": str(uuid.uuid4()),
                    "user_id": id,
                    "blocked_by": current_user.id,
                    "reason": reason,
                    "block_reason": self._determine_block_reason(reason),
                    "blocked_at": datetime.utcnow(),
                    "is_active": True
                }

                await self.user_block_repository.create(block_data)

                # Update user status
                user.status = UserStatus.BLOCKED
                user.blocked_at = datetime.utcnow()
                user.blocked_by = current_user.id

                await self.user_repository.update(user)

                # Invalidate all user sessions
                await self._invalidate_all_user_sessions(id)

                # Log security event
                await self._log_security_event(
                    id,
                    EventType.USER_BLOCKED,
                    f"User blocked by admin: {current_user.id}. Reason: {reason}",
                    info,
                    metadata={
                        "blocked_by": current_user.id,
                        "reason": reason,
                        "security_level": SecurityLevel.HIGH
                    }
                )

                # Send notification
                await self.notification_service.send_user_blocked_notification(user, reason)

                # Check for automated security responses
                await self._process_user_block_triggers(user, reason)

                await db.commit()
                return True

            except Exception as e:
                await db.rollback()
                self.logger.exception(f"User blocking failed: {e!s}")
                raise

    @mutation
    async def unblock_user(
        self,
        info: Info,
        id: str,
        reason: str
    ) -> bool:
        """
        Unblock user account.
        
        Args:
            id: User ID
            reason: Unblock reason
            
        Returns:
            True if user unblocked successfully
        """
        async with get_db_context() as db:
            try:
                # Check authorization
                current_user = info.context.get("current_user")
                if not current_user or not self._has_user_block_permission(current_user):
                    raise AuthorizationError("Insufficient permissions to unblock users")

                # Find user
                user = await self.user_repository.find_by_id(id)
                if not user:
                    raise NotFoundError("User not found")

                # Find active block
                active_block = await self.user_block_repository.find_active_block_by_user_id(id)
                if not active_block:
                    raise NotFoundError("No active block found for user")

                # Deactivate block
                active_block.is_active = False
                active_block.unblocked_at = datetime.utcnow()
                active_block.unblocked_by = current_user.id
                active_block.unblock_reason = reason

                await self.user_block_repository.update(active_block)

                # Update user status
                user.status = UserStatus.ACTIVE
                user.blocked_at = None
                user.blocked_by = None

                await self.user_repository.update(user)

                # Log security event
                await self._log_security_event(
                    id,
                    EventType.USER_UNBLOCKED,
                    f"User unblocked by admin: {current_user.id}. Reason: {reason}",
                    info,
                    metadata={
                        "unblocked_by": current_user.id,
                        "reason": reason
                    }
                )

                # Send notification
                await self.notification_service.send_user_unblocked_notification(user)

                await db.commit()
                return True

            except Exception as e:
                await db.rollback()
                self.logger.exception(f"User unblocking failed: {e!s}")
                raise

    @mutation
    async def add_to_blacklist(
        self,
        info: Info,
        input: BlacklistCreateInput
    ) -> BlacklistResponse:
        """
        Add entry to security blacklist.
        
        Args:
            input: Blacklist entry data
            
        Returns:
            BlacklistResponse with created entry
        """
        async with get_db_context() as db:
            try:
                # Check authorization
                current_user = info.context.get("current_user")
                if not current_user or not self._has_blacklist_manage_permission(current_user):
                    raise AuthorizationError("Insufficient permissions to manage blacklist")

                # Validate input
                await self._validate_blacklist_input(input)

                # Check if entry already exists
                existing_entry = await self.blacklist_repository.find_by_value_and_type(
                    input.value, input.blacklist_type
                )
                if existing_entry and existing_entry.is_active:
                    raise ConflictError("Entry already exists in blacklist")

                # Create blacklist entry
                blacklist_data = await self._prepare_blacklist_data(input, current_user)
                blacklist_entry = await self.blacklist_repository.create(blacklist_data)

                # Log security event
                await self._log_security_event(
                    current_user.id,
                    EventType.BLACKLIST_ENTRY_ADDED,
                    f"Blacklist entry added: {input.blacklist_type}:{input.value}",
                    info,
                    metadata={
                        "blacklist_id": blacklist_entry.id,
                        "blacklist_type": input.blacklist_type,
                        "value": input.value
                    }
                )

                # Clear blacklist cache
                await self._invalidate_blacklist_cache()

                await db.commit()

                return BlacklistResponse(entry=blacklist_entry)

            except Exception as e:
                await db.rollback()
                self.logger.exception(f"Blacklist addition failed: {e!s}")
                raise

    @mutation
    async def remove_from_blacklist(self, info: Info, id: str) -> bool:
        """
        Remove entry from security blacklist.
        
        Args:
            id: Blacklist entry ID
            
        Returns:
            True if entry removed successfully
        """
        async with get_db_context() as db:
            try:
                # Check authorization
                current_user = info.context.get("current_user")
                if not current_user or not self._has_blacklist_manage_permission(current_user):
                    raise AuthorizationError("Insufficient permissions to manage blacklist")

                # Find blacklist entry
                blacklist_entry = await self.blacklist_repository.find_by_id(id)
                if not blacklist_entry:
                    raise NotFoundError("Blacklist entry not found")

                # Deactivate entry
                blacklist_entry.is_active = False
                blacklist_entry.removed_at = datetime.utcnow()
                blacklist_entry.removed_by = current_user.id

                await self.blacklist_repository.update(blacklist_entry)

                # Log security event
                await self._log_security_event(
                    current_user.id,
                    EventType.BLACKLIST_ENTRY_REMOVED,
                    f"Blacklist entry removed: {blacklist_entry.blacklist_type}:{blacklist_entry.value}",
                    info,
                    metadata={
                        "blacklist_id": blacklist_entry.id,
                        "blacklist_type": blacklist_entry.blacklist_type,
                        "value": blacklist_entry.value
                    }
                )

                # Clear blacklist cache
                await self._invalidate_blacklist_cache()

                await db.commit()
                return True

            except Exception as e:
                await db.rollback()
                self.logger.exception(f"Blacklist removal failed: {e!s}")
                raise

    @mutation
    async def invalidate_session(self, info: Info, id: str) -> bool:
        """
        Invalidate specific user session.
        
        Args:
            id: Session ID
            
        Returns:
            True if session invalidated successfully
        """
        async with get_db_context() as db:
            try:
                # Check authorization
                current_user = info.context.get("current_user")
                if not current_user or not self._has_session_manage_permission(current_user):
                    raise AuthorizationError("Insufficient permissions to manage sessions")

                # Find session
                session = await self.session_repository.find_by_id(id)
                if not session:
                    raise NotFoundError("Session not found")

                # Check if current user can invalidate this session
                if not self._can_invalidate_session(current_user, session):
                    raise AuthorizationError("Cannot invalidate this session")

                # Invalidate session
                session.is_active = False
                session.invalidated_at = datetime.utcnow()
                session.invalidated_by = current_user.id

                await self.session_repository.update(session)

                # Remove from cache
                await self.cache.delete(f"session:{session.id}")

                # Log security event
                await self._log_security_event(
                    session.user_id,
                    EventType.SESSION_INVALIDATED,
                    f"Session invalidated by admin: {current_user.id}",
                    info,
                    metadata={
                        "session_id": session.id,
                        "invalidated_by": current_user.id
                    }
                )

                await db.commit()
                return True

            except Exception as e:
                await db.rollback()
                self.logger.exception(f"Session invalidation failed: {e!s}")
                raise

    @mutation
    async def invalidate_all_sessions(self, info: Info, user_id: str) -> bool:
        """
        Invalidate all sessions for a specific user.
        
        Args:
            user_id: User ID
            
        Returns:
            True if all sessions invalidated successfully
        """
        async with get_db_context() as db:
            try:
                # Check authorization
                current_user = info.context.get("current_user")
                if not current_user or not self._has_session_manage_permission(current_user):
                    raise AuthorizationError("Insufficient permissions to manage sessions")

                # Find user
                user = await self.user_repository.find_by_id(user_id)
                if not user:
                    raise NotFoundError("User not found")

                # Check if current user can invalidate sessions for this user
                if not self._can_manage_user_sessions(current_user, user):
                    raise AuthorizationError("Cannot manage sessions for this user")

                # Get all active sessions
                active_sessions = await self.session_repository.find_active_by_user_id(user_id)

                # Invalidate all sessions
                invalidated_count = 0
                for session in active_sessions:
                    session.is_active = False
                    session.invalidated_at = datetime.utcnow()
                    session.invalidated_by = current_user.id

                    await self.session_repository.update(session)
                    await self.cache.delete(f"session:{session.id}")

                    invalidated_count += 1

                # Clear user sessions cache
                await self.cache.delete(f"user_sessions:{user_id}")

                # Log security event
                await self._log_security_event(
                    user_id,
                    EventType.ALL_SESSIONS_INVALIDATED,
                    f"All sessions invalidated by admin: {current_user.id}. Count: {invalidated_count}",
                    info,
                    metadata={
                        "invalidated_by": current_user.id,
                        "session_count": invalidated_count
                    }
                )

                await db.commit()
                return True

            except Exception as e:
                await db.rollback()
                self.logger.exception(f"All sessions invalidation failed: {e!s}")
                raise

    # Helper methods

    def _has_security_event_create_permission(self, user) -> bool:
        """Check if user has permission to create security events."""
        return user.has_permission("security:event:create")

    def _has_security_event_resolve_permission(self, user) -> bool:
        """Check if user has permission to resolve security events."""
        return user.has_permission("security:event:resolve")

    def _has_user_block_permission(self, user) -> bool:
        """Check if user has permission to block/unblock users."""
        return user.has_permission("security:user:block")

    def _has_blacklist_manage_permission(self, user) -> bool:
        """Check if user has permission to manage blacklist."""
        return user.has_permission("security:blacklist:manage")

    def _has_session_manage_permission(self, user) -> bool:
        """Check if user has permission to manage sessions."""
        return user.has_permission("security:session:manage")

    def _can_invalidate_session(self, current_user, session: Session) -> bool:
        """Check if current user can invalidate specific session."""
        # Users can invalidate their own sessions
        if current_user.id == session.user_id:
            return True

        # Admins can invalidate any session
        return current_user.has_permission("security:session:manage")

    def _can_manage_user_sessions(self, current_user, target_user: User) -> bool:
        """Check if current user can manage target user's sessions."""
        # Users can manage their own sessions
        if current_user.id == target_user.id:
            return True

        # Admins can manage any user's sessions
        return current_user.has_permission("security:session:manage")

    def _determine_block_reason(self, reason: str) -> BlockReason:
        """Determine block reason enum from text."""
        reason_lower = reason.lower()

        if "security" in reason_lower or "threat" in reason_lower:
            return BlockReason.SECURITY_THREAT
        if "abuse" in reason_lower or "violation" in reason_lower:
            return BlockReason.ABUSE
        if "fraud" in reason_lower:
            return BlockReason.FRAUD
        if "spam" in reason_lower:
            return BlockReason.SPAM
        return BlockReason.OTHER

    async def _validate_security_event_input(self, input: SecurityEventCreateInput) -> None:
        """Validate security event input."""
        if not input.event_type:
            raise ValidationError("Event type is required")

        if not input.description or len(input.description.strip()) < 5:
            raise ValidationError("Description must be at least 5 characters")

        if hasattr(input, 'user_id') and input.user_id:
            user = await self.user_repository.find_by_id(input.user_id)
            if not user:
                raise ValidationError("Invalid user ID")

    async def _validate_blacklist_input(self, input: BlacklistCreateInput) -> None:
        """Validate blacklist input."""
        if not input.value or len(input.value.strip()) < 3:
            raise ValidationError("Blacklist value must be at least 3 characters")

        if not input.blacklist_type:
            raise ValidationError("Blacklist type is required")

        if hasattr(input, 'reason') and input.reason and len(input.reason) > 500:
            raise ValidationError("Reason cannot exceed 500 characters")

    async def _prepare_security_event_data(
        self,
        input: SecurityEventCreateInput,
        current_user,
        info: Info
    ) -> dict[str, Any]:
        """Prepare security event data."""
        return {
            "id": str(uuid.uuid4()),
            "user_id": getattr(input, "user_id", None),
            "event_type": input.event_type,
            "description": input.description.strip(),
            "severity": getattr(input, "severity", SecurityLevel.MEDIUM),
            "ip_address": info.context.get("ip_address"),
            "user_agent": info.context.get("user_agent"),
            "metadata": getattr(input, "metadata", {}),
            "created_by": current_user.id,
            "created_at": datetime.utcnow(),
            "is_resolved": False
        }

    async def _prepare_blacklist_data(
        self,
        input: BlacklistCreateInput,
        current_user
    ) -> dict[str, Any]:
        """Prepare blacklist data."""
        return {
            "id": str(uuid.uuid4()),
            "blacklist_type": input.blacklist_type,
            "value": input.value.strip(),
            "reason": getattr(input, "reason", ""),
            "expires_at": getattr(input, "expires_at", None),
            "created_by": current_user.id,
            "created_at": datetime.utcnow(),
            "is_active": True
        }

    async def _process_security_event_triggers(self, event: SecurityEvent) -> None:
        """Process automated security responses to events."""
        try:
            # Check for patterns that require immediate action
            if event.severity == SecurityLevel.CRITICAL:
                await self._handle_critical_security_event(event)

            # Check for brute force patterns
            if event.event_type == EventType.LOGIN_FAILED:
                await self._check_brute_force_pattern(event)

            # Check for suspicious activity patterns
            await self._check_suspicious_activity_patterns(event)

        except Exception as e:
            self.logger.exception(f"Security event trigger processing failed: {e!s}")

    async def _process_user_block_triggers(self, user: User, reason: str) -> None:
        """Process automated responses to user blocking."""
        try:
            # Invalidate API keys if user is blocked for security reasons
            if "security" in reason.lower():
                await self.security_service.invalidate_user_api_keys(user.id)

            # Add to temporary blacklist for fraud cases
            if "fraud" in reason.lower():
                await self._add_user_to_temporary_blacklist(user)

        except Exception as e:
            self.logger.exception(f"User block trigger processing failed: {e!s}")

    async def _handle_critical_security_event(self, event: SecurityEvent) -> None:
        """Handle critical security events."""
        # Notify security team immediately
        await self.notification_service.send_critical_security_alert(event)

        # If user-related, consider temporary restrictions
        if event.user_id:
            user = await self.user_repository.find_by_id(event.user_id)
            if user:
                # Add temporary rate limiting
                await self.cache.set(
                    f"security_restriction:{user.id}",
                    True,
                    expire_time=3600  # 1 hour
                )

    async def _check_brute_force_pattern(self, event: SecurityEvent) -> None:
        """Check for brute force attack patterns."""
        if not event.ip_address:
            return

        # Count recent failed login attempts from this IP
        recent_events = await self.security_event_repository.find_recent_by_ip_and_type(
            event.ip_address,
            EventType.LOGIN_FAILED,
            minutes=15
        )

        if len(recent_events) >= 10:  # 10 failed attempts in 15 minutes
            # Add IP to temporary blacklist
            await self._add_ip_to_temporary_blacklist(event.ip_address, "Brute force attack detected")

    async def _check_suspicious_activity_patterns(self, event: SecurityEvent) -> None:
        """Check for suspicious activity patterns."""
        if not event.user_id:
            return

        # Count security events for this user in the last hour
        recent_events = await self.security_event_repository.find_recent_by_user(
            event.user_id,
            hours=1
        )

        if len(recent_events) >= 20:  # 20 security events in 1 hour
            # Create high-priority security event
            await self.security_event_repository.create({
                "id": str(uuid.uuid4()),
                "user_id": event.user_id,
                "event_type": EventType.SUSPICIOUS_ACTIVITY,
                "description": f"Suspicious activity pattern detected: {len(recent_events)} events in 1 hour",
                "severity": SecurityLevel.HIGH,
                "created_at": datetime.utcnow(),
                "is_resolved": False
            })

    async def _add_ip_to_temporary_blacklist(self, ip_address: str, reason: str) -> None:
        """Add IP to temporary blacklist."""
        blacklist_data = {
            "id": str(uuid.uuid4()),
            "blacklist_type": "ip_address",
            "value": ip_address,
            "reason": reason,
            "expires_at": datetime.utcnow() + timedelta(hours=24),  # 24 hour ban
            "created_at": datetime.utcnow(),
            "is_active": True,
            "is_automatic": True
        }

        await self.blacklist_repository.create(blacklist_data)
        await self._invalidate_blacklist_cache()

    async def _add_user_to_temporary_blacklist(self, user: User) -> None:
        """Add user email to temporary blacklist."""
        blacklist_data = {
            "id": str(uuid.uuid4()),
            "blacklist_type": "email",
            "value": user.email,
            "reason": "User blocked for fraud",
            "expires_at": datetime.utcnow() + timedelta(days=7),  # 7 day ban
            "created_at": datetime.utcnow(),
            "is_active": True,
            "is_automatic": True
        }

        await self.blacklist_repository.create(blacklist_data)
        await self._invalidate_blacklist_cache()

    async def _invalidate_all_user_sessions(self, user_id: str) -> None:
        """Invalidate all user sessions."""
        active_sessions = await self.session_repository.find_active_by_user_id(user_id)

        for session in active_sessions:
            session.is_active = False
            session.invalidated_at = datetime.utcnow()
            await self.session_repository.update(session)
            await self.cache.delete(f"session:{session.id}")

        await self.cache.delete(f"user_sessions:{user_id}")

    async def _invalidate_blacklist_cache(self) -> None:
        """Invalidate blacklist cache."""
        cache_keys = [
            "blacklist:all",
            "blacklist:ip",
            "blacklist:email",
            "blacklist:phone"
        ]

        for key in cache_keys:
            await self.cache.delete(key)

    async def _log_security_event(
        self,
        user_id: str,
        event_type: EventType,
        description: str,
        info: Info,
        metadata: dict[str, Any] | None = None
    ) -> None:
        """Log security event."""
        event_data = {
            "id": str(uuid.uuid4()),
            "user_id": user_id,
            "event_type": event_type,
            "description": description,
            "ip_address": info.context.get("ip_address"),
            "user_agent": info.context.get("user_agent"),
            "metadata": metadata,
            "created_at": datetime.utcnow(),
            "is_resolved": False
        }

        await self.security_event_repository.create(event_data)
