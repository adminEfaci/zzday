"""
Update password policy command implementation.

Handles updating password security policies for the system or specific users.
"""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from app.core.cqrs import Command, CommandHandler
from app.core.events import EventBus
from app.core.infrastructure import UnitOfWork
from app.modules.identity.application.decorators import (
    audit_action,
    rate_limit,
    require_permission,
    validate_request,
)
from app.modules.identity.application.dtos.request import UpdatePasswordPolicyRequest
from app.modules.identity.application.dtos.response import PasswordPolicyResponse
from app.modules.identity.domain.entities import PasswordPolicy
from app.modules.identity.domain.enums import AuditAction
from app.modules.identity.domain.events import PasswordPolicyUpdated
from app.modules.identity.domain.exceptions import (
    ConflictError,
    NotFoundError,
    ValidationError,
)
from app.modules.identity.domain.interfaces.repositories.user_repository import (
    IUserRepository,
)
from app.modules.identity.domain.interfaces.services.communication.notification_service import (
    INotificationService,
)
from app.modules.identity.domain.interfaces.services.infrastructure.cache_port import (
    ICachePort as ICacheService,
)
from app.modules.identity.domain.services import SecurityService


class UpdatePasswordPolicyCommand(Command[PasswordPolicyResponse]):
    """Command to update password policy."""
    
    def __init__(
        self,
        policy_id: UUID | None = None,
        policy_name: str | None = None,
        min_length: int | None = None,
        max_length: int | None = None,
        require_uppercase: bool | None = None,
        require_lowercase: bool | None = None,
        require_numbers: bool | None = None,
        require_special: bool | None = None,
        min_unique_chars: int | None = None,
        password_history_count: int | None = None,
        password_expiry_days: int | None = None,
        block_common_passwords: bool | None = None,
        block_breached_passwords: bool | None = None,
        block_user_info_in_password: bool | None = None,
        block_repeated_chars: bool | None = None,
        block_sequential_chars: bool | None = None,
        max_consecutive_chars: int | None = None,
        custom_rules: dict[str, Any] | None = None,
        apply_to_users: list[UUID] | None = None,
        apply_to_roles: list[str] | None = None,
        is_default: bool | None = None,
        is_active: bool | None = None,
        updated_by: UUID | None = None,
        reason: str | None = None
    ):
        self.policy_id = policy_id
        self.policy_name = policy_name
        self.min_length = min_length
        self.max_length = max_length
        self.require_uppercase = require_uppercase
        self.require_lowercase = require_lowercase
        self.require_numbers = require_numbers
        self.require_special = require_special
        self.min_unique_chars = min_unique_chars
        self.password_history_count = password_history_count
        self.password_expiry_days = password_expiry_days
        self.block_common_passwords = block_common_passwords
        self.block_breached_passwords = block_breached_passwords
        self.block_user_info_in_password = block_user_info_in_password
        self.block_repeated_chars = block_repeated_chars
        self.block_sequential_chars = block_sequential_chars
        self.max_consecutive_chars = max_consecutive_chars
        self.custom_rules = custom_rules
        self.apply_to_users = apply_to_users
        self.apply_to_roles = apply_to_roles
        self.is_default = is_default
        self.is_active = is_active
        self.updated_by = updated_by
        self.reason = reason


class UpdatePasswordPolicyCommandHandler(CommandHandler[UpdatePasswordPolicyCommand, PasswordPolicyResponse]):
    """Handler for updating password policies."""
    
    def __init__(
        self,
        password_policy_repository: IPasswordPolicyRepository,
        user_repository: IUserRepository,
        security_service: SecurityService,
        notification_service: INotificationService,
        cache_service: ICacheService,
        event_bus: EventBus,
        unit_of_work: UnitOfWork
    ):
        self._password_policy_repository = password_policy_repository
        self._user_repository = user_repository
        self._security_service = security_service
        self._notification_service = notification_service
        self._cache_service = cache_service
        self._event_bus = event_bus
        self._unit_of_work = unit_of_work
    
    @audit_action(
        action=AuditAction.PASSWORD_POLICY_UPDATED,
        resource_type="password_policy",
        include_request=True
    )
    @require_permission(
        permission="security.update_password_policy",
        resource_type="system"
    )
    @validate_request(UpdatePasswordPolicyRequest)
    @rate_limit(
        max_requests=10,
        window_seconds=3600,
        strategy='user'
    )
    async def handle(self, command: UpdatePasswordPolicyCommand) -> PasswordPolicyResponse:
        """
        Update password policy.
        
        Process:
        1. Load existing policy
        2. Validate policy changes
        3. Apply updates
        4. Update user associations
        5. Clear caches
        6. Notify affected users
        7. Publish event
        
        Returns:
            PasswordPolicyResponse with updated policy
            
        Raises:
            NotFoundError: If policy not found
            ValidationError: If invalid policy settings
            ConflictError: If conflicts with other policies
        """
        async with self._unit_of_work:
            # 1. Load existing policy
            if command.policy_id:
                policy = await self._password_policy_repository.find_by_id(command.policy_id)
            elif command.policy_name:
                policy = await self._password_policy_repository.find_by_name(command.policy_name)
            else:
                raise ValidationError("Either policy_id or policy_name must be provided")
            
            if not policy:
                raise NotFoundError("Password policy not found")
            
            # 2. Store old values for comparison
            old_policy_data = self._serialize_policy(policy)
            
            # 3. Validate and apply updates
            self._apply_policy_updates(policy, command)
            
            # 4. Validate policy consistency
            self._validate_policy(policy)
            
            # 5. Check for conflicts
            await self._check_policy_conflicts(policy, command)
            
            # 6. Update policy
            policy.updated_at = datetime.now(UTC)
            policy.updated_by = command.updated_by
            
            await self._password_policy_repository.update(policy)
            
            # 7. Update user associations
            affected_users = []
            if command.apply_to_users:
                affected_users = await self._update_user_associations(
                    policy_id=policy.id,
                    user_ids=command.apply_to_users
                )
            
            # 8. Update role associations
            if command.apply_to_roles:
                await self._update_role_associations(
                    policy_id=policy.id,
                    roles=command.apply_to_roles
                )
            
            # 9. Handle default policy change
            if command.is_default is True:
                await self._set_as_default_policy(policy.id)
            
            # 10. Clear caches
            await self._clear_policy_caches(policy.id)
            
            # 11. Notify affected users
            if affected_users and policy.is_active:
                await self._notify_policy_changes(
                    policy=policy,
                    affected_users=affected_users,
                    changes=self._identify_changes(old_policy_data, policy)
                )
            
            # 12. Log security event
            await self._log_policy_update(
                policy=policy,
                old_data=old_policy_data,
                command=command,
                affected_users_count=len(affected_users)
            )
            
            # 13. Publish event
            await self._event_bus.publish(
                PasswordPolicyUpdated(
                    aggregate_id=policy.id,
                    policy_name=policy.name,
                    changes=self._identify_changes(old_policy_data, policy),
                    affected_users=len(affected_users),
                    updated_by=command.updated_by,
                    reason=command.reason
                )
            )
            
            # 14. Commit transaction
            await self._unit_of_work.commit()
            
            return PasswordPolicyResponse(
                id=policy.id,
                name=policy.name,
                description=policy.description,
                min_length=policy.min_length,
                max_length=policy.max_length,
                require_uppercase=policy.require_uppercase,
                require_lowercase=policy.require_lowercase,
                require_numbers=policy.require_numbers,
                require_special=policy.require_special,
                min_unique_chars=policy.min_unique_chars,
                password_history_count=policy.password_history_count,
                password_expiry_days=policy.password_expiry_days,
                block_common_passwords=policy.block_common_passwords,
                block_breached_passwords=policy.block_breached_passwords,
                block_user_info_in_password=policy.block_user_info_in_password,
                block_repeated_chars=policy.block_repeated_chars,
                block_sequential_chars=policy.block_sequential_chars,
                max_consecutive_chars=policy.max_consecutive_chars,
                custom_rules=policy.custom_rules,
                is_default=policy.is_default,
                is_active=policy.is_active,
                affected_users=len(affected_users),
                created_at=policy.created_at,
                updated_at=policy.updated_at,
                success=True,
                message="Password policy updated successfully"
            )
    
    def _apply_policy_updates(
        self,
        policy: PasswordPolicy,
        command: UpdatePasswordPolicyCommand
    ) -> None:
        """Apply updates to policy."""
        if command.min_length is not None:
            policy.min_length = command.min_length
        
        if command.max_length is not None:
            policy.max_length = command.max_length
        
        if command.require_uppercase is not None:
            policy.require_uppercase = command.require_uppercase
        
        if command.require_lowercase is not None:
            policy.require_lowercase = command.require_lowercase
        
        if command.require_numbers is not None:
            policy.require_numbers = command.require_numbers
        
        if command.require_special is not None:
            policy.require_special = command.require_special
        
        if command.min_unique_chars is not None:
            policy.min_unique_chars = command.min_unique_chars
        
        if command.password_history_count is not None:
            policy.password_history_count = command.password_history_count
        
        if command.password_expiry_days is not None:
            policy.password_expiry_days = command.password_expiry_days
        
        if command.block_common_passwords is not None:
            policy.block_common_passwords = command.block_common_passwords
        
        if command.block_breached_passwords is not None:
            policy.block_breached_passwords = command.block_breached_passwords
        
        if command.block_user_info_in_password is not None:
            policy.block_user_info_in_password = command.block_user_info_in_password
        
        if command.block_repeated_chars is not None:
            policy.block_repeated_chars = command.block_repeated_chars
        
        if command.block_sequential_chars is not None:
            policy.block_sequential_chars = command.block_sequential_chars
        
        if command.max_consecutive_chars is not None:
            policy.max_consecutive_chars = command.max_consecutive_chars
        
        if command.custom_rules is not None:
            policy.custom_rules = command.custom_rules
        
        if command.is_active is not None:
            policy.is_active = command.is_active
    
    def _validate_policy(self, policy: PasswordPolicy) -> None:
        """Validate policy settings."""
        # Validate length requirements
        if policy.min_length < 4:
            raise ValidationError("Minimum password length cannot be less than 4")
        
        if policy.max_length and policy.max_length < policy.min_length:
            raise ValidationError("Maximum length cannot be less than minimum length")
        
        if policy.max_length and policy.max_length > 256:
            raise ValidationError("Maximum length cannot exceed 256 characters")
        
        # Validate unique characters
        if policy.min_unique_chars and policy.min_unique_chars > policy.min_length:
            raise ValidationError(
                "Minimum unique characters cannot exceed minimum length"
            )
        
        # Validate consecutive characters
        if policy.max_consecutive_chars and policy.max_consecutive_chars < 2:
            raise ValidationError(
                "Maximum consecutive characters must be at least 2"
            )
        
        # Validate history count
        if policy.password_history_count and policy.password_history_count > 24:
            raise ValidationError(
                "Password history cannot exceed 24 passwords"
            )
        
        # Validate expiry days
        if policy.password_expiry_days and policy.password_expiry_days < 1:
            raise ValidationError(
                "Password expiry must be at least 1 day"
            )
        
        # Check if policy is too restrictive
        if (policy.min_length > 20 and
            policy.require_uppercase and
            policy.require_lowercase and
            policy.require_numbers and
            policy.require_special and
            policy.min_unique_chars and policy.min_unique_chars > 15):
            raise ValidationError(
                "Policy is too restrictive and may be difficult for users to comply with"
            )
    
    async def _check_policy_conflicts(
        self,
        policy: PasswordPolicy,
        command: UpdatePasswordPolicyCommand
    ) -> None:
        """Check for conflicts with other policies."""
        if command.is_default is True:
            # Check if another default policy exists
            current_default = await self._password_policy_repository.get_default()
            if current_default and current_default.id != policy.id:
                # Will be handled by _set_as_default_policy
                pass
        
        # Check for naming conflicts
        if command.policy_name and command.policy_name != policy.name:
            existing = await self._password_policy_repository.find_by_name(
                command.policy_name
            )
            if existing:
                raise ConflictError(
                    f"Policy with name '{command.policy_name}' already exists"
                )
            policy.name = command.policy_name
    
    async def _update_user_associations(
        self,
        policy_id: UUID,
        user_ids: list[UUID]
    ) -> list[UUID]:
        """Update user policy associations."""
        affected_users = []
        
        for user_id in user_ids:
            user = await self._user_repository.find_by_id(user_id)
            if user:
                await self._password_policy_repository.assign_to_user(
                    policy_id=policy_id,
                    user_id=user_id
                )
                affected_users.append(user_id)
        
        return affected_users
    
    async def _update_role_associations(
        self,
        policy_id: UUID,
        roles: list[str]
    ) -> None:
        """Update role policy associations."""
        for role in roles:
            await self._password_policy_repository.assign_to_role(
                policy_id=policy_id,
                role_name=role
            )
    
    async def _set_as_default_policy(self, policy_id: UUID) -> None:
        """Set policy as default."""
        # Remove default from current default
        current_default = await self._password_policy_repository.get_default()
        if current_default and current_default.id != policy_id:
            current_default.is_default = False
            await self._password_policy_repository.update(current_default)
        
        # This policy is already marked as default in _apply_policy_updates
    
    async def _clear_policy_caches(self, policy_id: UUID) -> None:
        """Clear policy-related caches."""
        cache_keys = [
            f"password_policy:{policy_id}",
            "default_password_policy",
            "user_password_policies:*"
        ]
        
        for key in cache_keys:
            if '*' in key:
                await self._cache_service.delete_pattern(key)
            else:
                await self._cache_service.delete(key)
    
    async def _notify_policy_changes(
        self,
        policy: PasswordPolicy,
        affected_users: list[UUID],
        changes: dict[str, Any]
    ) -> None:
        """Notify users about policy changes."""
        # Create notification content
        significant_changes = []
        
        if 'min_length' in changes:
            significant_changes.append(
                f"Minimum password length changed to {policy.min_length} characters"
            )
        
        if 'password_expiry_days' in changes:
            significant_changes.append(
                f"Passwords must be changed every {policy.password_expiry_days} days"
            )
        
        if 'block_breached_passwords' in changes and policy.block_breached_passwords:
            significant_changes.append(
                "Passwords found in data breaches are now blocked"
            )
        
        if significant_changes:
            for user_id in affected_users[:100]:  # Limit to prevent spam
                await self._notification_service.notify_user(
                    user_id=user_id,
                    title="Password Policy Updated",
                    message="Password requirements have been updated. " +
                           "Your next password change must comply with the new policy.",
                    details=significant_changes,
                    action_url="https://app.example.com/security/password-policy"
                )
    
    def _serialize_policy(self, policy: PasswordPolicy) -> dict[str, Any]:
        """Serialize policy for comparison."""
        return {
            'min_length': policy.min_length,
            'max_length': policy.max_length,
            'require_uppercase': policy.require_uppercase,
            'require_lowercase': policy.require_lowercase,
            'require_numbers': policy.require_numbers,
            'require_special': policy.require_special,
            'min_unique_chars': policy.min_unique_chars,
            'password_history_count': policy.password_history_count,
            'password_expiry_days': policy.password_expiry_days,
            'block_common_passwords': policy.block_common_passwords,
            'block_breached_passwords': policy.block_breached_passwords,
            'block_user_info_in_password': policy.block_user_info_in_password,
            'block_repeated_chars': policy.block_repeated_chars,
            'block_sequential_chars': policy.block_sequential_chars,
            'max_consecutive_chars': policy.max_consecutive_chars,
            'is_default': policy.is_default,
            'is_active': policy.is_active
        }
    
    def _identify_changes(
        self,
        old_data: dict[str, Any],
        policy: PasswordPolicy
    ) -> dict[str, Any]:
        """Identify what changed in the policy."""
        new_data = self._serialize_policy(policy)
        changes = {}
        
        for key, new_value in new_data.items():
            old_value = old_data.get(key)
            if old_value != new_value:
                changes[key] = {
                    'old': old_value,
                    'new': new_value
                }
        
        return changes
    
    async def _log_policy_update(
        self,
        policy: PasswordPolicy,
        old_data: dict[str, Any],
        command: UpdatePasswordPolicyCommand,
        affected_users_count: int
    ) -> None:
        """Log policy update for audit."""
        changes = self._identify_changes(old_data, policy)
        
        await self._security_service.log_security_event(
            user_id=command.updated_by,
            event_type="password_policy_updated",
            details={
                "policy_id": str(policy.id),
                "policy_name": policy.name,
                "changes": list(changes.keys()),
                "affected_users": affected_users_count,
                "reason": command.reason,
                "is_default": policy.is_default,
                "is_active": policy.is_active
            }
        )