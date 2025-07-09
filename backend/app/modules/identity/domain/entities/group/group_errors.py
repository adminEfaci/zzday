"""
Group Entity Errors

Error classes with rich context for group operations.
"""

from typing import Any
from uuid import UUID

from ...errors import AuthorizationError, BusinessRuleError, IdentityDomainError


class GroupError(IdentityDomainError):
    """Base error for group-related operations with enhanced context."""
    
    def __init__(
        self,
        message: str,
        code: str | None = None,
        user_message: str | None = None,
        details: dict[str, Any] | None = None
    ):
        super().__init__(message)
        self.code = code or "GROUP_ERROR"
        self.user_message = user_message or message
        self.details = details or {}


class GroupNotFoundError(GroupError):
    """Raised when a group cannot be found."""
    
    def __init__(self, group_id: UUID | None = None, group_name: str | None = None):
        if group_id:
            message = f"Group with ID {group_id} not found"
            details = {"group_id": str(group_id)}
        elif group_name:
            message = f"Group '{group_name}' not found"
            details = {"group_name": group_name}
        else:
            message = "Group not found"
            details = {}
            
        super().__init__(
            message=message,
            code="GROUP_NOT_FOUND",
            user_message="The group you're looking for doesn't exist or has been deleted.",
            details=details
        )


class GroupAlreadyExistsError(GroupError):
    """Raised when attempting to create a group that already exists."""
    
    def __init__(self, group_name: str):
        super().__init__(
            message=f"Group '{group_name}' already exists",
            code="GROUP_ALREADY_EXISTS",
            user_message=f"A group with the name '{group_name}' already exists. Please choose a different name.",
            details={"group_name": group_name}
        )


class GroupMembershipError(GroupError):
    """Base error for membership-related issues."""


class UserAlreadyMemberError(GroupMembershipError):
    """Raised when user is already a member of the group."""
    
    def __init__(self, user_id: UUID, group_id: UUID):
        super().__init__(
            message=f"User {user_id} is already a member of group {group_id}",
            code="USER_ALREADY_MEMBER",
            user_message="You are already a member of this group.",
            details={"user_id": str(user_id), "group_id": str(group_id)}
        )


class UserNotMemberError(GroupMembershipError):
    """Raised when user is not a member of the group."""
    
    def __init__(self, user_id: UUID, group_id: UUID):
        super().__init__(
            message=f"User {user_id} is not a member of group {group_id}",
            code="USER_NOT_MEMBER",
            user_message="You are not a member of this group.",
            details={"user_id": str(user_id), "group_id": str(group_id)}
        )


class InsufficientGroupPermissionsError(AuthorizationError):
    """Raised when user lacks required permissions for group operation."""
    
    def __init__(self, required_permission: str, current_role: str | None = None):
        message = f"Insufficient permissions. Required: {required_permission}"
        if current_role:
            message += f" (current role: {current_role})"
            
        super().__init__(message)
        self.code = "INSUFFICIENT_GROUP_PERMISSIONS"
        self.user_message = "You don't have permission to perform this action."
        self.details = {
            "required_permission": required_permission,
            "current_role": current_role
        }


class GroupQuotaExceededError(BusinessRuleError):
    """Raised when group size or resource limits are exceeded."""
    
    def __init__(self, quota_type: str, limit: int, current: int | None = None):
        message = f"Group {quota_type} quota exceeded. Limit: {limit}"
        if current is not None:
            message += f", current: {current}"
            
        user_messages = {
            "members": f"This group has reached its maximum capacity of {limit} members.",
            "owners": f"This group cannot have more than {limit} owners.",
            "subgroups": f"This group cannot have more than {limit} subgroups.",
            "tags": f"This group cannot have more than {limit} tags."
        }
        
        super().__init__(message)
        self.code = f"GROUP_{quota_type.upper()}_QUOTA_EXCEEDED"
        self.user_message = user_messages.get(quota_type, f"Group {quota_type} limit exceeded.")
        self.details = {
            "quota_type": quota_type,
            "limit": limit,
            "current": current
        }


class GroupHierarchyError(BusinessRuleError):
    """Raised when there are issues with group hierarchy."""


class CircularGroupHierarchyError(GroupHierarchyError):
    """Raised when circular reference is detected in group hierarchy."""
    
    def __init__(self, group_chain: list[UUID] | None = None):
        super().__init__(
            message="Circular reference detected in group hierarchy",
            code="CIRCULAR_GROUP_HIERARCHY",
            user_message="This action would create a circular reference in the group hierarchy.",
            details={"group_chain": [str(gid) for gid in group_chain] if group_chain else []}
        )


class MaxNestingDepthExceededError(GroupHierarchyError):
    """Raised when group nesting depth exceeds limit."""
    
    def __init__(self, max_depth: int, attempted_depth: int | None = None):
        message = f"Maximum group nesting depth ({max_depth}) exceeded"
        if attempted_depth:
            message += f". Attempted depth: {attempted_depth}"
            
        super().__init__(
            message=message,
            code="MAX_NESTING_DEPTH_EXCEEDED",
            user_message=f"Groups cannot be nested deeper than {max_depth} levels.",
            details={"max_depth": max_depth, "attempted_depth": attempted_depth}
        )


class GroupOperationError(GroupError):
    """Base error for group operations."""


class GroupInactiveError(GroupOperationError):
    """Raised when operation is attempted on inactive group."""
    
    def __init__(self, group_id: UUID, status: str | None = None):
        message = f"Cannot perform operation on inactive group {group_id}"
        if status:
            message += f" (status: {status})"
            
        super().__init__(
            message=message,
            code="GROUP_INACTIVE",
            user_message="This group is not active and cannot be modified.",
            details={"group_id": str(group_id), "status": status}
        )


class GroupArchivedError(GroupOperationError):
    """Raised when operation is attempted on archived group."""
    
    def __init__(self, group_id: UUID):
        super().__init__(
            message=f"Cannot perform operation on archived group {group_id}",
            code="GROUP_ARCHIVED",
            user_message="This group has been archived and cannot be modified.",
            details={"group_id": str(group_id)}
        )


class GroupInvitationError(GroupError):
    """Base error for invitation-related issues."""


class InvitationNotFoundError(GroupInvitationError):
    """Raised when invitation cannot be found."""
    
    def __init__(self, invitation_id: UUID):
        super().__init__(
            message=f"Invitation {invitation_id} not found",
            code="INVITATION_NOT_FOUND",
            user_message="The invitation you're looking for doesn't exist or has expired.",
            details={"invitation_id": str(invitation_id)}
        )


class InvitationExpiredError(GroupInvitationError):
    """Raised when invitation has expired."""
    
    def __init__(self, invitation_id: UUID, expired_at: str | None = None):
        super().__init__(
            message=f"Invitation {invitation_id} has expired",
            code="INVITATION_EXPIRED",
            user_message="This invitation has expired. Please request a new invitation.",
            details={"invitation_id": str(invitation_id), "expired_at": expired_at}
        )


class MembershipRequestError(GroupError):
    """Base error for membership request issues."""


class MembershipRequestNotFoundError(MembershipRequestError):
    """Raised when membership request cannot be found."""
    
    def __init__(self, request_id: UUID):
        super().__init__(
            message=f"Membership request {request_id} not found",
            code="MEMBERSHIP_REQUEST_NOT_FOUND",
            user_message="The membership request you're looking for doesn't exist.",
            details={"request_id": str(request_id)}
        )


class DuplicateMembershipRequestError(MembershipRequestError):
    """Raised when user already has pending membership request."""
    
    def __init__(self, user_id: UUID, group_id: UUID):
        super().__init__(
            message=f"User {user_id} already has pending request for group {group_id}",
            code="DUPLICATE_MEMBERSHIP_REQUEST",
            user_message="You already have a pending membership request for this group.",
            details={"user_id": str(user_id), "group_id": str(group_id)}
        )


class GroupNameTooLongError(GroupError):
    """Raised when group name exceeds maximum length."""
    
    def __init__(self, max_length: int, actual_length: int | None = None):
        message = f"Group name exceeds maximum length of {max_length} characters"
        if actual_length:
            message += f" (actual: {actual_length})"
            
        super().__init__(
            message=message,
            code="GROUP_NAME_TOO_LONG",
            user_message=f"Group name cannot be longer than {max_length} characters.",
            details={"max_length": max_length, "actual_length": actual_length}
        )


class InvalidGroupSettingsError(GroupError):
    """Raised when group settings are invalid."""
    
    def __init__(self, setting: str, reason: str, value: Any = None):
        super().__init__(
            message=f"Invalid group setting '{setting}': {reason}",
            code="INVALID_GROUP_SETTINGS",
            user_message=f"The {setting} setting is invalid: {reason}",
            details={"setting": setting, "reason": reason, "value": value}
        )


class InvalidGroupTypeError(GroupError):
    """Raised when group type is invalid for operation."""
    
    def __init__(self, group_type: str, operation: str):
        super().__init__(
            message=f"Group type '{group_type}' is invalid for {operation}",
            code="INVALID_GROUP_TYPE",
            user_message=f"This operation is not supported for {group_type} groups.",
            details={"group_type": group_type, "operation": operation}
        )


class InvitationAlreadyUsedError(GroupInvitationError):
    """Raised when invitation has already been used."""
    
    def __init__(self, invitation_id: UUID, used_at: str | None = None):
        super().__init__(
            message=f"Invitation {invitation_id} has already been used",
            code="INVITATION_ALREADY_USED",
            user_message="This invitation has already been used and cannot be used again.",
            details={"invitation_id": str(invitation_id), "used_at": used_at}
        )


# Export all errors
__all__ = [
    'CircularGroupHierarchyError',
    'DuplicateMembershipRequestError',
    'GroupAlreadyExistsError',
    'GroupArchivedError',
    'GroupError',
    'GroupHierarchyError',
    'GroupInactiveError',
    'GroupInvitationError',
    'GroupMembershipError',
    'GroupNameTooLongError',
    'GroupNotFoundError',
    'GroupOperationError',
    'GroupQuotaExceededError',
    'InsufficientGroupPermissionsError',
    'InvalidGroupSettingsError',
    'InvalidGroupTypeError',
    'InvitationAlreadyUsedError',
    'InvitationExpiredError',
    'InvitationNotFoundError',
    'MaxNestingDepthExceededError',
    'MembershipRequestError',
    'MembershipRequestNotFoundError',
    'UserAlreadyMemberError',
    'UserNotMemberError'
]