"""
Group Member Entity

Represents a member within a group with their role and permissions.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from ...shared.base_entity import ExpirableEntity
from .group_enums import GroupMemberRole, GroupMembershipType


@dataclass
class GroupMember(ExpirableEntity):
    """Entity representing a member within a group."""
    
    id: UUID
    group_id: UUID
    user_id: UUID
    role: GroupMemberRole
    membership_type: GroupMembershipType
    
    # Membership details
    joined_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    invited_by: UUID | None = None
    invitation_id: UUID | None = None
    expires_at: datetime | None = None
    
    # Permissions and flags
    custom_permissions: set[str] = field(default_factory=set)
    denied_permissions: set[str] = field(default_factory=set)
    is_active: bool = True
    can_leave: bool = True
    
    # Activity tracking
    last_activity: datetime | None = None
    activity_count: int = 0
    
    # Metadata
    metadata: dict[str, Any] = field(default_factory=dict)
    
    def _validate_entity(self) -> None:
        """Validate group member business rules - NO EVENT EMISSION."""
        if not self.group_id:
            raise ValueError("Group ID is required")
        
        if not self.user_id:
            raise ValueError("User ID is required")
        
        # Set default metadata
        if "joined_via" not in self.metadata:
            self.metadata["joined_via"] = self.membership_type.value
        
        # ✅ NO EVENT EMISSION - Events are handled by Group aggregate
    
    @classmethod
    def create(
        cls,
        group_id: UUID,
        user_id: UUID,
        role: GroupMemberRole,
        membership_type: GroupMembershipType = GroupMembershipType.DIRECT,
        invited_by: UUID | None = None,
        expires_at: datetime | None = None,
        metadata: dict[str, Any] | None = None
    ) -> 'GroupMember':
        """Create a new group member."""
        return cls(
            id=uuid4(),
            group_id=group_id,
            user_id=user_id,
            role=role,
            membership_type=membership_type,
            joined_at=datetime.now(UTC),
            invited_by=invited_by,
            expires_at=expires_at,
            metadata=metadata or {}
        )
    
    @property
    def is_owner(self) -> bool:
        """Check if member is an owner."""
        return self.role == GroupMemberRole.OWNER
    
    @property
    def is_admin(self) -> bool:
        """Check if member is an admin or higher."""
        return self.role in [GroupMemberRole.OWNER, GroupMemberRole.ADMIN]
    
    @property
    def is_moderator(self) -> bool:
        """Check if member is a moderator or higher."""
        return self.role in [
            GroupMemberRole.OWNER,
            GroupMemberRole.ADMIN,
            GroupMemberRole.MODERATOR
        ]
    
    @property
    def is_expired(self) -> bool:
        """Check if membership has expired."""
        if self.expires_at:
            return datetime.now(UTC) > self.expires_at
        return False
    
    @property
    def is_temporary(self) -> bool:
        """Check if membership is temporary."""
        return self.membership_type == GroupMembershipType.TEMPORARY or self.expires_at is not None
    
    def has_permission(self, permission: str) -> bool:
        """Check if member has specific permission."""
        # Use GroupPermissionService for complex logic
        from .group_permission_service import GroupPermissionService
        
        service = GroupPermissionService()
        return service.member_has_permission(self, permission)
    
    def change_role(self, new_role: GroupMemberRole, changed_by: UUID) -> None:
        """Change member's role - NO EVENT EMISSION."""
        if self.role == new_role:
            return
        
        self.role = new_role
        
        # Update metadata
        self.metadata["role_changed_at"] = datetime.now(UTC).isoformat()
        self.metadata["role_changed_by"] = str(changed_by)
        
        self.touch()
        
        # ✅ NO EVENT EMISSION - Events handled by Group aggregate
    
    def grant_permission(self, permission: str) -> None:
        """Grant a custom permission to the member."""
        self.custom_permissions.add(permission)
        self.denied_permissions.discard(permission)
    
    def revoke_permission(self, permission: str) -> None:
        """Revoke a custom permission from the member."""
        self.custom_permissions.discard(permission)
    
    def deny_permission(self, permission: str) -> None:
        """Explicitly deny a permission to the member."""
        self.denied_permissions.add(permission)
        self.custom_permissions.discard(permission)
    
    def extend_membership(self, new_expiry: datetime) -> None:
        """Extend temporary membership."""
        if not self.is_temporary:
            raise ValueError("Cannot extend non-temporary membership")
        
        if new_expiry <= datetime.now(UTC):
            raise ValueError("New expiry must be in the future")
        
        self.expires_at = new_expiry
        self.metadata["membership_extended_at"] = datetime.now(UTC).isoformat()
    
    def make_permanent(self) -> None:
        """Convert temporary membership to permanent."""
        self.expires_at = None
        self.membership_type = GroupMembershipType.DIRECT
        self.metadata["made_permanent_at"] = datetime.now(UTC).isoformat()
    
    def record_activity(self, activity_type: str = "interaction") -> None:
        """Record member activity."""
        self.last_activity = datetime.now(UTC)
        self.activity_count += 1
        
        # Track recent activities
        if "recent_activities" not in self.metadata:
            self.metadata["recent_activities"] = []
        
        self.metadata["recent_activities"].append({
            "type": activity_type,
            "timestamp": self.last_activity.isoformat()
        })
        
        # Keep only last 10 activities
        if len(self.metadata["recent_activities"]) > 10:
            self.metadata["recent_activities"] = self.metadata["recent_activities"][-10:]
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for persistence."""
        return {
            **super().to_dict(),
            "group_id": str(self.group_id),
            "user_id": str(self.user_id),
            "role": self.role.value,
            "membership_type": self.membership_type.value,
            "joined_at": self.joined_at.isoformat(),
            "invited_by": str(self.invited_by) if self.invited_by else None,
            "invitation_id": str(self.invitation_id) if self.invitation_id else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "custom_permissions": list(self.custom_permissions),
            "denied_permissions": list(self.denied_permissions),
            "is_active": self.is_active,
            "can_leave": self.can_leave,
            "last_activity": self.last_activity.isoformat() if self.last_activity else None,
            "activity_count": self.activity_count,
            "metadata": self.metadata
        }


# Export the entity
__all__ = ['GroupMember']