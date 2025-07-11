"""Role Repository Interface

Domain contract for role data access that must be implemented by the infrastructure layer.
"""

from typing import TYPE_CHECKING, Protocol
from uuid import UUID

if TYPE_CHECKING:
    from app.modules.identity.domain.entities.role.role import Role


class IRoleRepository(Protocol):
    """Repository interface for role management."""
    
    async def save(self, role: 'Role') -> None:
        """Save role entity (create or update).
        
        Args:
            role: Role entity to save
        """
        ...
    
    async def find_by_id(self, role_id: UUID) -> 'Role' | None:
        """Find role by ID.
        
        Args:
            role_id: Role identifier
            
        Returns:
            Role entity if found, None otherwise
        """
        ...
    
    async def find_by_name(self, name: str) -> 'Role' | None:
        """Find role by name.
        
        Args:
            name: Role name
            
        Returns:
            Role entity if found, None otherwise
        """
        ...
    
    async def find_all(self, include_inactive: bool = False) -> list['Role']:
        """Find all roles.
        
        Args:
            include_inactive: Whether to include inactive roles
            
        Returns:
            List of all role entities
        """
        ...
    
    async def find_by_user(self, user_id: UUID) -> list['Role']:
        """Find roles assigned to user.
        
        Args:
            user_id: User identifier
            
        Returns:
            List of user's role entities
        """
        ...
    
    async def assign_to_user(self, role_id: UUID, user_id: UUID) -> bool:
        """Assign role to user.
        
        Args:
            role_id: Role identifier
            user_id: User identifier
            
        Returns:
            True if assigned successfully
        """
        ...
    
    async def unassign_from_user(self, role_id: UUID, user_id: UUID) -> bool:
        """Unassign role from user.
        
        Args:
            role_id: Role identifier
            user_id: User identifier
            
        Returns:
            True if unassigned successfully
        """
        ...
    
    async def add_permission(self, role_id: UUID, permission_id: UUID) -> bool:
        """Add permission to role.
        
        Args:
            role_id: Role identifier
            permission_id: Permission identifier
            
        Returns:
            True if added successfully
        """
        ...
    
    async def remove_permission(self, role_id: UUID, permission_id: UUID) -> bool:
        """Remove permission from role.
        
        Args:
            role_id: Role identifier
            permission_id: Permission identifier
            
        Returns:
            True if removed successfully
        """
        ...
    
    async def exists(self, role_id: UUID) -> bool:
        """Check if role exists.
        
        Args:
            role_id: Role identifier
            
        Returns:
            True if role exists
        """
        ...
    
    async def exists_by_name(self, name: str) -> bool:
        """Check if role exists by name.
        
        Args:
            name: Role name
            
        Returns:
            True if role with name exists
        """
        ...
    
    async def find_system_roles(self) -> list['Role']:
        """Find all system roles.
        
        Returns:
            List of system role entities
        """
        ...
    
    async def find_by_level_range(self, min_level: int, max_level: int) -> list['Role']:
        """Find roles within a level range.
        
        Args:
            min_level: Minimum role level
            max_level: Maximum role level
            
        Returns:
            List of role entities within the range
        """
        ...
    
    async def delete(self, role_id: UUID) -> bool:
        """Delete role.
        
        Args:
            role_id: Role identifier
            
        Returns:
            True if deleted, False if not found
        """
        ...