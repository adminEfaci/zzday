"""Permission Repository Interface

Domain contract for permission data access that must be implemented by the infrastructure layer.
"""

from typing import TYPE_CHECKING, Protocol
from uuid import UUID

if TYPE_CHECKING:
    from app.modules.identity.domain.entities.role.permission import Permission


class IPermissionRepository(Protocol):
    """Repository interface for permission management."""
    
    async def save(self, permission: 'Permission') -> None:
        """Save permission entity (create or update).
        
        Args:
            permission: Permission entity to save
        """
        ...
    
    async def find_by_id(self, permission_id: UUID) -> 'Permission' | None:
        """Find permission by ID.
        
        Args:
            permission_id: Permission identifier
            
        Returns:
            Permission entity if found, None otherwise
        """
        ...
    
    async def find_by_code(self, code: str) -> 'Permission' | None:
        """Find permission by code.
        
        Args:
            code: Permission code (e.g., 'users.read')
            
        Returns:
            Permission entity if found, None otherwise
        """
        ...
    
    async def find_all(self, include_inactive: bool = False) -> list['Permission']:
        """Find all permissions.
        
        Args:
            include_inactive: Whether to include inactive permissions
            
        Returns:
            List of all permission entities
        """
        ...
    
    async def find_by_resource(self, resource: str) -> list['Permission']:
        """Find permissions for a resource.
        
        Args:
            resource: Resource name
            
        Returns:
            List of permission entities for the resource
        """
        ...
    
    async def find_by_parent(self, parent_id: UUID) -> list['Permission']:
        """Find child permissions of a parent.
        
        Args:
            parent_id: Parent permission identifier
            
        Returns:
            List of child permission entities
        """
        ...
    
    async def find_system_permissions(self) -> list['Permission']:
        """Find all system permissions.
        
        Returns:
            List of system permission entities
        """
        ...
    
    async def delete(self, permission_id: UUID) -> bool:
        """Delete permission.
        
        Args:
            permission_id: Permission identifier
            
        Returns:
            True if deleted, False if not found
        """
        ...
    
    async def exists(self, permission_id: UUID) -> bool:
        """Check if permission exists.
        
        Args:
            permission_id: Permission identifier
            
        Returns:
            True if permission exists
        """
        ...
    
    async def exists_by_code(self, code: str) -> bool:
        """Check if permission exists by code.
        
        Args:
            code: Permission code
            
        Returns:
            True if permission with code exists
        """
        ...