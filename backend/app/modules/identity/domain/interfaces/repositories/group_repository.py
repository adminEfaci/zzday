"""Group Repository Interface

Domain contract for group data access that must be implemented by the infrastructure layer.
"""

from typing import Protocol
from uuid import UUID

from app.modules.identity.domain.aggregates.group import Group


class IGroupRepository(Protocol):
    """Repository interface for Group aggregate."""
    
    async def find_by_id(self, group_id: UUID) -> Group | None:
        """Find group by ID.
        
        Args:
            group_id: Group identifier
            
        Returns:
            Group aggregate if found, None otherwise
        """
        ...
    
    async def find_by_name(self, name: str) -> Group | None:
        """Find group by name.
        
        Args:
            name: Group name (exact match)
            
        Returns:
            Group aggregate if found, None otherwise
        """
        ...
    
    async def save(self, group: Group) -> None:
        """Save group aggregate with all changes.
        
        Args:
            group: Group aggregate to save
        """
        ...
    
    async def delete(self, group_id: UUID) -> bool:
        """Hard delete group from storage.
        
        Args:
            group_id: Group identifier
            
        Returns:
            True if deleted, False if not found
        """
        ...
    
    async def find_by_user(self, user_id: UUID, include_inactive: bool = False) -> list[Group]:
        """Find all groups a user belongs to.
        
        Args:
            user_id: User identifier
            include_inactive: Include archived/inactive groups
            
        Returns:
            List of groups the user is a member of
        """
        ...
    
    async def find_subgroups(self, parent_group_id: UUID) -> list[Group]:
        """Find all direct subgroups of a parent group.
        
        Args:
            parent_group_id: Parent group identifier
            
        Returns:
            List of subgroups
        """
        ...
    
    async def find_by_type(self, group_type: str, limit: int = 100) -> list[Group]:
        """Find groups by type.
        
        Args:
            group_type: Group type to filter by
            limit: Maximum number of results
            
        Returns:
            List of groups of the specified type
        """
        ...
    
    async def search(
        self, 
        query: str,
        filters: dict | None = None,
        limit: int = 20,
        offset: int = 0
    ) -> tuple[list[Group], int]:
        """Search groups with filters.
        
        Args:
            query: Search query for name/description
            filters: Additional filters (type, visibility, etc.)
            limit: Maximum number of results
            offset: Number of results to skip
            
        Returns:
            Tuple of (groups, total_count)
        """
        ...
    
    async def count_by_status(self, status: str) -> int:
        """Count groups by status.
        
        Args:
            status: Group status to count
            
        Returns:
            Number of groups with the status
        """
        ...
    
    async def find_public_groups(self, limit: int = 50) -> list[Group]:
        """Find all public groups.
        
        Args:
            limit: Maximum number of results
            
        Returns:
            List of public groups
        """
        ...
    
    async def exists(self, group_id: UUID) -> bool:
        """Check if group exists.
        
        Args:
            group_id: Group identifier
            
        Returns:
            True if group exists
        """
        ...
    
    async def exists_by_name(self, name: str) -> bool:
        """Check if group exists by name.
        
        Args:
            name: Group name
            
        Returns:
            True if group with name exists
        """
        ...