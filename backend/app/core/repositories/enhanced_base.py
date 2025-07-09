"""
Enhanced Repository Base Class for All Modules

This base class provides consistent interface and performance optimizations
for all repository implementations across the application.
"""

from abc import ABC, abstractmethod
from typing import Generic, TypeVar, List, Optional, Dict, Any
from uuid import UUID

from app.core.domain.base import Entity
from app.core.domain.specification import Specification
from app.core.infrastructure.repository import BaseRepository
from typing import List, Optional, Dict, Any

TEntity = TypeVar("TEntity", bound=Entity)
TId = TypeVar("TId")


class EnhancedRepositoryBase(BaseRepository[TEntity, TId], ABC):
    """Enhanced base repository with consistent interface."""
    
    @abstractmethod
    async def find_by_id(self, id: TId) -> Optional[TEntity]:
        """Find entity by ID."""
        pass
    
    @abstractmethod
    async def save(self, entity: TEntity) -> TEntity:
        """Save entity."""
        pass
    
    @abstractmethod
    async def delete(self, id: TId) -> bool:
        """Delete entity by ID."""
        pass
    
    @abstractmethod
    async def find_many(
        self,
        specification: Optional[Specification] = None,
        offset: int = 0,
        limit: int = 100,
        order_by: Optional[str] = None
    ) -> List[TEntity]:
        """Find entities matching specification."""
        pass
    
    @abstractmethod
    async def count(self, specification: Optional[Specification] = None) -> int:
        """Count entities matching specification."""
        pass
    
    async def exists(self, id: TId) -> bool:
        """Check if entity exists."""
        entity = await self.find_by_id(id)
        return entity is not None
    
    async def find_all(self, limit: int = 1000) -> List[TEntity]:
        """Find all entities."""
        return await self.find_many(limit=limit)
    
    async def create(self, entity: TEntity) -> TEntity:
        """Create new entity."""
        return await self.save(entity)
    
    async def update(self, entity: TEntity) -> TEntity:
        """Update existing entity."""
        return await self.save(entity)
    
    async def delete_many(self, ids: List[TId]) -> int:
        """Delete multiple entities."""
        deleted_count = 0
        for id in ids:
            if await self.delete(id):
                deleted_count += 1
        return deleted_count
