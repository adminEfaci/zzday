"""
Role Repository Implementation

SQLModel-based implementation of the role repository interface.
"""

from datetime import UTC, datetime
from uuid import UUID

from sqlmodel import Session, and_, func, select

from app.core.infrastructure.repository import BaseRepository
from app.modules.identity.domain.entities.role.role import Role
from app.modules.identity.domain.interfaces.repositories.role_repository import (
    IRoleRepository,
)
from app.modules.identity.infrastructure.models.role_model import (
    RoleModel,
    RolePermissionAssociation,
    RoleUserAssociation,
)


class SQLRoleRepository(BaseRepository[Role, RoleModel], IRoleRepository):
    """SQLModel implementation of role repository."""
    
    def __init__(self, session: Session):
        super().__init__(session, RoleModel)
    
    async def create(
        self, 
        name: str,
        description: str,
        permissions: list[UUID] | None = None
    ) -> UUID:
        """Create new role."""
        # Create role entity
        role = Role.create(
            name=name,
            description=description,
            level=10,  # Default level for new roles
            permissions=[],  # Will add permissions separately
            is_system=False
        )
        
        # Create model
        model = RoleModel.from_domain(role)
        self.session.add(model)
        
        # Add permissions if provided
        if permissions:
            for permission_id in permissions:
                association = RolePermissionAssociation(
                    role_id=role.id,
                    permission_id=permission_id
                )
                self.session.add(association)
        
        await self.session.commit()
        return role.id
    
    async def find_by_id(self, role_id: UUID) -> Role | None:
        """Find role by ID."""
        stmt = select(RoleModel).where(RoleModel.id == role_id)
        result = await self.session.exec(stmt)
        model = result.first()
        
        if not model:
            return None
        
        return model.to_domain()
    
    async def find_by_name(self, name: str) -> Role | None:
        """Find role by name."""
        stmt = select(RoleModel).where(RoleModel.name == name)
        result = await self.session.exec(stmt)
        model = result.first()
        
        if not model:
            return None
        
        return model.to_domain()
    
    async def find_all(self) -> list[Role]:
        """Find all roles."""
        stmt = select(RoleModel).order_by(RoleModel.level.desc(), RoleModel.name)
        result = await self.session.exec(stmt)
        models = result.all()
        
        return [model.to_domain() for model in models]
    
    async def find_by_user(self, user_id: UUID) -> list[Role]:
        """Find roles assigned to user."""
        # Get role associations for user
        assoc_stmt = select(RoleUserAssociation).where(
            RoleUserAssociation.user_id == user_id
        )
        assoc_result = await self.session.exec(assoc_stmt)
        associations = assoc_result.all()
        
        if not associations:
            return []
        
        # Get roles
        role_ids = [assoc.role_id for assoc in associations]
        role_stmt = select(RoleModel).where(
            RoleModel.id.in_(role_ids)
        ).order_by(RoleModel.level.desc(), RoleModel.name)
        role_result = await self.session.exec(role_stmt)
        models = role_result.all()
        
        return [model.to_domain() for model in models]
    
    async def assign_to_user(self, role_id: UUID, user_id: UUID) -> bool:
        """Assign role to user."""
        # Check if role exists
        role = await self.session.get(RoleModel, role_id)
        if not role:
            return False
        
        # Check if assignment already exists
        existing_stmt = select(RoleUserAssociation).where(
            and_(
                RoleUserAssociation.role_id == role_id,
                RoleUserAssociation.user_id == user_id
            )
        )
        existing_result = await self.session.exec(existing_stmt)
        if existing_result.first():
            return True  # Already assigned
        
        # Create assignment
        association = RoleUserAssociation(
            role_id=role_id,
            user_id=user_id
        )
        self.session.add(association)
        await self.session.commit()
        
        return True
    
    async def unassign_from_user(self, role_id: UUID, user_id: UUID) -> bool:
        """Unassign role from user."""
        stmt = select(RoleUserAssociation).where(
            and_(
                RoleUserAssociation.role_id == role_id,
                RoleUserAssociation.user_id == user_id
            )
        )
        result = await self.session.exec(stmt)
        association = result.first()
        
        if not association:
            return False
        
        await self.session.delete(association)
        await self.session.commit()
        
        return True
    
    async def add_permission(self, role_id: UUID, permission_id: UUID) -> bool:
        """Add permission to role."""
        # Check if role exists
        role = await self.session.get(RoleModel, role_id)
        if not role:
            return False
        
        # Check if permission already assigned
        existing_stmt = select(RolePermissionAssociation).where(
            and_(
                RolePermissionAssociation.role_id == role_id,
                RolePermissionAssociation.permission_id == permission_id
            )
        )
        existing_result = await self.session.exec(existing_stmt)
        if existing_result.first():
            return True  # Already assigned
        
        # Create assignment
        association = RolePermissionAssociation(
            role_id=role_id,
            permission_id=permission_id
        )
        self.session.add(association)
        await self.session.commit()
        
        return True
    
    async def remove_permission(self, role_id: UUID, permission_id: UUID) -> bool:
        """Remove permission from role."""
        stmt = select(RolePermissionAssociation).where(
            and_(
                RolePermissionAssociation.role_id == role_id,
                RolePermissionAssociation.permission_id == permission_id
            )
        )
        result = await self.session.exec(stmt)
        association = result.first()
        
        if not association:
            return False
        
        await self.session.delete(association)
        await self.session.commit()
        
        return True
    
    async def get_role_permissions(self, role_id: UUID) -> list[UUID]:
        """Get all permissions for role."""
        stmt = select(RolePermissionAssociation).where(
            RolePermissionAssociation.role_id == role_id
        )
        result = await self.session.exec(stmt)
        associations = result.all()
        
        return [assoc.permission_id for assoc in associations]
    
    async def update(
        self, 
        role_id: UUID,
        name: str | None = None,
        description: str | None = None
    ) -> bool:
        """Update role."""
        model = await self.session.get(RoleModel, role_id)
        if not model:
            return False
        
        # Update fields
        if name is not None:
            model.name = name
        if description is not None:
            model.description = description
        
        model.updated_at = datetime.now(UTC)
        
        self.session.add(model)
        await self.session.commit()
        
        return True
    
    async def delete(self, role_id: UUID) -> bool:
        """Delete role."""
        model = await self.session.get(RoleModel, role_id)
        if not model:
            return False
        
        # Delete all associations first
        # Delete user associations
        user_assoc_stmt = select(RoleUserAssociation).where(
            RoleUserAssociation.role_id == role_id
        )
        user_assoc_result = await self.session.exec(user_assoc_stmt)
        for assoc in user_assoc_result.all():
            await self.session.delete(assoc)
        
        # Delete permission associations
        perm_assoc_stmt = select(RolePermissionAssociation).where(
            RolePermissionAssociation.role_id == role_id
        )
        perm_assoc_result = await self.session.exec(perm_assoc_stmt)
        for assoc in perm_assoc_result.all():
            await self.session.delete(assoc)
        
        # Delete role
        await self.session.delete(model)
        await self.session.commit()
        
        return True
    
    async def save(self, role: Role) -> None:
        """Save role aggregate."""
        model = RoleModel.from_domain(role)
        
        # Check if role exists
        existing = await self.session.get(RoleModel, role.id)
        if existing:
            # Update existing model
            for key, value in model.dict(exclude={'id'}).items():
                setattr(existing, key, value)
            self.session.add(existing)
        else:
            # Add new model
            self.session.add(model)
        
        await self.session.commit()
    
    async def find_active_roles(self, limit: int = 100) -> list[Role]:
        """Find active roles."""
        stmt = select(RoleModel).where(
            RoleModel.is_active == True
        ).order_by(RoleModel.level.desc(), RoleModel.name).limit(limit)
        
        result = await self.session.exec(stmt)
        models = result.all()
        
        return [model.to_domain() for model in models]
    
    async def find_system_roles(self) -> list[Role]:
        """Find system roles."""
        stmt = select(RoleModel).where(
            RoleModel.is_system == True
        ).order_by(RoleModel.level.desc())
        
        result = await self.session.exec(stmt)
        models = result.all()
        
        return [model.to_domain() for model in models]
    
    async def find_by_level_range(self, min_level: int, max_level: int) -> list[Role]:
        """Find roles within a level range."""
        stmt = select(RoleModel).where(
            and_(
                RoleModel.level >= min_level,
                RoleModel.level <= max_level
            )
        ).order_by(RoleModel.level.desc(), RoleModel.name)
        
        result = await self.session.exec(stmt)
        models = result.all()
        
        return [model.to_domain() for model in models]
    
    async def count_by_user(self, user_id: UUID) -> int:
        """Count roles assigned to user."""
        stmt = select(func.count(RoleUserAssociation.role_id)).where(
            RoleUserAssociation.user_id == user_id
        )
        result = await self.session.exec(stmt)
        return result.first() or 0
    
    async def exists_by_name(self, name: str) -> bool:
        """Check if role exists by name."""
        stmt = select(func.count(RoleModel.id)).where(RoleModel.name == name)
        result = await self.session.exec(stmt)
        return result.first() > 0