"""
Group Repository Implementation

SQLModel-based implementation of the group repository interface.
"""

from datetime import datetime, UTC
from typing import Any
from uuid import UUID

from sqlmodel import Session, select, and_, or_, col, func
from app.core.infrastructure.repository import SQLRepository
from app.modules.identity.domain.aggregates.group import Group, GroupMember, GroupName
from app.modules.identity.domain.interfaces.repositories.group_repository import IGroupRepository
from app.modules.identity.infrastructure.models.group_model import GroupModel, GroupMemberModel
from app.modules.identity.domain.specifications.base import Specification
from app.modules.identity.domain.aggregates.group import (
    GroupStatus, GroupType, GroupVisibility, GroupJoinMethod,
    GroupMemberRole, GroupMembershipType
)


class SQLGroupRepository(SQLRepository[Group, GroupModel], IGroupRepository):
    """SQLModel implementation of group repository."""
    
    def __init__(self, session: Session):
        super().__init__(session, GroupModel)
    
    async def find_by_id(self, group_id: UUID) -> Group | None:
        """Find group by ID."""
        stmt = select(GroupModel).where(GroupModel.id == group_id)
        result = await self.session.exec(stmt)
        model = result.first()
        
        if not model:
            return None
        
        # Load members
        members = await self._load_members(group_id)
        return self._to_domain(model, members)
    
    async def find_by_name(self, name: str) -> Group | None:
        """Find group by name."""
        stmt = select(GroupModel).where(GroupModel.name == name)
        result = await self.session.exec(stmt)
        model = result.first()
        
        if not model:
            return None
        
        # Load members
        members = await self._load_members(model.id)
        return self._to_domain(model, members)
    
    async def find_by_parent(self, parent_id: UUID, include_inactive: bool = False) -> list[Group]:
        """Find groups by parent ID."""
        stmt = select(GroupModel).where(GroupModel.parent_group_id == parent_id)
        
        if not include_inactive:
            stmt = stmt.where(GroupModel.status == GroupStatus.ACTIVE.value)
        
        result = await self.session.exec(stmt)
        models = result.all()
        
        groups = []
        for model in models:
            members = await self._load_members(model.id)
            groups.append(self._to_domain(model, members))
        
        return groups
    
    async def find_by_member(self, user_id: UUID, include_inactive: bool = False) -> list[Group]:
        """Find groups where user is a member."""
        # First find group IDs where user is a member
        member_stmt = select(GroupMemberModel.group_id).where(
            GroupMemberModel.user_id == user_id
        )
        
        if not include_inactive:
            member_stmt = member_stmt.where(GroupMemberModel.is_active == True)
        
        member_result = await self.session.exec(member_stmt)
        group_ids = member_result.all()
        
        if not group_ids:
            return []
        
        # Then fetch the groups
        stmt = select(GroupModel).where(GroupModel.id.in_(group_ids))
        
        if not include_inactive:
            stmt = stmt.where(GroupModel.status == GroupStatus.ACTIVE.value)
        
        result = await self.session.exec(stmt)
        models = result.all()
        
        groups = []
        for model in models:
            members = await self._load_members(model.id)
            groups.append(self._to_domain(model, members))
        
        return groups
    
    async def find_by_owner(self, owner_id: UUID) -> list[Group]:
        """Find groups owned by user."""
        # Find groups where user is in owner_ids
        stmt = select(GroupModel).where(
            GroupModel.owner_ids.op('@>')([str(owner_id)])
        )
        
        result = await self.session.exec(stmt)
        models = result.all()
        
        groups = []
        for model in models:
            members = await self._load_members(model.id)
            groups.append(self._to_domain(model, members))
        
        return groups
    
    async def exists_by_name(self, name: str) -> bool:
        """Check if group exists by name."""
        stmt = select(func.count(GroupModel.id)).where(GroupModel.name == name)
        result = await self.session.exec(stmt)
        return result.first() > 0
    
    async def save(self, group: Group) -> None:
        """Save group aggregate."""
        # Save group model
        model = self._from_domain(group)
        
        existing = await self.session.get(GroupModel, group.id)
        if existing:
            for key, value in model.dict(exclude={'id'}).items():
                setattr(existing, key, value)
            self.session.add(existing)
        else:
            self.session.add(model)
        
        # Save members
        await self._save_members(group)
        
        await self.session.commit()
    
    async def delete(self, group_id: UUID) -> None:
        """Delete group by ID."""
        # Delete members first
        member_stmt = select(GroupMemberModel).where(GroupMemberModel.group_id == group_id)
        member_result = await self.session.exec(member_stmt)
        members = member_result.all()
        
        for member in members:
            await self.session.delete(member)
        
        # Delete group
        model = await self.session.get(GroupModel, group_id)
        if model:
            await self.session.delete(model)
        
        await self.session.commit()
    
    async def find_many(
        self,
        specification: Specification | None = None,
        offset: int = 0,
        limit: int = 100,
        order_by: str | None = None
    ) -> list[Group]:
        """Find groups matching specification."""
        stmt = select(GroupModel)
        
        # Apply specification if provided
        if specification:
            conditions = self._build_conditions(specification)
            if conditions:
                stmt = stmt.where(and_(*conditions))
        
        # Apply ordering
        if order_by:
            if order_by.startswith('-'):
                stmt = stmt.order_by(col(GroupModel.__table__.c[order_by[1:]]).desc())
            else:
                stmt = stmt.order_by(col(GroupModel.__table__.c[order_by]))
        else:
            stmt = stmt.order_by(GroupModel.created_at.desc())
        
        # Apply pagination
        stmt = stmt.offset(offset).limit(limit)
        
        result = await self.session.exec(stmt)
        models = result.all()
        
        groups = []
        for model in models:
            members = await self._load_members(model.id)
            groups.append(self._to_domain(model, members))
        
        return groups
    
    async def count(self, specification: Specification | None = None) -> int:
        """Count groups matching specification."""
        stmt = select(func.count(GroupModel.id))
        
        if specification:
            conditions = self._build_conditions(specification)
            if conditions:
                stmt = stmt.where(and_(*conditions))
        
        result = await self.session.exec(stmt)
        return result.first() or 0
    
    async def search(self, query: str, limit: int = 100) -> list[Group]:
        """Search groups by name or description."""
        search_term = f"%{query.lower()}%"
        
        stmt = select(GroupModel).where(
            or_(
                col(GroupModel.name).ilike(search_term),
                col(GroupModel.description).ilike(search_term)
            )
        ).limit(limit)
        
        result = await self.session.exec(stmt)
        models = result.all()
        
        groups = []
        for model in models:
            members = await self._load_members(model.id)
            groups.append(self._to_domain(model, members))
        
        return groups
    
    async def update_member_count(self, group_id: UUID) -> None:
        """Update group member count."""
        # Count active members
        stmt = select(func.count(GroupMemberModel.id)).where(
            and_(
                GroupMemberModel.group_id == group_id,
                GroupMemberModel.is_active == True
            )
        )
        result = await self.session.exec(stmt)
        member_count = result.first() or 0
        
        # Count owners
        owner_stmt = select(func.count(GroupMemberModel.id)).where(
            and_(
                GroupMemberModel.group_id == group_id,
                GroupMemberModel.role == GroupMemberRole.OWNER.value,
                GroupMemberModel.is_active == True
            )
        )
        owner_result = await self.session.exec(owner_stmt)
        owner_count = owner_result.first() or 0
        
        # Update group
        model = await self.session.get(GroupModel, group_id)
        if model:
            model.member_count = member_count
            model.owner_count = owner_count
            model.updated_at = datetime.now(UTC)
            self.session.add(model)
            await self.session.commit()
    
    async def _load_members(self, group_id: UUID) -> list[GroupMember]:
        """Load group members."""
        stmt = select(GroupMemberModel).where(
            and_(
                GroupMemberModel.group_id == group_id,
                GroupMemberModel.is_active == True
            )
        )
        
        result = await self.session.exec(stmt)
        models = result.all()
        
        members = []
        for model in models:
            member = GroupMember(
                id=model.id,
                group_id=model.group_id,
                user_id=model.user_id,
                role=GroupMemberRole(model.role),
                membership_type=GroupMembershipType(model.membership_type),
                joined_at=model.joined_at,
                invited_by=model.invited_by,
                expires_at=model.expires_at,
                is_active=model.is_active,
                permissions=set(model.permissions) if model.permissions else set(),
                metadata=model.metadata or {}
            )
            members.append(member)
        
        return members
    
    async def _save_members(self, group: Group) -> None:
        """Save group members."""
        # Get existing members
        stmt = select(GroupMemberModel).where(GroupMemberModel.group_id == group.id)
        result = await self.session.exec(stmt)
        existing_models = {m.user_id: m for m in result.all()}
        
        # Update or create members
        current_member_ids = set()
        for member in group._members.values():
            current_member_ids.add(member.user_id)
            
            if member.user_id in existing_models:
                # Update existing
                model = existing_models[member.user_id]
                model.role = member.role.value
                model.membership_type = member.membership_type.value
                model.is_active = member.is_active
                model.expires_at = member.expires_at
                model.permissions = list(member.permissions) if hasattr(member, 'permissions') else []
                model.metadata = member.metadata if hasattr(member, 'metadata') else {}
                model.updated_at = datetime.now(UTC)
                self.session.add(model)
            else:
                # Create new
                model = GroupMemberModel(
                    id=member.id,
                    group_id=member.group_id,
                    user_id=member.user_id,
                    role=member.role.value,
                    membership_type=member.membership_type.value,
                    joined_at=member.joined_at,
                    invited_by=member.invited_by,
                    expires_at=member.expires_at,
                    is_active=member.is_active,
                    permissions=list(member.permissions) if hasattr(member, 'permissions') else [],
                    metadata=member.metadata if hasattr(member, 'metadata') else {}
                )
                self.session.add(model)
        
        # Mark removed members as inactive
        for user_id, model in existing_models.items():
            if user_id not in current_member_ids:
                model.is_active = False
                model.updated_at = datetime.now(UTC)
                self.session.add(model)
    
    def _from_domain(self, group: Group) -> GroupModel:
        """Convert domain entity to persistence model."""
        return GroupModel(
            id=group.id,
            name=group.name.value if isinstance(group.name, GroupName) else group.name,
            description=group.description,
            group_type=group.group_type.value if isinstance(group.group_type, GroupType) else group.group_type,
            status=group.status.value if isinstance(group.status, GroupStatus) else group.status,
            visibility=group.visibility.value if isinstance(group.visibility, GroupVisibility) else group.visibility,
            join_method=group.join_method.value if isinstance(group.join_method, GroupJoinMethod) else group.join_method,
            parent_group_id=group.parent_group_id,
            nesting_level=group.nesting_level,
            max_members=group.max_members,
            allow_nested_groups=group.allow_nested_groups,
            allow_guest_members=group.allow_guest_members,
            require_approval=group.require_approval,
            owner_ids=[str(owner_id) for owner_id in group._owner_ids],
            created_by=group.created_by,
            created_at=group.created_at,
            updated_at=group.updated_at,
            archived_at=group.archived_at,
            deleted_at=group.deleted_at,
            member_count=len(group._members),
            owner_count=len(group._owner_ids)
        )
    
    def _to_domain(self, model: GroupModel, members: list[GroupMember]) -> Group:
        """Convert persistence model to domain entity."""
        # Create group instance
        group = Group(
            id=model.id,
            name=GroupName(model.name),
            description=model.description,
            group_type=GroupType(model.group_type),
            status=GroupStatus(model.status),
            visibility=GroupVisibility(model.visibility),
            join_method=GroupJoinMethod(model.join_method),
            created_at=model.created_at,
            created_by=model.created_by,
            updated_at=model.updated_at,
            parent_group_id=model.parent_group_id,
            nesting_level=model.nesting_level,
            max_members=model.max_members,
            allow_nested_groups=model.allow_nested_groups,
            allow_guest_members=model.allow_guest_members,
            require_approval=model.require_approval,
            archived_at=model.archived_at,
            deleted_at=model.deleted_at
        )
        
        # Restore internal state
        group._owner_ids = set(UUID(owner_id) for owner_id in model.owner_ids)
        group._members = {member.user_id: member for member in members}
        
        return group
    
    def _build_conditions(self, specification: Specification) -> list[Any]:
        """Build SQLModel conditions from specification."""
        conditions = []
        
        # This would be customized based on the specific GroupSpecification
        # For now, return empty list
        return conditions