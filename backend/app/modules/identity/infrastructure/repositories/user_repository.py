"""
User Repository Implementation

SQLModel-based implementation of the user repository interface.
"""

from typing import Any
from uuid import UUID

from sqlmodel import Session, and_, col, func, or_, select

from app.core.infrastructure.repository import SQLRepository
from app.modules.identity.domain.aggregates.user import User
from app.modules.identity.domain.interfaces.repositories.user_repository import (
    IUserRepository,
)
from app.modules.identity.domain.specifications.user_specs import UserSpecification
from app.modules.identity.infrastructure.models.user_model import UserModel


class SQLUserRepository(BaseRepository[User, UserModel], IUserRepository):
    """SQLModel implementation of user repository."""
    
    def __init__(self, session: Session):
        super().__init__(session, UserModel)
    
    async def find_by_id(self, user_id: UUID) -> User | None:
        """Find user by ID."""
        stmt = select(UserModel).where(UserModel.id == user_id)
        result = await self.session.exec(stmt)
        model = result.first()
        return model.to_domain() if model else None
    
    async def find_by_email(self, email: str) -> User | None:
        """Find user by email address."""
        stmt = select(UserModel).where(UserModel.email == email.lower())
        result = await self.session.exec(stmt)
        model = result.first()
        return model.to_domain() if model else None
    
    async def find_by_username(self, username: str) -> User | None:
        """Find user by username."""
        stmt = select(UserModel).where(UserModel.username == username.lower())
        result = await self.session.exec(stmt)
        model = result.first()
        return model.to_domain() if model else None
    
    async def find_by_phone(self, phone_number: str) -> User | None:
        """Find user by phone number."""
        stmt = select(UserModel).where(UserModel.phone_number == phone_number)
        result = await self.session.exec(stmt)
        model = result.first()
        return model.to_domain() if model else None
    
    async def find_by_external_id(self, provider: str, external_id: str) -> User | None:
        """Find user by external provider ID."""
        stmt = select(UserModel).where(
            UserModel.external_ids.op('?')({provider: external_id})
        )
        result = await self.session.exec(stmt)
        model = result.first()
        return model.to_domain() if model else None
    
    async def exists_by_email(self, email: str) -> bool:
        """Check if user exists by email."""
        stmt = select(func.count(UserModel.id)).where(UserModel.email == email.lower())
        result = await self.session.exec(stmt)
        return result.first() > 0
    
    async def exists_by_username(self, username: str) -> bool:
        """Check if user exists by username."""
        stmt = select(func.count(UserModel.id)).where(UserModel.username == username.lower())
        result = await self.session.exec(stmt)
        return result.first() > 0
    
    async def exists_by_phone(self, phone_number: str) -> bool:
        """Check if user exists by phone."""
        stmt = select(func.count(UserModel.id)).where(UserModel.phone_number == phone_number)
        result = await self.session.exec(stmt)
        return result.first() > 0
    
    async def save(self, user: User) -> None:
        """Save user aggregate."""
        model = UserModel.from_domain(user)
        
        # Check if user exists
        existing = await self.session.get(UserModel, user.id)
        if existing:
            # Update existing model
            for key, value in model.dict(exclude={'id'}).items():
                setattr(existing, key, value)
            self.session.add(existing)
        else:
            # Add new model
            self.session.add(model)
        
        await self.session.commit()
    
    async def delete(self, user_id: UUID) -> bool:
        """Delete user by ID."""
        model = await self.session.get(UserModel, user_id)
        if model:
            await self.session.delete(model)
            await self.session.commit()
            return True
        return False
    
    async def find_many(
        self,
        specification: UserSpecification | None = None,
        offset: int = 0,
        limit: int = 100,
        order_by: str | None = None
    ) -> list[User]:
        """Find users matching specification."""
        stmt = select(UserModel)
        
        # Apply specification if provided
        if specification:
            conditions = self._build_conditions(specification)
            if conditions:
                stmt = stmt.where(and_(*conditions))
        
        # Apply ordering
        if order_by:
            if order_by.startswith('-'):
                stmt = stmt.order_by(col(UserModel.__table__.c[order_by[1:]]).desc())
            else:
                stmt = stmt.order_by(col(UserModel.__table__.c[order_by]))
        else:
            stmt = stmt.order_by(UserModel.created_at.desc())
        
        # Apply pagination
        stmt = stmt.offset(offset).limit(limit)
        
        result = await self.session.exec(stmt)
        models = result.all()
        return [model.to_domain() for model in models]
    
    async def count(self, specification: UserSpecification | None = None) -> int:
        """Count users matching specification."""
        stmt = select(func.count(UserModel.id))
        
        if specification:
            conditions = self._build_conditions(specification)
            if conditions:
                stmt = stmt.where(and_(*conditions))
        
        result = await self.session.exec(stmt)
        return result.first() or 0
    
    async def find_active_users(self, limit: int = 100) -> list[User]:
        """Find active users."""
        stmt = select(UserModel).where(
            UserModel.is_active == True
        ).limit(limit)
        
        result = await self.session.exec(stmt)
        models = result.all()
        return [model.to_domain() for model in models]
    
    async def find_by_role(self, role_id: UUID) -> list[User]:
        """Find users with specific role."""
        stmt = select(UserModel).where(
            UserModel.role_ids.op('@>')([str(role_id)])
        )
        
        result = await self.session.exec(stmt)
        models = result.all()
        return [model.to_domain() for model in models]
    
    async def search(
        self,
        query: str,
        fields: list[str] | None = None,
        limit: int = 100
    ) -> list[User]:
        """Search users by query."""
        if not fields:
            fields = ['email', 'username', 'full_name']
        
        # Build search conditions
        conditions = []
        search_term = f"%{query.lower()}%"
        
        for field in fields:
            if hasattr(UserModel, field):
                conditions.append(col(UserModel.__table__.c[field]).ilike(search_term))
        
        if not conditions:
            return []
        
        stmt = select(UserModel).where(or_(*conditions)).limit(limit)
        result = await self.session.exec(stmt)
        models = result.all()
        return [model.to_domain() for model in models]
    
    async def bulk_save(self, users: list[User]) -> None:
        """Save multiple users in a single transaction."""
        models = [UserModel.from_domain(user) for user in users]
        
        for model in models:
            existing = await self.session.get(UserModel, model.id)
            if existing:
                for key, value in model.dict(exclude={'id'}).items():
                    setattr(existing, key, value)
                self.session.add(existing)
            else:
                self.session.add(model)
        
        await self.session.commit()
    
    async def update_last_login(self, user_id: UUID, ip_address: str | None = None) -> None:
        """Update user's last login timestamp."""
        from datetime import UTC, datetime
        
        stmt = select(UserModel).where(UserModel.id == user_id)
        result = await self.session.exec(stmt)
        model = result.first()
        
        if model:
            model.last_login_at = datetime.now(UTC)
            if ip_address:
                model.last_login_ip = ip_address
            self.session.add(model)
            await self.session.commit()
    
    def _build_conditions(self, specification: UserSpecification) -> list[Any]:
        """Build SQLModel conditions from specification."""
        conditions = []
        
        # Map specification criteria to database conditions
        criteria = specification.to_dict()
        
        if criteria.get('email'):
            conditions.append(UserModel.email == criteria['email'].lower())
        
        if criteria.get('username'):
            conditions.append(UserModel.username == criteria['username'].lower())
        
        if criteria.get('is_active') is not None:
            conditions.append(UserModel.is_active == criteria['is_active'])
        
        if criteria.get('is_verified') is not None:
            conditions.append(UserModel.is_verified == criteria['is_verified'])
        
        if criteria.get('role_ids'):
            # Check if user has any of the specified roles
            role_conditions = []
            for role_id in criteria['role_ids']:
                role_conditions.append(UserModel.role_ids.op('@>')([str(role_id)]))
            conditions.append(or_(*role_conditions))
        
        if criteria.get('created_after'):
            conditions.append(UserModel.created_at >= criteria['created_after'])
        
        if criteria.get('created_before'):
            conditions.append(UserModel.created_at <= criteria['created_before'])
        
        if criteria.get('has_mfa'):
            conditions.append(UserModel.mfa_enabled == True)
        
        return conditions