"""
Access Token Repository Implementation

SQLModel-based implementation of the access token repository interface.
"""

from datetime import datetime, UTC
from typing import Any
from uuid import UUID

from sqlmodel import Session, select, and_, or_, col, func
from app.core.infrastructure.repository import SQLRepository
from app.modules.identity.domain.entities.admin.access_token import AccessToken, TokenStatus
from app.modules.identity.domain.interfaces.repositories.access_token_repository import IAccessTokenRepository
from app.modules.identity.infrastructure.models.access_token_model import AccessTokenModel


class SQLAccessTokenRepository(SQLRepository[AccessToken, AccessTokenModel], IAccessTokenRepository):
    """SQLModel implementation of access token repository."""
    
    def __init__(self, session: Session):
        super().__init__(session, AccessTokenModel)
    
    async def create(
        self, 
        user_id: UUID, 
        session_id: UUID, 
        token_hash: str,
        expires_at: datetime
    ) -> UUID:
        """Create new access token."""
        # Create token domain entity
        token, _, _ = AccessToken.create(
            user_id=user_id,
            scopes=["api"],  # Default scope
            client_id=None,
            access_token_ttl=int((expires_at - datetime.now(UTC)).total_seconds())
        )
        
        # Update with provided hash
        token.token_hash = token_hash
        
        # Save to database
        model = AccessTokenModel.from_domain(token)
        model.session_id = session_id
        self.session.add(model)
        await self.session.commit()
        
        return token.id
    
    async def find_by_hash(self, token_hash: str) -> AccessToken | None:
        """Find token by hash."""
        stmt = select(AccessTokenModel).where(
            and_(
                AccessTokenModel.token_hash == token_hash,
                AccessTokenModel.is_valid == True
            )
        )
        result = await self.session.exec(stmt)
        model = result.first()
        
        if not model:
            return None
        
        # Return domain entity
        return model.to_domain()
    
    async def invalidate(self, token_id: UUID) -> bool:
        """Invalidate access token."""
        model = await self.session.get(AccessTokenModel, token_id)
        if not model:
            return False
        
        model.status = TokenStatus.REVOKED.value
        model.revoked_at = datetime.now(UTC)
        model.is_valid = False
        self.session.add(model)
        await self.session.commit()
        
        return True
    
    async def invalidate_by_session(self, session_id: UUID) -> int:
        """Invalidate all tokens for a session."""
        stmt = select(AccessTokenModel).where(
            and_(
                AccessTokenModel.session_id == session_id,
                AccessTokenModel.is_valid == True
            )
        )
        result = await self.session.exec(stmt)
        models = result.all()
        
        count = len(models)
        for model in models:
            model.status = TokenStatus.REVOKED.value
            model.revoked_at = datetime.now(UTC)
            model.is_valid = False
            self.session.add(model)
        
        await self.session.commit()
        return count
    
    async def invalidate_by_user(self, user_id: UUID) -> int:
        """Invalidate all tokens for a user."""
        stmt = select(AccessTokenModel).where(
            and_(
                AccessTokenModel.user_id == user_id,
                AccessTokenModel.is_valid == True
            )
        )
        result = await self.session.exec(stmt)
        models = result.all()
        
        count = len(models)
        for model in models:
            model.status = TokenStatus.REVOKED.value
            model.revoked_at = datetime.now(UTC)
            model.is_valid = False
            self.session.add(model)
        
        await self.session.commit()
        return count
    
    async def cleanup_expired(self) -> int:
        """Remove expired tokens."""
        # Find expired tokens
        stmt = select(AccessTokenModel).where(
            or_(
                and_(
                    AccessTokenModel.expires_at < datetime.now(UTC),
                    AccessTokenModel.is_valid == True
                ),
                and_(
                    AccessTokenModel.refresh_token_expires_at < datetime.now(UTC),
                    AccessTokenModel.refresh_token_expires_at.isnot(None)
                )
            )
        )
        result = await self.session.exec(stmt)
        models = result.all()
        
        count = len(models)
        for model in models:
            # Mark as expired instead of deleting
            model.status = TokenStatus.EXPIRED.value
            model.is_valid = False
            self.session.add(model)
        
        # Delete very old tokens (older than 90 days)
        cutoff_date = datetime.now(UTC).replace(day=datetime.now(UTC).day - 90)
        stmt = select(AccessTokenModel).where(
            and_(
                AccessTokenModel.created_at < cutoff_date,
                AccessTokenModel.is_valid == False
            )
        )
        result = await self.session.exec(stmt)
        old_models = result.all()
        
        for model in old_models:
            await self.session.delete(model)
            count += 1
        
        await self.session.commit()
        return count
    
    async def is_valid(self, token_hash: str) -> bool:
        """Check if token is valid and not expired."""
        stmt = select(AccessTokenModel).where(
            and_(
                AccessTokenModel.token_hash == token_hash,
                AccessTokenModel.is_valid == True,
                AccessTokenModel.expires_at > datetime.now(UTC)
            )
        )
        result = await self.session.exec(stmt)
        model = result.first()
        
        return model is not None
    
    async def find_by_id(self, token_id: UUID) -> AccessToken | None:
        """Find token by ID."""
        model = await self.session.get(AccessTokenModel, token_id)
        return model.to_domain() if model else None
    
    async def find_by_user(self, user_id: UUID, limit: int = 100) -> list[AccessToken]:
        """Find all tokens for user."""
        stmt = select(AccessTokenModel).where(
            AccessTokenModel.user_id == user_id
        ).order_by(AccessTokenModel.created_at.desc()).limit(limit)
        
        result = await self.session.exec(stmt)
        models = result.all()
        return [model.to_domain() for model in models]
    
    async def find_active_by_user(self, user_id: UUID, limit: int = 100) -> list[AccessToken]:
        """Find active tokens for user."""
        stmt = select(AccessTokenModel).where(
            and_(
                AccessTokenModel.user_id == user_id,
                AccessTokenModel.is_valid == True,
                AccessTokenModel.expires_at > datetime.now(UTC)
            )
        ).order_by(AccessTokenModel.created_at.desc()).limit(limit)
        
        result = await self.session.exec(stmt)
        models = result.all()
        return [model.to_domain() for model in models]
    
    async def save(self, token: AccessToken) -> None:
        """Save access token."""
        model = AccessTokenModel.from_domain(token)
        
        # Check if token exists
        existing = await self.session.get(AccessTokenModel, token.id)
        if existing:
            # Update existing model
            for key, value in model.dict(exclude={'id'}).items():
                setattr(existing, key, value)
            self.session.add(existing)
        else:
            # Add new model
            self.session.add(model)
        
        await self.session.commit()
    
    async def update_usage(self, token_id: UUID) -> None:
        """Update token usage statistics."""
        model = await self.session.get(AccessTokenModel, token_id)
        if model:
            model.usage_count = (model.usage_count or 0) + 1
            model.last_used_at = datetime.now(UTC)
            self.session.add(model)
            await self.session.commit()
    
    async def find_by_family(self, family_id: UUID) -> list[AccessToken]:
        """Find all tokens in a family."""
        stmt = select(AccessTokenModel).where(
            AccessTokenModel.family_id == family_id
        ).order_by(AccessTokenModel.generation.asc())
        
        result = await self.session.exec(stmt)
        models = result.all()
        return [model.to_domain() for model in models]
    
    async def revoke_family(self, family_id: UUID, reason: str) -> int:
        """Revoke all tokens in a family."""
        stmt = select(AccessTokenModel).where(
            AccessTokenModel.family_id == family_id
        )
        result = await self.session.exec(stmt)
        models = result.all()
        
        count = len(models)
        for model in models:
            model.status = TokenStatus.REVOKED.value
            model.revoked_at = datetime.now(UTC)
            model.is_valid = False
            model.metadata = model.metadata or {}
            model.metadata['revocation_reason'] = reason
            self.session.add(model)
        
        await self.session.commit()
        return count