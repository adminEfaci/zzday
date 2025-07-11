"""Access Token Repository Interface

Domain contract for access token data access that must be implemented by the infrastructure layer.
"""

from datetime import datetime
from typing import Protocol
from uuid import UUID


class IAccessTokenRepository(Protocol):
    """Repository interface for access token management."""
    
    async def create(
        self, 
        user_id: UUID, 
        session_id: UUID, 
        token_hash: str,
        expires_at: datetime
    ) -> UUID:
        """Create new access token.
        
        Args:
            user_id: User identifier
            session_id: Session identifier
            token_hash: Hashed token value
            expires_at: Token expiration time
            
        Returns:
            Created token ID
        """
        ...
    
    async def find_by_hash(self, token_hash: str) -> dict | None:
        """Find token by hash.
        
        Args:
            token_hash: Hashed token value
            
        Returns:
            Token data if found, None otherwise
        """
        ...
    
    async def invalidate(self, token_id: UUID) -> bool:
        """Invalidate access token.
        
        Args:
            token_id: Token identifier
            
        Returns:
            True if invalidated, False if not found
        """
        ...
    
    async def invalidate_by_session(self, session_id: UUID) -> int:
        """Invalidate all tokens for a session.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Number of tokens invalidated
        """
        ...
    
    async def invalidate_by_user(self, user_id: UUID) -> int:
        """Invalidate all tokens for a user.
        
        Args:
            user_id: User identifier
            
        Returns:
            Number of tokens invalidated
        """
        ...
    
    async def cleanup_expired(self) -> int:
        """Remove expired tokens.
        
        Returns:
            Number of tokens removed
        """
        ...
    
    async def is_valid(self, token_hash: str) -> bool:
        """Check if token is valid and not expired.
        
        Args:
            token_hash: Hashed token value
            
        Returns:
            True if valid and not expired
        """
        ...