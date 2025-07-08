"""
Token Generator Interface

Port for token generation and validation operations.
"""

from abc import ABC, abstractmethod
from typing import Any
from uuid import UUID


class ITokenGenerator(ABC):
    """Port for token generation and validation."""
    
    @abstractmethod
    async def generate_access_token(
        self, 
        user_id: UUID, 
        claims: dict[str, Any],
        expires_in: int | None = None
    ) -> str:
        """
        Generate access token.
        
        Args:
            user_id: User identifier
            claims: Additional JWT claims
            expires_in: Token lifetime in seconds (None for default)
            
        Returns:
            JWT access token string
            
        Raises:
            TokenGenerationError: If token generation fails
        """
    
    @abstractmethod
    async def generate_refresh_token(
        self, 
        user_id: UUID,
        device_id: str | None = None
    ) -> str:
        """
        Generate refresh token.
        
        Args:
            user_id: User identifier
            device_id: Optional device identifier for token binding
            
        Returns:
            Refresh token string
        """
    
    @abstractmethod
    async def validate_token(
        self, 
        token: str, 
        token_type: str = "access"
    ) -> dict[str, Any]:
        """
        Validate token and return claims.
        
        Args:
            token: Token to validate
            token_type: Type of token (access/refresh)
            
        Returns:
            Dict containing token claims and metadata
            
        Raises:
            TokenValidationError: If token is invalid or expired
        """
    
    @abstractmethod
    async def revoke_token(self, token: str) -> None:
        """
        Revoke a specific token.
        
        Args:
            token: Token to revoke
            
        Raises:
            TokenNotFoundError: If token doesn't exist
        """
    
    @abstractmethod
    async def revoke_user_tokens(
        self, 
        user_id: UUID,
        token_type: str | None = None
    ) -> int:
        """
        Revoke all tokens for a user.
        
        Args:
            user_id: User identifier
            token_type: Optional type filter (access/refresh)
            
        Returns:
            Number of tokens revoked
        """
    
    @abstractmethod
    async def refresh_token_pair(
        self, 
        refresh_token: str
    ) -> tuple[str, str]:
        """
        Generate new token pair from refresh token.
        
        Args:
            refresh_token: Valid refresh token
            
        Returns:
            Tuple of (new_access_token, new_refresh_token)
            
        Raises:
            TokenValidationError: If refresh token is invalid
            TokenReusedError: If refresh token was already used
        """
