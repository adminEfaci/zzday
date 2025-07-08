"""
Password Hasher Interface

Port for password hashing operations in the identity domain.
"""

from abc import ABC, abstractmethod
from typing import Any

from ....value_objects.password_hash import PasswordHash


class IPasswordHasher(ABC):
    """Port for password hashing operations."""
    
    @abstractmethod
    async def hash_password(
        self, 
        password: str, 
        user_context: dict[str, Any] | None = None
    ) -> PasswordHash:
        """
        Hash a password using secure algorithm.
        
        Args:
            password: Plain text password to hash
            user_context: Optional context for salt generation
            
        Returns:
            PasswordHash value object containing hash and metadata
            
        Raises:
            ValueError: If password doesn't meet minimum requirements
        """
    
    @abstractmethod
    async def verify_password(
        self, 
        password: str, 
        password_hash: PasswordHash
    ) -> bool:
        """
        Verify password against hash.
        
        Args:
            password: Plain text password to verify
            password_hash: PasswordHash to verify against
            
        Returns:
            True if password matches, False otherwise
        """
    
    @abstractmethod
    async def needs_rehash(self, password_hash: PasswordHash) -> bool:
        """
        Check if password hash needs to be updated.
        
        Args:
            password_hash: Current password hash
            
        Returns:
            True if rehashing is recommended
        """
    
    @abstractmethod
    async def validate_password_strength(
        self, 
        password: str, 
        user_context: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """
        Validate password strength against policy.
        
        Args:
            password: Password to validate
            user_context: User context for validation (name, email, etc.)
            
        Returns:
            Dict containing:
                - is_valid: bool
                - score: float (0.0 to 1.0)
                - violations: List of policy violations
                - suggestions: List of improvement suggestions
        """
