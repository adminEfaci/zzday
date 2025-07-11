"""
Security Interfaces for Identity Domain

Domain ports for security operations following hexagonal architecture.
These interfaces define contracts that infrastructure adapters must implement.
"""

from abc import ABC, abstractmethod
from typing import Protocol

from ..value_objects import PasswordHash


class IPasswordHasher(Protocol):
    """Interface for password hashing operations."""
    
    @abstractmethod
    def hash_password(self, plain_password: str) -> PasswordHash:
        """Hash a plain text password.
        
        Args:
            plain_password: Plain text password to hash
            
        Returns:
            PasswordHash: Hashed password value object
        """
        ...
    
    @abstractmethod
    def verify_password(self, plain_password: str, password_hash: PasswordHash) -> bool:
        """Verify a password against its hash.
        
        Args:
            plain_password: Plain text password to verify
            password_hash: Stored password hash
            
        Returns:
            bool: True if password matches hash
        """
        ...


class ITokenGenerator(Protocol):
    """Interface for token generation operations."""
    
    @abstractmethod
    def generate_secure_token(self, length: int = 32) -> str:
        """Generate a cryptographically secure random token.
        
        Args:
            length: Token length in bytes
            
        Returns:
            str: Secure random token
        """
        ...
    
    @abstractmethod
    def generate_verification_token(self) -> str:
        """Generate a token for email verification.
        
        Returns:
            str: Verification token
        """
        ...
    
    @abstractmethod
    def generate_reset_token(self) -> str:
        """Generate a token for password reset.
        
        Returns:
            str: Reset token
        """
        ...


class ISecurityValidator(Protocol):
    """Interface for security validation operations."""
    
    @abstractmethod
    def is_password_secure(self, password: str) -> bool:
        """Check if password meets security requirements.
        
        Args:
            password: Password to validate
            
        Returns:
            bool: True if password is secure
        """
        ...
    
    @abstractmethod
    def validate_password_strength(self, password: str) -> tuple[bool, list[str]]:
        """Validate password strength and return violations.
        
        Args:
            password: Password to validate
            
        Returns:
            tuple: (is_valid, list_of_violations)
        """
        ...