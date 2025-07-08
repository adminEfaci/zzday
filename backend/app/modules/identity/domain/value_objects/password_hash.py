"""
Password Hash Value Object

Secure password hash wrapper with support for multiple hashing algorithms.
"""

import re
import secrets
from dataclasses import dataclass
from enum import Enum

from app.core.domain.base import ValueObject


class HashAlgorithm(Enum):
    """Supported password hashing algorithms."""
    
    ARGON2ID = "argon2id"
    PBKDF2_SHA256 = "pbkdf2_sha256"
    BCRYPT = "bcrypt"
    SCRYPT = "scrypt"


@dataclass(frozen=True)
class PasswordHash(ValueObject):
    """
    Value object representing a hashed password.
    
    Stores the algorithm, salt, and hash value for secure password verification.
    """
    
    algorithm: HashAlgorithm
    salt: str
    hash_value: str
    iterations: int | None = None  # For PBKDF2
    memory_cost: int | None = None  # For Argon2
    parallelism: int | None = None  # For Argon2
    
    def __post_init__(self):
        """Validate password hash components."""
        if not self.salt:
            raise ValueError("Salt is required")
        
        if not self.hash_value:
            raise ValueError("Hash value is required")
        
        # Validate salt format (should be base64 or hex)
        if not re.match(r'^[A-Za-z0-9+/=]+$', self.salt) and not re.match(r'^[0-9a-fA-F]+$', self.salt):
            raise ValueError("Invalid salt format")
        
        # Validate hash format
        if not re.match(r'^[A-Za-z0-9+/=]+$', self.hash_value) and not re.match(r'^[0-9a-fA-F]+$', self.hash_value):
            raise ValueError("Invalid hash format")
        
        # Validate algorithm-specific parameters
        if self.algorithm == HashAlgorithm.PBKDF2_SHA256 and not self.iterations:
            raise ValueError("Iterations required for PBKDF2")
        
        if self.algorithm == HashAlgorithm.ARGON2ID:
            if not self.memory_cost or not self.parallelism:
                raise ValueError("Memory cost and parallelism required for Argon2")
    
    @classmethod
    def from_string(cls, hash_string: str) -> 'PasswordHash':
        """
        Create PasswordHash from a formatted string.
        
        Format: algorithm$salt$hash$params
        Examples:
        - argon2id$salt$hash$m=65536,p=4
        - pbkdf2_sha256$salt$hash$i=100000
        - bcrypt$salt$hash
        """
        parts = hash_string.split('$')
        
        if len(parts) < 3:
            raise ValueError("Invalid hash string format")
        
        algorithm_str = parts[0]
        salt = parts[1]
        hash_value = parts[2]
        
        # Parse algorithm
        try:
            algorithm = HashAlgorithm(algorithm_str)
        except ValueError as e:
            raise ValueError(f"Unsupported algorithm: {algorithm_str}") from e
        
        # Parse additional parameters
        iterations = None
        memory_cost = None
        parallelism = None
        
        if len(parts) > 3:
            params = parts[3]
            
            if algorithm == HashAlgorithm.PBKDF2_SHA256:
                # Parse iterations
                match = re.match(r'i=(\d+)', params)
                if match:
                    iterations = int(match.group(1))
            
            elif algorithm == HashAlgorithm.ARGON2ID:
                # Parse memory cost and parallelism
                memory_match = re.match(r'.*m=(\d+)', params)
                parallel_match = re.match(r'.*p=(\d+)', params)
                
                if memory_match:
                    memory_cost = int(memory_match.group(1))
                if parallel_match:
                    parallelism = int(parallel_match.group(1))
        
        return cls(
            algorithm=algorithm,
            salt=salt,
            hash_value=hash_value,
            iterations=iterations,
            memory_cost=memory_cost,
            parallelism=parallelism
        )
    
    def to_string(self) -> str:
        """
        Convert to formatted string for storage.
        
        Format: algorithm$salt$hash$params
        """
        parts = [self.algorithm.value, self.salt, self.hash_value]
        
        # Add algorithm-specific parameters
        if self.algorithm == HashAlgorithm.PBKDF2_SHA256 and self.iterations:
            parts.append(f"i={self.iterations}")
        
        elif self.algorithm == HashAlgorithm.ARGON2ID:
            params = []
            if self.memory_cost:
                params.append(f"m={self.memory_cost}")
            if self.parallelism:
                params.append(f"p={self.parallelism}")
            if params:
                parts.append(','.join(params))
        
        return '$'.join(parts)
    
    @classmethod
    def create_from_password(
        cls,
        password: str,
        algorithm: HashAlgorithm = HashAlgorithm.ARGON2ID,
        salt: str | None = None
    ) -> 'PasswordHash':
        """
        Create a new password hash from a plain text password.
        
        This is a factory method that would typically delegate to
        infrastructure services for actual hashing.
        """
        if not password:
            raise ValueError("Password cannot be empty")
        
        # Generate salt if not provided
        if not salt:
            salt = secrets.token_urlsafe(32)
        
        # Default parameters based on algorithm
        if algorithm == HashAlgorithm.ARGON2ID:
            # These would be configurable in production
            return cls(
                algorithm=algorithm,
                salt=salt,
                hash_value="placeholder_hash",  # Would be computed by infrastructure
                memory_cost=65536,  # 64 MB
                parallelism=4
            )
        
        if algorithm == HashAlgorithm.PBKDF2_SHA256:
            return cls(
                algorithm=algorithm,
                salt=salt,
                hash_value="placeholder_hash",  # Would be computed by infrastructure
                iterations=100000
            )
        
        return cls(
            algorithm=algorithm,
            salt=salt,
            hash_value="placeholder_hash"  # Would be computed by infrastructure
        )
    
    def verify_password(self, password: str) -> bool:
        """
        Verify a password against this hash.
        
        Note: This would typically delegate to infrastructure services
        for actual verification. Returns placeholder for domain model.
        """
        # This is a domain model placeholder
        # Actual verification would be done by infrastructure
        return True  # Placeholder
    
    @property
    def is_legacy_algorithm(self) -> bool:
        """Check if using a legacy/deprecated algorithm."""
        # Consider PBKDF2 and older as legacy
        legacy_algorithms = {HashAlgorithm.PBKDF2_SHA256, HashAlgorithm.BCRYPT}
        return self.algorithm in legacy_algorithms
    
    @property
    def needs_rehash(self) -> bool:
        """
        Check if password needs rehashing.
        
        Returns True if using legacy algorithm or parameters are outdated.
        """
        if self.is_legacy_algorithm:
            return True
        
        # Check if parameters are below current standards
        if self.algorithm == HashAlgorithm.ARGON2ID:
            # Current OWASP recommendations
            if self.memory_cost and self.memory_cost < 46000:  # ~46MB
                return True
            if self.parallelism and self.parallelism < 1:
                return True
        
        elif self.algorithm == HashAlgorithm.PBKDF2_SHA256:
            # NIST recommends at least 10,000 iterations
            if self.iterations and self.iterations < 100000:
                return True
        
        return False
    
    @property
    def strength_score(self) -> int:
        """
        Get a strength score for the hash algorithm and parameters.
        
        Returns a score from 0-100.
        """
        base_scores = {
            HashAlgorithm.ARGON2ID: 90,
            HashAlgorithm.SCRYPT: 80,
            HashAlgorithm.BCRYPT: 60,
            HashAlgorithm.PBKDF2_SHA256: 50
        }
        
        score = base_scores.get(self.algorithm, 0)
        
        # Adjust based on parameters
        if self.algorithm == HashAlgorithm.ARGON2ID:
            if self.memory_cost and self.memory_cost >= 65536:
                score += 5
            if self.parallelism and self.parallelism >= 4:
                score += 5
        
        elif self.algorithm == HashAlgorithm.PBKDF2_SHA256:
            if self.iterations:
                if self.iterations >= 100000:
                    score += 10
                elif self.iterations >= 50000:
                    score += 5
        
        return min(score, 100)
    
    def get_metadata(self) -> dict:
        """Get hash metadata for auditing."""
        return {
            "algorithm": self.algorithm.value,
            "strength_score": self.strength_score,
            "is_legacy": self.is_legacy_algorithm,
            "needs_rehash": self.needs_rehash,
            "salt_length": len(self.salt),
            "hash_length": len(self.hash_value)
        }
    
    def __str__(self) -> str:
        """String representation (safe for logging)."""
        # Never include actual hash in logs
        return f"PasswordHash(algorithm={self.algorithm.value}, strength={self.strength_score})"
    
    def __repr__(self) -> str:
        """Debug representation."""
        return f"PasswordHash(algorithm={self.algorithm.value}, salt_length={len(self.salt)})"