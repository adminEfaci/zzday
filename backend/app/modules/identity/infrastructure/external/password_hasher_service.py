"""Password hasher service implementation."""

import base64
import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import argon2
import bcrypt

from app.core.logging import logger
from app.modules.identity.domain.contracts.interfaces import IPasswordHasher
from app.modules.identity.domain.value_objects import HashedPassword


@dataclass
class PasswordPolicy:
    """Password policy configuration."""
    min_length: int = 12
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_numbers: bool = True
    require_special: bool = True
    max_age_days: int = 90
    history_count: int = 5
    min_unique_chars: int = 8
    banned_passwords: list = None
    
    def __post_init__(self):
        if self.banned_passwords is None:
            self.banned_passwords = [
                "password", "123456", "qwerty", "abc123", "letmein",
                "welcome", "admin", "user", "test", "demo"
            ]


class PasswordHasherService(IPasswordHasher):
    """Service for hashing and verifying passwords."""
    
    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        self.algorithm = self.config.get("algorithm", "argon2")
        self.policy = PasswordPolicy(**self.config.get("policy", {}))
        
        # Initialize hashers
        self._argon2_hasher = argon2.PasswordHasher(
            time_cost=self.config.get("argon2_time_cost", 2),
            memory_cost=self.config.get("argon2_memory_cost", 65536),
            parallelism=self.config.get("argon2_parallelism", 1),
            hash_len=self.config.get("argon2_hash_len", 32),
            salt_len=self.config.get("argon2_salt_len", 16)
        )
        
        logger.info(f"PasswordHasherService initialized with algorithm: {self.algorithm}")
    
    async def hash_password(self, password: str) -> HashedPassword:
        """Hash a password using the configured algorithm."""
        try:
            # Validate password against policy
            validation_result = await self.validate_password_strength(password)
            if not validation_result["is_valid"]:
                raise ValueError(f"Password validation failed: {validation_result['errors']}")
            
            # Generate salt
            salt = secrets.token_bytes(32)
            
            # Hash based on algorithm
            if self.algorithm == "argon2":
                hash_value = self._argon2_hasher.hash(password)
            elif self.algorithm == "bcrypt":
                hash_value = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))
                hash_value = hash_value.decode('utf-8')
            elif self.algorithm == "pbkdf2":
                hash_value = self._hash_pbkdf2(password, salt)
            else:
                raise ValueError(f"Unsupported algorithm: {self.algorithm}")
            
            return HashedPassword(
                algorithm=self.algorithm,
                hash=hash_value,
                salt=base64.b64encode(salt).decode('utf-8'),
                iterations=self._get_iterations(),
                created_at=datetime.now(UTC)
            )
            
        except Exception as e:
            logger.error(f"Error hashing password: {e!s}")
            raise
    
    async def verify_password(
        self,
        password: str,
        hashed_password: HashedPassword
    ) -> bool:
        """Verify a password against its hash."""
        try:
            if hashed_password.algorithm == "argon2":
                try:
                    self._argon2_hasher.verify(hashed_password.hash, password)
                    return True
                except argon2.exceptions.VerifyMismatchError:
                    return False
                    
            elif hashed_password.algorithm == "bcrypt":
                return bcrypt.checkpw(
                    password.encode('utf-8'),
                    hashed_password.hash.encode('utf-8')
                )
                
            elif hashed_password.algorithm == "pbkdf2":
                salt = base64.b64decode(hashed_password.salt)
                test_hash = self._hash_pbkdf2(password, salt)
                return secrets.compare_digest(test_hash, hashed_password.hash)
                
            else:
                logger.warning(f"Unknown algorithm: {hashed_password.algorithm}")
                return False
                
        except Exception as e:
            logger.error(f"Error verifying password: {e!s}")
            return False
    
    async def needs_rehash(self, hashed_password: HashedPassword) -> bool:
        """Check if a password hash needs to be updated."""
        # Check if using outdated algorithm
        if hashed_password.algorithm != self.algorithm:
            return True
        
        # Check if parameters have changed for argon2
        if self.algorithm == "argon2":
            try:
                # Parse hash parameters
                params = self._parse_argon2_params(hashed_password.hash)
                
                # Check if parameters match current configuration
                if (params.get("time_cost") != self._argon2_hasher.time_cost or
                    params.get("memory_cost") != self._argon2_hasher.memory_cost or
                    params.get("parallelism") != self._argon2_hasher.parallelism):
                    return True
            except:
                return True
        
        # Check age of hash
        if hashed_password.created_at:
            age = datetime.now(UTC) - hashed_password.created_at
            if age > timedelta(days=365):  # Rehash annually
                return True
        
        return False
    
    async def validate_password_strength(self, password: str) -> dict[str, Any]:
        """Validate password against policy."""
        errors = []
        score = 100
        
        # Check length
        if len(password) < self.policy.min_length:
            errors.append(f"Password must be at least {self.policy.min_length} characters")
            score -= 20
        
        # Check character requirements
        if self.policy.require_uppercase and not any(c.isupper() for c in password):
            errors.append("Password must contain uppercase letters")
            score -= 15
            
        if self.policy.require_lowercase and not any(c.islower() for c in password):
            errors.append("Password must contain lowercase letters")
            score -= 15
            
        if self.policy.require_numbers and not any(c.isdigit() for c in password):
            errors.append("Password must contain numbers")
            score -= 15
            
        if self.policy.require_special and not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            errors.append("Password must contain special characters")
            score -= 15
        
        # Check unique characters
        unique_chars = len(set(password))
        if unique_chars < self.policy.min_unique_chars:
            errors.append(f"Password must contain at least {self.policy.min_unique_chars} unique characters")
            score -= 10
        
        # Check against banned passwords
        if password.lower() in [p.lower() for p in self.policy.banned_passwords]:
            errors.append("Password is too common")
            score = 0
        
        # Calculate entropy
        entropy = self._calculate_entropy(password)
        
        # Adjust score based on length
        if len(password) >= 16:
            score += 10
        elif len(password) >= 20:
            score += 20
        
        return {
            "is_valid": len(errors) == 0,
            "score": max(0, score),
            "errors": errors,
            "entropy": entropy,
            "strength": self._get_strength_label(score)
        }
    
    async def generate_secure_password(
        self,
        length: int = 16,
        include_symbols: bool = True
    ) -> str:
        """Generate a secure random password."""
        # Character sets
        lowercase = "abcdefghijklmnopqrstuvwxyz"
        uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        digits = "0123456789"
        symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        # Build character pool
        char_pool = lowercase + uppercase + digits
        if include_symbols:
            char_pool += symbols
        
        # Ensure minimum requirements
        password = [
            secrets.choice(lowercase),
            secrets.choice(uppercase),
            secrets.choice(digits)
        ]
        
        if include_symbols:
            password.append(secrets.choice(symbols))
        
        # Fill remaining length
        for _ in range(len(password), length):
            password.append(secrets.choice(char_pool))
        
        # Shuffle to avoid predictable patterns
        secrets.SystemRandom().shuffle(password)
        
        return ''.join(password)
    
    def _hash_pbkdf2(self, password: str, salt: bytes) -> str:
        """Hash password using PBKDF2."""
        iterations = self.config.get("pbkdf2_iterations", 100000)
        dk = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            iterations
        )
        return base64.b64encode(dk).decode('utf-8')
    
    def _get_iterations(self) -> int:
        """Get iteration count for current algorithm."""
        if self.algorithm == "argon2":
            return self._argon2_hasher.time_cost
        if self.algorithm == "bcrypt":
            return 12  # rounds
        if self.algorithm == "pbkdf2":
            return self.config.get("pbkdf2_iterations", 100000)
        return 1
    
    def _parse_argon2_params(self, hash_str: str) -> dict[str, int]:
        """Parse Argon2 hash parameters."""
        # Format: $argon2id$v=19$m=65536,t=2,p=1$...
        try:
            parts = hash_str.split('$')
            if len(parts) >= 4:
                params_str = parts[3]
                params = {}
                for param in params_str.split(','):
                    key, value = param.split('=')
                    if key == 'm':
                        params['memory_cost'] = int(value)
                    elif key == 't':
                        params['time_cost'] = int(value)
                    elif key == 'p':
                        params['parallelism'] = int(value)
                return params
        except:
            pass
        return {}
    
    def _calculate_entropy(self, password: str) -> float:
        """Calculate password entropy in bits."""
        char_space = 0
        
        if any(c.islower() for c in password):
            char_space += 26
        if any(c.isupper() for c in password):
            char_space += 26
        if any(c.isdigit() for c in password):
            char_space += 10
        if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            char_space += 32
        
        if char_space == 0:
            return 0
        
        import math
        return len(password) * math.log2(char_space)
    
    def _get_strength_label(self, score: int) -> str:
        """Get strength label from score."""
        if score >= 80:
            return "strong"
        if score >= 60:
            return "good"
        if score >= 40:
            return "fair"
        return "weak"