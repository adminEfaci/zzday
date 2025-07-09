"""
Security Utilities

Static utility methods for security-related operations.
"""

import secrets
import hashlib
from typing import Any


class SecurityUtils:
    """Static utility methods for security operations."""
    
    @staticmethod
    def generate_secure_token(length: int = 32) -> str:
        """Generate a cryptographically secure random token."""
        return secrets.token_hex(length)
    
    @staticmethod
    def generate_numeric_code(length: int = 6) -> str:
        """Generate a secure numeric code for MFA."""
        code = ""
        for _ in range(length):
            code += str(secrets.randbelow(10))
        return code
    
    @staticmethod
    def calculate_risk_score(factors: dict[str, Any]) -> float:
        """Calculate risk score based on various factors."""
        base_score = 0.0
        
        if factors.get('unknown_ip', False):
            base_score += 0.3
        
        if factors.get('new_location', False):
            base_score += 0.2
        
        if factors.get('multiple_failed_attempts', False):
            base_score += 0.4
        
        return min(base_score, 1.0)
    
    @staticmethod
    def hash_sensitive_data(data: str, salt: str = None) -> tuple[str, str]:
        """Hash sensitive data with salt."""
        if salt is None:
            salt = secrets.token_hex(16)
        
        key = hashlib.pbkdf2_hmac('sha256', data.encode('utf-8'), salt.encode('utf-8'), 100000)
        return key.hex(), salt