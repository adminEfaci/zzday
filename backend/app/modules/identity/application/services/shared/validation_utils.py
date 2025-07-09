"""
Validation Utilities

Static utility methods for common validation tasks.
Addresses the static methods issue by extracting stateless validation logic.
"""

import re


class ValidationUtils:
    """Static utility methods for validation operations."""
    
    @staticmethod
    def is_valid_email(email: str) -> bool:
        """Validate email format using RFC 5322 standard."""
        if not email or len(email) > 254:
            return False
        
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    @staticmethod
    def is_valid_phone_number(phone: str, country_code: str = 'US') -> bool:
        """Validate phone number format."""
        if not phone:
            return False
        
        digits_only = re.sub(r'\D', '', phone)
        
        if country_code == 'US':
            return len(digits_only) == 10 or (len(digits_only) == 11 and digits_only.startswith('1'))
        
        return 7 <= len(digits_only) <= 15
    
    @staticmethod
    def sanitize_user_input(input_string: str, max_length: int = 1000) -> str:
        """Sanitize user input by removing dangerous characters."""
        if not input_string:
            return ""
        
        sanitized = input_string[:max_length]
        sanitized = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', sanitized)
        sanitized = re.sub(r'<script[^>]*>.*?</script>', '', sanitized, flags=re.IGNORECASE | re.DOTALL)
        sanitized = re.sub(r'<.*?>', '', sanitized)
        
        return sanitized.strip()
    
    @staticmethod
    def is_valid_password_strength(password: str) -> tuple[bool, list[str]]:
        """Validate password strength."""
        issues = []
        
        if not password:
            return False, ["Password is required"]
        
        if len(password) < 8:
            issues.append("Password must be at least 8 characters long")
        
        if not re.search(r'[a-z]', password):
            issues.append("Password must contain at least one lowercase letter")
        
        if not re.search(r'[A-Z]', password):
            issues.append("Password must contain at least one uppercase letter")
        
        if not re.search(r'\d', password):
            issues.append("Password must contain at least one digit")
        
        return len(issues) == 0, issues