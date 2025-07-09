"""
Validation Utilities

Static utility methods for common validation tasks.
Addresses the static methods issue by extracting stateless validation logic.
"""

import re
from typing import Any
from uuid import UUID

from app.modules.identity.domain.entities import User, UserProfile
from app.modules.identity.domain.enums import MFAMethod
from app.modules.identity.domain.value_objects import Email, PhoneNumber


class ValidationUtils:
    """Static utility methods for validation operations."""
    
    @staticmethod
    def is_valid_email(email: str) -> bool:
        """
        Validate email format using RFC 5322 standard.
        
        Args:
            email: Email address to validate
            
        Returns:
            True if email format is valid
        """
        if not email or len(email) > 254:
            return False
        
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    @staticmethod
    def is_valid_phone_number(phone: str, country_code: str = 'US') -> bool:
        """
        Validate phone number format.
        
        Args:
            phone: Phone number to validate
            country_code: Country code for validation (default: US)
            
        Returns:
            True if phone number format is valid
        """
        if not phone:
            return False
        
        # Remove all non-digit characters
        digits_only = re.sub(r'\D', '', phone)
        
        if country_code == 'US':
            # US phone numbers should be 10 digits (with optional +1)
            return len(digits_only) == 10 or (len(digits_only) == 11 and digits_only.startswith('1'))
        
        # International format: 7-15 digits
        return 7 <= len(digits_only) <= 15
    
    @staticmethod
    def is_valid_timezone(timezone: str) -> bool:
        """
        Validate timezone string.
        
        Args:
            timezone: Timezone string to validate
            
        Returns:
            True if timezone is valid
        """
        try:
            import zoneinfo
            zoneinfo.ZoneInfo(timezone)
            return True
        except Exception:
            return False
    
    @staticmethod
    def is_valid_language_code(code: str) -> bool:
        """
        Validate ISO 639-1 language code.
        
        Args:
            code: Language code to validate (e.g., 'en', 'es', 'fr')
            
        Returns:
            True if language code is valid
        """
        if not code or len(code) != 2:
            return False
        
        # Common ISO 639-1 language codes
        valid_codes = {
            'en', 'es', 'fr', 'de', 'it', 'pt', 'ru', 'ja', 'ko', 'zh',
            'ar', 'hi', 'th', 'vi', 'tr', 'pl', 'nl', 'sv', 'da', 'no',
            'fi', 'el', 'he', 'cs', 'sk', 'hu', 'ro', 'bg', 'hr', 'sl',
            'et', 'lv', 'lt', 'mt', 'cy', 'ga', 'eu', 'ca', 'gl', 'is'
        }
        
        return code.lower() in valid_codes
    
    @staticmethod
    def is_valid_uuid(uuid_string: str) -> bool:
        """
        Validate UUID format.
        
        Args:
            uuid_string: UUID string to validate
            
        Returns:
            True if UUID format is valid
        """
        try:
            UUID(uuid_string)
            return True
        except (ValueError, TypeError):
            return False
    
    @staticmethod
    def is_valid_username(username: str) -> bool:
        """
        Validate username format.
        
        Args:
            username: Username to validate
            
        Returns:
            True if username format is valid
        """
        if not username or not (3 <= len(username) <= 50):
            return False
        
        # Username can contain letters, numbers, underscores, and hyphens
        pattern = r'^[a-zA-Z0-9_-]+$'
        return bool(re.match(pattern, username))
    
    @staticmethod
    def is_valid_password_strength(password: str) -> tuple[bool, list[str]]:
        """
        Validate password strength.
        
        Args:
            password: Password to validate
            
        Returns:
            Tuple of (is_valid, list_of_issues)
        """
        issues = []
        
        if not password:
            return False, ["Password is required"]
        
        if len(password) < 8:
            issues.append("Password must be at least 8 characters long")
        
        if len(password) > 128:
            issues.append("Password must be no more than 128 characters long")
        
        if not re.search(r'[a-z]', password):
            issues.append("Password must contain at least one lowercase letter")
        
        if not re.search(r'[A-Z]', password):
            issues.append("Password must contain at least one uppercase letter")
        
        if not re.search(r'\d', password):
            issues.append("Password must contain at least one digit")
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            issues.append("Password must contain at least one special character")
        
        # Check for common weak patterns
        if re.search(r'(.)\1{2,}', password):
            issues.append("Password must not contain repeated characters")
        
        common_patterns = ['123', 'abc', 'qwe', 'password', '111', '000']
        if any(pattern in password.lower() for pattern in common_patterns):
            issues.append("Password must not contain common patterns")
        
        return len(issues) == 0, issues
    
    @staticmethod
    def is_valid_url(url: str) -> bool:
        """
        Validate URL format.
        
        Args:
            url: URL to validate
            
        Returns:
            True if URL format is valid
        """
        if not url:
            return False
        
        pattern = r'^https?://[^\s/$.?#].[^\s]*$'
        return bool(re.match(pattern, url))
    
    @staticmethod
    def is_valid_ip_address(ip: str) -> bool:
        """
        Validate IP address format (IPv4 or IPv6).
        
        Args:
            ip: IP address to validate
            
        Returns:
            True if IP address format is valid
        """
        import ipaddress
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def calculate_profile_completion(user: User, profile: UserProfile) -> float:
        """
        Calculate user profile completion percentage.
        
        Args:
            user: User entity
            profile: User profile entity
            
        Returns:
            Completion percentage (0.0 to 1.0)
        """
        total_fields = 10
        completed_fields = 0
        
        # Required fields
        if user.email and ValidationUtils.is_valid_email(user.email.value):
            completed_fields += 1
        
        if user.first_name and len(user.first_name.strip()) > 0:
            completed_fields += 1
        
        if user.last_name and len(user.last_name.strip()) > 0:
            completed_fields += 1
        
        # Profile fields
        if profile.phone_number and ValidationUtils.is_valid_phone_number(profile.phone_number.value):
            completed_fields += 1
        
        if profile.date_of_birth:
            completed_fields += 1
        
        if profile.timezone and ValidationUtils.is_valid_timezone(profile.timezone):
            completed_fields += 1
        
        if profile.language and ValidationUtils.is_valid_language_code(profile.language):
            completed_fields += 1
        
        if profile.bio and len(profile.bio.strip()) > 10:
            completed_fields += 1
        
        if profile.location and len(profile.location.strip()) > 0:
            completed_fields += 1
        
        if profile.avatar_url and ValidationUtils.is_valid_url(profile.avatar_url):
            completed_fields += 1
        
        return completed_fields / total_fields
    
    @staticmethod
    def mask_sensitive_data(data: dict, permissions: list[str]) -> dict[str, Any]:
        """
        Mask sensitive data based on user permissions.
        
        Args:
            data: Data dictionary to mask
            permissions: List of user permissions
            
        Returns:
            Masked data dictionary
        """
        masked_data = data.copy()
        
        # Sensitive fields that require special permissions
        sensitive_fields = {
            'password': 'view_passwords',
            'password_hash': 'view_passwords',
            'ssn': 'view_pii',
            'social_security_number': 'view_pii',
            'credit_card': 'view_financial',
            'bank_account': 'view_financial',
            'phone_number': 'view_contact_info',
            'email': 'view_contact_info',
            'ip_address': 'view_technical_data',
            'device_fingerprint': 'view_technical_data',
        }
        
        for field, required_permission in sensitive_fields.items():
            if field in masked_data and required_permission not in permissions:
                if field in ['password', 'password_hash']:
                    masked_data[field] = '***HIDDEN***'
                elif field in ['ssn', 'social_security_number']:
                    value = str(masked_data[field])
                    masked_data[field] = f"***-**-{value[-4:]}" if len(value) >= 4 else "***-**-****"
                elif field in ['credit_card', 'bank_account']:
                    value = str(masked_data[field])
                    masked_data[field] = f"****-****-****-{value[-4:]}" if len(value) >= 4 else "****-****-****-****"
                elif field == 'phone_number':
                    value = str(masked_data[field])
                    masked_data[field] = f"***-***-{value[-4:]}" if len(value) >= 4 else "***-***-****"
                elif field == 'email':
                    value = str(masked_data[field])
                    if '@' in value:
                        local, domain = value.split('@', 1)
                        masked_local = local[0] + '*' * (len(local) - 1) if len(local) > 1 else '*'
                        masked_data[field] = f"{masked_local}@{domain}"
                    else:
                        masked_data[field] = '***@***.***'
                else:
                    masked_data[field] = '***HIDDEN***'
        
        return masked_data
    
    @staticmethod
    def sanitize_user_input(input_string: str, max_length: int = 1000) -> str:
        """
        Sanitize user input by removing dangerous characters.
        
        Args:
            input_string: Input string to sanitize
            max_length: Maximum allowed length
            
        Returns:
            Sanitized input string
        """
        if not input_string:
            return ""
        
        # Truncate if too long
        sanitized = input_string[:max_length]
        
        # Remove null bytes and control characters
        sanitized = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', sanitized)
        
        # Remove potentially dangerous HTML/script tags
        sanitized = re.sub(r'<script[^>]*>.*?</script>', '', sanitized, flags=re.IGNORECASE | re.DOTALL)
        sanitized = re.sub(r'<.*?>', '', sanitized)
        
        # Remove SQL injection patterns
        sql_patterns = [
            r'(\s*(;|\'|\"|`|--|\#))',
            r'(\s*(union|select|insert|update|delete|drop|create|alter|exec|execute)\s+)',
        ]
        
        for pattern in sql_patterns:
            sanitized = re.sub(pattern, '', sanitized, flags=re.IGNORECASE)
        
        return sanitized.strip()
    
    @staticmethod
    def validate_mfa_method(method: str) -> bool:
        """
        Validate MFA method.
        
        Args:
            method: MFA method string to validate
            
        Returns:
            True if MFA method is valid
        """
        try:
            MFAMethod(method)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_json_structure(data: dict, required_fields: list[str]) -> tuple[bool, list[str]]:
        """
        Validate JSON structure has required fields.
        
        Args:
            data: JSON data to validate
            required_fields: List of required field names
            
        Returns:
            Tuple of (is_valid, list_of_missing_fields)
        """
        missing_fields = []
        
        for field in required_fields:
            if field not in data or data[field] is None:
                missing_fields.append(field)
        
        return len(missing_fields) == 0, missing_fields