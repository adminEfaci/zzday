"""
Email value object test data builder.

Provides utilities for generating unique Email test data.
"""

import uuid

from app.modules.identity.domain.value_objects.email import Email


class EmailBuilder:
    """Builder for Email value objects with unique values."""
    
    @staticmethod
    def unique(domain: str = "test.local") -> Email:
        """Generate unique email address."""
        unique_id = uuid.uuid4().hex[:8]
        return Email(f"user_{unique_id}@{domain}")
        
    @staticmethod
    def with_prefix(prefix: str, domain: str = "test.local") -> Email:
        """Generate email with specific prefix but unique suffix."""
        unique_id = uuid.uuid4().hex[:6]
        return Email(f"{prefix}_{unique_id}@{domain}")
        
    @staticmethod
    def admin() -> Email:
        """Generate unique admin email."""
        return EmailBuilder.with_prefix("admin", "company.local")
        
    @staticmethod
    def user() -> Email:
        """Generate unique user email."""
        return EmailBuilder.with_prefix("user", "company.local")
        
    @staticmethod
    def test() -> Email:
        """Generate unique test email."""
        return EmailBuilder.unique("test.local")