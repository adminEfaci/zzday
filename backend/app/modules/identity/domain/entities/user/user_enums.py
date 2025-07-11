"""
User Entity Enumerations

Enums specific to user preferences, profile, and user-specific operations.
"""

from enum import Enum


class Relationship(Enum):
    """Emergency contact relationship enumeration."""
    SPOUSE = "spouse"
    PARENT = "parent"
    CHILD = "child"
    SIBLING = "sibling"
    RELATIVE = "relative"
    FRIEND = "friend"
    COLLEAGUE = "colleague"
    GUARDIAN = "guardian"
    OTHER = "other"
    
    def get_display_name(self) -> str:
        """Get human-readable display name."""
        return self.value.title()


class AccountType(Enum):
    """User account type enumeration (customer types)."""
    INDIVIDUAL = "individual"
    BUSINESS = "business"
    ENTERPRISE = "enterprise"
    GOVERNMENT = "government"
    NON_PROFIT = "non_profit"
    EDUCATIONAL = "educational"
    
    def get_display_name(self) -> str:
        """Get human-readable display name."""
        display_names = {
            self.INDIVIDUAL: "Individual",
            self.BUSINESS: "Business",
            self.ENTERPRISE: "Enterprise",
            self.GOVERNMENT: "Government",
            self.NON_PROFIT: "Non-Profit",
            self.EDUCATIONAL: "Educational"
        }
        return display_names.get(self, self.value)


class Department(Enum):
    """Department enumeration."""
    OPERATIONS = "operations"
    DISPATCH = "dispatch"
    MAINTENANCE = "maintenance"
    CUSTOMER_SERVICE = "customer_service"
    BILLING = "billing"
    COMPLIANCE = "compliance"
    IT = "it"
    HR = "hr"
    FINANCE = "finance"
    MANAGEMENT = "management"
    
    def get_display_name(self) -> str:
        """Get human-readable display name."""
        display_names = {
            self.OPERATIONS: "Operations",
            self.DISPATCH: "Dispatch",
            self.MAINTENANCE: "Maintenance",
            self.CUSTOMER_SERVICE: "Customer Service",
            self.BILLING: "Billing",
            self.COMPLIANCE: "Compliance",
            self.IT: "Information Technology",
            self.HR: "Human Resources",
            self.FINANCE: "Finance",
            self.MANAGEMENT: "Management"
        }
        return display_names.get(self, self.value)


class Language(Enum):
    """Language preference enumeration."""
    EN = "en"
    ES = "es"
    FR = "fr"
    DE = "de"
    IT = "it"
    PT = "pt"
    ZH = "zh"
    JA = "ja"
    KO = "ko"
    AR = "ar"
    
    def get_display_name(self) -> str:
        """Get human-readable display name."""
        display_names = {
            self.EN: "English",
            self.ES: "Spanish",
            self.FR: "French",
            self.DE: "German",
            self.IT: "Italian",
            self.PT: "Portuguese",
            self.ZH: "Chinese",
            self.JA: "Japanese",
            self.KO: "Korean",
            self.AR: "Arabic"
        }
        return display_names.get(self, self.value)


class DateFormat(Enum):
    """Date format preference enumeration."""
    ISO = "YYYY-MM-DD"
    US = "MM/DD/YYYY"
    EUROPEAN = "DD/MM/YYYY"
    DD_MON_YYYY = "DD-MON-YYYY"
    
    def get_display_name(self) -> str:
        """Get human-readable display name."""
        display_names = {
            self.US: "MM/DD/YYYY (US)",
            self.EUROPEAN: "DD/MM/YYYY (EU)",
            self.ISO: "YYYY-MM-DD (ISO)",
            self.DD_MON_YYYY: "DD-MON-YYYY"
        }
        return display_names.get(self, self.value)


class TimeFormat(Enum):
    """Time format preference enumeration."""
    TWELVE_HOUR = "12h"
    TWENTY_FOUR_HOUR = "24h"
    
    @property
    def uses_am_pm(self) -> bool:
        """Check if format uses AM/PM."""
        return self == self.TWELVE_HOUR
    
    def get_display_name(self) -> str:
        """Get human-readable display name."""
        display_names = {
            self.TWELVE_HOUR: "12-hour (AM/PM)",
            self.TWENTY_FOUR_HOUR: "24-hour"
        }
        return display_names.get(self, self.value)


class NotificationChannel(Enum):
    """Notification channel preference enumeration."""
    EMAIL = "email"
    SMS = "sms"
    PUSH = "push"
    IN_APP = "in_app"
    WEBHOOK = "webhook"
    
    def get_display_name(self) -> str:
        """Get human-readable display name."""
        display_names = {
            self.EMAIL: "Email",
            self.SMS: "SMS",
            self.PUSH: "Push Notification",
            self.IN_APP: "In-App",
            self.WEBHOOK: "Webhook"
        }
        return display_names.get(self, self.value)

# Add missing LoginFailureReason enum
class LoginFailureReason(Enum):
    """Login failure reason enumeration."""
    INVALID_CREDENTIALS = "invalid_credentials"
    INVALID_EMAIL = "invalid_email"
    INVALID_PASSWORD = "invalid_password"
    ACCOUNT_NOT_FOUND = "account_not_found"
    ACCOUNT_INACTIVE = "account_inactive"
    ACCOUNT_LOCKED = "account_locked"
    ACCOUNT_SUSPENDED = "account_suspended"
    EMAIL_NOT_VERIFIED = "email_not_verified"
    MFA_REQUIRED = "mfa_required"
    MFA_FAILED = "mfa_failed"
    PASSWORD_EXPIRED = "password_expired"
    TOO_MANY_ATTEMPTS = "too_many_attempts"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    IP_BLOCKED = "ip_blocked"
    MAINTENANCE_MODE = "maintenance_mode"

ContactRelationship = Relationship  

# Export all enums
__all__ = [
    'AccountType',
    'DateFormat',
    'Department',
    'Language',
    'NotificationChannel',
    'Relationship',
    'LoginFailureReason',
    'TimeFormat'
]