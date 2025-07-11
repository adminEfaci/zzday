"""
Identity Domain Value Objects

This module contains only the production-justified value objects that enforce business rules.
All other fields use primitives (str, int, enum) for simplicity and maintainability.
"""

from .address import Address
from .api_key_hash import APIKeyHash
from .audit_entry import AuditEntry
from .authorization_context import AuthorizationContext
from .backup_code import BackupCode
from .base import ValueObject
from .compliance_record import ComplianceRecord
from .date_of_birth import DateOfBirth
from .device_fingerprint import DeviceFingerprint
from .device_name import DeviceName
from .email import Email
from .geolocation import Geolocation
from .group_name import GroupName
from .ip_address import IpAddress
from .mfa_secret import MFASecret
from .password_hash import PasswordHash
from .password_strength import PasswordStrength
from .password_validation_result import PasswordValidationResult
from .permission_result import PermissionResult
from .person_name import PersonName
from .phone_number import PhoneNumber
from .postal_code import PostalCode
from .security_stamp import SecurityStamp
from .SIN import SIN
from .token import Token
from .user_agent import UserAgent
from .username import Username

__all__ = [
    "SIN",
    "APIKeyHash",
    "Address",
    "AuditEntry",
    "AuthorizationContext",
    "BackupCode",
    "ComplianceRecord",
    "DateOfBirth",
    "DeviceFingerprint",
    "DeviceName",
    "Email",
    "Geolocation",
    "GroupName",
    "IpAddress",
    "MFASecret",
    "PasswordHash",
    "PasswordStrength",
    "PasswordValidationResult",
    "PermissionResult",
    "PersonName",
    "PhoneNumber",
    "PostalCode",
    "SecurityStamp",
    "Token",
    "UserAgent",
    "Username",
    "ValueObject"
]
