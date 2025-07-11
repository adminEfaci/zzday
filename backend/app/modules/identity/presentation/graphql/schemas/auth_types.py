"""
Authentication GraphQL Type Definitions for Identity Module

This module contains all GraphQL types related to authentication, including
sessions, MFA devices, API keys, login attempts, and related input types.
"""


import graphene

from .common_types import (
    AuditMetadataType,
    ConnectionType,
    DateRangeInput,
    EdgeType,
    FilterInput,
    GeolocationInput,
    GeolocationResponse,
    MetadataType,
    PageInfoType,
)
from .enums import (
    AuthenticationMethodEnum,
    DeviceTypeEnum,
    LoginFailureReasonEnum,
    MFAMethodEnum,
    RiskLevelEnum,
    SessionStatusEnum,
    SessionTypeEnum,
    VerificationStatusEnum,
)


class DeviceInfoType(graphene.ObjectType):
    """Device information for sessions and authentication."""
    
    class Meta:
        description = "Information about a device used for authentication"
    
    fingerprint = graphene.String(
        description="Unique device fingerprint"
    )
    
    device_type = graphene.Field(
        DeviceTypeEnum,
        description="Type of device"
    )
    
    operating_system = graphene.String(
        description="Operating system name and version"
    )
    
    browser = graphene.String(
        description="Browser name and version"
    )
    
    user_agent = graphene.String(
        description="Full user agent string"
    )
    
    ip_address = graphene.String(
        description="IP address of the device"
    )
    
    location = graphene.Field(
        GeolocationResponse,
        description="Geographic location of the device"
    )
    
    is_trusted = graphene.Boolean(
        default_value=False,
        description="Whether this device is marked as trusted"
    )
    
    is_mobile = graphene.Boolean(
        description="Whether this is a mobile device"
    )
    
    screen_resolution = graphene.String(
        description="Screen resolution of the device"
    )
    
    timezone = graphene.String(
        description="Device timezone"
    )


class SessionType(graphene.ObjectType):
    """User session information."""
    
    class Meta:
        description = "Active or historical user session"
    
    id = graphene.ID(
        required=True,
        description="Unique identifier for the session"
    )
    
    user_id = graphene.ID(
        required=True,
        description="ID of the user who owns this session"
    )
    
    session_token = graphene.String(
        description="Session token (hashed for security)"
    )
    
    refresh_token = graphene.String(
        description="Refresh token (hashed for security)"
    )
    
    status = graphene.Field(
        SessionStatusEnum,
        required=True,
        description="Current status of the session"
    )
    
    session_type = graphene.Field(
        SessionTypeEnum,
        required=True,
        description="Type of session"
    )
    
    device_info = graphene.Field(
        DeviceInfoType,
        description="Information about the device used"
    )
    
    ip_address = graphene.String(
        description="IP address when session was created"
    )
    
    location = graphene.Field(
        GeolocationResponse,
        description="Geographic location when session was created"
    )
    
    started_at = graphene.DateTime(
        required=True,
        description="When the session was started"
    )
    
    last_activity = graphene.DateTime(
        description="Last activity timestamp for this session"
    )
    
    expires_at = graphene.DateTime(
        description="When the session expires"
    )
    
    ended_at = graphene.DateTime(
        description="When the session was ended (if terminated)"
    )
    
    is_current = graphene.Boolean(
        description="Whether this is the current session"
    )
    
    authentication_methods = graphene.List(
        AuthenticationMethodEnum,
        description="Authentication methods used for this session"
    )
    
    risk_level = graphene.Field(
        RiskLevelEnum,
        description="Risk assessment level for this session"
    )
    
    metadata = graphene.Field(
        AuditMetadataType,
        required=True,
        description="Creation, modification, and audit metadata"
    )


class MFADeviceType(graphene.ObjectType):
    """Multi-factor authentication device information."""
    
    class Meta:
        description = "MFA device registered for a user"
    
    id = graphene.ID(
        required=True,
        description="Unique identifier for the MFA device"
    )
    
    user_id = graphene.ID(
        required=True,
        description="ID of the user who owns this device"
    )
    
    device_name = graphene.String(
        required=True,
        description="User-friendly name for the device"
    )
    
    method = graphene.Field(
        MFAMethodEnum,
        required=True,
        description="MFA method for this device"
    )
    
    phone_number = graphene.String(
        description="Phone number for SMS-based MFA (masked)"
    )
    
    email = graphene.String(
        description="Email address for email-based MFA (masked)"
    )
    
    is_primary = graphene.Boolean(
        default_value=False,
        description="Whether this is the primary MFA device"
    )
    
    is_verified = graphene.Boolean(
        default_value=False,
        description="Whether this device has been verified"
    )
    
    is_active = graphene.Boolean(
        default_value=True,
        description="Whether this device is active"
    )
    
    last_used = graphene.DateTime(
        description="When this device was last used for authentication"
    )
    
    backup_codes_count = graphene.Int(
        description="Number of remaining backup codes (if applicable)"
    )
    
    verification_status = graphene.Field(
        VerificationStatusEnum,
        description="Verification status of the device"
    )
    
    metadata = graphene.Field(
        MetadataType,
        required=True,
        description="Creation and modification metadata"
    )


class ApiKeyType(graphene.ObjectType):
    """API key information."""
    
    class Meta:
        description = "API key for programmatic access"
    
    id = graphene.ID(
        required=True,
        description="Unique identifier for the API key"
    )
    
    user_id = graphene.ID(
        required=True,
        description="ID of the user who owns this API key"
    )
    
    name = graphene.String(
        required=True,
        description="User-friendly name for the API key"
    )
    
    key_prefix = graphene.String(
        description="First few characters of the API key for identification"
    )
    
    scopes = graphene.List(
        graphene.String,
        description="List of permission scopes for this API key"
    )
    
    is_active = graphene.Boolean(
        default_value=True,
        description="Whether this API key is active"
    )
    
    last_used = graphene.DateTime(
        description="When this API key was last used"
    )
    
    usage_count = graphene.Int(
        default_value=0,
        description="Number of times this API key has been used"
    )
    
    rate_limit = graphene.Int(
        description="Rate limit for this API key (requests per hour)"
    )
    
    expires_at = graphene.DateTime(
        description="When this API key expires"
    )
    
    last_used_ip = graphene.String(
        description="Last IP address that used this API key"
    )
    
    allowed_ips = graphene.List(
        graphene.String,
        description="List of IP addresses allowed to use this key"
    )
    
    metadata = graphene.Field(
        MetadataType,
        required=True,
        description="Creation and modification metadata"
    )


class LoginAttemptType(graphene.ObjectType):
    """Login attempt information."""
    
    class Meta:
        description = "Record of a login attempt (successful or failed)"
    
    id = graphene.ID(
        required=True,
        description="Unique identifier for the login attempt"
    )
    
    user_id = graphene.ID(
        description="ID of the user (if identified)"
    )
    
    username = graphene.String(
        description="Username used in the attempt"
    )
    
    email = graphene.String(
        description="Email used in the attempt"
    )
    
    was_successful = graphene.Boolean(
        required=True,
        description="Whether the login attempt was successful"
    )
    
    failure_reason = graphene.Field(
        LoginFailureReasonEnum,
        description="Reason for failure (if unsuccessful)"
    )
    
    ip_address = graphene.String(
        description="IP address of the login attempt"
    )
    
    user_agent = graphene.String(
        description="User agent string of the login attempt"
    )
    
    device_info = graphene.Field(
        DeviceInfoType,
        description="Information about the device used"
    )
    
    location = graphene.Field(
        GeolocationResponse,
        description="Geographic location of the attempt"
    )
    
    authentication_methods = graphene.List(
        AuthenticationMethodEnum,
        description="Authentication methods attempted"
    )
    
    mfa_required = graphene.Boolean(
        description="Whether MFA was required for this attempt"
    )
    
    mfa_completed = graphene.Boolean(
        description="Whether MFA was successfully completed"
    )
    
    risk_level = graphene.Field(
        RiskLevelEnum,
        description="Risk assessment level for this attempt"
    )
    
    blocked_by_policy = graphene.Boolean(
        default_value=False,
        description="Whether the attempt was blocked by security policy"
    )
    
    session_id = graphene.ID(
        description="ID of the session created (if successful)"
    )
    
    attempted_at = graphene.DateTime(
        required=True,
        description="When the login attempt occurred"
    )


# Input Types for Authentication Operations

class DeviceInfoInput(graphene.InputObjectType):
    """Input type for device information."""
    
    class Meta:
        description = "Input for device information"
    
    fingerprint = graphene.String(
        description="Unique device fingerprint"
    )
    
    device_type = graphene.Field(
        DeviceTypeEnum,
        description="Type of device"
    )
    
    operating_system = graphene.String(
        description="Operating system name and version"
    )
    
    browser = graphene.String(
        description="Browser name and version"
    )
    
    user_agent = graphene.String(
        description="Full user agent string"
    )
    
    screen_resolution = graphene.String(
        description="Screen resolution of the device"
    )
    
    timezone = graphene.String(
        description="Device timezone"
    )
    
    location = graphene.Field(
        GeolocationInput,
        description="Geographic location of the device"
    )


class AuthenticationInput(graphene.InputObjectType):
    """Input type for authentication requests."""
    
    class Meta:
        description = "Input for user authentication"
    
    username = graphene.String(
        description="Username for authentication"
    )
    
    email = graphene.String(
        description="Email for authentication"
    )
    
    password = graphene.String(
        required=True,
        description="Password for authentication"
    )
    
    mfa_code = graphene.String(
        description="Multi-factor authentication code"
    )
    
    mfa_method = graphene.Field(
        MFAMethodEnum,
        description="MFA method being used"
    )
    
    remember_device = graphene.Boolean(
        default_value=False,
        description="Whether to remember this device for future logins"
    )
    
    device_info = graphene.Field(
        DeviceInfoInput,
        description="Information about the device being used"
    )


class MFASetupInput(graphene.InputObjectType):
    """Input type for MFA device setup."""
    
    class Meta:
        description = "Input for setting up MFA device"
    
    device_name = graphene.String(
        required=True,
        description="User-friendly name for the device"
    )
    
    method = graphene.Field(
        MFAMethodEnum,
        required=True,
        description="MFA method for this device"
    )
    
    phone_number = graphene.String(
        description="Phone number for SMS-based MFA"
    )
    
    email = graphene.String(
        description="Email address for email-based MFA"
    )
    
    verification_code = graphene.String(
        description="Verification code to confirm setup"
    )
    
    is_primary = graphene.Boolean(
        default_value=False,
        description="Whether this should be the primary MFA device"
    )


class SessionCreateInput(graphene.InputObjectType):
    """Input type for creating a session."""
    
    class Meta:
        description = "Input for creating a new session"
    
    session_type = graphene.Field(
        SessionTypeEnum,
        default_value=SessionTypeEnum.WEB,
        description="Type of session to create"
    )
    
    device_info = graphene.Field(
        DeviceInfoInput,
        description="Information about the device"
    )
    
    remember_me = graphene.Boolean(
        default_value=False,
        description="Whether to create a long-lived session"
    )
    
    timeout_seconds = graphene.Int(
        description="Custom timeout for this session in seconds"
    )


class SessionUpdateInput(graphene.InputObjectType):
    """Input type for updating a session."""
    
    class Meta:
        description = "Input for updating session information"
    
    extend_expiry = graphene.Boolean(
        description="Whether to extend the session expiry"
    )
    
    mark_trusted_device = graphene.Boolean(
        description="Whether to mark the device as trusted"
    )


class ApiKeyCreateInput(graphene.InputObjectType):
    """Input type for creating an API key."""
    
    class Meta:
        description = "Input for creating a new API key"
    
    name = graphene.String(
        required=True,
        description="User-friendly name for the API key"
    )
    
    scopes = graphene.List(
        graphene.String,
        description="List of permission scopes for this API key"
    )
    
    expires_in_days = graphene.Int(
        description="Number of days until the API key expires"
    )
    
    rate_limit = graphene.Int(
        description="Rate limit for this API key (requests per hour)"
    )
    
    allowed_ips = graphene.List(
        graphene.String,
        description="List of IP addresses allowed to use this key"
    )


class ApiKeyUpdateInput(graphene.InputObjectType):
    """Input type for updating an API key."""
    
    class Meta:
        description = "Input for updating an API key"
    
    name = graphene.String(
        description="Updated name for the API key"
    )
    
    is_active = graphene.Boolean(
        description="Whether the API key should be active"
    )
    
    rate_limit = graphene.Int(
        description="Updated rate limit for this API key"
    )
    
    allowed_ips = graphene.List(
        graphene.String,
        description="Updated list of allowed IP addresses"
    )


# Filter Input Types

class SessionFilterInput(FilterInput):
    """Input type for filtering sessions."""
    
    class Meta:
        description = "Filters for querying sessions"
    
    user_id = graphene.ID(
        description="Filter by user ID"
    )
    
    status = graphene.List(
        SessionStatusEnum,
        description="Filter by session status"
    )
    
    session_type = graphene.List(
        SessionTypeEnum,
        description="Filter by session type"
    )
    
    device_type = graphene.List(
        DeviceTypeEnum,
        description="Filter by device type"
    )
    
    ip_address = graphene.String(
        description="Filter by IP address"
    )
    
    is_current = graphene.Boolean(
        description="Filter by current session status"
    )
    
    started_at = graphene.Field(
        DateRangeInput,
        description="Filter by session start date range"
    )
    
    last_activity = graphene.Field(
        DateRangeInput,
        description="Filter by last activity date range"
    )


class MFADeviceFilterInput(FilterInput):
    """Input type for filtering MFA devices."""
    
    class Meta:
        description = "Filters for querying MFA devices"
    
    user_id = graphene.ID(
        description="Filter by user ID"
    )
    
    method = graphene.List(
        MFAMethodEnum,
        description="Filter by MFA method"
    )
    
    is_primary = graphene.Boolean(
        description="Filter by primary device status"
    )
    
    is_verified = graphene.Boolean(
        description="Filter by verification status"
    )
    
    is_active = graphene.Boolean(
        description="Filter by active status"
    )


class ApiKeyFilterInput(FilterInput):
    """Input type for filtering API keys."""
    
    class Meta:
        description = "Filters for querying API keys"
    
    user_id = graphene.ID(
        description="Filter by user ID"
    )
    
    is_active = graphene.Boolean(
        description="Filter by active status"
    )
    
    scopes = graphene.List(
        graphene.String,
        description="Filter by required scopes"
    )
    
    expires_at = graphene.Field(
        DateRangeInput,
        description="Filter by expiration date range"
    )


class LoginAttemptFilterInput(FilterInput):
    """Input type for filtering login attempts."""
    
    class Meta:
        description = "Filters for querying login attempts"
    
    user_id = graphene.ID(
        description="Filter by user ID"
    )
    
    username = graphene.String(
        description="Filter by username"
    )
    
    was_successful = graphene.Boolean(
        description="Filter by success status"
    )
    
    failure_reason = graphene.List(
        LoginFailureReasonEnum,
        description="Filter by failure reason"
    )
    
    ip_address = graphene.String(
        description="Filter by IP address"
    )
    
    risk_level = graphene.List(
        RiskLevelEnum,
        description="Filter by risk level"
    )
    
    attempted_at = graphene.Field(
        DateRangeInput,
        description="Filter by attempt date range"
    )


# Connection Types for Relay Pagination

class SessionEdge(graphene.ObjectType):
    """Session edge for Relay connections."""
    
    class Meta:
        interfaces = (EdgeType,)
        description = "Session edge containing cursor and node"
    
    node = graphene.Field(
        SessionType,
        description="The session node"
    )
    
    cursor = graphene.String(
        required=True,
        description="Cursor for this edge"
    )


class SessionConnection(graphene.ObjectType):
    """Session connection for Relay pagination."""
    
    class Meta:
        interfaces = (ConnectionType,)
        description = "Session connection with edges and page info"
    
    edges = graphene.List(
        SessionEdge,
        description="List of session edges"
    )
    
    page_info = graphene.Field(
        PageInfoType,
        required=True,
        description="Pagination information"
    )
    
    total_count = graphene.Int(
        description="Total number of sessions matching the query"
    )


# Export all types
__all__ = [
    "ApiKeyCreateInput",
    "ApiKeyFilterInput",
    "ApiKeyType",
    "ApiKeyUpdateInput",
    "AuthenticationInput",
    "DeviceInfoInput",
    "DeviceInfoType",
    "LoginAttemptFilterInput",
    "LoginAttemptType",
    "MFADeviceFilterInput",
    "MFADeviceType",
    "MFASetupInput",
    "SessionConnection",
    "SessionCreateInput",
    "SessionEdge",
    "SessionFilterInput",
    "SessionType",
    "SessionUpdateInput",
]