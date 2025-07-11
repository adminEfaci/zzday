"""
User GraphQL Type Definitions for Identity Module

This module contains all GraphQL types related to users, including
user profiles, preferences, contact information, and related input types.
"""


import graphene

from .common_types import (
    AddressInput,
    AddressType,
    AuditMetadataType,
    ConnectionType,
    DateRangeInput,
    EdgeType,
    FilterInput,
    MetadataType,
    PageInfoType,
    PaginationType,
    SortInput,
)
from .enums import (
    AccountTypeEnum,
    DateFormatEnum,
    DepartmentEnum,
    LanguageEnum,
    MFAMethodEnum,
    NotificationChannelEnum,
    RelationshipEnum,
    SortDirection,
    TimeFormatEnum,
    UserStatusEnum,
)


class EmergencyContactType(graphene.ObjectType):
    """Emergency contact information."""
    
    class Meta:
        description = "Emergency contact information for a user"
    
    id = graphene.ID(
        required=True,
        description="Unique identifier for the emergency contact"
    )
    
    name = graphene.String(
        required=True,
        description="Full name of the emergency contact"
    )
    
    relationship = graphene.Field(
        RelationshipEnum,
        required=True,
        description="Relationship to the user"
    )
    
    phone = graphene.String(
        required=True,
        description="Primary phone number"
    )
    
    mobile = graphene.String(
        description="Mobile phone number"
    )
    
    email = graphene.String(
        description="Email address"
    )
    
    address = graphene.Field(
        AddressType,
        description="Address information"
    )
    
    is_primary = graphene.Boolean(
        default_value=False,
        description="Whether this is the primary emergency contact"
    )
    
    notes = graphene.String(
        description="Additional notes about the contact"
    )
    
    metadata = graphene.Field(
        MetadataType,
        required=True,
        description="Creation and modification metadata"
    )


class UserPreferencesType(graphene.ObjectType):
    """User preferences and settings."""
    
    class Meta:
        description = "User preferences and application settings"
    
    language = graphene.Field(
        LanguageEnum,
        default_value=LanguageEnum.EN,
        description="Preferred language for the interface"
    )
    
    date_format = graphene.Field(
        DateFormatEnum,
        default_value=DateFormatEnum.YYYY_MM_DD,
        description="Preferred date format"
    )
    
    time_format = graphene.Field(
        TimeFormatEnum,
        default_value=TimeFormatEnum.TWENTY_FOUR_HOUR,
        description="Preferred time format"
    )
    
    timezone = graphene.String(
        default_value="UTC",
        description="User's timezone"
    )
    
    notification_channels = graphene.List(
        NotificationChannelEnum,
        description="Preferred notification channels"
    )
    
    email_notifications = graphene.Boolean(
        default_value=True,
        description="Whether to receive email notifications"
    )
    
    sms_notifications = graphene.Boolean(
        default_value=False,
        description="Whether to receive SMS notifications"
    )
    
    push_notifications = graphene.Boolean(
        default_value=True,
        description="Whether to receive push notifications"
    )
    
    marketing_emails = graphene.Boolean(
        default_value=False,
        description="Whether to receive marketing emails"
    )
    
    two_factor_required = graphene.Boolean(
        default_value=False,
        description="Whether two-factor authentication is required"
    )
    
    session_timeout = graphene.Int(
        default_value=3600,
        description="Session timeout in seconds"
    )
    
    dark_mode = graphene.Boolean(
        default_value=False,
        description="Whether to use dark mode interface"
    )
    
    compact_view = graphene.Boolean(
        default_value=False,
        description="Whether to use compact view layout"
    )
    
    metadata = graphene.Field(
        MetadataType,
        required=True,
        description="Creation and modification metadata"
    )


class UserProfileType(graphene.ObjectType):
    """User profile information."""
    
    class Meta:
        description = "Extended user profile information"
    
    id = graphene.ID(
        required=True,
        description="Unique identifier for the profile"
    )
    
    user_id = graphene.ID(
        required=True,
        description="ID of the associated user"
    )
    
    first_name = graphene.String(
        description="User's first name"
    )
    
    last_name = graphene.String(
        description="User's last name"
    )
    
    middle_name = graphene.String(
        description="User's middle name"
    )
    
    display_name = graphene.String(
        description="Display name for the user"
    )
    
    avatar_url = graphene.String(
        description="URL to user's avatar image"
    )
    
    bio = graphene.String(
        description="User's biography or description"
    )
    
    title = graphene.String(
        description="Job title or position"
    )
    
    department = graphene.Field(
        DepartmentEnum,
        description="Department the user belongs to"
    )
    
    manager_id = graphene.ID(
        description="ID of the user's manager"
    )
    
    employee_id = graphene.String(
        description="Employee identification number"
    )
    
    hire_date = graphene.Date(
        description="Date when the user was hired"
    )
    
    date_of_birth = graphene.Date(
        description="User's date of birth"
    )
    
    gender = graphene.String(
        description="User's gender"
    )
    
    phone = graphene.String(
        description="Primary phone number"
    )
    
    mobile = graphene.String(
        description="Mobile phone number"
    )
    
    emergency_contacts = graphene.List(
        EmergencyContactType,
        description="List of emergency contacts"
    )
    
    address = graphene.Field(
        AddressType,
        description="Primary address"
    )
    
    secondary_addresses = graphene.List(
        AddressType,
        description="Additional addresses"
    )
    
    social_security_number = graphene.String(
        description="Social security or national ID number (encrypted)"
    )
    
    driver_license = graphene.String(
        description="Driver's license number"
    )
    
    passport_number = graphene.String(
        description="Passport number"
    )
    
    metadata = graphene.Field(
        MetadataType,
        required=True,
        description="Creation and modification metadata"
    )


class UserSummaryType(graphene.ObjectType):
    """Minimal user information for lists and references."""
    
    class Meta:
        description = "Summary user information for listings and references"
    
    id = graphene.ID(
        required=True,
        description="Unique identifier for the user"
    )
    
    username = graphene.String(
        required=True,
        description="User's unique username"
    )
    
    email = graphene.String(
        required=True,
        description="User's email address"
    )
    
    display_name = graphene.String(
        description="Display name for the user"
    )
    
    first_name = graphene.String(
        description="User's first name"
    )
    
    last_name = graphene.String(
        description="User's last name"
    )
    
    avatar_url = graphene.String(
        description="URL to user's avatar image"
    )
    
    status = graphene.Field(
        UserStatusEnum,
        required=True,
        description="Current status of the user account"
    )
    
    account_type = graphene.Field(
        AccountTypeEnum,
        required=True,
        description="Type of user account"
    )
    
    is_active = graphene.Boolean(
        required=True,
        description="Whether the user account is active"
    )
    
    last_login = graphene.DateTime(
        description="Last login timestamp"
    )
    
    created_at = graphene.DateTime(
        required=True,
        description="When the user account was created"
    )


class UserType(graphene.ObjectType):
    """Complete user information."""
    
    class Meta:
        description = "Complete user account information"
    
    id = graphene.ID(
        required=True,
        description="Unique identifier for the user"
    )
    
    username = graphene.String(
        required=True,
        description="User's unique username"
    )
    
    email = graphene.String(
        required=True,
        description="User's email address"
    )
    
    email_verified = graphene.Boolean(
        default_value=False,
        description="Whether the email address has been verified"
    )
    
    status = graphene.Field(
        UserStatusEnum,
        required=True,
        description="Current status of the user account"
    )
    
    account_type = graphene.Field(
        AccountTypeEnum,
        required=True,
        description="Type of user account"
    )
    
    is_active = graphene.Boolean(
        required=True,
        description="Whether the user account is active"
    )
    
    is_staff = graphene.Boolean(
        default_value=False,
        description="Whether the user is a staff member"
    )
    
    is_superuser = graphene.Boolean(
        default_value=False,
        description="Whether the user has superuser privileges"
    )
    
    mfa_enabled = graphene.Boolean(
        default_value=False,
        description="Whether multi-factor authentication is enabled"
    )
    
    mfa_methods = graphene.List(
        MFAMethodEnum,
        description="List of enabled MFA methods"
    )
    
    password_expires_at = graphene.DateTime(
        description="When the current password expires"
    )
    
    last_login = graphene.DateTime(
        description="Last successful login timestamp"
    )
    
    last_password_change = graphene.DateTime(
        description="When the password was last changed"
    )
    
    failed_login_attempts = graphene.Int(
        default_value=0,
        description="Number of consecutive failed login attempts"
    )
    
    lockout_until = graphene.DateTime(
        description="Account lockout expiration time"
    )
    
    profile = graphene.Field(
        UserProfileType,
        description="Extended profile information"
    )
    
    preferences = graphene.Field(
        UserPreferencesType,
        description="User preferences and settings"
    )
    
    roles = graphene.List(
        "RoleType",
        description="Roles assigned to the user"
    )
    
    permissions = graphene.List(
        "PermissionType",
        description="Direct permissions granted to the user"
    )
    
    active_sessions_count = graphene.Int(
        description="Number of currently active sessions"
    )
    
    metadata = graphene.Field(
        AuditMetadataType,
        required=True,
        description="Creation, modification, and audit metadata"
    )


# Input Types for User Operations

class EmergencyContactInput(graphene.InputObjectType):
    """Input type for emergency contact information."""
    
    class Meta:
        description = "Input for creating or updating emergency contact"
    
    name = graphene.String(
        required=True,
        description="Full name of the emergency contact"
    )
    
    relationship = graphene.Field(
        RelationshipEnum,
        required=True,
        description="Relationship to the user"
    )
    
    phone = graphene.String(
        required=True,
        description="Primary phone number"
    )
    
    mobile = graphene.String(
        description="Mobile phone number"
    )
    
    email = graphene.String(
        description="Email address"
    )
    
    address = graphene.Field(
        AddressInput,
        description="Address information"
    )
    
    is_primary = graphene.Boolean(
        default_value=False,
        description="Whether this is the primary emergency contact"
    )
    
    notes = graphene.String(
        description="Additional notes about the contact"
    )


class UserPreferencesInput(graphene.InputObjectType):
    """Input type for user preferences."""
    
    class Meta:
        description = "Input for updating user preferences"
    
    language = graphene.Field(
        LanguageEnum,
        description="Preferred language for the interface"
    )
    
    date_format = graphene.Field(
        DateFormatEnum,
        description="Preferred date format"
    )
    
    time_format = graphene.Field(
        TimeFormatEnum,
        description="Preferred time format"
    )
    
    timezone = graphene.String(
        description="User's timezone"
    )
    
    notification_channels = graphene.List(
        NotificationChannelEnum,
        description="Preferred notification channels"
    )
    
    email_notifications = graphene.Boolean(
        description="Whether to receive email notifications"
    )
    
    sms_notifications = graphene.Boolean(
        description="Whether to receive SMS notifications"
    )
    
    push_notifications = graphene.Boolean(
        description="Whether to receive push notifications"
    )
    
    marketing_emails = graphene.Boolean(
        description="Whether to receive marketing emails"
    )
    
    session_timeout = graphene.Int(
        description="Session timeout in seconds"
    )
    
    dark_mode = graphene.Boolean(
        description="Whether to use dark mode interface"
    )
    
    compact_view = graphene.Boolean(
        description="Whether to use compact view layout"
    )


class UserProfileInput(graphene.InputObjectType):
    """Input type for user profile information."""
    
    class Meta:
        description = "Input for creating or updating user profile"
    
    first_name = graphene.String(
        description="User's first name"
    )
    
    last_name = graphene.String(
        description="User's last name"
    )
    
    middle_name = graphene.String(
        description="User's middle name"
    )
    
    display_name = graphene.String(
        description="Display name for the user"
    )
    
    bio = graphene.String(
        description="User's biography or description"
    )
    
    title = graphene.String(
        description="Job title or position"
    )
    
    department = graphene.Field(
        DepartmentEnum,
        description="Department the user belongs to"
    )
    
    manager_id = graphene.ID(
        description="ID of the user's manager"
    )
    
    employee_id = graphene.String(
        description="Employee identification number"
    )
    
    hire_date = graphene.Date(
        description="Date when the user was hired"
    )
    
    date_of_birth = graphene.Date(
        description="User's date of birth"
    )
    
    gender = graphene.String(
        description="User's gender"
    )
    
    phone = graphene.String(
        description="Primary phone number"
    )
    
    mobile = graphene.String(
        description="Mobile phone number"
    )
    
    emergency_contacts = graphene.List(
        EmergencyContactInput,
        description="List of emergency contacts"
    )
    
    address = graphene.Field(
        AddressInput,
        description="Primary address"
    )
    
    secondary_addresses = graphene.List(
        AddressInput,
        description="Additional addresses"
    )


class UserCreateInput(graphene.InputObjectType):
    """Input type for creating a new user."""
    
    class Meta:
        description = "Input for creating a new user account"
    
    username = graphene.String(
        required=True,
        description="Unique username for the user"
    )
    
    email = graphene.String(
        required=True,
        description="Email address for the user"
    )
    
    password = graphene.String(
        required=True,
        description="Initial password for the user"
    )
    
    account_type = graphene.Field(
        AccountTypeEnum,
        default_value=AccountTypeEnum.INDIVIDUAL,
        description="Type of user account"
    )
    
    profile = graphene.Field(
        UserProfileInput,
        description="Initial profile information"
    )
    
    preferences = graphene.Field(
        UserPreferencesInput,
        description="Initial preferences"
    )
    
    send_welcome_email = graphene.Boolean(
        default_value=True,
        description="Whether to send a welcome email"
    )
    
    require_email_verification = graphene.Boolean(
        default_value=True,
        description="Whether email verification is required"
    )


class UserUpdateInput(graphene.InputObjectType):
    """Input type for updating an existing user."""
    
    class Meta:
        description = "Input for updating an existing user account"
    
    username = graphene.String(
        description="Updated username (must be unique)"
    )
    
    email = graphene.String(
        description="Updated email address"
    )
    
    status = graphene.Field(
        UserStatusEnum,
        description="Updated account status"
    )
    
    account_type = graphene.Field(
        AccountTypeEnum,
        description="Updated account type"
    )
    
    is_staff = graphene.Boolean(
        description="Whether the user is a staff member"
    )
    
    profile = graphene.Field(
        UserProfileInput,
        description="Updated profile information"
    )
    
    preferences = graphene.Field(
        UserPreferencesInput,
        description="Updated preferences"
    )


class UserFilterInput(FilterInput):
    """Input type for filtering users."""
    
    class Meta:
        description = "Filters for querying users"
    
    username = graphene.String(
        description="Filter by username (partial match)"
    )
    
    email = graphene.String(
        description="Filter by email address (partial match)"
    )
    
    status = graphene.List(
        UserStatusEnum,
        description="Filter by account status"
    )
    
    account_type = graphene.List(
        AccountTypeEnum,
        description="Filter by account type"
    )
    
    is_active = graphene.Boolean(
        description="Filter by active status"
    )
    
    is_staff = graphene.Boolean(
        description="Filter by staff status"
    )
    
    mfa_enabled = graphene.Boolean(
        description="Filter by MFA enabled status"
    )
    
    department = graphene.List(
        DepartmentEnum,
        description="Filter by department"
    )
    
    role_ids = graphene.List(
        graphene.ID,
        description="Filter by assigned role IDs"
    )
    
    last_login = graphene.Field(
        DateRangeInput,
        description="Filter by last login date range"
    )


class UserSortInput(SortInput):
    """Input type for sorting users."""
    
    class Meta:
        description = "Sorting options for user queries"
    
    # Override to provide specific sort field options
    sort_by = graphene.String(
        description="Field to sort by: username, email, created_at, last_login, status"
    )
    
    direction = graphene.Field(
        SortDirection,
        default_value=SortDirection.ASC,
        description="Sort direction"
    )


# Connection Types for Relay Pagination

class UserEdge(graphene.ObjectType):
    """User edge for Relay connections."""
    
    class Meta:
        interfaces = (EdgeType,)
        description = "User edge containing cursor and node"
    
    node = graphene.Field(
        UserType,
        description="The user node"
    )
    
    cursor = graphene.String(
        required=True,
        description="Cursor for this edge"
    )


class UserConnection(graphene.ObjectType):
    """User connection for Relay pagination."""
    
    class Meta:
        interfaces = (ConnectionType,)
        description = "User connection with edges and page info"
    
    edges = graphene.List(
        UserEdge,
        description="List of user edges"
    )
    
    page_info = graphene.Field(
        PageInfoType,
        required=True,
        description="Pagination information"
    )
    
    total_count = graphene.Int(
        description="Total number of users matching the query"
    )


class UserListResponse(graphene.ObjectType):
    """Response type for user list queries."""
    
    class Meta:
        description = "Response containing users and pagination information"
    
    users = graphene.List(
        UserType,
        required=True,
        description="List of users"
    )
    
    pagination = graphene.Field(
        PaginationType,
        required=True,
        description="Pagination information"
    )
    
    total_count = graphene.Int(
        required=True,
        description="Total number of users matching the query"
    )


# Export all types
__all__ = [
    "EmergencyContactInput",
    "EmergencyContactType",
    "UserConnection",
    "UserCreateInput",
    "UserEdge",
    "UserFilterInput",
    "UserListResponse",
    "UserPreferencesInput",
    "UserPreferencesType",
    "UserProfileInput",
    "UserProfileType",
    "UserSortInput",
    "UserSummaryType",
    "UserType",
    "UserUpdateInput",
]