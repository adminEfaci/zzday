"""
API Integration Contracts.

Defines comprehensive contracts for exposing identity services through REST APIs
with enterprise-grade security, versioning, and integration capabilities.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID


class APIVersion(Enum):
    """API version enumeration."""
    V1 = "v1"
    V2 = "v2"
    BETA = "beta"


class APIMethod(Enum):
    """HTTP methods for API operations."""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class AuthenticationMethod(Enum):
    """API authentication methods."""
    JWT_BEARER = "jwt_bearer"
    API_KEY = "api_key"
    OAUTH2 = "oauth2"
    BASIC_AUTH = "basic_auth"
    MUTUAL_TLS = "mutual_tls"
    HMAC_SIGNATURE = "hmac_signature"


class RateLimitType(Enum):
    """Rate limiting types."""
    REQUESTS_PER_MINUTE = "requests_per_minute"
    REQUESTS_PER_HOUR = "requests_per_hour"
    REQUESTS_PER_DAY = "requests_per_day"
    BANDWIDTH_LIMIT = "bandwidth_limit"
    CONCURRENT_REQUESTS = "concurrent_requests"


class APIErrorType(Enum):
    """API error types."""
    VALIDATION_ERROR = "validation_error"
    AUTHENTICATION_ERROR = "authentication_error"
    AUTHORIZATION_ERROR = "authorization_error"
    NOT_FOUND = "not_found"
    CONFLICT = "conflict"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    INTERNAL_ERROR = "internal_error"
    SERVICE_UNAVAILABLE = "service_unavailable"


@dataclass
class APIConfiguration:
    """API configuration parameters."""
    
    # Basic Configuration
    base_url: str
    version: APIVersion
    title: str
    description: str
    
    # Authentication
    authentication_methods: list[AuthenticationMethod]
    default_auth_method: AuthenticationMethod
    
    # Rate Limiting
    default_rate_limits: dict[RateLimitType, int]
    per_user_rate_limits: dict[str, dict[RateLimitType, int]]

    # JWT Configuration
    jwt_audience: str
    jwt_issuer: str

    # Security
    cors_origins: list[str]
    cors_methods: list[str]
    cors_headers: list[str]

    cors_credentials: bool = True
    jwt_algorithm: str = "RS256"

    # Request/Response
    max_request_size: int = 10 * 1024 * 1024  # 10MB
    request_timeout: int = 30
    default_page_size: int = 20
    max_page_size: int = 100
    
    # API Keys
    api_key_header: str = "X-API-Key"
    api_key_prefix: str = "Bearer"
    

    
    # OpenAPI/Swagger
    openapi_enabled: bool = True
    swagger_ui_enabled: bool = True
    redoc_enabled: bool = True
    
    # Monitoring
    metrics_enabled: bool = True
    logging_enabled: bool = True
    tracing_enabled: bool = True


@dataclass
class APIRequest:
    """Generic API request structure."""
    
    # Request identification
    request_id: str
    correlation_id: str | None
    
    # HTTP details
    method: APIMethod
    path: str
    query_params: dict[str, Any]
    headers: dict[str, str]
    body: dict[str, Any] | None
    
    # Authentication
    auth_method: AuthenticationMethod | None
    api_key: str | None
    bearer_token: str | None
    
    # Client information
    client_ip: str
    user_agent: str
    client_id: str | None
    
    # Rate limiting
    rate_limit_key: str | None
    
    # Security context
    user_id: UUID | None
    session_id: UUID | None
    permissions: list[str]
    scopes: list[str]

    # Request metadata
    timestamp: datetime
    content_type: str = "application/json"
    accept: str = "application/json"


@dataclass
class APIResponse:
    """Generic API response structure."""
    
    # Response identification
    request_id: str
    correlation_id: str | None
    
    # HTTP response
    status_code: int
    headers: dict[str, str]
    body: dict[str, Any] | None
    
    # Metadata
    timestamp: datetime
    execution_time_ms: int
    
    # Pagination (for list responses)
    total_count: int | None = None
    page: int | None = None
    page_size: int | None = None
    has_next: bool | None = None
    
    # Rate limiting
    rate_limit_remaining: int | None = None
    rate_limit_reset: datetime | None = None
    
    # Caching
    cache_control: str | None = None
    etag: str | None = None
    last_modified: datetime | None = None


@dataclass
class APIError:
    """API error response structure."""
    
    # Error identification
    error_id: str
    error_type: APIErrorType
    error_code: str
    
    # Error details
    message: str
    details: dict[str, Any] | None
    
    # Context
    field_errors: dict[str, list[str]] | None
    stack_trace: str | None
    
    # Request context
    request_id: str
    timestamp: datetime
    
    # Help information
    documentation_url: str | None
    support_contact: str | None


@dataclass
class APIEndpoint:
    """API endpoint definition."""
    
    # Endpoint details
    path: str
    method: APIMethod
    operation_id: str
    summary: str
    description: str
    
    # Authentication/Authorization
    authentication_required: bool
    required_permissions: list[str]
    required_scopes: list[str]
    
    # Rate limiting
    rate_limits: dict[RateLimitType, int] | None
    
    # Request/Response schemas
    request_schema: dict[str, Any] | None
    response_schema: dict[int, dict[str, Any]]
    
    # Parameters
    path_parameters: list[dict[str, Any]]
    query_parameters: list[dict[str, Any]]
    header_parameters: list[dict[str, Any]]
    
    # OpenAPI metadata
    tags: list[str]
    external_docs: dict[str, str] | None
    deprecated: bool = False


class IdentityAPIContract(ABC):
    """Contract for core identity API operations."""
    
    @abstractmethod
    async def health_check(
        self,
        request: APIRequest
    ) -> APIResponse:
        """Health check endpoint."""
    
    @abstractmethod
    async def get_api_info(
        self,
        request: APIRequest
    ) -> APIResponse:
        """Get API information and capabilities."""
    
    @abstractmethod
    async def get_openapi_spec(
        self,
        request: APIRequest
    ) -> APIResponse:
        """Get OpenAPI specification."""
    
    @abstractmethod
    async def authenticate(
        self,
        request: APIRequest
    ) -> APIResponse:
        """Authenticate user and return tokens."""
    
    @abstractmethod
    async def refresh_token(
        self,
        request: APIRequest
    ) -> APIResponse:
        """Refresh access token."""
    
    @abstractmethod
    async def revoke_token(
        self,
        request: APIRequest
    ) -> APIResponse:
        """Revoke access or refresh token."""
    
    @abstractmethod
    async def introspect_token(
        self,
        request: APIRequest
    ) -> APIResponse:
        """Introspect token for validation."""
    
    @abstractmethod
    async def get_public_keys(
        self,
        request: APIRequest
    ) -> APIResponse:
        """Get public keys for token validation."""


class UserManagementAPIContract(ABC):
    """Contract for user management API operations."""
    
    @abstractmethod
    async def create_user(
        self,
        request: APIRequest
    ) -> APIResponse:
        """Create new user account."""
    
    @abstractmethod
    async def get_user(
        self,
        request: APIRequest,
        user_id: UUID
    ) -> APIResponse:
        """Get user by ID."""
    
    @abstractmethod
    async def update_user(
        self,
        request: APIRequest,
        user_id: UUID
    ) -> APIResponse:
        """Update user information."""
    
    @abstractmethod
    async def delete_user(
        self,
        request: APIRequest,
        user_id: UUID
    ) -> APIResponse:
        """Delete user account."""
    
    @abstractmethod
    async def list_users(
        self,
        request: APIRequest
    ) -> APIResponse:
        """List users with filtering and pagination."""
    
    @abstractmethod
    async def search_users(
        self,
        request: APIRequest
    ) -> APIResponse:
        """Search users with advanced criteria."""
    
    @abstractmethod
    async def get_user_profile(
        self,
        request: APIRequest,
        user_id: UUID
    ) -> APIResponse:
        """Get user profile information."""
    
    @abstractmethod
    async def update_user_profile(
        self,
        request: APIRequest,
        user_id: UUID
    ) -> APIResponse:
        """Update user profile."""
    
    @abstractmethod
    async def change_password(
        self,
        request: APIRequest,
        user_id: UUID
    ) -> APIResponse:
        """Change user password."""
    
    @abstractmethod
    async def reset_password(
        self,
        request: APIRequest
    ) -> APIResponse:
        """Reset user password."""
    
    @abstractmethod
    async def verify_email(
        self,
        request: APIRequest
    ) -> APIResponse:
        """Verify email address."""
    
    @abstractmethod
    async def resend_verification(
        self,
        request: APIRequest,
        user_id: UUID
    ) -> APIResponse:
        """Resend email verification."""
    
    @abstractmethod
    async def enable_user(
        self,
        request: APIRequest,
        user_id: UUID
    ) -> APIResponse:
        """Enable user account."""
    
    @abstractmethod
    async def disable_user(
        self,
        request: APIRequest,
        user_id: UUID
    ) -> APIResponse:
        """Disable user account."""
    
    @abstractmethod
    async def lock_user(
        self,
        request: APIRequest,
        user_id: UUID
    ) -> APIResponse:
        """Lock user account."""
    
    @abstractmethod
    async def unlock_user(
        self,
        request: APIRequest,
        user_id: UUID
    ) -> APIResponse:
        """Unlock user account."""


class AuthenticationAPIContract(ABC):
    """Contract for authentication API operations."""
    
    @abstractmethod
    async def login(
        self,
        request: APIRequest
    ) -> APIResponse:
        """User login with credentials."""
    
    @abstractmethod
    async def logout(
        self,
        request: APIRequest
    ) -> APIResponse:
        """User logout."""
    
    @abstractmethod
    async def logout_all(
        self,
        request: APIRequest
    ) -> APIResponse:
        """Logout from all sessions."""
    
    @abstractmethod
    async def validate_session(
        self,
        request: APIRequest
    ) -> APIResponse:
        """Validate current session."""
    
    @abstractmethod
    async def get_current_user(
        self,
        request: APIRequest
    ) -> APIResponse:
        """Get current authenticated user."""
    
    @abstractmethod
    async def mfa_setup(
        self,
        request: APIRequest
    ) -> APIResponse:
        """Setup multi-factor authentication."""
    
    @abstractmethod
    async def mfa_verify(
        self,
        request: APIRequest
    ) -> APIResponse:
        """Verify MFA code."""
    
    @abstractmethod
    async def mfa_backup_codes(
        self,
        request: APIRequest
    ) -> APIResponse:
        """Generate MFA backup codes."""
    
    @abstractmethod
    async def sso_redirect(
        self,
        request: APIRequest,
        provider: str
    ) -> APIResponse:
        """SSO redirect to external provider."""
    
    @abstractmethod
    async def sso_callback(
        self,
        request: APIRequest,
        provider: str
    ) -> APIResponse:
        """SSO callback from external provider."""
    
    @abstractmethod
    async def device_registration(
        self,
        request: APIRequest
    ) -> APIResponse:
        """Register trusted device."""
    
    @abstractmethod
    async def device_verification(
        self,
        request: APIRequest
    ) -> APIResponse:
        """Verify device registration."""


class AuthorizationAPIContract(ABC):
    """Contract for authorization API operations."""
    
    @abstractmethod
    async def check_permission(
        self,
        request: APIRequest
    ) -> APIResponse:
        """Check if user has specific permission."""
    
    @abstractmethod
    async def check_multiple_permissions(
        self,
        request: APIRequest
    ) -> APIResponse:
        """Check multiple permissions at once."""
    
    @abstractmethod
    async def get_user_permissions(
        self,
        request: APIRequest,
        user_id: UUID
    ) -> APIResponse:
        """Get all permissions for user."""
    
    @abstractmethod
    async def get_user_roles(
        self,
        request: APIRequest,
        user_id: UUID
    ) -> APIResponse:
        """Get all roles for user."""
    
    @abstractmethod
    async def assign_role(
        self,
        request: APIRequest,
        user_id: UUID
    ) -> APIResponse:
        """Assign role to user."""
    
    @abstractmethod
    async def revoke_role(
        self,
        request: APIRequest,
        user_id: UUID
    ) -> APIResponse:
        """Revoke role from user."""
    
    @abstractmethod
    async def grant_permission(
        self,
        request: APIRequest,
        user_id: UUID
    ) -> APIResponse:
        """Grant direct permission to user."""
    
    @abstractmethod
    async def revoke_permission(
        self,
        request: APIRequest,
        user_id: UUID
    ) -> APIResponse:
        """Revoke direct permission from user."""
    
    @abstractmethod
    async def create_role(
        self,
        request: APIRequest
    ) -> APIResponse:
        """Create new role."""
    
    @abstractmethod
    async def update_role(
        self,
        request: APIRequest,
        role_id: UUID
    ) -> APIResponse:
        """Update role definition."""
    
    @abstractmethod
    async def delete_role(
        self,
        request: APIRequest,
        role_id: UUID
    ) -> APIResponse:
        """Delete role."""
    
    @abstractmethod
    async def list_roles(
        self,
        request: APIRequest
    ) -> APIResponse:
        """List all available roles."""
    
    @abstractmethod
    async def create_permission(
        self,
        request: APIRequest
    ) -> APIResponse:
        """Create new permission."""
    
    @abstractmethod
    async def update_permission(
        self,
        request: APIRequest,
        permission_id: UUID
    ) -> APIResponse:
        """Update permission definition."""
    
    @abstractmethod
    async def delete_permission(
        self,
        request: APIRequest,
        permission_id: UUID
    ) -> APIResponse:
        """Delete permission."""
    
    @abstractmethod
    async def list_permissions(
        self,
        request: APIRequest
    ) -> APIResponse:
        """List all available permissions."""
    
    @abstractmethod
    async def get_resource_access(
        self,
        request: APIRequest,
        resource_id: str
    ) -> APIResponse:
        """Get access information for resource."""
    
    @abstractmethod
    async def grant_resource_access(
        self,
        request: APIRequest,
        resource_id: str
    ) -> APIResponse:
        """Grant access to resource."""
    
    @abstractmethod
    async def revoke_resource_access(
        self,
        request: APIRequest,
        resource_id: str
    ) -> APIResponse:
        """Revoke access to resource."""


class APIGatewayContract(ABC):
    """Contract for API Gateway integration."""
    
    @abstractmethod
    async def register_api(
        self,
        config: APIConfiguration,
        endpoints: list[APIEndpoint]
    ) -> bool:
        """Register API with gateway."""
    
    @abstractmethod
    async def update_api(
        self,
        api_id: str,
        config: APIConfiguration,
        endpoints: list[APIEndpoint]
    ) -> bool:
        """Update API registration."""
    
    @abstractmethod
    async def deregister_api(
        self,
        api_id: str
    ) -> bool:
        """Deregister API from gateway."""
    
    @abstractmethod
    async def validate_request(
        self,
        request: APIRequest,
        endpoint: APIEndpoint
    ) -> tuple[bool, APIError | None]:
        """Validate incoming API request."""
    
    @abstractmethod
    async def enforce_rate_limits(
        self,
        request: APIRequest
    ) -> tuple[bool, dict[str, Any] | None]:
        """Enforce rate limiting."""
    
    @abstractmethod
    async def log_request(
        self,
        request: APIRequest,
        response: APIResponse
    ) -> None:
        """Log API request/response."""
    
    @abstractmethod
    async def generate_metrics(
        self,
        request: APIRequest,
        response: APIResponse
    ) -> dict[str, Any]:
        """Generate metrics for request."""


class APIDocumentationContract(ABC):
    """Contract for API documentation generation."""
    
    @abstractmethod
    async def generate_openapi_spec(
        self,
        config: APIConfiguration,
        endpoints: list[APIEndpoint]
    ) -> dict[str, Any]:
        """Generate OpenAPI specification."""
    
    @abstractmethod
    async def generate_swagger_ui(
        self,
        openapi_spec: dict[str, Any]
    ) -> str:
        """Generate Swagger UI HTML."""
    
    @abstractmethod
    async def generate_redoc(
        self,
        openapi_spec: dict[str, Any]
    ) -> str:
        """Generate ReDoc HTML."""
    
    @abstractmethod
    async def generate_postman_collection(
        self,
        config: APIConfiguration,
        endpoints: list[APIEndpoint]
    ) -> dict[str, Any]:
        """Generate Postman collection."""
    
    @abstractmethod
    async def generate_client_sdk(
        self,
        language: str,
        openapi_spec: dict[str, Any]
    ) -> bytes:
        """Generate client SDK."""


class APISecurityContract(ABC):
    """Contract for API security operations."""
    
    @abstractmethod
    async def validate_api_key(
        self,
        api_key: str
    ) -> tuple[bool, dict[str, Any] | None]:
        """Validate API key."""
    
    @abstractmethod
    async def validate_jwt_token(
        self,
        token: str,
        config: APIConfiguration
    ) -> tuple[bool, dict[str, Any] | None]:
        """Validate JWT token."""
    
    @abstractmethod
    async def validate_oauth_token(
        self,
        token: str
    ) -> tuple[bool, dict[str, Any] | None]:
        """Validate OAuth token."""
    
    @abstractmethod
    async def verify_signature(
        self,
        request: APIRequest,
        secret: str
    ) -> bool:
        """Verify HMAC signature."""
    
    @abstractmethod
    async def encrypt_sensitive_data(
        self,
        data: dict[str, Any],
        fields: list[str]
    ) -> dict[str, Any]:
        """Encrypt sensitive fields in response."""
    
    @abstractmethod
    async def mask_sensitive_data(
        self,
        data: dict[str, Any],
        fields: list[str]
    ) -> dict[str, Any]:
        """Mask sensitive fields in logs."""
    
    @abstractmethod
    async def detect_anomalies(
        self,
        request: APIRequest
    ) -> tuple[bool, dict[str, Any] | None]:
        """Detect request anomalies."""
