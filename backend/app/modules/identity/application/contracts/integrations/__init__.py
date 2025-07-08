"""
Identity domain integration contracts.

Defines comprehensive integration contracts for external systems including
SSO providers, API specifications, webhook contracts, directory services,
and third-party service integrations.
"""

# API Contracts
from .api_contracts import (
    APIConfiguration,
    APIDocumentationContract,
    APIEndpoint,
    APIError,
    APIErrorType,
    APIGatewayContract,
    APIMethod,
    APIRequest,
    APIResponse,
    APISecurityContract,
    APIVersion,
    AuthenticationAPIContract,
    AuthenticationMethod,
    AuthorizationAPIContract,
    IdentityAPIContract,
    RateLimitType,
    UserManagementAPIContract,
)

# SSO Contracts
from .sso_contracts import (
    LDAPAuthMethod,
    LDAPConfiguration,
    LDAPContract,
    OAuthConfiguration,
    OAuthContract,
    OAuthGrantType,
    OpenIDConnectConfiguration,
    OpenIDConnectContract,
    OpenIDScope,
    SAMLBinding,
    SAMLConfiguration,
    SAMLContract,
    SAMLNameIDFormat,
    SSOAuthenticationRequest,
    SSOAuthenticationResponse,
    SSOLogoutRequest,
    SSOLogoutResponse,
)

# Webhook Contracts
from .webhook_contracts import (
    AuditWebhookContract,
    ComplianceWebhookContract,
    RetryStrategy,
    SecurityWebhookContract,
    UserWebhookContract,
    WebhookConfiguration,
    WebhookDelivery,
    WebhookDeliveryContract,
    WebhookEvent,
    WebhookEventType,
    WebhookFilter,
    WebhookManagementContract,
    WebhookSignatureMethod,
    WebhookStatus,
)

__all__ = [
    "APIConfiguration",
    "APIDocumentationContract",
    "APIEndpoint",
    "APIError",
    "APIErrorType",
    "APIGatewayContract",
    "APIMethod",
    "APIRequest",
    "APIResponse",
    "APISecurityContract",
    # API Integration Contracts
    "APIVersion",
    "AuditWebhookContract",
    "AuthenticationAPIContract",
    "AuthenticationMethod",
    "AuthorizationAPIContract",
    "ComplianceWebhookContract",
    "IdentityAPIContract",
    "LDAPAuthMethod",
    "LDAPConfiguration",
    "LDAPContract",
    "OAuthConfiguration",
    "OAuthContract",
    "OAuthGrantType",
    "OpenIDConnectConfiguration",
    "OpenIDConnectContract",
    "OpenIDScope",
    "RateLimitType",
    "RetryStrategy",
    # SSO Integration Contracts
    "SAMLBinding",
    "SAMLConfiguration",
    "SAMLContract",
    "SAMLNameIDFormat",
    "SSOAuthenticationRequest",
    "SSOAuthenticationResponse",
    "SSOLogoutRequest",
    "SSOLogoutResponse",
    "SecurityWebhookContract",
    "UserManagementAPIContract",
    "UserWebhookContract",
    "WebhookConfiguration",
    "WebhookDelivery",
    "WebhookDeliveryContract",
    "WebhookEvent",
    # Webhook Contracts
    "WebhookEventType",
    "WebhookFilter",
    "WebhookManagementContract",
    "WebhookSignatureMethod",
    "WebhookStatus",
]