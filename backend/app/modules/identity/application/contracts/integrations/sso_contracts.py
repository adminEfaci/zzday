"""
SSO Integration Contracts.

Defines comprehensive contracts for Single Sign-On integrations including
SAML, OAuth, OpenID Connect, and LDAP protocols with enterprise features.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any


class SAMLBinding(Enum):
    """SAML binding types."""
    HTTP_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    HTTP_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
    HTTP_ARTIFACT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"
    SOAP = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP"


class SAMLNameIDFormat(Enum):
    """SAML NameID format types."""
    PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
    TRANSIENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
    EMAIL = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    UNSPECIFIED = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"


class OAuthGrantType(Enum):
    """OAuth grant types."""
    AUTHORIZATION_CODE = "authorization_code"
    IMPLICIT = "implicit"
    RESOURCE_OWNER_PASSWORD = "password"
    CLIENT_CREDENTIALS = "client_credentials"
    REFRESH_TOKEN = "refresh_token"
    DEVICE_CODE = "urn:ietf:params:oauth:grant-type:device_code"
    JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"


class OpenIDScope(Enum):
    """OpenID Connect scopes."""
    OPENID = "openid"
    PROFILE = "profile"
    EMAIL = "email"
    ADDRESS = "address"
    PHONE = "phone"
    OFFLINE_ACCESS = "offline_access"


class LDAPAuthMethod(Enum):
    """LDAP authentication methods."""
    SIMPLE = "simple"
    SASL = "sasl"
    GSSAPI = "gssapi"
    DIGEST_MD5 = "digest-md5"


@dataclass
class SAMLConfiguration:
    """SAML configuration parameters."""
    
    # Required fields (no defaults) - MUST come first
    idp_entity_id: str
    idp_sso_url: str
    idp_x509_cert: str
    sp_entity_id: str
    sp_acs_url: str
    name_id_format: SAMLNameIDFormat
    binding: SAMLBinding
    attribute_mapping: dict[str, str]
    required_attributes: list[str]

    # Optional fields (with defaults) - come after required fields
    idp_slo_url: str | None = None
    idp_metadata_url: str | None = None
    sp_sls_url: str | None = None
    sp_x509_cert: str | None = None
    sp_private_key: str | None = None
    sign_requests: bool = True
    encrypt_assertions: bool = False
    want_assertions_signed: bool = True
    want_response_signed: bool = True
    signature_algorithm: str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
    digest_algorithm: str = "http://www.w3.org/2001/04/xmlenc#sha256"
    session_timeout: timedelta = timedelta(hours=8)
    force_authn: bool = False
    is_passive: bool = False


@dataclass
class OAuthConfiguration:
    """OAuth configuration parameters."""

    # Required fields (no defaults) - MUST come first
    provider_name: str
    authorization_url: str
    token_url: str
    client_id: str
    client_secret: str
    redirect_uri: str
    grant_types: list[OAuthGrantType]
    response_types: list[str]
    scopes: list[str]
    attribute_mapping: dict[str, str]

    # Optional fields (with defaults) - come after required fields
    userinfo_url: str | None = None
    revocation_url: str | None = None
    jwks_url: str | None = None
    use_pkce: bool = True
    pkce_method: str = "S256"
    state_required: bool = True
    nonce_required: bool = False
    access_token_lifetime: timedelta = timedelta(hours=1)
    refresh_token_lifetime: timedelta = timedelta(days=30)
    user_id_claim: str = "sub"
    email_claim: str = "email"
    name_claim: str = "name"


@dataclass
class OpenIDConnectConfiguration:
    """OpenID Connect configuration parameters."""

    # Required fields (no defaults) - MUST come first
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str
    jwks_uri: str
    client_id: str
    client_secret: str
    redirect_uris: list[str]
    post_logout_redirect_uris: list[str]
    response_types: list[str]
    grant_types: list[OAuthGrantType]
    scopes: list[OpenIDScope]
    claims_supported: list[str]
    id_token_claims: list[str]
    userinfo_claims: list[str]
    claim_mapping: dict[str, str]

    # Optional fields (with defaults) - come after required fields
    end_session_endpoint: str | None = None
    id_token_signing_alg: str = "RS256"
    id_token_encryption_alg: str | None = None
    userinfo_signing_alg: str | None = None
    userinfo_encryption_alg: str | None = None
    session_management_supported: bool = True
    check_session_iframe: str | None = None
    subject_type: str = "public"


@dataclass
class LDAPConfiguration:
    """LDAP configuration parameters."""

    # Required fields (no defaults) - MUST come first
    server_uri: str
    bind_dn: str
    bind_password: str
    base_dn: str
    attribute_mapping: dict[str, str]
    required_attributes: list[str]

    # Optional fields (with defaults) - come after required fields
    use_tls: bool = True
    tls_cert_path: str | None = None
    connection_timeout: int = 30
    search_timeout: int = 60
    auth_method: LDAPAuthMethod = LDAPAuthMethod.SIMPLE
    user_search_filter: str = "(uid={username})"
    user_search_base: str | None = None
    user_id_attribute: str = "uid"
    email_attribute: str = "mail"
    name_attribute: str = "cn"
    group_attribute: str = "memberOf"
    group_search_base: str | None = None
    group_search_filter: str = "(member={user_dn})"
    group_name_attribute: str = "cn"
    cache_ttl: timedelta = timedelta(minutes=15)
    enable_attribute_cache: bool = True


@dataclass
class SSOAuthenticationRequest:
    """SSO authentication request."""

    # Required fields (no defaults) - MUST come first
    request_id: str
    provider_type: str
    provider_name: str
    created_at: datetime
    client_ip: str
    user_agent: str

    # Optional fields (with defaults) - come after required fields
    relay_state: str | None = None
    force_authn: bool = False
    is_passive: bool = False
    requested_authn_context: list[str] | None = None
    csrf_token: str | None = None
    state_parameter: str | None = None


@dataclass
class SSOAuthenticationResponse:
    """SSO authentication response."""

    # Required fields (no defaults) - MUST come first
    response_id: str
    request_id: str
    provider_type: str
    provider_name: str
    success: bool
    attributes: dict[str, Any]
    issuer: str
    issued_at: datetime
    not_before: datetime
    not_on_or_after: datetime

    # Optional fields (with defaults) - come after required fields
    error_code: str | None = None
    error_description: str | None = None
    user_id: str | None = None
    username: str | None = None
    email: str | None = None
    display_name: str | None = None
    authn_context_class: str | None = None
    session_index: str | None = None
    assertion_id: str | None = None
    audience: str | None = None
    access_token: str | None = None
    refresh_token: str | None = None
    id_token: str | None = None
    token_type: str = "Bearer"
    expires_in: int | None = None


@dataclass
class SSOLogoutRequest:
    """SSO logout request."""

    # Required fields (no defaults) - MUST come first
    request_id: str
    provider_type: str
    provider_name: str
    user_id: str
    created_at: datetime
    client_ip: str

    # Optional fields (with defaults) - come after required fields
    session_index: str | None = None
    global_logout: bool = True
    post_logout_redirect_uri: str | None = None


@dataclass
class SSOLogoutResponse:
    """SSO logout response."""

    # Required fields (no defaults) - MUST come first
    response_id: str
    request_id: str
    provider_type: str
    provider_name: str
    success: bool
    processed_at: datetime

    # Optional fields (with defaults) - come after required fields
    error_code: str | None = None
    error_description: str | None = None


class SAMLContract(ABC):
    """Contract for SAML integration operations."""
    
    @abstractmethod
    async def generate_authn_request(
        self,
        config: SAMLConfiguration,
        request: SSOAuthenticationRequest
    ) -> str:
        """Generate SAML authentication request."""
    
    @abstractmethod
    async def process_authn_response(
        self,
        config: SAMLConfiguration,
        saml_response: str,
        relay_state: str | None = None
    ) -> SSOAuthenticationResponse:
        """Process SAML authentication response."""
    
    @abstractmethod
    async def generate_logout_request(
        self,
        config: SAMLConfiguration,
        request: SSOLogoutRequest
    ) -> str:
        """Generate SAML logout request."""
    
    @abstractmethod
    async def process_logout_response(
        self,
        config: SAMLConfiguration,
        saml_response: str
    ) -> SSOLogoutResponse:
        """Process SAML logout response."""
    
    @abstractmethod
    async def validate_metadata(
        self,
        metadata_xml: str
    ) -> dict[str, Any]:
        """Validate and parse SAML metadata."""
    
    @abstractmethod
    async def generate_metadata(
        self,
        config: SAMLConfiguration
    ) -> str:
        """Generate service provider metadata."""
    
    @abstractmethod
    async def decrypt_assertion(
        self,
        encrypted_assertion: str,
        private_key: str
    ) -> str:
        """Decrypt SAML assertion."""
    
    @abstractmethod
    async def verify_signature(
        self,
        signed_xml: str,
        certificate: str
    ) -> bool:
        """Verify XML digital signature."""


class OAuthContract(ABC):
    """Contract for OAuth integration operations."""
    
    @abstractmethod
    async def generate_authorization_url(
        self,
        config: OAuthConfiguration,
        request: SSOAuthenticationRequest,
        scopes: list[str] | None = None
    ) -> tuple[str, str]:
        """Generate OAuth authorization URL and state."""
    
    @abstractmethod
    async def exchange_code_for_tokens(
        self,
        config: OAuthConfiguration,
        authorization_code: str,
        state: str,
        code_verifier: str | None = None
    ) -> dict[str, Any]:
        """Exchange authorization code for tokens."""
    
    @abstractmethod
    async def refresh_access_token(
        self,
        config: OAuthConfiguration,
        refresh_token: str
    ) -> dict[str, Any]:
        """Refresh access token."""
    
    @abstractmethod
    async def revoke_token(
        self,
        config: OAuthConfiguration,
        token: str,
        token_type: str = "access_token"
    ) -> bool:
        """Revoke OAuth token."""
    
    @abstractmethod
    async def get_user_info(
        self,
        config: OAuthConfiguration,
        access_token: str
    ) -> SSOAuthenticationResponse:
        """Get user information using access token."""
    
    @abstractmethod
    async def validate_token(
        self,
        config: OAuthConfiguration,
        token: str
    ) -> dict[str, Any]:
        """Validate OAuth token."""
    
    @abstractmethod
    async def introspect_token(
        self,
        config: OAuthConfiguration,
        token: str
    ) -> dict[str, Any]:
        """Introspect OAuth token."""


class OpenIDConnectContract(ABC):
    """Contract for OpenID Connect integration operations."""
    
    @abstractmethod
    async def discover_provider(
        self,
        issuer_url: str
    ) -> dict[str, Any]:
        """Discover OpenID Connect provider configuration."""
    
    @abstractmethod
    async def generate_authorization_url(
        self,
        config: OpenIDConnectConfiguration,
        request: SSOAuthenticationRequest,
        scopes: list[OpenIDScope] | None = None,
        claims: dict[str, Any] | None = None
    ) -> tuple[str, str, str]:
        """Generate OIDC authorization URL with state and nonce."""
    
    @abstractmethod
    async def exchange_code_for_tokens(
        self,
        config: OpenIDConnectConfiguration,
        authorization_code: str,
        state: str,
        nonce: str,
        code_verifier: str | None = None
    ) -> dict[str, Any]:
        """Exchange authorization code for ID token, access token, and refresh token."""
    
    @abstractmethod
    async def validate_id_token(
        self,
        config: OpenIDConnectConfiguration,
        id_token: str,
        nonce: str,
        access_token: str | None = None
    ) -> dict[str, Any]:
        """Validate and decode ID token."""
    
    @abstractmethod
    async def get_user_info(
        self,
        config: OpenIDConnectConfiguration,
        access_token: str
    ) -> SSOAuthenticationResponse:
        """Get user information from userinfo endpoint."""
    
    @abstractmethod
    async def end_session(
        self,
        config: OpenIDConnectConfiguration,
        request: SSOLogoutRequest,
        id_token_hint: str | None = None
    ) -> str:
        """Generate end session URL for logout."""
    
    @abstractmethod
    async def get_jwks(
        self,
        jwks_uri: str
    ) -> dict[str, Any]:
        """Get JSON Web Key Set."""
    
    @abstractmethod
    async def verify_jwt_signature(
        self,
        token: str,
        jwks: dict[str, Any],
        algorithm: str = "RS256"
    ) -> bool:
        """Verify JWT signature using JWKS."""


class LDAPContract(ABC):
    """Contract for LDAP integration operations."""
    
    @abstractmethod
    async def authenticate_user(
        self,
        config: LDAPConfiguration,
        username: str,
        password: str
    ) -> SSOAuthenticationResponse:
        """Authenticate user against LDAP directory."""
    
    @abstractmethod
    async def search_user(
        self,
        config: LDAPConfiguration,
        username: str
    ) -> dict[str, Any] | None:
        """Search for user in LDAP directory."""
    
    @abstractmethod
    async def get_user_groups(
        self,
        config: LDAPConfiguration,
        user_dn: str
    ) -> list[str]:
        """Get groups for user."""
    
    @abstractmethod
    async def search_groups(
        self,
        config: LDAPConfiguration,
        search_filter: str | None = None
    ) -> list[dict[str, Any]]:
        """Search for groups in LDAP directory."""
    
    @abstractmethod
    async def bind_connection(
        self,
        config: LDAPConfiguration
    ) -> Any:
        """Establish and bind LDAP connection."""
    
    @abstractmethod
    async def test_connection(
        self,
        config: LDAPConfiguration
    ) -> bool:
        """Test LDAP connection."""
    
    @abstractmethod
    async def sync_user_attributes(
        self,
        config: LDAPConfiguration,
        user_dn: str
    ) -> dict[str, Any]:
        """Synchronize user attributes from LDAP."""
    
    @abstractmethod
    async def change_password(
        self,
        config: LDAPConfiguration,
        user_dn: str,
        old_password: str,
        new_password: str
    ) -> bool:
        """Change user password in LDAP."""
    
    @abstractmethod
    async def reset_password(
        self,
        config: LDAPConfiguration,
        user_dn: str,
        new_password: str
    ) -> bool:
        """Reset user password in LDAP."""
    
    @abstractmethod
    async def create_user(
        self,
        config: LDAPConfiguration,
        user_attributes: dict[str, Any]
    ) -> str:
        """Create user in LDAP directory."""
    
    @abstractmethod
    async def update_user(
        self,
        config: LDAPConfiguration,
        user_dn: str,
        attributes: dict[str, Any]
    ) -> bool:
        """Update user attributes in LDAP."""
    
    @abstractmethod
    async def delete_user(
        self,
        config: LDAPConfiguration,
        user_dn: str
    ) -> bool:
        """Delete user from LDAP directory."""
    
    @abstractmethod
    async def enable_user(
        self,
        config: LDAPConfiguration,
        user_dn: str
    ) -> bool:
        """Enable user account in LDAP."""
    
    @abstractmethod
    async def disable_user(
        self,
        config: LDAPConfiguration,
        user_dn: str
    ) -> bool:
        """Disable user account in LDAP."""
