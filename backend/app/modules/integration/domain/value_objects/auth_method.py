"""Authentication method value object for secure credential management.

This module provides comprehensive authentication configuration with
support for various auth types and secure credential handling.
"""

import re
from datetime import UTC, datetime
from typing import Any

from app.core.domain.base import ValueObject
from app.core.errors import ValidationError
from app.modules.integration.domain.enums import AuthType


class AuthMethod(ValueObject):
    """Value object representing authentication configuration.

    This class encapsulates authentication details for external systems,
    providing secure credential management and validation.
    """

    def __init__(
        self,
        auth_type: AuthType,
        credentials: dict[str, Any],
        token_endpoint: str | None = None,
        scopes: list[str] | None = None,
        expires_at: datetime | None = None,
        refresh_token: str | None = None,
        custom_headers: dict[str, str] | None = None,
    ):
        """Initialize authentication method.

        Args:
            auth_type: Type of authentication
            credentials: Authentication credentials (keys depend on auth_type)
            token_endpoint: Optional token endpoint for OAuth2
            scopes: Optional OAuth2 scopes
            expires_at: Optional token expiration time
            refresh_token: Optional refresh token for OAuth2
            custom_headers: Optional custom headers for auth requests

        Raises:
            ValidationError: If authentication configuration is invalid
        """
        # Validate auth type
        if not isinstance(auth_type, AuthType):
            raise ValidationError("auth_type must be an AuthType enum")
        self.auth_type = auth_type

        # Validate credentials based on auth type
        self.credentials = self._validate_credentials(auth_type, credentials)

        # Validate token endpoint for OAuth2
        if auth_type == AuthType.OAUTH2:
            if not token_endpoint:
                raise ValidationError("OAuth2 requires token_endpoint")
            self.token_endpoint = self._validate_url(token_endpoint, "token_endpoint")
        else:
            self.token_endpoint = token_endpoint

        # Validate scopes
        self.scopes = self._validate_scopes(scopes) if scopes else []

        # Validate expiration
        if expires_at:
            if not isinstance(expires_at, datetime):
                raise ValidationError("expires_at must be a datetime")
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=UTC)
        self.expires_at = expires_at

        # Store refresh token (encrypted in production)
        self.refresh_token = refresh_token

        # Validate custom headers
        self.custom_headers = custom_headers or {}
        if not isinstance(self.custom_headers, dict):
            raise ValidationError("custom_headers must be a dictionary")

        # Freeze the object
        self._freeze()

    def _validate_credentials(
        self, auth_type: AuthType, credentials: dict[str, Any]
    ) -> dict[str, Any]:
        """Validate credentials based on auth type.

        Args:
            auth_type: Type of authentication
            credentials: Credentials to validate

        Returns:
            dict[str, Any]: Validated credentials

        Raises:
            ValidationError: If credentials are invalid
        """
        if not isinstance(credentials, dict):
            raise ValidationError("Credentials must be a dictionary")

        validated = {}

        if auth_type == AuthType.API_KEY:
            # API Key requires 'api_key' and optional 'header_name'
            if "api_key" not in credentials:
                raise ValidationError("API Key authentication requires 'api_key'")

            api_key = credentials["api_key"]
            if not api_key or not isinstance(api_key, str):
                raise ValidationError("api_key must be a non-empty string")

            validated["api_key"] = api_key
            validated["header_name"] = credentials.get("header_name", "X-API-Key")

        elif auth_type == AuthType.BASIC:
            # Basic auth requires 'username' and 'password'
            if "username" not in credentials or "password" not in credentials:
                raise ValidationError(
                    "Basic authentication requires 'username' and 'password'"
                )

            username = credentials["username"]
            password = credentials["password"]

            if not username or not isinstance(username, str):
                raise ValidationError("username must be a non-empty string")
            if not password or not isinstance(password, str):
                raise ValidationError("password must be a non-empty string")

            validated["username"] = username
            validated["password"] = password

        elif auth_type == AuthType.OAUTH2:
            # OAuth2 requires either client credentials or existing token
            if "access_token" in credentials:
                # Existing token
                token = credentials["access_token"]
                if not token or not isinstance(token, str):
                    raise ValidationError("access_token must be a non-empty string")
                validated["access_token"] = token

            elif "client_id" in credentials and "client_secret" in credentials:
                # Client credentials
                client_id = credentials["client_id"]
                client_secret = credentials["client_secret"]

                if not client_id or not isinstance(client_id, str):
                    raise ValidationError("client_id must be a non-empty string")
                if not client_secret or not isinstance(client_secret, str):
                    raise ValidationError("client_secret must be a non-empty string")

                validated["client_id"] = client_id
                validated["client_secret"] = client_secret
                validated["grant_type"] = credentials.get(
                    "grant_type", "client_credentials"
                )

            else:
                raise ValidationError(
                    "OAuth2 requires either 'access_token' or 'client_id' and 'client_secret'"
                )

        elif auth_type == AuthType.JWT:
            # JWT requires either 'token' or credentials to generate token
            if "token" in credentials:
                token = credentials["token"]
                if not token or not isinstance(token, str):
                    raise ValidationError("token must be a non-empty string")
                validated["token"] = token

            elif "private_key" in credentials:
                # JWT with private key
                private_key = credentials["private_key"]
                if not private_key or not isinstance(private_key, str):
                    raise ValidationError("private_key must be a non-empty string")

                validated["private_key"] = private_key
                validated["algorithm"] = credentials.get("algorithm", "RS256")
                validated["issuer"] = credentials.get("issuer")
                validated["audience"] = credentials.get("audience")

            else:
                raise ValidationError("JWT requires either 'token' or 'private_key'")

        return validated

    def _validate_url(self, url: str, field_name: str) -> str:
        """Validate URL format.

        Args:
            url: URL to validate
            field_name: Field name for error messages

        Returns:
            str: Validated URL

        Raises:
            ValidationError: If URL is invalid
        """
        if not url:
            raise ValidationError(f"{field_name} cannot be empty")

        # Basic URL pattern
        url_pattern = re.compile(
            r"^https?://"  # http:// or https://
            r"(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|"  # domain...
            r"localhost|"  # localhost...
            r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"  # ...or ip
            r"(?::\d+)?"  # optional port
            r"(?:/?|[/?]\S+)$",
            re.IGNORECASE,
        )

        if not url_pattern.match(url):
            raise ValidationError(f"Invalid URL format for {field_name}")

        return url

    def _validate_scopes(self, scopes: list[str]) -> list[str]:
        """Validate OAuth2 scopes.

        Args:
            scopes: Scopes to validate

        Returns:
            list[str]: Validated scopes

        Raises:
            ValidationError: If scopes are invalid
        """
        if not isinstance(scopes, list):
            raise ValidationError("Scopes must be a list")

        validated = []
        for scope in scopes:
            if not isinstance(scope, str) or not scope:
                raise ValidationError("Each scope must be a non-empty string")
            validated.append(scope)

        return validated

    @property
    def is_expired(self) -> bool:
        """Check if authentication has expired."""
        if not self.expires_at:
            return False
        return datetime.now(UTC) > self.expires_at

    @property
    def requires_refresh(self) -> bool:
        """Check if authentication requires refresh."""
        return self.auth_type.requires_refresh and self.is_expired

    @property
    def has_refresh_capability(self) -> bool:
        """Check if authentication can be refreshed."""
        if self.auth_type == AuthType.OAUTH2:
            return bool(self.refresh_token) or "client_id" in self.credentials
        return False

    def get_auth_header(self) -> dict[str, str]:
        """Get authentication header based on auth type.

        Returns:
            dict[str, str]: Authentication header

        Raises:
            ValidationError: If unable to generate header
        """
        headers = {}

        if self.auth_type == AuthType.API_KEY:
            header_name = self.credentials.get("header_name", "X-API-Key")
            headers[header_name] = self.credentials["api_key"]

        elif self.auth_type == AuthType.BASIC:
            import base64

            username = self.credentials["username"]
            password = self.credentials["password"]
            encoded = base64.b64encode(f"{username}:{password}".encode()).decode()
            headers["Authorization"] = f"Basic {encoded}"

        elif self.auth_type == AuthType.OAUTH2:
            if "access_token" in self.credentials:
                headers["Authorization"] = f"Bearer {self.credentials['access_token']}"
            else:
                raise ValidationError("OAuth2 access token not available")

        elif self.auth_type == AuthType.JWT:
            if "token" in self.credentials:
                headers["Authorization"] = f"Bearer {self.credentials['token']}"
            else:
                raise ValidationError("JWT token not available")

        # Add custom headers
        headers.update(self.custom_headers)

        return headers

    def with_token(
        self, access_token: str, expires_at: datetime | None = None
    ) -> "AuthMethod":
        """Create new auth method with updated token.

        Args:
            access_token: New access token
            expires_at: Optional token expiration

        Returns:
            AuthMethod: New auth method instance
        """
        new_credentials = self.credentials.copy()

        if self.auth_type == AuthType.OAUTH2:
            new_credentials["access_token"] = access_token
        elif self.auth_type == AuthType.JWT:
            new_credentials["token"] = access_token
        else:
            raise ValidationError(f"Token update not supported for {self.auth_type}")

        return AuthMethod(
            auth_type=self.auth_type,
            credentials=new_credentials,
            token_endpoint=self.token_endpoint,
            scopes=self.scopes.copy() if self.scopes else None,
            expires_at=expires_at,
            refresh_token=self.refresh_token,
            custom_headers=self.custom_headers.copy() if self.custom_headers else None,
        )

    def __str__(self) -> str:
        """Return string representation of auth method."""
        return f"{self.auth_type.value} authentication"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        # Sanitize credentials for serialization
        sanitized_credentials = {}
        for key, value in self.credentials.items():
            if key in (
                "password",
                "client_secret",
                "private_key",
                "api_key",
                "access_token",
                "token",
            ):
                sanitized_credentials[key] = "***REDACTED***"
            else:
                sanitized_credentials[key] = value

        return {
            "auth_type": self.auth_type.value,
            "credentials": sanitized_credentials,
            "token_endpoint": self.token_endpoint,
            "scopes": self.scopes,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "has_refresh_token": bool(self.refresh_token),
            "is_expired": self.is_expired,
            "requires_refresh": self.requires_refresh,
        }
