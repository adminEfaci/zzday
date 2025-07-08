"""OAuth client for OAuth 2.0 authentication flows.

This module provides OAuth 2.0 client implementation with support for
various grant types and token management.
"""

import base64
import hashlib
import logging
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

from app.modules.integration.infrastructure.http_clients.rest_api import (
    RestApiClient,
    RestApiClientError,
)

logger = logging.getLogger(__name__)


class OAuthError(Exception):
    """OAuth specific errors."""


class OAuthClient(RestApiClient):
    """OAuth 2.0 client implementation."""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        authorization_url: str,
        token_url: str,
        redirect_uri: str | None = None,
        scopes: list[str] | None = None,
        **kwargs,
    ):
        """Initialize OAuth client.

        Args:
            client_id: OAuth client ID
            client_secret: OAuth client secret
            authorization_url: Authorization endpoint URL
            token_url: Token endpoint URL
            redirect_uri: Redirect URI for authorization code flow
            scopes: List of OAuth scopes
            **kwargs: Additional arguments for RestApiClient
        """
        # Extract base URL from token URL
        parsed = urlparse(token_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        super().__init__(base_url, **kwargs)

        self.client_id = client_id
        self.client_secret = client_secret
        self.authorization_url = authorization_url
        self.token_url = token_url
        self.redirect_uri = redirect_uri
        self.scopes = scopes or []

        # Token storage (in production, use secure storage)
        self._tokens: dict[str, Any] = {}

        # PKCE support
        self._pkce_verifier: str | None = None

    def get_authorization_url(
        self,
        state: str | None = None,
        scopes: list[str] | None = None,
        use_pkce: bool = False,
        additional_params: dict[str, str] | None = None,
    ) -> str:
        """Generate authorization URL for OAuth flow.

        Args:
            state: State parameter for CSRF protection
            scopes: Override default scopes
            use_pkce: Use PKCE for enhanced security
            additional_params: Additional query parameters

        Returns:
            Authorization URL
        """
        params = {
            "client_id": self.client_id,
            "response_type": "code",
            "redirect_uri": self.redirect_uri,
        }

        # Add state
        if state:
            params["state"] = state
        else:
            params["state"] = secrets.token_urlsafe(32)

        # Add scopes
        scope_list = scopes if scopes is not None else self.scopes
        if scope_list:
            params["scope"] = " ".join(scope_list)

        # Add PKCE challenge if requested
        if use_pkce:
            self._pkce_verifier = secrets.token_urlsafe(32)
            challenge = (
                base64.urlsafe_b64encode(
                    hashlib.sha256(self._pkce_verifier.encode()).digest()
                )
                .decode()
                .rstrip("=")
            )
            params["code_challenge"] = challenge
            params["code_challenge_method"] = "S256"

        # Add additional parameters
        if additional_params:
            params.update(additional_params)

        return f"{self.authorization_url}?{urlencode(params)}"

    async def exchange_code_for_token(
        self, code: str, state: str | None = None
    ) -> dict[str, Any]:
        """Exchange authorization code for access token.

        Args:
            code: Authorization code
            state: State parameter to verify

        Returns:
            Token response with access_token, refresh_token, etc.

        Raises:
            OAuthError: If token exchange fails
        """
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }

        # Add PKCE verifier if used
        if self._pkce_verifier:
            data["code_verifier"] = self._pkce_verifier
            self._pkce_verifier = None  # Clear after use

        try:
            response = await self.post(
                self.token_url,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

            # Store tokens
            self._store_tokens(response)

            return response

        except RestApiClientError as e:
            raise OAuthError(f"Token exchange failed: {e!s}")

    async def get_token_with_client_credentials(
        self, scopes: list[str] | None = None
    ) -> dict[str, Any]:
        """Get access token using client credentials grant.

        Args:
            scopes: Override default scopes

        Returns:
            Token response
        """
        data = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }

        # Add scopes
        scope_list = scopes if scopes is not None else self.scopes
        if scope_list:
            data["scope"] = " ".join(scope_list)

        try:
            response = await self.post(
                self.token_url,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

            # Store tokens
            self._store_tokens(response)

            return response

        except RestApiClientError as e:
            raise OAuthError(f"Client credentials grant failed: {e!s}")

    async def refresh_token(self, refresh_token: str | None = None) -> dict[str, Any]:
        """Refresh access token using refresh token.

        Args:
            refresh_token: Refresh token (uses stored if not provided)

        Returns:
            New token response

        Raises:
            OAuthError: If refresh fails
        """
        if not refresh_token:
            refresh_token = self._tokens.get("refresh_token")

        if not refresh_token:
            raise OAuthError("No refresh token available")

        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }

        try:
            response = await self.post(
                self.token_url,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

            # Store new tokens
            self._store_tokens(response)

            return response

        except RestApiClientError as e:
            raise OAuthError(f"Token refresh failed: {e!s}")

    async def revoke_token(
        self, token: str | None = None, token_type_hint: str = "access_token"
    ) -> bool:
        """Revoke an access or refresh token.

        Args:
            token: Token to revoke (uses stored if not provided)
            token_type_hint: Type of token (access_token or refresh_token)

        Returns:
            True if revocation succeeded
        """
        if not token:
            if token_type_hint == "refresh_token":
                token = self._tokens.get("refresh_token")
            else:
                token = self._tokens.get("access_token")

        if not token:
            return True  # No token to revoke

        # Try to find revocation endpoint
        revoke_url = self.token_url.replace("/token", "/revoke")

        data = {
            "token": token,
            "token_type_hint": token_type_hint,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }

        try:
            await self.post(
                revoke_url,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

            # Clear stored tokens
            if token_type_hint == "refresh_token":
                self._tokens.pop("refresh_token", None)
            else:
                self._tokens.pop("access_token", None)

            return True

        except Exception as e:
            logger.warning(f"Token revocation failed: {e}")
            return False

    async def introspect_token(self, token: str | None = None) -> dict[str, Any]:
        """Introspect token to get metadata.

        Args:
            token: Token to introspect (uses stored if not provided)

        Returns:
            Token metadata
        """
        if not token:
            token = self._tokens.get("access_token")

        if not token:
            raise OAuthError("No token available for introspection")

        # Try to find introspection endpoint
        introspect_url = self.token_url.replace("/token", "/introspect")

        data = {
            "token": token,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }

        try:
            return await self.post(
                introspect_url,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        except RestApiClientError as e:
            raise OAuthError(f"Token introspection failed: {e!s}")

    def _store_tokens(self, token_response: dict[str, Any]) -> None:
        """Store tokens from response.

        Args:
            token_response: Token endpoint response
        """
        if "access_token" in token_response:
            self._tokens["access_token"] = token_response["access_token"]

        if "refresh_token" in token_response:
            self._tokens["refresh_token"] = token_response["refresh_token"]

        if "expires_in" in token_response:
            expires_at = datetime.now(UTC) + timedelta(
                seconds=token_response["expires_in"]
            )
            self._tokens["expires_at"] = expires_at

        if "token_type" in token_response:
            self._tokens["token_type"] = token_response["token_type"]

        # Update auth header for future requests
        if "access_token" in self._tokens:
            self._update_auth_header()

    def _update_auth_header(self) -> None:
        """Update authorization header with current token."""
        if self._session and "access_token" in self._tokens:
            token_type = self._tokens.get("token_type", "Bearer")
            self._session.headers[
                "Authorization"
            ] = f"{token_type} {self._tokens['access_token']}"

    def get_access_token(self) -> str | None:
        """Get current access token."""
        return self._tokens.get("access_token")

    def get_refresh_token(self) -> str | None:
        """Get current refresh token."""
        return self._tokens.get("refresh_token")

    def is_token_expired(self) -> bool:
        """Check if access token is expired."""
        expires_at = self._tokens.get("expires_at")
        if not expires_at:
            return False
        return datetime.now(UTC) >= expires_at

    async def ensure_valid_token(self) -> str:
        """Ensure we have a valid access token.

        Returns:
            Valid access token

        Raises:
            OAuthError: If unable to get valid token
        """
        # Check if we have a token
        access_token = self.get_access_token()

        if not access_token:
            # Try client credentials grant
            await self.get_token_with_client_credentials()
            access_token = self.get_access_token()

        elif self.is_token_expired():
            # Try to refresh
            refresh_token = self.get_refresh_token()
            if refresh_token:
                await self.refresh_token()
                access_token = self.get_access_token()
            else:
                # Get new token with client credentials
                await self.get_token_with_client_credentials()
                access_token = self.get_access_token()

        if not access_token:
            raise OAuthError("Unable to obtain valid access token")

        return access_token

    @staticmethod
    def parse_callback_url(url: str) -> dict[str, str]:
        """Parse OAuth callback URL to extract code and state.

        Args:
            url: Callback URL with query parameters

        Returns:
            Dictionary with code, state, and any error
        """
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        result = {}

        # Extract single-value parameters
        for key in ["code", "state", "error", "error_description"]:
            if key in params:
                result[key] = params[key][0]

        return result
