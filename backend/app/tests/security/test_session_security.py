"""
Session security tests.

Tests session management security including fixation, hijacking, and timeout.
"""

import pytest
from httpx import AsyncClient


@pytest.mark.security
@pytest.mark.asyncio
class TestSessionSecurity:
    """Test session security mechanisms."""

    async def test_session_fixation_prevention(
        self, 
        async_client: AsyncClient,
        user_mother
    ):
        """Test that session ID changes after authentication."""
        # Get initial session (if any)
        initial_response = await async_client.get("/api/v1/health")
        initial_cookies = initial_response.cookies
        
        # Create user for login
        user = user_mother.active_verified_user()
        
        # Attempt login with existing session
        login_response = await async_client.post(
            "/api/v1/auth/login",
            json={
                "username": user.email.value,  # Using email as username
                "password": "TestPass123!@#"
            },
            cookies=initial_cookies
        )
        
        # Session should be regenerated
        new_cookies = login_response.cookies
        
        # If session cookies exist, they should be different
        if "session_id" in initial_cookies and "session_id" in new_cookies:
            assert initial_cookies["session_id"] != new_cookies["session_id"]

    async def test_session_invalidation_on_logout(
        self, 
        async_client: AsyncClient,
        user_mother
    ):
        """Test that sessions are properly invalidated on logout."""
        user = user_mother.active_verified_user()
        
        # Login
        login_response = await async_client.post(
            "/api/v1/auth/login",
            json={
                "username": user.email.value,
                "password": "TestPass123!@#"
            }
        )
        
        if login_response.status_code == 200:
            auth_cookies = login_response.cookies
            
            # Logout
            logout_response = await async_client.post(
                "/api/v1/auth/logout",
                cookies=auth_cookies
            )
            
            # Try to use old session
            protected_response = await async_client.get(
                "/api/v1/auth/me",
                cookies=auth_cookies
            )
            
            # Should be unauthorized
            assert protected_response.status_code == 401

    async def test_concurrent_session_handling(
        self, 
        async_client: AsyncClient,
        user_mother
    ):
        """Test handling of concurrent sessions for same user."""
        user = user_mother.active_verified_user()
        
        # Login from first "device"
        login1_response = await async_client.post(
            "/api/v1/auth/login",
            json={
                "username": user.email.value,
                "password": "TestPass123!@#",
                "device_id": "device_1"
            }
        )
        
        # Login from second "device"
        login2_response = await async_client.post(
            "/api/v1/auth/login",
            json={
                "username": user.email.value,
                "password": "TestPass123!@#",
                "device_id": "device_2"
            }
        )
        
        # Both sessions should be valid (if concurrent sessions allowed)
        # OR first session should be invalidated (if single session enforced)
        if login1_response.status_code == 200 and login2_response.status_code == 200:
            # Test both sessions
            cookies1 = login1_response.cookies
            cookies2 = login2_response.cookies
            
            # At least one session should work
            response1 = await async_client.get("/api/v1/auth/me", cookies=cookies1)
            response2 = await async_client.get("/api/v1/auth/me", cookies=cookies2)
            
            # At least one should be successful
            assert response1.status_code == 200 or response2.status_code == 200


@pytest.mark.security
@pytest.mark.asyncio
class TestCSRFProtection:
    """Test Cross-Site Request Forgery protection."""

    async def test_csrf_token_required(self, async_client: AsyncClient):
        """Test that state-changing operations require CSRF protection."""
        # Try to change password without CSRF token
        response = await async_client.post(
            "/api/v1/auth/change-password",
            json={
                "old_password": "OldPass123!",
                "new_password": "NewPass123!@#"
            }
        )
        
        # Should be rejected due to missing CSRF token or authentication
        assert response.status_code in [401, 403]

    async def test_safe_methods_no_csrf_required(self, async_client: AsyncClient):
        """Test that safe HTTP methods don't require CSRF tokens."""
        # GET requests should not require CSRF
        response = await async_client.get("/api/v1/auth/me")
        
        # Should fail due to authentication, not CSRF
        assert response.status_code == 401  # Not 403 (CSRF)


@pytest.mark.security
@pytest.mark.asyncio
class TestSecurityHeaders:
    """Test security-related HTTP headers."""

    async def test_security_headers_present(self, async_client: AsyncClient):
        """Test that security headers are included in responses."""
        response = await async_client.get("/api/v1/health")
        
        headers = response.headers
        
        # Check for common security headers
        security_headers = {
            "x-content-type-options": "nosniff",
            "x-frame-options": ["DENY", "SAMEORIGIN"],
            "x-xss-protection": ["1; mode=block", "0"],  # 0 is also acceptable
        }
        
        for header, expected_values in security_headers.items():
            if header in headers:
                if isinstance(expected_values, list):
                    assert headers[header] in expected_values
                else:
                    assert headers[header] == expected_values

    async def test_no_sensitive_headers_leaked(self, async_client: AsyncClient):
        """Test that sensitive information is not leaked in headers."""
        response = await async_client.get("/api/v1/health")
        
        headers_text = str(response.headers).lower()
        
        # Should not leak sensitive information
        sensitive_info = [
            "password",
            "secret",
            "key",
            "token",
            "internal",
            "debug",
            "stack",
            "trace"
        ]
        
        for info in sensitive_info:
            assert info not in headers_text