"""
Tests for GraphQL authorization system.
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch
from strawberry.types import Info
from strawberry import GraphQLError

from app.presentation.graphql.authorization import (
    AuthorizationError,
    requires_auth,
    requires_permission,
    requires_any_permission,
    requires_all_permissions,
    requires_role,
    public,
    authorize_field,
    AuthorizationContext,
)


@pytest.fixture
def mock_info():
    """Create a mock Info object with context."""
    info = Mock(spec=Info)
    info.context = {
        "user": None,
        "is_authenticated": False,
        "container": Mock()
    }
    return info


@pytest.fixture
def authenticated_info(mock_info):
    """Create a mock Info object with authenticated user."""
    mock_info.context["user"] = Mock(id="user123", email="test@example.com")
    mock_info.context["is_authenticated"] = True
    return mock_info


class TestAuthorizationError:
    """Test AuthorizationError class."""
    
    def test_authorization_error_creation(self):
        """Test creating AuthorizationError."""
        error = AuthorizationError(
            message="Access denied",
            code="FORBIDDEN",
            required_permission="users:read"
        )
        
        assert str(error) == "Access denied"
        assert error.extensions["code"] == "FORBIDDEN"
        assert error.extensions["required_permission"] == "users:read"
    
    def test_authorization_error_defaults(self):
        """Test AuthorizationError with defaults."""
        error = AuthorizationError()
        
        assert str(error) == "Unauthorized"
        assert error.extensions["code"] == "FORBIDDEN"
        assert error.extensions["required_permission"] is None


class TestAuthDecorators:
    """Test authentication decorators."""
    
    @pytest.mark.asyncio
    async def test_requires_auth_success(self, authenticated_info):
        """Test requires_auth with authenticated user."""
        @requires_auth
        async def protected_resolver(self, info: Info):
            return "protected data"
        
        result = await protected_resolver(None, authenticated_info)
        assert result == "protected data"
    
    @pytest.mark.asyncio
    async def test_requires_auth_failure(self, mock_info):
        """Test requires_auth without authentication."""
        @requires_auth
        async def protected_resolver(self, info: Info):
            return "protected data"
        
        with pytest.raises(AuthorizationError) as exc_info:
            await protected_resolver(None, mock_info)
        
        assert exc_info.value.extensions["code"] == "UNAUTHENTICATED"
    
    @pytest.mark.asyncio
    async def test_requires_permission_success(self, authenticated_info):
        """Test requires_permission with valid permission."""
        # Mock the permission check
        with patch("app.presentation.graphql.authorization._check_user_permission") as mock_check:
            mock_check.return_value = True
            
            @requires_permission("users:read")
            async def protected_resolver(self, info: Info):
                return "protected data"
            
            result = await protected_resolver(None, authenticated_info)
            assert result == "protected data"
            mock_check.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_requires_permission_failure(self, authenticated_info):
        """Test requires_permission without permission."""
        with patch("app.presentation.graphql.authorization._check_user_permission") as mock_check:
            mock_check.return_value = False
            
            @requires_permission("users:admin")
            async def protected_resolver(self, info: Info):
                return "protected data"
            
            with pytest.raises(AuthorizationError) as exc_info:
                await protected_resolver(None, authenticated_info)
            
            assert exc_info.value.extensions["code"] == "FORBIDDEN"
            assert exc_info.value.extensions["required_permission"] == "users:admin"
    
    @pytest.mark.asyncio
    async def test_requires_any_permission_success(self, authenticated_info):
        """Test requires_any_permission with at least one valid permission."""
        with patch("app.presentation.graphql.authorization._check_user_permission") as mock_check:
            # First call returns False, second returns True
            mock_check.side_effect = [False, True]
            
            @requires_any_permission("users:admin", "users:read")
            async def protected_resolver(self, info: Info):
                return "protected data"
            
            result = await protected_resolver(None, authenticated_info)
            assert result == "protected data"
            assert mock_check.call_count == 2
    
    @pytest.mark.asyncio
    async def test_requires_all_permissions_success(self, authenticated_info):
        """Test requires_all_permissions with all permissions."""
        with patch("app.presentation.graphql.authorization._check_user_permission") as mock_check:
            mock_check.return_value = True
            
            @requires_all_permissions("users:read", "users:write")
            async def protected_resolver(self, info: Info):
                return "protected data"
            
            result = await protected_resolver(None, authenticated_info)
            assert result == "protected data"
            assert mock_check.call_count == 2
    
    @pytest.mark.asyncio
    async def test_requires_role_success(self, authenticated_info):
        """Test requires_role with valid role."""
        with patch("app.presentation.graphql.authorization._check_user_role") as mock_check:
            mock_check.return_value = True
            
            @requires_role("admin")
            async def protected_resolver(self, info: Info):
                return "admin data"
            
            result = await protected_resolver(None, authenticated_info)
            assert result == "admin data"
            mock_check.assert_called_once()
    
    def test_public_decorator(self):
        """Test public decorator marks function."""
        @public
        def public_resolver(self, info: Info):
            return "public data"
        
        assert hasattr(public_resolver, "_is_public")
        assert public_resolver._is_public is True


class TestFieldAuthorization:
    """Test field-level authorization."""
    
    @pytest.mark.asyncio
    async def test_authorize_field_with_permission(self, authenticated_info):
        """Test authorize_field with permission check."""
        with patch("app.presentation.graphql.authorization._check_user_permission") as mock_check:
            mock_check.return_value = True
            
            class UserType:
                def __init__(self):
                    self._ssn = "123-45-6789"
                
                @authorize_field(permission="users:read:sensitive")
                async def ssn(self, info: Info):
                    return self._ssn
            
            user = UserType()
            result = await user.ssn(authenticated_info)
            assert result == "123-45-6789"
    
    @pytest.mark.asyncio
    async def test_authorize_field_with_condition(self, authenticated_info):
        """Test authorize_field with custom condition."""
        def is_self(user, obj):
            return user.id == obj.id
        
        class UserType:
            def __init__(self, id):
                self.id = id
                self._email = "private@example.com"
            
            @authorize_field(condition=is_self, default_value="[hidden]")
            async def email(self, info: Info):
                return self._email
        
        # Test accessing own data
        user1 = UserType("user123")
        result1 = await user1.email(authenticated_info)
        assert result1 == "private@example.com"
        
        # Test accessing other's data
        user2 = UserType("user456")
        result2 = await user2.email(authenticated_info)
        assert result2 == "[hidden]"


class TestAuthorizationContext:
    """Test AuthorizationContext manager."""
    
    @pytest.mark.asyncio
    async def test_authorization_context_basic(self, authenticated_info):
        """Test basic AuthorizationContext functionality."""
        async with AuthorizationContext(authenticated_info) as auth:
            assert auth.user is not None
            assert auth.user.id == "user123"
    
    @pytest.mark.asyncio
    async def test_authorization_context_permission_check(self, authenticated_info):
        """Test permission checking in context."""
        with patch("app.presentation.graphql.authorization._check_user_permission") as mock_check:
            mock_check.side_effect = [True, False, True]
            
            async with AuthorizationContext(authenticated_info) as auth:
                # First check (cached)
                assert await auth.has_permission("users:read") is True
                # Second call should use cache
                assert await auth.has_permission("users:read") is True
                
                # Different permission
                assert await auth.has_permission("users:admin") is False
                
                # Check any permission
                assert await auth.has_any_permission("users:admin", "users:write") is True
    
    @pytest.mark.asyncio
    async def test_authorization_context_require_methods(self, authenticated_info):
        """Test require methods in context."""
        async with AuthorizationContext(authenticated_info) as auth:
            # Should not raise
            auth.require_auth()
            
            with patch("app.presentation.graphql.authorization._check_user_permission") as mock_check:
                mock_check.return_value = False
                
                # Should raise
                with pytest.raises(AuthorizationError):
                    await auth.require_permission("admin:all")
    
    @pytest.mark.asyncio
    async def test_authorization_context_no_user(self, mock_info):
        """Test context without authenticated user."""
        async with AuthorizationContext(mock_info) as auth:
            assert auth.user is None
            
            with pytest.raises(AuthorizationError) as exc_info:
                auth.require_auth()
            
            assert exc_info.value.extensions["code"] == "UNAUTHENTICATED"


class TestHelperFunctions:
    """Test helper functions."""
    
    @pytest.mark.asyncio
    async def test_check_user_permission(self, authenticated_info):
        """Test _check_user_permission function."""
        from app.presentation.graphql.authorization import _check_user_permission
        
        # Mock the authorization service
        mock_auth_service = Mock()
        mock_auth_service.user_has_permission = AsyncMock(return_value=True)
        authenticated_info.context["container"].resolve.return_value = mock_auth_service
        
        result = await _check_user_permission(
            authenticated_info,
            authenticated_info.context["user"],
            "test:permission"
        )
        
        assert result is True
        mock_auth_service.user_has_permission.assert_called_once_with(
            "user123",
            "test:permission"
        )
    
    @pytest.mark.asyncio
    async def test_check_user_permission_error(self, authenticated_info):
        """Test _check_user_permission with error."""
        from app.presentation.graphql.authorization import _check_user_permission
        
        # Make container.resolve raise an exception
        authenticated_info.context["container"].resolve.side_effect = Exception("Service error")
        
        result = await _check_user_permission(
            authenticated_info,
            authenticated_info.context["user"],
            "test:permission"
        )
        
        assert result is False