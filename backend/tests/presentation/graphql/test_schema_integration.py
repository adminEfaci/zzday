"""
Integration tests for GraphQL schema composition.
"""

import pytest
from unittest.mock import Mock, patch
from strawberry import Schema
from graphql import graphql, build_schema, get_introspection_query

from app.presentation.graphql.schema import (
    Query,
    Mutation,
    Subscription,
    create_schema,
    get_context,
)


class TestSchemaComposition:
    """Test main schema composition."""
    
    def test_create_schema(self):
        """Test schema creation."""
        schema = create_schema()
        
        assert isinstance(schema, Schema)
        assert schema.query is Query
        assert schema.mutation is Mutation
        assert schema.subscription is not None
    
    def test_schema_introspection(self):
        """Test schema introspection works."""
        schema = create_schema()
        
        # Execute introspection query
        result = schema.execute_sync(get_introspection_query())
        
        assert result.errors is None
        assert result.data is not None
        assert "__schema" in result.data
    
    def test_query_type_fields(self):
        """Test Query type has expected fields."""
        schema = create_schema()
        query_type = schema.schema.query_type
        
        # Check module fields exist
        assert "identity" in query_type.fields
        assert "audit" in query_type.fields
        assert "notification" in query_type.fields
        assert "integration" in query_type.fields
    
    def test_mutation_type_fields(self):
        """Test Mutation type has expected fields."""
        schema = create_schema()
        mutation_type = schema.schema.mutation_type
        
        # Check module fields exist
        assert "identity" in mutation_type.fields
        assert "audit" in mutation_type.fields
        assert "notification" in mutation_type.fields
        assert "integration" in mutation_type.fields
    
    def test_subscription_type_fields(self):
        """Test Subscription type is properly built."""
        schema = create_schema()
        subscription_type = schema.schema.subscription_type
        
        # Should have at least placeholder or module subscriptions
        assert subscription_type is not None
        assert len(subscription_type.fields) > 0


class TestContextCreation:
    """Test GraphQL context creation."""
    
    @pytest.mark.asyncio
    async def test_get_context_basic(self):
        """Test basic context creation."""
        # Mock request
        mock_request = Mock()
        mock_request.app.state.container = Mock()
        mock_request.state.user = None
        
        context = await get_context(mock_request)
        
        assert "request" in context
        assert context["request"] is mock_request
        assert "container" in context
        assert context["container"] is mock_request.app.state.container
        assert "get_session" in context
        assert "user" in context
        assert context["user"] is None
        assert "is_authenticated" in context
        assert context["is_authenticated"] is False
        assert "loaders" in context
    
    @pytest.mark.asyncio
    async def test_get_context_with_authenticated_user(self):
        """Test context creation with authenticated user."""
        # Mock request with user
        mock_request = Mock()
        mock_request.app.state.container = Mock()
        mock_user = Mock(id="user123", email="test@example.com")
        mock_request.state.user = mock_user
        
        context = await get_context(mock_request)
        
        assert context["user"] is mock_user
        assert context["is_authenticated"] is True
    
    @pytest.mark.asyncio
    async def test_get_context_with_response(self):
        """Test context creation with response object."""
        mock_request = Mock()
        mock_request.app.state.container = Mock()
        mock_response = Mock()
        
        context = await get_context(mock_request, mock_response)
        
        assert context["response"] is mock_response
    
    @pytest.mark.asyncio
    async def test_get_context_without_container(self):
        """Test context creation without DI container."""
        # Mock request without container
        mock_request = Mock()
        mock_request.app.state = Mock(spec=[])  # No container attribute
        
        with patch("app.presentation.graphql.schema.logger") as mock_logger:
            context = await get_context(mock_request)
            
            assert context["container"] is None
            assert context["loaders"] is None
            mock_logger.warning.assert_called_once_with(
                "No container available for dataloader creation"
            )


class TestModuleIntegration:
    """Test module schema integration."""
    
    @pytest.mark.asyncio
    async def test_identity_module_queries(self):
        """Test identity module query integration."""
        schema = create_schema()
        
        # Simple query to test identity module
        query = """
        query {
            identity {
                placeholder
            }
        }
        """
        
        result = schema.execute_sync(query)
        
        # Should work even with placeholder
        assert result.errors is None or len(result.errors) == 0
    
    @pytest.mark.asyncio
    async def test_module_fallback_handling(self):
        """Test fallback handling for missing modules."""
        # This is already handled in the imports with try/except
        # Just verify the schema still works
        schema = create_schema()
        
        query = """
        query {
            __schema {
                queryType {
                    name
                    fields {
                        name
                    }
                }
            }
        }
        """
        
        result = schema.execute_sync(query)
        
        assert result.errors is None
        assert result.data["__schema"]["queryType"]["name"] == "Query"
        
        # All module fields should exist
        field_names = [f["name"] for f in result.data["__schema"]["queryType"]["fields"]]
        assert "identity" in field_names
        assert "audit" in field_names
        assert "notification" in field_names
        assert "integration" in field_names


class TestSchemaWithDataLoaders:
    """Test schema with dataloader integration."""
    
    @pytest.mark.asyncio
    async def test_context_includes_dataloaders(self):
        """Test that context includes dataloaders when container is available."""
        mock_request = Mock()
        
        # Mock container with resolve method
        mock_container = Mock()
        mock_container.resolve.return_value = Mock()  # Mock repository
        mock_request.app.state.container = mock_container
        
        with patch("app.presentation.graphql.schema.create_loaders") as mock_create:
            mock_loaders = Mock()
            mock_create.return_value = mock_loaders
            
            context = await get_context(mock_request)
            
            assert context["loaders"] is mock_loaders
            mock_create.assert_called_once_with(mock_container)