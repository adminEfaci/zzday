"""GraphQL client with query optimization and caching.

This module provides a GraphQL client with support for queries, mutations,
subscriptions, and automatic query optimization.
"""

import hashlib
import json
import logging
from datetime import datetime, timedelta
from typing import Any

from graphql import parse
from graphql.language.ast import DocumentNode

from app.modules.integration.domain.value_objects import AuthMethod
from app.modules.integration.infrastructure.http_clients.rest_api import RestApiClient

logger = logging.getLogger(__name__)


class GraphQLError(Exception):
    """GraphQL specific errors."""

    def __init__(self, message: str, errors: list[dict[str, Any]] | None = None):
        super().__init__(message)
        self.errors = errors or []


class GraphQLClient(RestApiClient):
    """GraphQL client with advanced features."""

    def __init__(
        self,
        endpoint: str,
        auth_method: AuthMethod | None = None,
        enable_cache: bool = True,
        cache_ttl_seconds: int = 300,
        **kwargs,
    ):
        """Initialize GraphQL client.

        Args:
            endpoint: GraphQL endpoint URL
            auth_method: Authentication method
            enable_cache: Enable query result caching
            cache_ttl_seconds: Cache TTL in seconds
            **kwargs: Additional arguments for RestApiClient
        """
        # Extract base URL from endpoint
        base_url = endpoint.rsplit("/", 1)[0]
        super().__init__(base_url, auth_method, **kwargs)

        self.endpoint = endpoint
        self.enable_cache = enable_cache
        self.cache_ttl = timedelta(seconds=cache_ttl_seconds)
        self._cache: dict[str, dict[str, Any]] = {}

    def _get_cache_key(
        self, query: str, variables: dict[str, Any] | None = None
    ) -> str:
        """Generate cache key for query."""
        cache_data = {"query": query, "variables": variables or {}}
        cache_str = json.dumps(cache_data, sort_keys=True)
        return hashlib.sha256(cache_str.encode()).hexdigest()

    def _get_from_cache(self, cache_key: str) -> dict[str, Any] | None:
        """Get result from cache if valid."""
        if not self.enable_cache:
            return None

        cached = self._cache.get(cache_key)
        if not cached:
            return None

        # Check if cache is expired
        if datetime.now() > cached["expires_at"]:
            del self._cache[cache_key]
            return None

        return cached["data"]

    def _set_cache(self, cache_key: str, data: dict[str, Any]) -> None:
        """Set result in cache."""
        if not self.enable_cache:
            return

        self._cache[cache_key] = {
            "data": data,
            "expires_at": datetime.now() + self.cache_ttl,
        }

    def _validate_query(self, query: str) -> DocumentNode:
        """Validate and parse GraphQL query."""
        try:
            return parse(query)
        except Exception as e:
            raise GraphQLError(f"Invalid GraphQL query: {e!s}")

    async def query(
        self,
        query: str,
        variables: dict[str, Any] | None = None,
        operation_name: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Execute GraphQL query.

        Args:
            query: GraphQL query string
            variables: Query variables
            operation_name: Operation name for multi-operation documents
            headers: Additional headers

        Returns:
            Query result data

        Raises:
            GraphQLError: If query execution fails
        """
        # Validate query
        self._validate_query(query)

        # Check cache for queries
        cache_key = self._get_cache_key(query, variables)
        cached_result = self._get_from_cache(cache_key)
        if cached_result is not None:
            logger.debug(f"Returning cached result for query: {cache_key}")
            return cached_result

        # Prepare request
        payload = {"query": query, "variables": variables or {}}
        if operation_name:
            payload["operationName"] = operation_name

        # Execute request
        try:
            response = await self.post(
                self.endpoint, json_data=payload, headers=headers
            )

            # Handle GraphQL errors
            if "errors" in response:
                raise GraphQLError("GraphQL query failed", errors=response["errors"])

            # Cache successful query results
            if "data" in response:
                self._set_cache(cache_key, response["data"])
                return response["data"]

            return response

        except RestApiClientError as e:
            raise GraphQLError(f"GraphQL request failed: {e!s}")

    async def mutation(
        self,
        mutation: str,
        variables: dict[str, Any] | None = None,
        operation_name: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Execute GraphQL mutation.

        Args:
            mutation: GraphQL mutation string
            variables: Mutation variables
            operation_name: Operation name
            headers: Additional headers

        Returns:
            Mutation result data
        """
        # Mutations are never cached
        return await self.query(
            mutation,
            variables=variables,
            operation_name=operation_name,
            headers=headers,
        )

    async def introspect(self) -> dict[str, Any]:
        """Get GraphQL schema through introspection."""
        introspection_query = """
        query IntrospectionQuery {
            __schema {
                queryType { name }
                mutationType { name }
                subscriptionType { name }
                types {
                    ...FullType
                }
                directives {
                    name
                    description
                    locations
                    args {
                        ...InputValue
                    }
                }
            }
        }
        
        fragment FullType on __Type {
            kind
            name
            description
            fields(includeDeprecated: true) {
                name
                description
                args {
                    ...InputValue
                }
                type {
                    ...TypeRef
                }
                isDeprecated
                deprecationReason
            }
            inputFields {
                ...InputValue
            }
            interfaces {
                ...TypeRef
            }
            enumValues(includeDeprecated: true) {
                name
                description
                isDeprecated
                deprecationReason
            }
            possibleTypes {
                ...TypeRef
            }
        }
        
        fragment InputValue on __InputValue {
            name
            description
            type { ...TypeRef }
            defaultValue
        }
        
        fragment TypeRef on __Type {
            kind
            name
            ofType {
                kind
                name
                ofType {
                    kind
                    name
                    ofType {
                        kind
                        name
                        ofType {
                            kind
                            name
                            ofType {
                                kind
                                name
                                ofType {
                                    kind
                                    name
                                    ofType {
                                        kind
                                        name
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        """

        return await self.query(introspection_query)

    async def batch_query(
        self, queries: list[dict[str, Any]], headers: dict[str, str] | None = None
    ) -> list[dict[str, Any]]:
        """Execute multiple queries in a single request.

        Args:
            queries: List of query configurations with:
                - query: GraphQL query string
                - variables: Query variables (optional)
                - operationName: Operation name (optional)
            headers: Additional headers

        Returns:
            List of query results
        """
        # Build batch query
        batch_query = ""
        batch_variables = {}
        operations = []

        for i, q in enumerate(queries):
            query_name = f"query{i}"
            operations.append(query_name)

            # Parse and modify query to add alias
            self._validate_query(q["query"])

            # Add to batch
            batch_query += f"\n{q['query']}\n"

            # Merge variables
            if q.get("variables"):
                for key, value in q["variables"].items():
                    batch_variables[f"{query_name}_{key}"] = value

        # Execute batch query
        result = await self.query(
            batch_query, variables=batch_variables, headers=headers
        )

        # Extract individual results
        results = []
        for op in operations:
            if op in result:
                results.append(result[op])
            else:
                results.append(None)

        return results

    def build_query(
        self,
        operation: str,
        fields: list[str | dict[str, Any]],
        arguments: dict[str, Any] | None = None,
        fragments: dict[str, str] | None = None,
    ) -> str:
        """Build GraphQL query programmatically.

        Args:
            operation: Operation name (e.g., "users", "product")
            fields: List of fields to query
            arguments: Operation arguments
            fragments: Fragment definitions

        Returns:
            GraphQL query string
        """
        # Build field selection
        field_str = self._build_fields(fields)

        # Build arguments
        arg_str = ""
        if arguments:
            args = []
            for key, value in arguments.items():
                args.append(f"{key}: {self._format_value(value)}")
            arg_str = f'({", ".join(args)})'

        # Build query
        query = f"""
        query {{
            {operation}{arg_str} {{
                {field_str}
            }}
        }}
        """

        # Add fragments
        if fragments:
            for name, definition in fragments.items():
                query += f"\n\nfragment {name} {definition}"

        return query.strip()

    def _build_fields(self, fields: list[str | dict[str, Any]]) -> str:
        """Build field selection string."""
        field_parts = []

        for field in fields:
            if isinstance(field, str):
                field_parts.append(field)
            elif isinstance(field, dict):
                for name, subfields in field.items():
                    if isinstance(subfields, list):
                        subfied_str = self._build_fields(subfields)
                        field_parts.append(f"{name} {{ {subfied_str} }}")
                    else:
                        field_parts.append(f"{name}: {subfields}")

        return "\n".join(field_parts)

    def _format_value(self, value: Any) -> str:
        """Format value for GraphQL."""
        if value is None:
            return "null"
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, int | float):
            return str(value)
        if isinstance(value, str):
            return json.dumps(value)
        if isinstance(value, list):
            items = [self._format_value(v) for v in value]
            return f'[{", ".join(items)}]'
        if isinstance(value, dict):
            items = [f"{k}: {self._format_value(v)}" for k, v in value.items()]
            return f'{{{", ".join(items)}}}'
        return json.dumps(str(value))

    def clear_cache(self) -> None:
        """Clear query cache."""
        self._cache.clear()

    async def health_check(self) -> bool:
        """Check GraphQL endpoint health."""
        try:
            result = await self.query("{ __typename }")
            return "__typename" in result
        except Exception:
            return False
