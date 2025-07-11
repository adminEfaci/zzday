"""
GraphQL Query Complexity Analysis

Provides tools for analyzing and limiting query complexity to prevent
expensive queries that could cause performance issues or DoS attacks.
"""

import logging
from collections.abc import Callable
from typing import Any

from graphql import (
    DocumentNode,
    FieldNode,
    FragmentDefinitionNode,
    FragmentSpreadNode,
    GraphQLObjectType,
    GraphQLSchema,
    InlineFragmentNode,
    OperationDefinitionNode,
    SelectionSetNode,
    get_named_type,
    is_list_type,
)
from strawberry import GraphQLError

logger = logging.getLogger(__name__)


class ComplexityError(GraphQLError):
    """Error raised when query complexity exceeds limits"""
    
    def __init__(
        self, 
        complexity: int, 
        max_complexity: int,
        message: str | None = None
    ):
        super().__init__(
            message or f"Query complexity {complexity} exceeds maximum allowed complexity {max_complexity}",
            extensions={
                "code": "QUERY_TOO_COMPLEX",
                "complexity": complexity,
                "max_complexity": max_complexity
            }
        )


class QueryComplexityAnalyzer:
    """
    Analyzes GraphQL query complexity based on configurable rules.
    
    Complexity is calculated based on:
    - Field selections (base cost)
    - List multipliers 
    - Pagination arguments
    - Custom field costs
    """
    
    def __init__(  # noqa: PLR0913
        self,
        schema: GraphQLSchema,
        max_complexity: int = 1000,
        default_field_cost: int = 1,
        default_list_multiplier: int = 10,
        field_costs: dict[str, int] | None = None,
        list_multipliers: dict[str, int] | None = None
    ):
        """
        Initialize the complexity analyzer.
        
        Args:
            schema: The GraphQL schema
            max_complexity: Maximum allowed complexity
            default_field_cost: Default cost for each field
            default_list_multiplier: Default multiplier for list fields
            field_costs: Custom costs for specific fields
            list_multipliers: Custom multipliers for specific list fields
        """
        self.schema = schema
        self.max_complexity = max_complexity
        self.default_field_cost = default_field_cost
        self.default_list_multiplier = default_list_multiplier
        self.field_costs = field_costs or {}
        self.list_multipliers = list_multipliers or {}
        
        # Add default high costs for expensive operations
        self.field_costs.update({
            # Expensive queries
            "users": 10,
            "allUsers": 20,
            "search": 15,
            "analytics": 25,
            "reports": 30,
            
            # Mutations are generally more expensive
            "createUser": 20,
            "updateUser": 15,
            "deleteUser": 15,
            "bulkOperation": 50,
        })
    
    def validate_query(
        self, 
        document: DocumentNode,
        variables: dict[str, Any] | None = None
    ) -> int:
        """
        Validate query complexity and raise error if too complex.
        
        Returns the calculated complexity if valid.
        """
        complexity = self.calculate_complexity(document, variables)
        
        if complexity > self.max_complexity:
            logger.warning(
                f"Query rejected due to high complexity: {complexity} > {self.max_complexity}"
            )
            raise ComplexityError(complexity, self.max_complexity)
        
        return complexity
    
    def calculate_complexity(
        self,
        document: DocumentNode,
        variables: dict[str, Any] | None = None
    ) -> int:
        """Calculate the total complexity of a GraphQL query"""
        total_complexity = 0
        
        # Process each operation in the document
        for definition in document.definitions:
            if isinstance(definition, OperationDefinitionNode):
                # Get the root type for this operation
                root_type = self._get_root_type(definition.operation)
                if root_type:
                    complexity = self._calculate_selection_set_complexity(
                        definition.selection_set,
                        root_type,
                        variables or {},
                        self._get_fragments(document)
                    )
                    total_complexity += complexity
        
        logger.debug(f"Calculated query complexity: {total_complexity}")
        return total_complexity
    
    def _get_root_type(self, operation: str) -> GraphQLObjectType | None:
        """Get the root type for an operation"""
        if operation == "query":
            return self.schema.query_type
        if operation == "mutation":
            return self.schema.mutation_type
        if operation == "subscription":
            return self.schema.subscription_type
        return None
    
    def _get_fragments(self, document: DocumentNode) -> dict[str, FragmentDefinitionNode]:
        """Extract all fragment definitions from the document"""
        fragments = {}
        for definition in document.definitions:
            if isinstance(definition, FragmentDefinitionNode):
                fragments[definition.name.value] = definition
        return fragments
    
    def _calculate_selection_set_complexity(
        self,
        selection_set: SelectionSetNode,
        parent_type: GraphQLObjectType,
        variables: dict[str, Any],
        fragments: dict[str, FragmentDefinitionNode],
        visited_fragments: set[str] | None = None
    ) -> int:
        """Calculate complexity for a selection set"""
        if visited_fragments is None:
            visited_fragments = set()
        
        complexity = 0
        
        for selection in selection_set.selections:
            if isinstance(selection, FieldNode):
                complexity += self._calculate_field_complexity(
                    selection,
                    parent_type,
                    variables,
                    fragments,
                    visited_fragments
                )
            elif isinstance(selection, InlineFragmentNode):
                # Process inline fragments
                if selection.selection_set:
                    type_name = selection.type_condition.name.value if selection.type_condition else parent_type.name
                    fragment_type = self.schema.type_map.get(type_name)
                    if isinstance(fragment_type, GraphQLObjectType):
                        complexity += self._calculate_selection_set_complexity(
                            selection.selection_set,
                            fragment_type,
                            variables,
                            fragments,
                            visited_fragments
                        )
            elif isinstance(selection, FragmentSpreadNode):
                # Process fragment spreads
                fragment_name = selection.name.value
                if fragment_name not in visited_fragments and fragment_name in fragments:
                    visited_fragments.add(fragment_name)
                    fragment = fragments[fragment_name]
                    fragment_type_name = fragment.type_condition.name.value
                    fragment_type = self.schema.type_map.get(fragment_type_name)
                    if isinstance(fragment_type, GraphQLObjectType):
                        complexity += self._calculate_selection_set_complexity(
                            fragment.selection_set,
                            fragment_type,
                            variables,
                            fragments,
                            visited_fragments
                        )
        
        return complexity
    
    def _calculate_field_complexity(
        self,
        field: FieldNode,
        parent_type: GraphQLObjectType,
        variables: dict[str, Any],
        fragments: dict[str, FragmentDefinitionNode],
        visited_fragments: set[str]
    ) -> int:
        """Calculate complexity for a single field"""
        field_name = field.name.value
        
        # Skip introspection fields
        if field_name.startswith("__"):
            return 0
        
        # Get field definition
        field_def = parent_type.fields.get(field_name)
        if not field_def:
            return 0
        
        # Get base cost for this field
        field_key = f"{parent_type.name}.{field_name}"
        base_cost = self.field_costs.get(field_key, self.default_field_cost)
        
        # Apply list multiplier if this is a list field
        field_type = field_def.type
        multiplier = 1
        
        if is_list_type(field_type):
            # Get pagination arguments
            first = self._get_argument_value(field, "first", variables)
            last = self._get_argument_value(field, "last", variables)
            limit = self._get_argument_value(field, "limit", variables)
            
            # Use the pagination value or default multiplier
            if first is not None:
                multiplier = min(first, 100)  # Cap at 100
            elif last is not None:
                multiplier = min(last, 100)
            elif limit is not None:
                multiplier = min(limit, 100)
            else:
                # Use custom or default multiplier
                multiplier = self.list_multipliers.get(
                    field_key, 
                    self.default_list_multiplier
                )
        
        # Calculate total cost for this field
        field_complexity = base_cost * multiplier
        
        # Add complexity for nested selections
        if field.selection_set:
            # Get the return type (unwrap lists/non-nulls)
            return_type = get_named_type(field_def.type)
            if isinstance(return_type, GraphQLObjectType):
                nested_complexity = self._calculate_selection_set_complexity(
                    field.selection_set,
                    return_type,
                    variables,
                    fragments,
                    visited_fragments
                )
                field_complexity += nested_complexity * multiplier
        
        return field_complexity
    
    def _get_argument_value(
        self,
        field: FieldNode,
        arg_name: str,
        variables: dict[str, Any]
    ) -> Any | None:
        """Get the value of a field argument"""
        for argument in field.arguments:
            if argument.name.value == arg_name:
                value = argument.value
                # Handle variable references
                if hasattr(value, 'name'):
                    return variables.get(value.name.value)
                # Handle literal values
                if hasattr(value, 'value'):
                    return value.value
        return None


class QueryDepthAnalyzer:
    """
    Analyzes query depth to prevent deeply nested queries.
    """
    
    def __init__(self, max_depth: int = 10):
        """
        Initialize the depth analyzer.
        
        Args:
            max_depth: Maximum allowed query depth
        """
        self.max_depth = max_depth
    
    def validate_depth(
        self,
        document: DocumentNode,
        schema: GraphQLSchema
    ) -> int:
        """
        Validate query depth and raise error if too deep.
        
        Returns the maximum depth if valid.
        """
        max_depth = self.calculate_depth(document, schema)
        
        if max_depth > self.max_depth:
            logger.warning(
                f"Query rejected due to excessive depth: {max_depth} > {self.max_depth}"
            )
            raise GraphQLError(
                f"Query depth {max_depth} exceeds maximum allowed depth {self.max_depth}",
                extensions={
                    "code": "QUERY_TOO_DEEP",
                    "depth": max_depth,
                    "max_depth": self.max_depth
                }
            )
        
        return max_depth
    
    def calculate_depth(
        self,
        document: DocumentNode,
        schema: GraphQLSchema
    ) -> int:
        """Calculate the maximum depth of a GraphQL query"""
        max_depth = 0
        fragments = self._get_fragments(document)
        
        for definition in document.definitions:
            if isinstance(definition, OperationDefinitionNode):
                depth = self._calculate_selection_set_depth(
                    definition.selection_set,
                    fragments,
                    set()
                )
                max_depth = max(max_depth, depth)
        
        return max_depth
    
    def _get_fragments(self, document: DocumentNode) -> dict[str, FragmentDefinitionNode]:
        """Extract all fragment definitions from the document"""
        fragments = {}
        for definition in document.definitions:
            if isinstance(definition, FragmentDefinitionNode):
                fragments[definition.name.value] = definition
        return fragments
    
    def _calculate_selection_set_depth(
        self,
        selection_set: SelectionSetNode,
        fragments: dict[str, FragmentDefinitionNode],
        visited_fragments: set[str]
    ) -> int:
        """Calculate depth for a selection set"""
        max_depth = 0
        
        for selection in selection_set.selections:
            if isinstance(selection, FieldNode):
                depth = 1
                if selection.selection_set:
                    depth += self._calculate_selection_set_depth(
                        selection.selection_set,
                        fragments,
                        visited_fragments
                    )
                max_depth = max(max_depth, depth)
            elif isinstance(selection, InlineFragmentNode):
                if selection.selection_set:
                    depth = self._calculate_selection_set_depth(
                        selection.selection_set,
                        fragments,
                        visited_fragments
                    )
                    max_depth = max(max_depth, depth)
            elif isinstance(selection, FragmentSpreadNode):
                fragment_name = selection.name.value
                if fragment_name not in visited_fragments and fragment_name in fragments:
                    visited_fragments.add(fragment_name)
                    fragment = fragments[fragment_name]
                    depth = self._calculate_selection_set_depth(
                        fragment.selection_set,
                        fragments,
                        visited_fragments
                    )
                    max_depth = max(max_depth, depth)
        
        return max_depth


# ============================================================================
# Middleware for automatic complexity validation
# ============================================================================

def create_complexity_validator(
    max_complexity: int = 1000,
    max_depth: int = 10,
    **kwargs
) -> Callable:
    """
    Create a complexity validation function for use with Strawberry.
    
    Usage:
        schema = strawberry.Schema(
            query=Query,
            extensions=[
                QueryComplexityExtension(
                    max_complexity=1000,
                    max_depth=10
                )
            ]
        )
    """
    def validate_complexity(
        schema: GraphQLSchema,
        document: DocumentNode,
        variables: dict[str, Any] | None = None
    ):
        # Validate complexity
        complexity_analyzer = QueryComplexityAnalyzer(
            schema,
            max_complexity=max_complexity,
            **kwargs
        )
        complexity_analyzer.validate_query(document, variables)
        
        # Validate depth
        depth_analyzer = QueryDepthAnalyzer(max_depth=max_depth)
        depth_analyzer.validate_depth(document, schema)
    
    return validate_complexity


__all__ = [
    "ComplexityError",
    "QueryComplexityAnalyzer",
    "QueryDepthAnalyzer",
    "create_complexity_validator",
]