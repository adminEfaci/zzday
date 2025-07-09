"""
Data Mapping Service Interface

Port for data transformation and mapping operations between
internal domain models and external integration formats.
"""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, TypeVar
from uuid import UUID

if TYPE_CHECKING:
    from app.modules.integration.domain.value_objects import MappingRule, TransformationChain

T = TypeVar('T')


class IDataMappingService(ABC):
    """Port for data mapping and transformation operations."""
    
    @abstractmethod
    async def create_mapping(
        self,
        name: str,
        source_schema: dict[str, Any],
        target_schema: dict[str, Any],
        mapping_rules: list["MappingRule"],
        bidirectional: bool = False
    ) -> UUID:
        """
        Create a data mapping configuration.
        
        Args:
            name: Mapping name
            source_schema: Source data schema
            target_schema: Target data schema
            mapping_rules: List of mapping rules
            bidirectional: Whether mapping works both ways
            
        Returns:
            ID of created mapping
            
        Raises:
            InvalidSchemaError: If schema is invalid
            IncompatibleSchemasError: If schemas can't be mapped
            InvalidMappingRuleError: If any rule is invalid
        """
        ...
    
    @abstractmethod
    async def transform_data(
        self,
        mapping_id: UUID,
        source_data: dict[str, Any],
        direction: str = "forward"
    ) -> dict[str, Any]:
        """
        Transform data using mapping.
        
        Args:
            mapping_id: ID of mapping to use
            source_data: Data to transform
            direction: "forward" or "reverse"
            
        Returns:
            Transformed data
            
        Raises:
            MappingNotFoundError: If mapping doesn't exist
            TransformationError: If transformation fails
            InvalidDirectionError: If direction not supported
        """
        ...
    
    @abstractmethod
    async def validate_mapping(
        self,
        mapping_id: UUID,
        sample_data: dict[str, Any] | None = None
    ) -> tuple[bool, list[str]]:
        """
        Validate a mapping configuration.
        
        Args:
            mapping_id: ID of mapping to validate
            sample_data: Optional sample data to test
            
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        ...
    
    @abstractmethod
    async def apply_transformation_chain(
        self,
        data: dict[str, Any],
        transformations: "TransformationChain"
    ) -> dict[str, Any]:
        """
        Apply a chain of transformations to data.
        
        Args:
            data: Input data
            transformations: Chain of transformations
            
        Returns:
            Transformed data
            
        Raises:
            TransformationError: If any transformation fails
        """
        ...
    
    @abstractmethod
    async def map_field(
        self,
        source_value: Any,
        source_type: str,
        target_type: str,
        conversion_rules: dict[str, Any] | None = None
    ) -> Any:
        """
        Map a single field value between types.
        
        Args:
            source_value: Value to map
            source_type: Source data type
            target_type: Target data type
            conversion_rules: Optional conversion rules
            
        Returns:
            Mapped value
            
        Raises:
            IncompatibleTypesError: If types can't be mapped
            ConversionError: If conversion fails
        """
        ...
    
    @abstractmethod
    async def enrich_data(
        self,
        data: dict[str, Any],
        enrichment_rules: list[dict[str, Any]],
        external_sources: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """
        Enrich data with additional information.
        
        Args:
            data: Base data to enrich
            enrichment_rules: Rules for enrichment
            external_sources: Optional external data sources
            
        Returns:
            Enriched data
        """
        ...
    
    @abstractmethod
    async def filter_sensitive_data(
        self,
        data: dict[str, Any],
        sensitivity_rules: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Filter out sensitive data based on rules.
        
        Args:
            data: Data to filter
            sensitivity_rules: Rules defining sensitive fields
            
        Returns:
            Filtered data with sensitive fields removed/masked
        """
        ...
    
    @abstractmethod
    async def generate_mapping_documentation(
        self,
        mapping_id: UUID
    ) -> dict[str, Any]:
        """
        Generate documentation for a mapping.
        
        Args:
            mapping_id: ID of mapping
            
        Returns:
            Documentation including field mappings, rules, examples
        """
        ...
    
    @abstractmethod
    async def detect_schema_changes(
        self,
        mapping_id: UUID,
        new_source_schema: dict[str, Any] | None = None,
        new_target_schema: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """
        Detect changes between current and new schemas.
        
        Args:
            mapping_id: ID of mapping
            new_source_schema: Optional new source schema
            new_target_schema: Optional new target schema
            
        Returns:
            Dictionary of detected changes and impacts
        """
        ...
    
    @abstractmethod
    async def auto_map_schemas(
        self,
        source_schema: dict[str, Any],
        target_schema: dict[str, Any],
        mapping_hints: dict[str, Any] | None = None
    ) -> list["MappingRule"]:
        """
        Automatically generate mapping rules between schemas.
        
        Args:
            source_schema: Source schema
            target_schema: Target schema
            mapping_hints: Optional hints for mapping
            
        Returns:
            List of generated mapping rules
        """
        ...