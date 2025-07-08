"""
EventTransformer - Event Format Transformation and Adaptation

Provides comprehensive event transformation capabilities for converting events between
different formats, versions, and schemas. Supports event enrichment, data mapping,
and cross-system integration.

Key Features:
- Event format transformation and adaptation
- Schema version migration and compatibility
- Event enrichment and data augmentation
- Cross-system event mapping
- Transformation pipelines and chaining
- Data validation and sanitization
- Performance-optimized transformations
- Transformation monitoring and analytics
"""

import copy
import json
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from app.core.events.types import EventFactory
from app.core.logging import get_logger
from app.modules.identity.domain.events import IdentityDomainEvent

if TYPE_CHECKING:
    from .adapter import EventBusAdapter

logger = get_logger(__name__)


class TransformationType(Enum):
    """Type of event transformation."""
    FORMAT_CONVERSION = "format_conversion"
    SCHEMA_MIGRATION = "schema_migration"
    DATA_ENRICHMENT = "data_enrichment"
    FIELD_MAPPING = "field_mapping"
    AGGREGATION = "aggregation"
    SPLITTING = "splitting"
    FILTERING = "filtering"
    VALIDATION = "validation"


class TransformationResult(Enum):
    """Result of transformation operation."""
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    PARTIAL = "partial"


@dataclass
class TransformationContext:
    """Context information for event transformations."""
    transformation_id: UUID
    source_event: IdentityDomainEvent
    transformation_type: TransformationType
    pipeline_name: str | None = None
    step_number: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    def add_metadata(self, key: str, value: Any) -> None:
        """Add metadata to transformation context."""
        self.metadata[key] = value
    
    def get_metadata(self, key: str, default: Any = None) -> Any:
        """Get metadata from transformation context."""
        return self.metadata.get(key, default)


@dataclass
class TransformationRule:
    """Defines a transformation rule for events."""
    rule_id: str
    name: str
    source_event_types: list[str]
    target_event_type: str | None = None
    transformation_type: TransformationType = TransformationType.FORMAT_CONVERSION
    transformation_function: Callable[[IdentityDomainEvent, TransformationContext], Any] | None = None
    field_mappings: dict[str, str] = field(default_factory=dict)
    conditions: dict[str, Any] = field(default_factory=dict)
    priority: int = 100
    enabled: bool = True
    
    def matches_event(self, event: IdentityDomainEvent) -> bool:
        """Check if this rule applies to the given event."""
        if not self.enabled:
            return False
        
        # Check event type
        event_type = event.__class__.__name__
        if event_type not in self.source_event_types:
            return False
        
        # Check conditions
        for field_path, expected_value in self.conditions.items():
            try:
                actual_value = event
                for attr in field_path.split('.'):
                    actual_value = getattr(actual_value, attr)
                
                if actual_value != expected_value:
                    return False
            except AttributeError:
                return False
        
        return True


class BaseTransformer(ABC):
    """Base class for event transformers."""
    
    def __init__(self, transformer_name: str):
        self.transformer_name = transformer_name
        self.transformation_count = 0
        self.success_count = 0
        self.failure_count = 0
    
    @abstractmethod
    async def transform(
        self,
        event: IdentityDomainEvent,
        context: TransformationContext
    ) -> tuple[Any, TransformationResult]:
        """Transform an event. Must be implemented by subclasses."""
    
    def get_statistics(self) -> dict[str, Any]:
        """Get transformer statistics."""
        success_rate = (
            self.success_count / self.transformation_count
            if self.transformation_count > 0 else 0.0
        )
        
        return {
            'transformer_name': self.transformer_name,
            'transformation_count': self.transformation_count,
            'success_count': self.success_count,
            'failure_count': self.failure_count,
            'success_rate': success_rate
        }


class FormatConverter(BaseTransformer):
    """Converts events between different formats (JSON, dict, etc.)."""
    
    def __init__(self):
        super().__init__("FormatConverter")
    
    async def transform(
        self,
        event: IdentityDomainEvent,
        context: TransformationContext
    ) -> tuple[Any, TransformationResult]:
        """Convert event to specified format."""
        try:
            self.transformation_count += 1
            target_format = context.get_metadata('target_format', 'dict')
            
            if target_format == 'dict':
                result = event.to_dict()
            elif target_format == 'json':
                result = json.dumps(event.to_dict(), default=str, indent=2)
            elif target_format == 'compact_json':
                result = json.dumps(event.to_dict(), default=str, separators=(',', ':'))
            else:
                raise ValueError(f"Unsupported target format: {target_format}")
            
            self.success_count += 1
            return result, TransformationResult.SUCCESS
            
        except Exception as e:
            self.failure_count += 1
            logger.exception(
                "Format conversion failed",
                transformer=self.transformer_name,
                event_type=event.__class__.__name__,
                error=str(e)
            )
            return None, TransformationResult.FAILED


class SchemaVersionMigrator(BaseTransformer):
    """Migrates events between different schema versions."""
    
    def __init__(self):
        super().__init__("SchemaVersionMigrator")
        self.migration_rules: dict[str, dict[str, Callable]] = {}
    
    def add_migration_rule(
        self,
        event_type: str,
        from_version: str,
        to_version: str,
        migration_function: Callable[[dict[str, Any]], dict[str, Any]]
    ) -> None:
        """Add a migration rule for schema version conversion."""
        if event_type not in self.migration_rules:
            self.migration_rules[event_type] = {}
        
        migration_key = f"{from_version}->{to_version}"
        self.migration_rules[event_type][migration_key] = migration_function
        
        logger.debug(
            "Migration rule added",
            event_type=event_type,
            from_version=from_version,
            to_version=to_version
        )
    
    async def transform(
        self,
        event: IdentityDomainEvent,
        context: TransformationContext
    ) -> tuple[IdentityDomainEvent | None, TransformationResult]:
        """Migrate event to target schema version."""
        try:
            self.transformation_count += 1
            
            event_type = event.__class__.__name__
            from_version = context.get_metadata('from_version')
            to_version = context.get_metadata('to_version')
            
            if not from_version or not to_version:
                return event, TransformationResult.SKIPPED
            
            if from_version == to_version:
                return event, TransformationResult.SKIPPED
            
            # Check for migration rule
            if event_type not in self.migration_rules:
                return event, TransformationResult.SKIPPED
            
            migration_key = f"{from_version}->{to_version}"
            if migration_key not in self.migration_rules[event_type]:
                return event, TransformationResult.SKIPPED
            
            # Apply migration
            migration_function = self.migration_rules[event_type][migration_key]
            event_data = event.to_dict()
            migrated_data = migration_function(event_data)
            
            # Reconstruct event
            migrated_event = EventFactory.reconstruct_event(migrated_data)
            
            self.success_count += 1
            return migrated_event, TransformationResult.SUCCESS
            
        except Exception as e:
            self.failure_count += 1
            logger.exception(
                "Schema migration failed",
                transformer=self.transformer_name,
                event_type=event.__class__.__name__,
                error=str(e)
            )
            return None, TransformationResult.FAILED


class DataEnricher(BaseTransformer):
    """Enriches events with additional data."""
    
    def __init__(self):
        super().__init__("DataEnricher")
        self.enrichment_functions: dict[str, list[Callable]] = {}
    
    def add_enrichment_function(
        self,
        event_type: str,
        enrichment_function: Callable[[IdentityDomainEvent], dict[str, Any]]
    ) -> None:
        """Add an enrichment function for an event type."""
        if event_type not in self.enrichment_functions:
            self.enrichment_functions[event_type] = []
        
        self.enrichment_functions[event_type].append(enrichment_function)
        
        logger.debug(
            "Enrichment function added",
            event_type=event_type,
            function_count=len(self.enrichment_functions[event_type])
        )
    
    async def transform(
        self,
        event: IdentityDomainEvent,
        context: TransformationContext
    ) -> tuple[IdentityDomainEvent, TransformationResult]:
        """Enrich event with additional data."""
        try:
            self.transformation_count += 1
            
            event_type = event.__class__.__name__
            
            if event_type not in self.enrichment_functions:
                return event, TransformationResult.SKIPPED
            
            # Apply enrichment functions
            enriched_event = copy.deepcopy(event)
            enrichment_applied = False
            
            for enrichment_function in self.enrichment_functions[event_type]:
                try:
                    enrichment_data = enrichment_function(event)
                    
                    # Add enrichment data to event
                    for key, value in enrichment_data.items():
                        if not hasattr(enriched_event, key):
                            setattr(enriched_event, key, value)
                            enrichment_applied = True
                
                except Exception as e:
                    logger.warning(
                        "Enrichment function failed",
                        event_type=event_type,
                        error=str(e)
                    )
            
            if enrichment_applied:
                self.success_count += 1
                return enriched_event, TransformationResult.SUCCESS
            return event, TransformationResult.SKIPPED
                
        except Exception as e:
            self.failure_count += 1
            logger.exception(
                "Data enrichment failed",
                transformer=self.transformer_name,
                event_type=event.__class__.__name__,
                error=str(e)
            )
            return event, TransformationResult.FAILED


class FieldMapper(BaseTransformer):
    """Maps fields between different event schemas."""
    
    def __init__(self):
        super().__init__("FieldMapper")
    
    async def transform(
        self,
        event: IdentityDomainEvent,
        context: TransformationContext
    ) -> tuple[dict[str, Any], TransformationResult]:
        """Map event fields according to mapping rules."""
        try:
            self.transformation_count += 1
            
            field_mappings = context.get_metadata('field_mappings', {})
            
            if not field_mappings:
                return event.to_dict(), TransformationResult.SKIPPED
            
            event_data = event.to_dict()
            mapped_data = {}
            
            # Apply field mappings
            for source_field, target_field in field_mappings.items():
                value = self._get_nested_value(event_data, source_field)
                if value is not None:
                    self._set_nested_value(mapped_data, target_field, value)
            
            # Copy unmapped fields if specified
            copy_unmapped = context.get_metadata('copy_unmapped_fields', False)
            if copy_unmapped:
                for key, value in event_data.items():
                    if key not in field_mappings and key not in mapped_data:
                        mapped_data[key] = value
            
            self.success_count += 1
            return mapped_data, TransformationResult.SUCCESS
            
        except Exception as e:
            self.failure_count += 1
            logger.exception(
                "Field mapping failed",
                transformer=self.transformer_name,
                event_type=event.__class__.__name__,
                error=str(e)
            )
            return {}, TransformationResult.FAILED
    
    def _get_nested_value(self, data: dict[str, Any], field_path: str) -> Any:
        """Get value from nested dictionary using dot notation."""
        try:
            value = data
            for key in field_path.split('.'):
                value = value[key]
            return value
        except (KeyError, TypeError):
            return None
    
    def _set_nested_value(self, data: dict[str, Any], field_path: str, value: Any) -> None:
        """Set value in nested dictionary using dot notation."""
        keys = field_path.split('.')
        current = data
        
        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        
        current[keys[-1]] = value


@dataclass
class TransformationPipeline:
    """Represents a pipeline of transformations."""
    pipeline_id: str
    name: str
    transformers: list[BaseTransformer] = field(default_factory=list)
    enabled: bool = True
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    def add_transformer(self, transformer: BaseTransformer) -> None:
        """Add a transformer to the pipeline."""
        self.transformers.append(transformer)
    
    def remove_transformer(self, transformer: BaseTransformer) -> None:
        """Remove a transformer from the pipeline."""
        if transformer in self.transformers:
            self.transformers.remove(transformer)
    
    async def execute(
        self,
        event: IdentityDomainEvent,
        context: TransformationContext
    ) -> tuple[Any, list[TransformationResult]]:
        """Execute the transformation pipeline."""
        current_data = event
        results = []
        
        context.pipeline_name = self.name
        
        for i, transformer in enumerate(self.transformers):
            context.step_number = i + 1
            
            try:
                current_data, result = await transformer.transform(current_data, context)
                results.append(result)
                
                if result == TransformationResult.FAILED:
                    logger.warning(
                        "Pipeline transformation failed",
                        pipeline=self.name,
                        step=i + 1,
                        transformer=transformer.transformer_name
                    )
                    break
                    
            except Exception as e:
                logger.exception(
                    "Pipeline execution error",
                    pipeline=self.name,
                    step=i + 1,
                    transformer=transformer.transformer_name,
                    error=str(e)
                )
                results.append(TransformationResult.FAILED)
                break
        
        return current_data, results


class EventTransformer:
    """
    Comprehensive event transformation engine.
    
    Provides event format transformation, schema migration, data enrichment,
    and field mapping capabilities with pipeline support.
    """
    
    def __init__(self, event_bus_adapter: 'EventBusAdapter'):
        """
        Initialize the event transformer.
        
        Args:
            event_bus_adapter: Event bus adapter for integration
        """
        self.event_bus_adapter = event_bus_adapter
        
        # Built-in transformers
        self.format_converter = FormatConverter()
        self.schema_migrator = SchemaVersionMigrator()
        self.data_enricher = DataEnricher()
        self.field_mapper = FieldMapper()
        
        # Transformation rules and pipelines
        self.transformation_rules: list[TransformationRule] = []
        self.pipelines: dict[str, TransformationPipeline] = {}
        
        # Performance tracking
        self.total_transformations = 0
        self.successful_transformations = 0
        self.failed_transformations = 0
        
        logger.info("EventTransformer initialized")
    
    def add_transformation_rule(self, rule: TransformationRule) -> None:
        """Add a transformation rule."""
        self.transformation_rules.append(rule)
        
        # Sort rules by priority (higher priority first)
        self.transformation_rules.sort(key=lambda r: r.priority, reverse=True)
        
        logger.debug(
            "Transformation rule added",
            rule_id=rule.rule_id,
            name=rule.name,
            priority=rule.priority
        )
    
    def remove_transformation_rule(self, rule_id: str) -> bool:
        """Remove a transformation rule by ID."""
        for i, rule in enumerate(self.transformation_rules):
            if rule.rule_id == rule_id:
                del self.transformation_rules[i]
                logger.debug("Transformation rule removed", rule_id=rule_id)
                return True
        return False
    
    def create_pipeline(self, pipeline_id: str, name: str) -> TransformationPipeline:
        """Create a new transformation pipeline."""
        pipeline = TransformationPipeline(pipeline_id=pipeline_id, name=name)
        self.pipelines[pipeline_id] = pipeline
        
        logger.debug("Transformation pipeline created", pipeline_id=pipeline_id, name=name)
        return pipeline
    
    def get_pipeline(self, pipeline_id: str) -> TransformationPipeline | None:
        """Get a transformation pipeline by ID."""
        return self.pipelines.get(pipeline_id)
    
    def remove_pipeline(self, pipeline_id: str) -> bool:
        """Remove a transformation pipeline."""
        if pipeline_id in self.pipelines:
            del self.pipelines[pipeline_id]
            logger.debug("Transformation pipeline removed", pipeline_id=pipeline_id)
            return True
        return False
    
    async def transform_event(
        self,
        event: IdentityDomainEvent,
        transformation_type: TransformationType = TransformationType.FORMAT_CONVERSION,
        pipeline_id: str | None = None,
        **kwargs
    ) -> tuple[Any, TransformationResult]:
        """
        Transform an event using rules or pipelines.
        
        Args:
            event: Event to transform
            transformation_type: Type of transformation
            pipeline_id: Optional pipeline ID for pipeline transformation
            **kwargs: Additional transformation parameters
            
        Returns:
            Tuple of (transformed_data, result_status)
        """
        try:
            self.total_transformations += 1
            
            # Create transformation context
            context = TransformationContext(
                transformation_id=uuid4(),
                source_event=event,
                transformation_type=transformation_type
            )
            
            # Add kwargs to context metadata
            for key, value in kwargs.items():
                context.add_metadata(key, value)
            
            # Execute pipeline if specified
            if pipeline_id and pipeline_id in self.pipelines:
                pipeline = self.pipelines[pipeline_id]
                if pipeline.enabled:
                    result_data, pipeline_results = await pipeline.execute(event, context)
                    
                    # Determine overall result
                    if any(r == TransformationResult.FAILED for r in pipeline_results):
                        overall_result = TransformationResult.FAILED
                    elif any(r == TransformationResult.SUCCESS for r in pipeline_results):
                        overall_result = TransformationResult.SUCCESS
                    else:
                        overall_result = TransformationResult.SKIPPED
                    
                    if overall_result == TransformationResult.SUCCESS:
                        self.successful_transformations += 1
                    else:
                        self.failed_transformations += 1
                    
                    return result_data, overall_result
            
            # Apply transformation rules
            for rule in self.transformation_rules:
                if rule.matches_event(event):
                    result_data, result_status = await self._apply_transformation_rule(
                        rule, event, context
                    )
                    
                    if result_status == TransformationResult.SUCCESS:
                        self.successful_transformations += 1
                        return result_data, result_status
                    if result_status == TransformationResult.FAILED:
                        self.failed_transformations += 1
                        return result_data, result_status
            
            # No transformations applied
            return event, TransformationResult.SKIPPED
            
        except Exception as e:
            self.failed_transformations += 1
            logger.exception(
                "Event transformation failed",
                event_type=event.__class__.__name__,
                transformation_type=transformation_type.value,
                error=str(e)
            )
            return None, TransformationResult.FAILED
    
    async def transform_to_format(
        self,
        event: IdentityDomainEvent,
        target_format: str = 'dict'
    ) -> tuple[Any, TransformationResult]:
        """Transform event to specific format."""
        return await self.transform_event(
            event,
            TransformationType.FORMAT_CONVERSION,
            target_format=target_format
        )
    
    async def migrate_schema(
        self,
        event: IdentityDomainEvent,
        from_version: str,
        to_version: str
    ) -> tuple[IdentityDomainEvent | None, TransformationResult]:
        """Migrate event schema version."""
        return await self.transform_event(
            event,
            TransformationType.SCHEMA_MIGRATION,
            from_version=from_version,
            to_version=to_version
        )
    
    async def enrich_event(
        self,
        event: IdentityDomainEvent
    ) -> tuple[IdentityDomainEvent, TransformationResult]:
        """Enrich event with additional data."""
        return await self.transform_event(event, TransformationType.DATA_ENRICHMENT)
    
    async def map_fields(
        self,
        event: IdentityDomainEvent,
        field_mappings: dict[str, str],
        copy_unmapped_fields: bool = False
    ) -> tuple[dict[str, Any], TransformationResult]:
        """Map event fields according to mapping rules."""
        return await self.transform_event(
            event,
            TransformationType.FIELD_MAPPING,
            field_mappings=field_mappings,
            copy_unmapped_fields=copy_unmapped_fields
        )
    
    def get_statistics(self) -> dict[str, Any]:
        """Get transformation statistics."""
        success_rate = (
            self.successful_transformations / self.total_transformations
            if self.total_transformations > 0 else 0.0
        )
        
        transformer_stats = {
            'format_converter': self.format_converter.get_statistics(),
            'schema_migrator': self.schema_migrator.get_statistics(),
            'data_enricher': self.data_enricher.get_statistics(),
            'field_mapper': self.field_mapper.get_statistics()
        }
        
        return {
            'total_transformations': self.total_transformations,
            'successful_transformations': self.successful_transformations,
            'failed_transformations': self.failed_transformations,
            'success_rate': success_rate,
            'transformation_rules': len(self.transformation_rules),
            'pipelines': len(self.pipelines),
            'transformer_statistics': transformer_stats
        }
    
    # Private methods
    
    async def _apply_transformation_rule(
        self,
        rule: TransformationRule,
        event: IdentityDomainEvent,
        context: TransformationContext
    ) -> tuple[Any, TransformationResult]:
        """Apply a specific transformation rule."""
        try:
            # Use custom transformation function if provided
            if rule.transformation_function:
                result_data = rule.transformation_function(event, context)
                return result_data, TransformationResult.SUCCESS
            
            # Apply built-in transformations based on type
            if rule.transformation_type == TransformationType.FORMAT_CONVERSION:
                return await self.format_converter.transform(event, context)
            
            if rule.transformation_type == TransformationType.SCHEMA_MIGRATION:
                return await self.schema_migrator.transform(event, context)
            
            if rule.transformation_type == TransformationType.DATA_ENRICHMENT:
                return await self.data_enricher.transform(event, context)
            
            if rule.transformation_type == TransformationType.FIELD_MAPPING:
                context.add_metadata('field_mappings', rule.field_mappings)
                return await self.field_mapper.transform(event, context)
            
            logger.warning(
                "Unsupported transformation type",
                transformation_type=rule.transformation_type.value,
                rule_id=rule.rule_id
            )
            return event, TransformationResult.SKIPPED
                
        except Exception as e:
            logger.exception(
                "Transformation rule application failed",
                rule_id=rule.rule_id,
                error=str(e)
            )
            return None, TransformationResult.FAILED