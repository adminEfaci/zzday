"""
GraphQL Schema Versioning System

Provides comprehensive schema versioning capabilities including backwards compatibility,
deprecation management, migration tools, and version negotiation.
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from uuid import uuid4

from graphql import (
    GraphQLSchema,
    build_ast_schema,
    build_schema,
    get_introspection_query,
    introspection_from_schema,
    parse,
    print_schema,
    validate_schema,
)
from strawberry import GraphQLError
from strawberry.extensions import Extension
from strawberry.schema import Schema as StrawberrySchema
from strawberry.types import ExecutionContext, ExecutionResult

logger = logging.getLogger(__name__)


class VersioningStrategy(Enum):
    """Schema versioning strategies."""
    SEMANTIC = "semantic"  # v1.0.0, v1.1.0, v2.0.0
    DATE_BASED = "date_based"  # 2024-01-01, 2024-02-15
    INCREMENTAL = "incremental"  # v1, v2, v3
    CUSTOM = "custom"  # Custom versioning scheme


class ChangeType(Enum):
    """Types of schema changes."""
    BREAKING = "breaking"
    NON_BREAKING = "non_breaking"
    DEPRECATION = "deprecation"
    REMOVAL = "removal"


class CompatibilityLevel(Enum):
    """Schema compatibility levels."""
    FULL = "full"  # Fully compatible
    PARTIAL = "partial"  # Partially compatible
    BREAKING = "breaking"  # Breaking changes
    INCOMPATIBLE = "incompatible"  # Incompatible


@dataclass
class SchemaVersion:
    """Represents a schema version."""
    version: str
    schema: GraphQLSchema
    created_at: datetime
    description: Optional[str] = None
    
    # Metadata
    author: Optional[str] = None
    changelog: List[str] = field(default_factory=list)
    breaking_changes: List[str] = field(default_factory=list)
    deprecations: List[str] = field(default_factory=list)
    
    # Version info
    is_active: bool = True
    is_deprecated: bool = False
    deprecation_date: Optional[datetime] = None
    end_of_life_date: Optional[datetime] = None
    
    # Compatibility
    compatible_versions: Set[str] = field(default_factory=set)
    incompatible_versions: Set[str] = field(default_factory=set)
    
    def __post_init__(self):
        """Initialize version after creation."""
        if not self.version:
            self.version = str(uuid4())
    
    @property
    def is_end_of_life(self) -> bool:
        """Check if version is end of life."""
        if not self.end_of_life_date:
            return False
        return datetime.utcnow() > self.end_of_life_date
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'version': self.version,
            'created_at': self.created_at.isoformat(),
            'description': self.description,
            'author': self.author,
            'changelog': self.changelog,
            'breaking_changes': self.breaking_changes,
            'deprecations': self.deprecations,
            'is_active': self.is_active,
            'is_deprecated': self.is_deprecated,
            'deprecation_date': self.deprecation_date.isoformat() if self.deprecation_date else None,
            'end_of_life_date': self.end_of_life_date.isoformat() if self.end_of_life_date else None,
            'compatible_versions': list(self.compatible_versions),
            'incompatible_versions': list(self.incompatible_versions)
        }


@dataclass
class SchemaChange:
    """Represents a change between schema versions."""
    change_type: ChangeType
    path: str
    old_value: Optional[Any] = None
    new_value: Optional[Any] = None
    description: Optional[str] = None
    impact: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'change_type': self.change_type.value,
            'path': self.path,
            'old_value': self.old_value,
            'new_value': self.new_value,
            'description': self.description,
            'impact': self.impact
        }


@dataclass
class CompatibilityReport:
    """Schema compatibility analysis report."""
    from_version: str
    to_version: str
    compatibility_level: CompatibilityLevel
    changes: List[SchemaChange] = field(default_factory=list)
    breaking_changes: List[SchemaChange] = field(default_factory=list)
    deprecations: List[SchemaChange] = field(default_factory=list)
    
    # Migration info
    migration_required: bool = False
    migration_steps: List[str] = field(default_factory=list)
    estimated_migration_time: Optional[int] = None  # in minutes
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'from_version': self.from_version,
            'to_version': self.to_version,
            'compatibility_level': self.compatibility_level.value,
            'changes': [change.to_dict() for change in self.changes],
            'breaking_changes': [change.to_dict() for change in self.breaking_changes],
            'deprecations': [change.to_dict() for change in self.deprecations],
            'migration_required': self.migration_required,
            'migration_steps': self.migration_steps,
            'estimated_migration_time': self.estimated_migration_time
        }


class SchemaComparator:
    """Compares GraphQL schemas for compatibility analysis."""
    
    def __init__(self):
        self.breaking_change_rules = [
            self._check_removed_types,
            self._check_removed_fields,
            self._check_field_type_changes,
            self._check_removed_enum_values,
            self._check_required_field_additions,
            self._check_input_field_removals,
        ]
    
    def compare_schemas(
        self,
        old_schema: GraphQLSchema,
        new_schema: GraphQLSchema,
        old_version: str,
        new_version: str
    ) -> CompatibilityReport:
        """Compare two schemas and generate compatibility report."""
        changes = []
        breaking_changes = []
        deprecations = []
        
        # Get introspection for both schemas
        old_introspection = introspection_from_schema(old_schema)
        new_introspection = introspection_from_schema(new_schema)
        
        # Compare types
        type_changes = self._compare_types(old_introspection, new_introspection)
        changes.extend(type_changes)
        
        # Check for breaking changes
        for rule in self.breaking_change_rules:
            rule_changes = rule(old_introspection, new_introspection)
            breaking_changes.extend(rule_changes)
        
        # Check for deprecations
        deprecation_changes = self._check_deprecations(old_introspection, new_introspection)
        deprecations.extend(deprecation_changes)
        
        # Determine compatibility level
        compatibility_level = self._determine_compatibility_level(breaking_changes, changes)
        
        # Generate migration steps
        migration_steps = self._generate_migration_steps(breaking_changes, changes)
        
        return CompatibilityReport(
            from_version=old_version,
            to_version=new_version,
            compatibility_level=compatibility_level,
            changes=changes,
            breaking_changes=breaking_changes,
            deprecations=deprecations,
            migration_required=bool(breaking_changes),
            migration_steps=migration_steps,
            estimated_migration_time=self._estimate_migration_time(breaking_changes)
        )
    
    def _compare_types(self, old_schema: Dict, new_schema: Dict) -> List[SchemaChange]:
        """Compare types between schemas."""
        changes = []
        
        old_types = {t['name']: t for t in old_schema['data']['__schema']['types']}
        new_types = {t['name']: t for t in new_schema['data']['__schema']['types']}
        
        # Check for added types
        for type_name in new_types:
            if type_name not in old_types:
                changes.append(SchemaChange(
                    change_type=ChangeType.NON_BREAKING,
                    path=f"types.{type_name}",
                    new_value=new_types[type_name],
                    description=f"Added type {type_name}"
                ))
        
        # Check for removed types
        for type_name in old_types:
            if type_name not in new_types:
                changes.append(SchemaChange(
                    change_type=ChangeType.BREAKING,
                    path=f"types.{type_name}",
                    old_value=old_types[type_name],
                    description=f"Removed type {type_name}"
                ))
        
        # Check for modified types
        for type_name in old_types:
            if type_name in new_types:
                type_changes = self._compare_type_fields(
                    old_types[type_name], new_types[type_name], type_name
                )
                changes.extend(type_changes)
        
        return changes
    
    def _compare_type_fields(self, old_type: Dict, new_type: Dict, type_name: str) -> List[SchemaChange]:
        """Compare fields within a type."""
        changes = []
        
        old_fields = {f['name']: f for f in old_type.get('fields', [])}
        new_fields = {f['name']: f for f in new_type.get('fields', [])}
        
        # Check for added fields
        for field_name in new_fields:
            if field_name not in old_fields:
                changes.append(SchemaChange(
                    change_type=ChangeType.NON_BREAKING,
                    path=f"types.{type_name}.fields.{field_name}",
                    new_value=new_fields[field_name],
                    description=f"Added field {field_name} to type {type_name}"
                ))
        
        # Check for removed fields
        for field_name in old_fields:
            if field_name not in new_fields:
                changes.append(SchemaChange(
                    change_type=ChangeType.BREAKING,
                    path=f"types.{type_name}.fields.{field_name}",
                    old_value=old_fields[field_name],
                    description=f"Removed field {field_name} from type {type_name}"
                ))
        
        return changes
    
    def _check_removed_types(self, old_schema: Dict, new_schema: Dict) -> List[SchemaChange]:
        """Check for removed types (breaking change)."""
        changes = []
        
        old_types = {t['name'] for t in old_schema['data']['__schema']['types']}
        new_types = {t['name'] for t in new_schema['data']['__schema']['types']}
        
        for type_name in old_types - new_types:
            changes.append(SchemaChange(
                change_type=ChangeType.BREAKING,
                path=f"types.{type_name}",
                description=f"Removed type {type_name}",
                impact="Clients using this type will break"
            ))
        
        return changes
    
    def _check_removed_fields(self, old_schema: Dict, new_schema: Dict) -> List[SchemaChange]:
        """Check for removed fields (breaking change)."""
        changes = []
        
        old_types = {t['name']: t for t in old_schema['data']['__schema']['types']}
        new_types = {t['name']: t for t in new_schema['data']['__schema']['types']}
        
        for type_name in old_types:
            if type_name in new_types:
                old_fields = {f['name'] for f in old_types[type_name].get('fields', [])}
                new_fields = {f['name'] for f in new_types[type_name].get('fields', [])}
                
                for field_name in old_fields - new_fields:
                    changes.append(SchemaChange(
                        change_type=ChangeType.BREAKING,
                        path=f"types.{type_name}.fields.{field_name}",
                        description=f"Removed field {field_name} from type {type_name}",
                        impact="Clients querying this field will break"
                    ))
        
        return changes
    
    def _check_field_type_changes(self, old_schema: Dict, new_schema: Dict) -> List[SchemaChange]:
        """Check for field type changes (potentially breaking)."""
        changes = []
        
        old_types = {t['name']: t for t in old_schema['data']['__schema']['types']}
        new_types = {t['name']: t for t in new_schema['data']['__schema']['types']}
        
        for type_name in old_types:
            if type_name in new_types:
                old_fields = {f['name']: f for f in old_types[type_name].get('fields', [])}
                new_fields = {f['name']: f for f in new_types[type_name].get('fields', [])}
                
                for field_name in old_fields:
                    if field_name in new_fields:
                        old_field_type = old_fields[field_name]['type']
                        new_field_type = new_fields[field_name]['type']
                        
                        if old_field_type != new_field_type:
                            changes.append(SchemaChange(
                                change_type=ChangeType.BREAKING,
                                path=f"types.{type_name}.fields.{field_name}.type",
                                old_value=old_field_type,
                                new_value=new_field_type,
                                description=f"Changed type of field {field_name} in type {type_name}",
                                impact="Clients expecting the old type will break"
                            ))
        
        return changes
    
    def _check_removed_enum_values(self, old_schema: Dict, new_schema: Dict) -> List[SchemaChange]:
        """Check for removed enum values (breaking change)."""
        changes = []
        
        old_types = {t['name']: t for t in old_schema['data']['__schema']['types'] if t['kind'] == 'ENUM'}
        new_types = {t['name']: t for t in new_schema['data']['__schema']['types'] if t['kind'] == 'ENUM'}
        
        for type_name in old_types:
            if type_name in new_types:
                old_values = {v['name'] for v in old_types[type_name].get('enumValues', [])}
                new_values = {v['name'] for v in new_types[type_name].get('enumValues', [])}
                
                for value_name in old_values - new_values:
                    changes.append(SchemaChange(
                        change_type=ChangeType.BREAKING,
                        path=f"types.{type_name}.enumValues.{value_name}",
                        description=f"Removed enum value {value_name} from {type_name}",
                        impact="Clients using this enum value will break"
                    ))
        
        return changes
    
    def _check_required_field_additions(self, old_schema: Dict, new_schema: Dict) -> List[SchemaChange]:
        """Check for added required fields (breaking change)."""
        changes = []
        
        old_types = {t['name']: t for t in old_schema['data']['__schema']['types']}
        new_types = {t['name']: t for t in new_schema['data']['__schema']['types']}
        
        for type_name in old_types:
            if type_name in new_types:
                old_fields = {f['name']: f for f in old_types[type_name].get('inputFields', [])}
                new_fields = {f['name']: f for f in new_types[type_name].get('inputFields', [])}
                
                for field_name in new_fields:
                    if field_name not in old_fields:
                        new_field = new_fields[field_name]
                        if new_field['type']['kind'] == 'NON_NULL':
                            changes.append(SchemaChange(
                                change_type=ChangeType.BREAKING,
                                path=f"types.{type_name}.inputFields.{field_name}",
                                new_value=new_field,
                                description=f"Added required field {field_name} to input type {type_name}",
                                impact="Clients not providing this field will break"
                            ))
        
        return changes
    
    def _check_input_field_removals(self, old_schema: Dict, new_schema: Dict) -> List[SchemaChange]:
        """Check for removed input fields (breaking change)."""
        changes = []
        
        old_types = {t['name']: t for t in old_schema['data']['__schema']['types']}
        new_types = {t['name']: t for t in new_schema['data']['__schema']['types']}
        
        for type_name in old_types:
            if type_name in new_types:
                old_fields = {f['name'] for f in old_types[type_name].get('inputFields', [])}
                new_fields = {f['name'] for f in new_types[type_name].get('inputFields', [])}
                
                for field_name in old_fields - new_fields:
                    changes.append(SchemaChange(
                        change_type=ChangeType.BREAKING,
                        path=f"types.{type_name}.inputFields.{field_name}",
                        description=f"Removed input field {field_name} from type {type_name}",
                        impact="Clients providing this field will break"
                    ))
        
        return changes
    
    def _check_deprecations(self, old_schema: Dict, new_schema: Dict) -> List[SchemaChange]:
        """Check for deprecations."""
        changes = []
        
        new_types = {t['name']: t for t in new_schema['data']['__schema']['types']}
        
        for type_name, type_def in new_types.items():
            for field in type_def.get('fields', []):
                if field.get('isDeprecated'):
                    changes.append(SchemaChange(
                        change_type=ChangeType.DEPRECATION,
                        path=f"types.{type_name}.fields.{field['name']}",
                        description=f"Deprecated field {field['name']} in type {type_name}",
                        impact=f"Reason: {field.get('deprecationReason', 'No reason provided')}"
                    ))
        
        return changes
    
    def _determine_compatibility_level(self, breaking_changes: List[SchemaChange], all_changes: List[SchemaChange]) -> CompatibilityLevel:
        """Determine compatibility level based on changes."""
        if breaking_changes:
            return CompatibilityLevel.BREAKING
        
        if all_changes:
            return CompatibilityLevel.PARTIAL
        
        return CompatibilityLevel.FULL
    
    def _generate_migration_steps(self, breaking_changes: List[SchemaChange], all_changes: List[SchemaChange]) -> List[str]:
        """Generate migration steps for breaking changes."""
        steps = []
        
        for change in breaking_changes:
            if change.change_type == ChangeType.BREAKING:
                if "Removed type" in change.description:
                    steps.append(f"Update queries to remove references to {change.path}")
                elif "Removed field" in change.description:
                    steps.append(f"Update queries to remove field {change.path}")
                elif "Changed type" in change.description:
                    steps.append(f"Update queries to handle new type for {change.path}")
                elif "Added required field" in change.description:
                    steps.append(f"Update mutations to provide required field {change.path}")
        
        return steps
    
    def _estimate_migration_time(self, breaking_changes: List[SchemaChange]) -> Optional[int]:
        """Estimate migration time in minutes."""
        if not breaking_changes:
            return None
        
        # Simple estimation: 30 minutes per breaking change
        return len(breaking_changes) * 30


class SchemaVersionManager:
    """Manages GraphQL schema versions."""
    
    def __init__(self, versioning_strategy: VersioningStrategy = VersioningStrategy.SEMANTIC):
        self.versioning_strategy = versioning_strategy
        self.versions: Dict[str, SchemaVersion] = {}
        self.current_version: Optional[str] = None
        self.comparator = SchemaComparator()
    
    def add_version(
        self,
        version: str,
        schema: GraphQLSchema,
        description: Optional[str] = None,
        author: Optional[str] = None,
        changelog: Optional[List[str]] = None,
        set_as_current: bool = True
    ) -> SchemaVersion:
        """Add a new schema version."""
        # Validate schema
        errors = validate_schema(schema)
        if errors:
            raise ValueError(f"Invalid schema: {errors}")
        
        # Create version
        schema_version = SchemaVersion(
            version=version,
            schema=schema,
            created_at=datetime.utcnow(),
            description=description,
            author=author,
            changelog=changelog or []
        )
        
        # Check compatibility with existing versions
        if self.current_version:
            current_schema_version = self.versions[self.current_version]
            compatibility_report = self.comparator.compare_schemas(
                current_schema_version.schema,
                schema,
                self.current_version,
                version
            )
            
            # Update version with compatibility info
            schema_version.breaking_changes = [
                change.description for change in compatibility_report.breaking_changes
            ]
            schema_version.deprecations = [
                change.description for change in compatibility_report.deprecations
            ]
            
            if compatibility_report.compatibility_level == CompatibilityLevel.BREAKING:
                schema_version.is_deprecated = False  # New major version
            else:
                # Mark as compatible
                schema_version.compatible_versions.add(self.current_version)
        
        self.versions[version] = schema_version
        
        if set_as_current:
            self.current_version = version
        
        logger.info(f"Added schema version {version}")
        return schema_version
    
    def get_version(self, version: str) -> Optional[SchemaVersion]:
        """Get schema version by version string."""
        return self.versions.get(version)
    
    def get_current_version(self) -> Optional[SchemaVersion]:
        """Get current schema version."""
        if self.current_version:
            return self.versions.get(self.current_version)
        return None
    
    def get_all_versions(self) -> List[SchemaVersion]:
        """Get all schema versions."""
        return list(self.versions.values())
    
    def get_active_versions(self) -> List[SchemaVersion]:
        """Get active schema versions."""
        return [v for v in self.versions.values() if v.is_active and not v.is_end_of_life]
    
    def deprecate_version(self, version: str, deprecation_date: Optional[datetime] = None, end_of_life_date: Optional[datetime] = None):
        """Deprecate a schema version."""
        if version not in self.versions:
            raise ValueError(f"Version {version} not found")
        
        schema_version = self.versions[version]
        schema_version.is_deprecated = True
        schema_version.deprecation_date = deprecation_date or datetime.utcnow()
        schema_version.end_of_life_date = end_of_life_date
        
        logger.info(f"Deprecated schema version {version}")
    
    def deactivate_version(self, version: str):
        """Deactivate a schema version."""
        if version not in self.versions:
            raise ValueError(f"Version {version} not found")
        
        schema_version = self.versions[version]
        schema_version.is_active = False
        
        logger.info(f"Deactivated schema version {version}")
    
    def compare_versions(self, from_version: str, to_version: str) -> CompatibilityReport:
        """Compare two schema versions."""
        if from_version not in self.versions:
            raise ValueError(f"Version {from_version} not found")
        if to_version not in self.versions:
            raise ValueError(f"Version {to_version} not found")
        
        from_schema = self.versions[from_version]
        to_schema = self.versions[to_version]
        
        return self.comparator.compare_schemas(
            from_schema.schema,
            to_schema.schema,
            from_version,
            to_version
        )
    
    def get_compatible_versions(self, version: str) -> List[str]:
        """Get compatible versions for a given version."""
        if version not in self.versions:
            return []
        
        schema_version = self.versions[version]
        return list(schema_version.compatible_versions)
    
    def negotiate_version(self, requested_version: Optional[str] = None) -> str:
        """Negotiate the best schema version to use."""
        if requested_version:
            # Check if requested version exists and is active
            if requested_version in self.versions:
                schema_version = self.versions[requested_version]
                if schema_version.is_active and not schema_version.is_end_of_life:
                    return requested_version
        
        # Fall back to current version
        if self.current_version:
            return self.current_version
        
        # Fall back to latest active version
        active_versions = self.get_active_versions()
        if active_versions:
            # Sort by creation date and return latest
            latest_version = max(active_versions, key=lambda v: v.created_at)
            return latest_version.version
        
        raise ValueError("No active schema versions available")
    
    def get_schema_for_version(self, version: str) -> Optional[GraphQLSchema]:
        """Get GraphQL schema for a specific version."""
        schema_version = self.get_version(version)
        if schema_version:
            return schema_version.schema
        return None
    
    def generate_migration_guide(self, from_version: str, to_version: str) -> Dict[str, Any]:
        """Generate a migration guide between versions."""
        compatibility_report = self.compare_versions(from_version, to_version)
        
        return {
            'from_version': from_version,
            'to_version': to_version,
            'compatibility_report': compatibility_report.to_dict(),
            'migration_guide': {
                'breaking_changes': len(compatibility_report.breaking_changes),
                'migration_required': compatibility_report.migration_required,
                'estimated_time_minutes': compatibility_report.estimated_migration_time,
                'steps': compatibility_report.migration_steps,
                'recommendations': self._generate_migration_recommendations(compatibility_report)
            }
        }
    
    def _generate_migration_recommendations(self, report: CompatibilityReport) -> List[str]:
        """Generate migration recommendations."""
        recommendations = []
        
        if report.breaking_changes:
            recommendations.append("Review all breaking changes before migrating")
            recommendations.append("Test client applications thoroughly")
            recommendations.append("Consider gradual migration approach")
        
        if report.deprecations:
            recommendations.append("Plan to update deprecated field usage")
            recommendations.append("Monitor deprecation warnings")
        
        if report.migration_required:
            recommendations.append("Implement migration in staging environment first")
            recommendations.append("Prepare rollback plan")
        
        return recommendations
    
    def get_version_stats(self) -> Dict[str, Any]:
        """Get version statistics."""
        total_versions = len(self.versions)
        active_versions = len(self.get_active_versions())
        deprecated_versions = len([v for v in self.versions.values() if v.is_deprecated])
        
        return {
            'total_versions': total_versions,
            'active_versions': active_versions,
            'deprecated_versions': deprecated_versions,
            'current_version': self.current_version,
            'versioning_strategy': self.versioning_strategy.value,
            'versions': {
                version: schema_version.to_dict()
                for version, schema_version in self.versions.items()
            }
        }


class SchemaVersioningExtension(Extension):
    """Strawberry extension for schema versioning."""
    
    def __init__(self, version_manager: SchemaVersionManager):
        self.version_manager = version_manager
        self.negotiated_version: Optional[str] = None
    
    def on_request_start(self):
        """Handle request start for versioning."""
        # Get requested version from headers or query params
        context = getattr(self.execution_context, 'context', {})
        requested_version = None
        
        # Check headers
        if 'headers' in context:
            requested_version = context['headers'].get('GraphQL-Version')
        
        # Check query variables
        if not requested_version and hasattr(self.execution_context, 'variable_values'):
            variables = self.execution_context.variable_values or {}
            requested_version = variables.get('version')
        
        # Negotiate version
        try:
            self.negotiated_version = self.version_manager.negotiate_version(requested_version)
        except ValueError as e:
            logger.error(f"Version negotiation failed: {e}")
            self.negotiated_version = None
    
    def on_request_end(self, result: ExecutionResult):
        """Handle request end for versioning."""
        # Add version info to extensions
        if not result.extensions:
            result.extensions = {}
        
        result.extensions['version'] = {
            'negotiated_version': self.negotiated_version,
            'current_version': self.version_manager.current_version,
            'active_versions': [v.version for v in self.version_manager.get_active_versions()]
        }


# Global version manager instance
version_manager = SchemaVersionManager()


def create_version_manager(strategy: VersioningStrategy = VersioningStrategy.SEMANTIC) -> SchemaVersionManager:
    """Create and configure a version manager."""
    return SchemaVersionManager(strategy)


__all__ = [
    'SchemaVersionManager',
    'SchemaVersioningExtension',
    'SchemaVersion',
    'SchemaComparator',
    'CompatibilityReport',
    'SchemaChange',
    'VersioningStrategy',
    'ChangeType',
    'CompatibilityLevel',
    'version_manager',
    'create_version_manager',
]