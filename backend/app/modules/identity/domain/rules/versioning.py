"""
Policy Versioning and Migration

Support for policy version management and migration between policy versions.
"""

from abc import abstractmethod
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import uuid4

from app.core.config import PolicyConfiguration

from .base import BusinessRule, PolicyViolation


class MigrationType(Enum):
    """Types of policy migrations."""
    CONFIGURATION_UPDATE = "configuration_update"
    RULE_ADDITION = "rule_addition"
    RULE_REMOVAL = "rule_removal"
    SEVERITY_CHANGE = "severity_change"
    THRESHOLD_ADJUSTMENT = "threshold_adjustment"


@dataclass
class PolicyMigration:
    """Represents a policy migration."""
    migration_id: str
    from_version: str
    to_version: str
    migration_type: MigrationType
    description: str
    changes: dict[str, Any]
    rollback_data: dict[str, Any]
    created_at: datetime
    applied_at: datetime | None = None
    rolled_back_at: datetime | None = None


class PolicyVersionManager:
    """Manages policy versions and migrations."""
    
    def __init__(self):
        self.current_version = "1.0.0"
        self.migrations: list[PolicyMigration] = []
        self.version_history: dict[str, PolicyConfiguration] = {}
    
    def create_migration(self, from_version: str, to_version: str,
                        migration_type: MigrationType, description: str,
                        changes: dict[str, Any]) -> PolicyMigration:
        """Create a new policy migration."""
        migration = PolicyMigration(
            migration_id=str(uuid4()),
            from_version=from_version,
            to_version=to_version,
            migration_type=migration_type,
            description=description,
            changes=changes,
            rollback_data=self._create_rollback_data(changes),
            created_at=datetime.now(UTC)
        )
        
        self.migrations.append(migration)
        return migration
    
    def apply_migration(self, migration: PolicyMigration,
                       current_config: PolicyConfiguration) -> PolicyConfiguration:
        """Apply a migration to the current configuration."""
        new_config = self._apply_changes(current_config, migration.changes)
        
        # Store version in history
        self.version_history[migration.to_version] = new_config
        
        # Mark migration as applied
        migration.applied_at = datetime.now(UTC)
        
        return new_config
    
    def rollback_migration(self, migration: PolicyMigration,
                          current_config: PolicyConfiguration) -> PolicyConfiguration:
        """Rollback a migration."""
        if not migration.applied_at:
            raise ValueError("Cannot rollback unapplied migration")
        
        # Apply rollback data
        rolled_back_config = self._apply_changes(current_config, migration.rollback_data)
        
        # Mark migration as rolled back
        migration.rolled_back_at = datetime.now(UTC)
        
        return rolled_back_config
    
    def get_version_diff(self, from_version: str, to_version: str) -> dict[str, Any]:
        """Get differences between two policy versions."""
        from_config = self.version_history.get(from_version)
        to_config = self.version_history.get(to_version)
        
        if not from_config or not to_config:
            raise ValueError("Version not found in history")
        
        return self._calculate_diff(from_config, to_config)
    
    def _create_rollback_data(self, changes: dict[str, Any]) -> dict[str, Any]:
        """Create rollback data for changes."""
        # This would contain the inverse operations
        # For now, return empty dict - implement based on change types
        return {}
    
    def _apply_changes(self, config: PolicyConfiguration,
                      changes: dict[str, Any]) -> PolicyConfiguration:
        """Apply changes to configuration."""
        # Create a copy and apply changes
        # Implementation would depend on change format
        return config
    
    def _calculate_diff(self, config1: PolicyConfiguration,
                       config2: PolicyConfiguration) -> dict[str, Any]:
        """Calculate differences between configurations."""
        # Implementation would compare configurations
        return {}


class VersionedBusinessRule(BusinessRule):
    """Business rule with version support."""
    
    def __init__(self, rule_name: str, version: str = "1.0.0"):
        super().__init__(rule_name)
        self.version = version
        self.version_manager = PolicyVersionManager()
    
    @abstractmethod
    def validate_v1(self, *args, **kwargs) -> list[PolicyViolation]:
        """Validate using version 1.0 rules."""
    
    def validate(self, *args, **kwargs) -> list[PolicyViolation]:
        """Validate using current version."""
        # Route to appropriate version method
        if self.version.startswith("1."):
            return self.validate_v1(*args, **kwargs)
        raise ValueError(f"Unsupported version: {self.version}")
    
    def migrate_to_version(self, target_version: str) -> None:
        """Migrate rule to target version."""
        if self.version == target_version:
            return
        
        # Create and apply migration
        self.version_manager.create_migration(
            from_version=self.version,
            to_version=target_version,
            migration_type=MigrationType.CONFIGURATION_UPDATE,
            description=f"Migrate {self.rule_name} from {self.version} to {target_version}",
            changes={}
        )
        
        # Apply migration logic here
        self.version = target_version


class PolicyCompatibilityChecker:
    """Checks compatibility between policy versions."""
    
    def __init__(self):
        self.compatibility_matrix = {
            "1.0.0": ["1.0.1", "1.1.0"],
            "1.0.1": ["1.0.0", "1.1.0"],
            "1.1.0": ["1.0.0", "1.0.1", "1.2.0"]
        }
    
    def is_compatible(self, version1: str, version2: str) -> bool:
        """Check if two versions are compatible."""
        return version2 in self.compatibility_matrix.get(version1, [])
    
    def get_migration_path(self, from_version: str, to_version: str) -> list[str]:
        """Get migration path between versions."""
        # Simple implementation - would use graph traversal in practice
        if self.is_compatible(from_version, to_version):
            return [from_version, to_version]
        
        # Find intermediate versions
        return []
    
    def validate_migration(self, migration: PolicyMigration) -> list[str]:
        """Validate a migration for potential issues."""
        issues = []
        
        # Check version compatibility
        if not self.is_compatible(migration.from_version, migration.to_version):
            issues.append(f"Versions {migration.from_version} and {migration.to_version} are not compatible")
        
        # Check for breaking changes
        if migration.migration_type == MigrationType.RULE_REMOVAL:
            issues.append("Rule removal may cause breaking changes")
        
        return issues
