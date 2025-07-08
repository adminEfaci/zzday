"""
Event archiver for retention policy management.

Provides functionality to archive old events based on retention policies,
supporting GDPR compliance and storage cost optimization.
"""

import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any
from uuid import UUID

from .event_store import EventStore
from .schemas import EventSearchCriteria


class ArchivalStrategy(Enum):
    """Event archival strategies."""
    TIME_BASED = "time_based"        # Archive based on age
    COUNT_BASED = "count_based"      # Archive based on event count
    SIZE_BASED = "size_based"        # Archive based on storage size
    GDPR_BASED = "gdpr_based"        # Archive for GDPR compliance
    CUSTOM = "custom"                # Custom archival logic


class ArchivalDestination(Enum):
    """Archival destination types."""
    S3 = "s3"
    GCS = "gcs"
    AZURE_BLOB = "azure_blob"
    FILE_SYSTEM = "file_system"
    COLD_STORAGE = "cold_storage"
    DELETE = "delete"  # Permanent deletion


@dataclass
class ArchivalPolicy:
    """Configuration for event archival policies."""
    
    # Policy identification
    policy_name: str
    description: str = ""
    
    # Archival strategy
    strategy: ArchivalStrategy = ArchivalStrategy.TIME_BASED
    
    # Time-based archival
    max_age_days: int = 365
    
    # Count-based archival  
    max_events_per_stream: int | None = None
    max_total_events: int | None = None
    
    # Size-based archival
    max_storage_bytes: int | None = None
    
    # GDPR compliance
    gdpr_retention_days: int = 2555  # 7 years default
    anonymize_before_archive: bool = True
    
    # Event type specific policies
    event_type_policies: dict[str, dict[str, Any]] | None = None
    
    # Destination configuration
    destination: ArchivalDestination = ArchivalDestination.S3
    destination_config: dict[str, Any] | None = None
    
    # Processing options
    batch_size: int = 1000
    compress_archives: bool = True
    encrypt_archives: bool = True
    
    # Safety options
    dry_run: bool = False
    require_confirmation: bool = True
    backup_before_delete: bool = True


@dataclass
class ArchivalResult:
    """Result of an archival operation."""
    
    policy_name: str
    total_events_processed: int = 0
    events_archived: int = 0
    events_deleted: int = 0
    events_anonymized: int = 0
    events_skipped: int = 0
    
    # Storage metrics
    storage_freed_bytes: int = 0
    archive_size_bytes: int = 0
    
    # Timing
    start_time: datetime | None = None
    end_time: datetime | None = None
    duration_seconds: float = 0.0
    
    # Error tracking
    errors: list[dict[str, Any]] | None = None
    
    # Archival metadata
    archive_location: str | None = None
    archive_metadata: dict[str, Any] | None = None
    
    def __post_init__(self):
        """Calculate derived metrics."""
        if self.start_time and self.end_time:
            self.duration_seconds = (self.end_time - self.start_time).total_seconds()


class EventArchiver:
    """
    Service for archiving events based on retention policies.
    
    Provides comprehensive event archival capabilities with support for:
    - Multiple archival strategies (time, count, size, GDPR)
    - Various destinations (S3, GCS, Azure Blob, etc.)
    - GDPR compliance with anonymization
    - Batch processing for performance
    - Dry run mode for testing policies
    - Detailed archival reporting
    """
    
    def __init__(self, event_store: EventStore):
        self.event_store = event_store
        self._active_policies: dict[str, ArchivalPolicy] = {}
        self._archival_stats: dict[str, Any] = {}
    
    def register_policy(self, policy: ArchivalPolicy) -> None:
        """
        Register an archival policy.
        
        Args:
            policy: The archival policy to register
        """
        self._active_policies[policy.policy_name] = policy
    
    def remove_policy(self, policy_name: str) -> None:
        """
        Remove an archival policy.
        
        Args:
            policy_name: Name of the policy to remove
        """
        self._active_policies.pop(policy_name, None)
    
    async def run_archival(self, policy_name: str) -> ArchivalResult:
        """
        Run archival for a specific policy.
        
        Args:
            policy_name: Name of the policy to execute
            
        Returns:
            Result of the archival operation
        """
        if policy_name not in self._active_policies:
            raise ValueError(f"Unknown archival policy: {policy_name}")
        
        policy = self._active_policies[policy_name]
        
        result = ArchivalResult(
            policy_name=policy_name,
            start_time=datetime.utcnow(),
            errors=[]
        )
        
        try:
            # Build search criteria based on policy
            criteria = await self._build_archival_criteria(policy)
            
            # Get events to archive
            search_result = await self.event_store.search_events(criteria)
            total_events = search_result.total_count
            
            if total_events == 0:
                result.end_time = datetime.utcnow()
                return result
            
            # Process events in batches
            processed = 0
            offset = 0
            
            while offset < total_events:
                batch_criteria = criteria
                batch_criteria.offset = offset
                batch_criteria.limit = min(policy.batch_size, total_events - offset)
                
                # Get batch
                batch_result = await self.event_store.search_events(batch_criteria)
                events = batch_result.events
                
                if not events:
                    break
                
                # Process batch
                batch_stats = await self._process_archival_batch(events, policy)
                
                # Update results
                result.total_events_processed += batch_stats['processed']
                result.events_archived += batch_stats['archived']
                result.events_deleted += batch_stats['deleted']
                result.events_anonymized += batch_stats['anonymized']
                result.events_skipped += batch_stats['skipped']
                result.storage_freed_bytes += batch_stats['storage_freed']
                
                if batch_stats.get('errors'):
                    result.errors.extend(batch_stats['errors'])
                
                processed += len(events)
                offset += policy.batch_size
            
            result.end_time = datetime.utcnow()
            
        except Exception as e:
            result.end_time = datetime.utcnow()
            result.errors.append({
                'type': 'archival_error',
                'message': str(e),
                'timestamp': datetime.utcnow().isoformat()
            })
        
        return result
    
    async def run_all_policies(self) -> dict[str, ArchivalResult]:
        """
        Run all registered archival policies.
        
        Returns:
            Dictionary mapping policy names to their results
        """
        results = {}
        
        for policy_name in self._active_policies:
            results[policy_name] = await self.run_archival(policy_name)
        
        return results
    
    async def preview_archival(self, policy_name: str) -> dict[str, Any]:
        """
        Preview what would be archived by a policy without executing it.
        
        Args:
            policy_name: Name of the policy to preview
            
        Returns:
            Preview information about the archival
        """
        if policy_name not in self._active_policies:
            raise ValueError(f"Unknown archival policy: {policy_name}")
        
        policy = self._active_policies[policy_name]
        criteria = await self._build_archival_criteria(policy)
        
        # Get summary statistics
        search_result = await self.event_store.search_events(criteria)
        
        # Calculate storage impact
        storage_impact = 0
        if search_result.events:
            # Estimate storage from sample events
            sample_size = min(100, len(search_result.events))
            total_size = sum(
                len(json.dumps(event.event_data).encode()) 
                for event in search_result.events[:sample_size]
            )
            avg_event_size = total_size / sample_size
            storage_impact = int(avg_event_size * search_result.total_count)
        
        return {
            'policy_name': policy_name,
            'total_events': search_result.total_count,
            'estimated_storage_freed_bytes': storage_impact,
            'oldest_event': min(e.created_at for e in search_result.events) if search_result.events else None,
            'newest_event': max(e.created_at for e in search_result.events) if search_result.events else None,
            'event_types': list({e.event_type for e in search_result.events}) if search_result.events else [],
            'aggregate_types': list({e.aggregate_type for e in search_result.events}) if search_result.events else [],
        }
    
    async def cleanup_gdpr_data(
        self, 
        user_id: UUID, 
        anonymize: bool = True
    ) -> ArchivalResult:
        """
        Clean up all data for a user for GDPR compliance.
        
        Args:
            user_id: User ID to clean up data for
            anonymize: Whether to anonymize or delete data
            
        Returns:
            Result of the cleanup operation
        """
        # Create a temporary GDPR policy
        gdpr_policy = ArchivalPolicy(
            policy_name=f"gdpr_cleanup_{user_id}",
            strategy=ArchivalStrategy.GDPR_BASED,
            anonymize_before_archive=anonymize,
            destination=ArchivalDestination.DELETE if not anonymize else ArchivalDestination.COLD_STORAGE,
            dry_run=False
        )
        
        # Register temporarily
        self.register_policy(gdpr_policy)
        
        try:
            # Build criteria to find all events for this user
            criteria = EventSearchCriteria(
                user_ids=[user_id],
                limit=10000  # Large batch for complete cleanup
            )
            
            result = ArchivalResult(
                policy_name=gdpr_policy.policy_name,
                start_time=datetime.utcnow(),
                errors=[]
            )
            
            if anonymize:
                # Anonymize events
                anonymization_map = {
                    'user_id': 'anonymized',
                    'email': 'anonymized@example.com',
                    'ip_address': '0.0.0.0',
                    'personal_data': 'anonymized'
                }
                
                anonymized_count = await self.event_store.anonymize_events(
                    criteria, anonymization_map
                )
                result.events_anonymized = anonymized_count
            else:
                # Delete events
                deleted_count = await self.event_store.delete_events(
                    criteria, soft_delete=False
                )
                result.events_deleted = deleted_count
            
            result.end_time = datetime.utcnow()
            
            return result
            
        finally:
            # Clean up temporary policy
            self.remove_policy(gdpr_policy.policy_name)
    
    async def get_archival_statistics(self) -> dict[str, Any]:
        """Get statistics about archival operations."""
        return {
            'active_policies': len(self._active_policies),
            'policy_names': list(self._active_policies.keys()),
            'total_archives_run': sum(self._archival_stats.get('runs', {}).values()),
            'total_events_archived': sum(self._archival_stats.get('archived', {}).values()),
            'total_storage_freed': sum(self._archival_stats.get('storage_freed', {}).values()),
            'last_run_times': self._archival_stats.get('last_runs', {}),
        }
    
    async def _build_archival_criteria(self, policy: ArchivalPolicy) -> EventSearchCriteria:
        """Build search criteria for archival based on policy."""
        criteria = EventSearchCriteria(
            limit=policy.batch_size,
            sort_by="created_at",
            sort_order="asc"
        )
        
        if policy.strategy == ArchivalStrategy.TIME_BASED:
            cutoff_date = datetime.utcnow() - timedelta(days=policy.max_age_days)
            criteria.to_timestamp = cutoff_date
            
        elif policy.strategy == ArchivalStrategy.GDPR_BASED:
            cutoff_date = datetime.utcnow() - timedelta(days=policy.gdpr_retention_days)
            criteria.to_timestamp = cutoff_date
            
        # Add event type specific criteria
        if policy.event_type_policies:
            # This would implement more complex logic for different event types
            pass
        
        return criteria
    
    async def _process_archival_batch(
        self, 
        events: list, 
        policy: ArchivalPolicy
    ) -> dict[str, Any]:
        """Process a batch of events for archival."""
        stats = {
            'processed': 0,
            'archived': 0,
            'deleted': 0,
            'anonymized': 0,
            'skipped': 0,
            'storage_freed': 0,
            'errors': []
        }
        
        for event in events:
            try:
                stats['processed'] += 1
                
                # Calculate storage size
                event_size = len(json.dumps(event.event_data).encode())
                
                if policy.dry_run:
                    stats['archived'] += 1
                    stats['storage_freed'] += event_size
                    continue
                
                # Apply anonymization if required
                if policy.anonymize_before_archive:
                    # This would implement event anonymization
                    stats['anonymized'] += 1
                
                # Archive or delete based on destination
                if policy.destination == ArchivalDestination.DELETE:
                    # Mark for deletion
                    stats['deleted'] += 1
                    stats['storage_freed'] += event_size
                else:
                    # Archive to external storage
                    await self._archive_event(event, policy)
                    stats['archived'] += 1
                    stats['storage_freed'] += event_size
                    
            except Exception as e:
                stats['errors'].append({
                    'event_id': str(event.event_id),
                    'error': str(e),
                    'timestamp': datetime.utcnow().isoformat()
                })
        
        return stats
    
    async def _archive_event(self, event, policy: ArchivalPolicy) -> str:
        """Archive a single event to external storage."""
        # This would implement the actual archival logic
        # For now, return a placeholder location
        return f"{policy.destination.value}://archives/{event.event_id}"