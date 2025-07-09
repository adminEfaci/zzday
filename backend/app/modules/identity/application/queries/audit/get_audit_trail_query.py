"""
Get audit trail query implementation.

Handles retrieval of audit trail data with filtering, pagination, and export capabilities.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import UUID

from app.core.cqrs import Query, QueryHandler
from app.core.infrastructure import UnitOfWork
from app.modules.identity.domain.interfaces.repositories.audit_repository import IAuditRepository
from app.modules.identity.domain.interfaces.repositories.security_event_repository import ISecurityRepository
from app.modules.identity.domain.interfaces.repositories.user_repository import IUserRepository
from app.modules.identity.application.decorators import (
    rate_limit,
    require_permission,
    validate_request,
)
from app.modules.identity.application.dtos.response import AuditTrailResponse
from app.modules.identity.domain.enums import AuditAction, RiskLevel
from app.modules.identity.domain.exceptions import (
    AuditQueryError,
    InvalidFilterError,
    UnauthorizedAccessError,
)


class AuditFilterType(Enum):
    """Types of audit trail filters."""
    BY_USER = "by_user"
    BY_ACTION = "by_action"
    BY_DATE_RANGE = "by_date_range"
    BY_RISK_LEVEL = "by_risk_level"
    BY_RESOURCE = "by_resource"
    BY_IP_ADDRESS = "by_ip_address"
    BY_SESSION = "by_session"
    BY_STATUS = "by_status"


@dataclass
class GetAuditTrailQuery(Query[AuditTrailResponse]):
    """Query to retrieve audit trail data."""

    # Access control
    requester_id: UUID
    requester_permissions: list[str] = field(default_factory=list)

    # Filtering parameters
    user_id: UUID | None = None
    action_types: list[AuditAction] | None = None
    start_date: datetime | None = None
    end_date: datetime | None = None
    risk_levels: list[RiskLevel] | None = None
    resource_types: list[str] | None = None
    ip_addresses: list[str] | None = None
    session_ids: list[UUID] | None = None
    
    # Pagination
    page: int = 1
    page_size: int = 50
    
    # Sorting
    sort_by: str = "timestamp"
    sort_order: str = "desc"
    
    # Export options
    export_format: str | None = None
    include_details: bool = True
    include_metadata: bool = False


class GetAuditTrailQueryHandler(QueryHandler[GetAuditTrailQuery, AuditTrailResponse]):
    """Handler for audit trail retrieval queries."""
    
    def __init__(
        self,
        uow: UnitOfWork,
        audit_repository: IAuditRepository,
        user_repository: IUserRepository,
        security_repository: ISecurityRepository
    ):
        self.uow = uow
        self.audit_repository = audit_repository
        self.user_repository = user_repository
        self.security_repository = security_repository
    
    @rate_limit(max_calls=100, window_seconds=3600)
    @require_permission("audit.read")
    @validate_request
    async def handle(self, query: GetAuditTrailQuery) -> AuditTrailResponse:
        """Handle audit trail retrieval query."""
        
        try:
            async with self.uow:
                # Validate access permissions
                await self._validate_access_permissions(query)
                
                # Build filter criteria
                filter_criteria = await self._build_filter_criteria(query)
                
                # Retrieve audit trail data
                audit_entries = await self.audit_repository.get_audit_trail(
                    filters=filter_criteria,
                    page=query.page,
                    page_size=query.page_size,
                    sort_by=query.sort_by,
                    sort_order=query.sort_order
                )
                
                # Get total count for pagination
                total_count = await self.audit_repository.count_audit_entries(
                    filters=filter_criteria
                )
                
                # Enrich with additional data if requested
                if query.include_details:
                    audit_entries = await self._enrich_audit_entries(audit_entries)
                
                # Generate metadata if requested
                metadata = None
                if query.include_metadata:
                    metadata = await self._generate_metadata(filter_criteria)
                
                # Handle export if requested
                export_data = None
                if query.export_format:
                    export_data = await self._prepare_export_data(
                        audit_entries, query.export_format
                    )
                
                return AuditTrailResponse(
                    audit_entries=audit_entries,
                    total_count=total_count,
                    page=query.page,
                    page_size=query.page_size,
                    total_pages=(total_count + query.page_size - 1) // query.page_size,
                    filters_applied=filter_criteria,
                    metadata=metadata,
                    export_data=export_data,
                    query_timestamp=datetime.now(UTC)
                )
                
        except Exception as e:
            raise AuditQueryError(f"Failed to retrieve audit trail: {e!s}") from e
    
    async def _validate_access_permissions(self, query: GetAuditTrailQuery) -> None:
        """Validate user has appropriate permissions for audit access."""
        
        # Check basic audit read permission
        if "audit.read" not in query.requester_permissions:
            raise UnauthorizedAccessError("Insufficient permissions for audit access")
        
        # Check if user can access other users' audit data
        if query.user_id and query.user_id != query.requester_id:
            if "audit.read.all" not in query.requester_permissions:
                raise UnauthorizedAccessError("Cannot access other users' audit data")
        
        # Check admin-level audit access for sensitive operations
        sensitive_actions = [
            AuditAction.ADMIN_OPERATION,
            AuditAction.SECURITY_POLICY_CHANGE,
            AuditAction.PRIVILEGE_ESCALATION
        ]
        
        if query.action_types and any(action in sensitive_actions for action in query.action_types):
            if "audit.admin" not in query.requester_permissions:
                raise UnauthorizedAccessError("Admin permissions required for sensitive audit data")
    
    async def _build_filter_criteria(self, query: GetAuditTrailQuery) -> dict[str, Any]:
        """Build filter criteria from query parameters."""
        
        filters = {}
        
        if query.user_id:
            filters["user_id"] = query.user_id
        
        if query.action_types:
            filters["action_types"] = [action.value for action in query.action_types]
        
        if query.start_date:
            filters["start_date"] = query.start_date
        
        if query.end_date:
            filters["end_date"] = query.end_date
        
        if query.risk_levels:
            filters["risk_levels"] = [level.value for level in query.risk_levels]
        
        if query.resource_types:
            filters["resource_types"] = query.resource_types
        
        if query.ip_addresses:
            filters["ip_addresses"] = query.ip_addresses
        
        if query.session_ids:
            filters["session_ids"] = [str(sid) for sid in query.session_ids]
        
        return filters
    
    async def _enrich_audit_entries(self, audit_entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Enrich audit entries with additional context data."""
        
        enriched_entries = []
        
        for entry in audit_entries:
            enriched_entry = entry.copy()
            
            # Add user information
            if entry.get("user_id"):
                user = await self.user_repository.find_by_id(UUID(entry["user_id"]))
                if user:
                    enriched_entry["user_info"] = {
                        "username": user.username,
                        "email": user.email,
                        "full_name": f"{user.first_name} {user.last_name}"
                    }
            
            # Add geolocation if IP address available
            if entry.get("ip_address"):
                geo_data = await self._get_geolocation_data(entry["ip_address"])
                if geo_data:
                    enriched_entry["geolocation"] = geo_data
            
            # Add risk assessment
            enriched_entry["risk_assessment"] = await self._assess_entry_risk(entry)
            
            enriched_entries.append(enriched_entry)
        
        return enriched_entries
    
    async def _generate_metadata(self, filter_criteria: dict[str, Any]) -> dict[str, Any]:
        """Generate metadata about the audit trail query."""
        
        # Get aggregated statistics
        stats = await self.audit_repository.get_audit_statistics(filter_criteria)
        
        # Generate risk distribution
        risk_distribution = await self.audit_repository.get_risk_distribution(filter_criteria)
        
        # Get top actions
        top_actions = await self.audit_repository.get_top_actions(filter_criteria, limit=10)
        
        # Get geographic distribution
        geo_distribution = await self.audit_repository.get_geographic_distribution(filter_criteria)
        
        return {
            "statistics": stats,
            "risk_distribution": risk_distribution,
            "top_actions": top_actions,
            "geographic_distribution": geo_distribution,
            "generated_at": datetime.now(UTC)
        }
    
    async def _prepare_export_data(
        self, 
        audit_entries: list[dict[str, Any]], 
        export_format: str
    ) -> dict[str, Any]:
        """Prepare audit data for export in specified format."""
        
        if export_format.lower() == "csv":
            return await self._prepare_csv_export(audit_entries)
        if export_format.lower() == "json":
            return await self._prepare_json_export(audit_entries)
        if export_format.lower() == "pdf":
            return await self._prepare_pdf_export(audit_entries)
        raise InvalidFilterError(f"Unsupported export format: {export_format}")
    
    async def _prepare_csv_export(self, audit_entries: list[dict[str, Any]]) -> dict[str, Any]:
        """Prepare CSV export format."""
        
        import csv
        from io import StringIO
        
        output = StringIO()
        
        if audit_entries:
            fieldnames = audit_entries[0].keys()
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(audit_entries)
        
        return {
            "format": "csv",
            "content": output.getvalue(),
            "filename": f"audit_trail_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}.csv"
        }
    
    async def _prepare_json_export(self, audit_entries: list[dict[str, Any]]) -> dict[str, Any]:
        """Prepare JSON export format."""
        
        import json
        
        export_data = {
            "audit_trail": audit_entries,
            "export_metadata": {
                "generated_at": datetime.now(UTC).isoformat(),
                "entry_count": len(audit_entries),
                "format_version": "1.0"
            }
        }
        
        return {
            "format": "json",
            "content": json.dumps(export_data, indent=2, default=str),
            "filename": f"audit_trail_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}.json"
        }
    
    async def _prepare_pdf_export(self, audit_entries: list[dict[str, Any]]) -> dict[str, Any]:
        """Prepare PDF export format."""
        
        # This would typically use a PDF generation library
        # For now, return a placeholder
        return {
            "format": "pdf",
            "content": f"PDF export of {len(audit_entries)} audit entries",
            "filename": f"audit_trail_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}.pdf"
        }
    
    async def _get_geolocation_data(self, ip_address: str) -> dict[str, Any] | None:
        """Get geolocation data for IP address."""
        
        # This would typically call a geolocation service
        # For now, return a placeholder
        return {
            "country": "Unknown",
            "city": "Unknown",
            "coordinates": {"lat": 0.0, "lon": 0.0}
        }
    
    async def _assess_entry_risk(self, entry: dict[str, Any]) -> dict[str, Any]:
        """Assess risk level of audit entry."""
        
        risk_score = 0
        risk_factors = []
        
        # Assess based on action type
        if entry.get("action") in ["LOGIN_FAILURE", "PRIVILEGE_ESCALATION"]:
            risk_score += 30
            risk_factors.append("High-risk action")
        
        # Assess based on unusual timing
        timestamp = entry.get("timestamp")
        if timestamp:
            # Check if outside business hours
            hour = timestamp.hour if isinstance(timestamp, datetime) else 12
            if hour < 6 or hour > 22:
                risk_score += 15
                risk_factors.append("Outside business hours")
        
        # Assess based on IP reputation
        if entry.get("ip_address"):
            # This would check against threat intelligence
            risk_score += 10
            risk_factors.append("Unknown IP address")
        
        # Determine risk level
        if risk_score >= 50:
            risk_level = RiskLevel.HIGH
        elif risk_score >= 25:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.LOW
        
        return {
            "risk_level": risk_level.value,
            "risk_score": risk_score,
            "risk_factors": risk_factors
        }