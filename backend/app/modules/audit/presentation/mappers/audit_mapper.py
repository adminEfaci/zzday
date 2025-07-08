"""
Audit Domain to GraphQL Mapping

This module provides comprehensive mapping between audit domain objects and GraphQL types,
ensuring clean separation between the domain layer and presentation layer while maintaining
data integrity and type safety.

Features:
- Domain entity to GraphQL type conversion
- DTO to GraphQL type mapping
- Search result transformation
- Aggregation data mapping
- Error handling and validation
"""

import json
from typing import Any

# Core imports
from app.core.logging import get_logger
from app.modules.audit.application.dtos.audit_entry_dto import AuditEntryDTO
from app.modules.audit.application.dtos.audit_search_criteria_dto import (
    AuditSearchResultDTO,
)

# Domain imports
from app.modules.audit.domain.entities.audit_entry import AuditEntry
from app.modules.audit.presentation.graphql.schemas.enums import (
    AuditCategoryEnum,
    AuditOutcomeEnum,
    AuditSeverityEnum,
)

# GraphQL types
from app.modules.audit.presentation.graphql.schemas.types.audit_entry_type import (
    AuditActionType,
    AuditContextType,
    AuditEntryAggregation,
    AuditEntryConnection,
    AuditEntryType,
    AuditFieldChangeType,
    AuditMetadataType,
    AuditResourceType,
    AuditResultType,
    AuditUserType,
)
from app.modules.audit.presentation.graphql.schemas.types.search_result_type import (
    AuditSearchResultType,
    FacetValueType,
    SearchFacetType,
    SearchHighlightType,
    SearchMetadataType,
)

logger = get_logger(__name__)


class AuditMapper:
    """
    Comprehensive mapper for audit domain objects to GraphQL types.

    Provides static methods for converting between domain entities, DTOs,
    and GraphQL types while maintaining data integrity and type safety.
    """

    @staticmethod
    def domain_to_graphql(audit_entry: AuditEntry) -> AuditEntryType:
        """
        Convert audit entry domain entity to GraphQL type.

        Args:
            audit_entry: Audit entry domain entity

        Returns:
            AuditEntryType GraphQL representation
        """
        try:
            return AuditEntryType(
                # Identity
                id=str(audit_entry.id),
                audit_log_id=str(audit_entry.audit_log_id),
                # User information
                user=AuditUserType(
                    user_id=str(audit_entry.user_id) if audit_entry.user_id else None,
                    user_email=audit_entry.user_email,
                    user_name=audit_entry.user_name,
                ),
                # Action details
                action=AuditActionType(
                    action_type=audit_entry.action.action_type.value,
                    operation=audit_entry.action.operation,
                    description=audit_entry.action.description,
                ),
                # Resource details
                resource=AuditResourceType(
                    resource_type=audit_entry.resource.resource_type.value,
                    resource_id=audit_entry.resource.resource_id,
                    resource_name=audit_entry.resource.resource_name,
                ),
                # Context information
                context=AuditContextType(
                    ip_address=audit_entry.context.ip_address,
                    user_agent=audit_entry.context.user_agent,
                    session_id=str(audit_entry.context.session_id)
                    if audit_entry.context.session_id
                    else None,
                    correlation_id=audit_entry.context.correlation_id,
                ),
                # Result information
                result=AuditResultType(
                    outcome=AuditOutcomeEnum(audit_entry.result.outcome.value),
                    severity=AuditSeverityEnum(audit_entry.result.severity.value),
                    category=AuditCategoryEnum(audit_entry.result.category.value),
                    duration_ms=audit_entry.result.duration_ms,
                    error_details=audit_entry.result.error_details,
                ),
                # Changes (for update operations)
                changes=[
                    AuditFieldChangeType(
                        field_name=change.field_name,
                        old_value=change.old_value,
                        new_value=change.new_value,
                        field_type=change.field_type,
                    )
                    for change in audit_entry.changes
                ],
                # Metadata
                metadata=AuditMetadataType(
                    tags=audit_entry.metadata.tags,
                    compliance_tags=audit_entry.metadata.compliance_tags,
                    custom_fields=json.dumps(audit_entry.metadata.custom_fields)
                    if audit_entry.metadata.custom_fields
                    else None,
                ),
                # Timestamps
                created_at=audit_entry.created_at,
            )

        except Exception as e:
            logger.error(
                f"Failed to convert audit entry to GraphQL: {e}", exc_info=True
            )
            raise ValueError(f"Audit entry conversion failed: {e}")

    @staticmethod
    def dto_to_graphql(audit_entry_dto: AuditEntryDTO) -> AuditEntryType:
        """
        Convert audit entry DTO to GraphQL type.

        Args:
            audit_entry_dto: Audit entry DTO

        Returns:
            AuditEntryType GraphQL representation
        """
        try:
            return AuditEntryType(
                # Identity
                id=str(audit_entry_dto.id),
                audit_log_id=str(audit_entry_dto.audit_log_id),
                # User information
                user=AuditUserType(
                    user_id=str(audit_entry_dto.user_id)
                    if audit_entry_dto.user_id
                    else None,
                    user_email=audit_entry_dto.user_email,
                    user_name=audit_entry_dto.user_name,
                ),
                # Action details
                action=AuditActionType(
                    action_type=audit_entry_dto.action_type,
                    operation=audit_entry_dto.operation,
                    description=audit_entry_dto.description,
                ),
                # Resource details
                resource=AuditResourceType(
                    resource_type=audit_entry_dto.resource_type,
                    resource_id=audit_entry_dto.resource_id,
                    resource_name=audit_entry_dto.resource_name,
                ),
                # Context information
                context=AuditContextType(
                    ip_address=audit_entry_dto.ip_address,
                    user_agent=audit_entry_dto.user_agent,
                    session_id=str(audit_entry_dto.session_id)
                    if audit_entry_dto.session_id
                    else None,
                    correlation_id=audit_entry_dto.correlation_id,
                ),
                # Result information
                result=AuditResultType(
                    outcome=AuditOutcomeEnum(audit_entry_dto.outcome),
                    severity=AuditSeverityEnum(audit_entry_dto.severity),
                    category=AuditCategoryEnum(audit_entry_dto.category),
                    duration_ms=audit_entry_dto.duration_ms,
                    error_details=audit_entry_dto.error_details,
                ),
                # Changes
                changes=[
                    AuditFieldChangeType(
                        field_name=change.get("field_name", ""),
                        old_value=change.get("old_value"),
                        new_value=change.get("new_value"),
                        field_type=change.get("field_type", "string"),
                    )
                    for change in (audit_entry_dto.changes or [])
                ],
                # Metadata
                metadata=AuditMetadataType(
                    tags=audit_entry_dto.tags or [],
                    compliance_tags=audit_entry_dto.compliance_tags or [],
                    custom_fields=json.dumps(audit_entry_dto.custom_fields)
                    if audit_entry_dto.custom_fields
                    else None,
                ),
                # Timestamps
                created_at=audit_entry_dto.created_at,
            )

        except Exception as e:
            logger.error(
                f"Failed to convert audit entry DTO to GraphQL: {e}", exc_info=True
            )
            raise ValueError(f"Audit entry DTO conversion failed: {e}")

    @staticmethod
    def search_result_to_graphql(
        search_result: AuditSearchResultDTO,
        include_highlights: bool = True,
        include_facets: bool = True,
    ) -> AuditSearchResultType:
        """
        Convert audit search result DTO to GraphQL type.

        Args:
            search_result: Search result DTO
            include_highlights: Include search highlights
            include_facets: Include search facets

        Returns:
            AuditSearchResultType GraphQL representation
        """
        try:
            # Convert entries
            entries = [
                AuditMapper.dto_to_graphql(entry) for entry in search_result.entries
            ]

            # Convert highlights
            highlights = []
            if include_highlights and hasattr(search_result, "highlights"):
                highlights = [
                    SearchHighlightType(
                        field=highlight.get("field", ""),
                        value=highlight.get("value", ""),
                        highlights=highlight.get("highlights", []),
                    )
                    for highlight in (search_result.highlights or [])
                ]

            # Convert facets
            facets = []
            if include_facets and hasattr(search_result, "facets"):
                facets = [
                    SearchFacetType(
                        field=facet.get("field", ""),
                        label=facet.get("label", ""),
                        values=[
                            FacetValueType(
                                value=value.get("value", ""),
                                label=value.get("label", ""),
                                count=value.get("count", 0),
                                selected=value.get("selected", False),
                            )
                            for value in facet.get("values", [])
                        ],
                    )
                    for facet in (search_result.facets or [])
                ]

            # Convert aggregations
            aggregations = []
            if hasattr(search_result, "aggregations"):
                aggregations = [
                    AuditMapper.aggregation_to_graphql(agg)
                    for agg in (search_result.aggregations or [])
                ]

            # Create search metadata
            search_metadata = SearchMetadataType(
                total_results=search_result.total_count,
                search_time_ms=getattr(search_result, "search_time_ms", 0.0),
                query_complexity=getattr(search_result, "query_complexity", 1),
                cached=getattr(search_result, "cached", False),
                suggestions=getattr(search_result, "suggestions", []),
            )

            return AuditSearchResultType(
                entries=entries,
                total_count=search_result.total_count,
                page=search_result.page,
                page_size=search_result.page_size,
                has_next_page=search_result.has_next_page,
                has_previous_page=search_result.has_previous_page,
                highlights=highlights,
                facets=facets,
                aggregations=aggregations,
                search_metadata=search_metadata,
            )

        except Exception as e:
            logger.error(
                f"Failed to convert search result to GraphQL: {e}", exc_info=True
            )
            raise ValueError(f"Search result conversion failed: {e}")

    @staticmethod
    def log_result_to_connection(log_result: Any) -> AuditEntryConnection:
        """
        Convert audit log result to GraphQL connection format.

        Args:
            log_result: Audit log query result

        Returns:
            AuditEntryConnection with pagination metadata
        """
        try:
            # Convert entries to edges
            edges = []
            for i, entry in enumerate(log_result.entries):
                edge = AuditEntryConnection.Edge(
                    node=AuditMapper.dto_to_graphql(entry),
                    cursor=AuditMapper._generate_cursor(entry, i),
                )
                edges.append(edge)

            # Create page info
            page_info = AuditEntryConnection.PageInfo(
                has_next_page=log_result.has_next_page,
                has_previous_page=log_result.has_previous_page,
                start_cursor=edges[0].cursor if edges else None,
                end_cursor=edges[-1].cursor if edges else None,
            )

            return AuditEntryConnection(
                edges=edges, page_info=page_info, total_count=log_result.total_count
            )

        except Exception as e:
            logger.error(
                f"Failed to convert log result to connection: {e}", exc_info=True
            )
            raise ValueError(f"Log result conversion failed: {e}")

    @staticmethod
    def aggregation_to_graphql(aggregation: dict[str, Any]) -> AuditEntryAggregation:
        """
        Convert aggregation data to GraphQL type.

        Args:
            aggregation: Aggregation data dictionary

        Returns:
            AuditEntryAggregation GraphQL representation
        """
        try:
            total_count = aggregation.get("total_count", 0)
            count = aggregation.get("count", 0)

            percentage = 0.0
            if total_count > 0:
                percentage = (count / total_count) * 100

            return AuditEntryAggregation(
                field=aggregation.get("field", ""),
                value=aggregation.get("value", ""),
                count=count,
                percentage=percentage,
            )

        except Exception as e:
            logger.error(
                f"Failed to convert aggregation to GraphQL: {e}", exc_info=True
            )
            raise ValueError(f"Aggregation conversion failed: {e}")

    @staticmethod
    def _generate_cursor(entry: Any, index: int) -> str:
        """
        Generate cursor for pagination.

        Args:
            entry: Audit entry
            index: Entry index

        Returns:
            Base64 encoded cursor
        """
        try:
            import base64

            # Create cursor data
            cursor_data = {
                "id": str(entry.id),
                "created_at": entry.created_at.isoformat(),
                "index": index,
            }

            # Encode as base64
            cursor_json = json.dumps(cursor_data)
            cursor_bytes = cursor_json.encode("utf-8")
            return base64.b64encode(cursor_bytes).decode("utf-8")

        except Exception as e:
            logger.error(f"Failed to generate cursor: {e}", exc_info=True)
            return f"cursor_{index}"

    @staticmethod
    def graphql_to_domain_action(action_input: Any) -> dict[str, Any]:
        """
        Convert GraphQL action input to domain action data.

        Args:
            action_input: GraphQL action input

        Returns:
            Domain action data dictionary
        """
        try:
            return {
                "action_type": action_input.action_type.value,
                "operation": action_input.operation,
                "description": action_input.description,
            }

        except Exception as e:
            logger.error(f"Failed to convert action input: {e}", exc_info=True)
            raise ValueError(f"Action input conversion failed: {e}")

    @staticmethod
    def graphql_to_domain_resource(resource_input: Any) -> dict[str, Any]:
        """
        Convert GraphQL resource input to domain resource data.

        Args:
            resource_input: GraphQL resource input

        Returns:
            Domain resource data dictionary
        """
        try:
            return {
                "resource_type": resource_input.resource_type.value,
                "resource_id": resource_input.resource_id,
                "resource_name": resource_input.resource_name,
            }

        except Exception as e:
            logger.error(f"Failed to convert resource input: {e}", exc_info=True)
            raise ValueError(f"Resource input conversion failed: {e}")

    @staticmethod
    def graphql_to_domain_context(context_input: Any) -> dict[str, Any]:
        """
        Convert GraphQL context input to domain context data.

        Args:
            context_input: GraphQL context input

        Returns:
            Domain context data dictionary
        """
        try:
            return {
                "ip_address": context_input.ip_address,
                "user_agent": context_input.user_agent,
                "session_id": context_input.session_id,
                "correlation_id": context_input.correlation_id,
            }

        except Exception as e:
            logger.error(f"Failed to convert context input: {e}", exc_info=True)
            raise ValueError(f"Context input conversion failed: {e}")

    @staticmethod
    def graphql_to_domain_result(result_input: Any) -> dict[str, Any]:
        """
        Convert GraphQL result input to domain result data.

        Args:
            result_input: GraphQL result input

        Returns:
            Domain result data dictionary
        """
        try:
            return {
                "outcome": result_input.outcome.value,
                "severity": result_input.severity.value,
                "category": result_input.category.value,
                "duration_ms": result_input.duration_ms,
                "error_details": result_input.error_details,
            }

        except Exception as e:
            logger.error(f"Failed to convert result input: {e}", exc_info=True)
            raise ValueError(f"Result input conversion failed: {e}")

    @staticmethod
    def graphql_to_domain_metadata(metadata_input: Any) -> dict[str, Any]:
        """
        Convert GraphQL metadata input to domain metadata data.

        Args:
            metadata_input: GraphQL metadata input

        Returns:
            Domain metadata data dictionary
        """
        try:
            custom_fields = None
            if metadata_input.custom_fields:
                try:
                    custom_fields = json.loads(metadata_input.custom_fields)
                except json.JSONDecodeError:
                    logger.warning("Invalid JSON in custom fields, ignoring")

            return {
                "tags": metadata_input.tags or [],
                "compliance_tags": metadata_input.compliance_tags or [],
                "custom_fields": custom_fields,
            }

        except Exception as e:
            logger.error(f"Failed to convert metadata input: {e}", exc_info=True)
            raise ValueError(f"Metadata input conversion failed: {e}")

    @staticmethod
    def graphql_to_domain_changes(changes_input: list[Any]) -> list[dict[str, Any]]:
        """
        Convert GraphQL field changes input to domain changes data.

        Args:
            changes_input: List of GraphQL field change inputs

        Returns:
            List of domain change data dictionaries
        """
        try:
            return [
                {
                    "field_name": change.field_name,
                    "old_value": change.old_value,
                    "new_value": change.new_value,
                    "field_type": change.field_type,
                }
                for change in changes_input
            ]

        except Exception as e:
            logger.error(f"Failed to convert changes input: {e}", exc_info=True)
            raise ValueError(f"Changes input conversion failed: {e}")
