"""Test audit-related GraphQL queries."""
from datetime import datetime, timedelta

import pytest
from httpx import AsyncClient

from app.modules.audit.domain.entities import AuditEntry


class TestAuditQueries:
    """Test cases for audit log queries."""

    @pytest.mark.asyncio
    async def test_get_audit_logs(
        self,
        authenticated_graphql_client: AsyncClient,
        audit_logs_query: str,
        make_graphql_request,
        assert_graphql_success,
        audit_entry_factory,
    ):
        """Test retrieving audit logs."""
        # Arrange
        request = make_graphql_request(
            query=audit_logs_query,
            variables={"pagination": {"page": 1, "pageSize": 20}},
        )

        # Act
        response = await authenticated_graphql_client.post("", json=request)
        result = response.json()

        # Assert
        assert_graphql_success(result, "auditLogs")
        audit_data = result["data"]["auditLogs"]
        assert "items" in audit_data
        assert isinstance(audit_data["items"], list)
        assert audit_data["page"] == 1
        assert audit_data["pageSize"] == 20

    @pytest.mark.asyncio
    async def test_filter_audit_logs_by_action(
        self,
        authenticated_graphql_client: AsyncClient,
        audit_logs_query: str,
        make_graphql_request,
        assert_graphql_success,
    ):
        """Test filtering audit logs by action."""
        # Arrange
        request = make_graphql_request(
            query=audit_logs_query, variables={"filter": {"action": "user.login"}}
        )

        # Act
        response = await authenticated_graphql_client.post("", json=request)
        result = response.json()

        # Assert
        assert_graphql_success(result, "auditLogs")
        items = result["data"]["auditLogs"]["items"]

        # Verify all items have the filtered action
        for item in items:
            assert item["action"] == "user.login"

    @pytest.mark.asyncio
    async def test_filter_audit_logs_by_resource_type(
        self,
        authenticated_graphql_client: AsyncClient,
        audit_logs_query: str,
        make_graphql_request,
        assert_graphql_success,
    ):
        """Test filtering audit logs by resource type."""
        # Arrange
        request = make_graphql_request(
            query=audit_logs_query, variables={"filter": {"resourceType": "user"}}
        )

        # Act
        response = await authenticated_graphql_client.post("", json=request)
        result = response.json()

        # Assert
        assert_graphql_success(result, "auditLogs")
        items = result["data"]["auditLogs"]["items"]

        # Verify all items have the filtered resource type
        for item in items:
            assert item["resourceType"] == "user"

    @pytest.mark.asyncio
    async def test_filter_audit_logs_by_actor(
        self,
        authenticated_graphql_client: AsyncClient,
        audit_logs_query: str,
        test_user,
        make_graphql_request,
        assert_graphql_success,
    ):
        """Test filtering audit logs by actor ID."""
        # Arrange
        request = make_graphql_request(
            query=audit_logs_query,
            variables={"filter": {"actorId": str(test_user.id.value)}},
        )

        # Act
        response = await authenticated_graphql_client.post("", json=request)
        result = response.json()

        # Assert
        assert_graphql_success(result, "auditLogs")
        items = result["data"]["auditLogs"]["items"]

        # Verify all items have the filtered actor
        for item in items:
            assert item["actorId"] == str(test_user.id.value)

    @pytest.mark.asyncio
    async def test_filter_audit_logs_by_date_range(
        self,
        authenticated_graphql_client: AsyncClient,
        audit_logs_query: str,
        make_graphql_request,
        assert_graphql_success,
    ):
        """Test filtering audit logs by date range."""
        # Arrange
        start_date = (datetime.utcnow() - timedelta(days=7)).isoformat()
        end_date = datetime.utcnow().isoformat()

        request = make_graphql_request(
            query=audit_logs_query,
            variables={"filter": {"startDate": start_date, "endDate": end_date}},
        )

        # Act
        response = await authenticated_graphql_client.post("", json=request)
        result = response.json()

        # Assert
        assert_graphql_success(result, "auditLogs")
        items = result["data"]["auditLogs"]["items"]

        # Verify all items are within date range
        for item in items:
            timestamp = datetime.fromisoformat(item["timestamp"].replace("Z", "+00:00"))
            assert timestamp >= datetime.fromisoformat(start_date)
            assert timestamp <= datetime.fromisoformat(end_date)

    @pytest.mark.asyncio
    async def test_search_audit_logs(
        self,
        authenticated_graphql_client: AsyncClient,
        make_graphql_request,
        assert_graphql_success,
    ):
        """Test searching audit logs by query."""
        # Arrange
        query = """
        query SearchAuditLogs($searchQuery: String!, $filters: AuditLogFilterInput) {
            searchAuditLogs(query: $searchQuery, filters: $filters) {
                items {
                    id
                    action
                    resourceType
                    resourceId
                    metadata
                    score
                }
                total
            }
        }
        """

        request = make_graphql_request(
            query=query,
            variables={
                "searchQuery": "login failed",
                "filters": {"resourceType": "user"},
            },
        )

        # Act
        response = await authenticated_graphql_client.post("", json=request)
        result = response.json()

        # Assert
        assert_graphql_success(result, "searchAuditLogs")
        search_results = result["data"]["searchAuditLogs"]
        assert "items" in search_results

        # Verify search relevance score
        if search_results["items"]:
            assert "score" in search_results["items"][0]

    @pytest.mark.asyncio
    async def test_get_audit_log_by_id(
        self,
        authenticated_graphql_client: AsyncClient,
        test_audit_entry: AuditEntry,
        make_graphql_request,
        assert_graphql_success,
    ):
        """Test getting specific audit log entry by ID."""
        # Arrange
        query = """
        query GetAuditLog($id: ID!) {
            auditLog(id: $id) {
                id
                action
                resourceType
                resourceId
                actorId
                metadata
                ipAddress
                userAgent
                timestamp
                actor {
                    id
                    username
                }
            }
        }
        """

        request = make_graphql_request(
            query=query, variables={"id": str(test_audit_entry.id.value)}
        )

        # Act
        response = await authenticated_graphql_client.post("", json=request)
        result = response.json()

        # Assert
        assert_graphql_success(result, "auditLog")
        audit_data = result["data"]["auditLog"]
        assert audit_data["id"] == str(test_audit_entry.id.value)
        assert audit_data["action"] == test_audit_entry.action.value
        assert audit_data["resourceType"] == test_audit_entry.resource_type.value

    @pytest.mark.asyncio
    async def test_get_audit_log_statistics(
        self,
        authenticated_graphql_client: AsyncClient,
        make_graphql_request,
        assert_graphql_success,
    ):
        """Test getting audit log statistics."""
        # Arrange
        query = """
        query GetAuditStatistics($filter: AuditLogFilterInput) {
            auditStatistics(filter: $filter) {
                totalEvents
                uniqueActors
                actionBreakdown {
                    action
                    count
                    percentage
                }
                resourceTypeBreakdown {
                    resourceType
                    count
                    percentage
                }
                timeSeriesData {
                    date
                    count
                }
            }
        }
        """

        request = make_graphql_request(
            query=query,
            variables={
                "filter": {
                    "startDate": (datetime.utcnow() - timedelta(days=30)).isoformat(),
                    "endDate": datetime.utcnow().isoformat(),
                }
            },
        )

        # Act
        response = await authenticated_graphql_client.post("", json=request)
        result = response.json()

        # Assert
        assert_graphql_success(result, "auditStatistics")
        stats = result["data"]["auditStatistics"]
        assert isinstance(stats["totalEvents"], int)
        assert isinstance(stats["uniqueActors"], int)
        assert isinstance(stats["actionBreakdown"], list)
        assert isinstance(stats["resourceTypeBreakdown"], list)
        assert isinstance(stats["timeSeriesData"], list)

    @pytest.mark.asyncio
    async def test_export_audit_logs(
        self,
        authenticated_graphql_client: AsyncClient,
        make_graphql_request,
        assert_graphql_success,
    ):
        """Test exporting audit logs."""
        # Arrange
        query = """
        query ExportAuditLogs($filter: AuditLogFilterInput, $format: ExportFormat!) {
            exportAuditLogs(filter: $filter, format: $format) {
                url
                filename
                expiresAt
                format
            }
        }
        """

        request = make_graphql_request(
            query=query,
            variables={
                "filter": {
                    "startDate": (datetime.utcnow() - timedelta(days=7)).isoformat()
                },
                "format": "CSV",
            },
        )

        # Act
        response = await authenticated_graphql_client.post("", json=request)
        result = response.json()

        # Assert
        assert_graphql_success(result, "exportAuditLogs")
        export_data = result["data"]["exportAuditLogs"]
        assert export_data["url"] is not None
        assert export_data["filename"].endswith(".csv")
        assert export_data["format"] == "CSV"

    @pytest.mark.asyncio
    async def test_get_user_activity_timeline(
        self,
        authenticated_graphql_client: AsyncClient,
        test_user,
        make_graphql_request,
        assert_graphql_success,
    ):
        """Test getting user activity timeline."""
        # Arrange
        query = """
        query GetUserActivityTimeline($userId: ID!, $limit: Int) {
            userActivityTimeline(userId: $userId, limit: $limit) {
                items {
                    id
                    action
                    resourceType
                    resourceId
                    timestamp
                    description
                }
                total
            }
        }
        """

        request = make_graphql_request(
            query=query, variables={"userId": str(test_user.id.value), "limit": 50}
        )

        # Act
        response = await authenticated_graphql_client.post("", json=request)
        result = response.json()

        # Assert
        assert_graphql_success(result, "userActivityTimeline")
        timeline = result["data"]["userActivityTimeline"]
        assert "items" in timeline
        assert isinstance(timeline["total"], int)
