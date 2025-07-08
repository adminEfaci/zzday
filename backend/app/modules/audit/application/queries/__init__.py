"""Audit application queries.

This module contains all queries for the audit module,
implementing the read side of CQRS pattern.
"""

from .get_audit_log_query import GetAuditLogQuery, GetAuditLogQueryHandler
from .get_audit_report_query import GetAuditReportQuery, GetAuditReportQueryHandler
from .get_compliance_report_query import (
    GetComplianceReportQuery,
    GetComplianceReportQueryHandler,
)
from .get_security_events_query import (
    GetSecurityEventsQuery,
    GetSecurityEventsQueryHandler,
)
from .get_user_activity_query import GetUserActivityQuery, GetUserActivityQueryHandler
from .search_audit_entries_query import (
    SearchAuditEntriesQuery,
    SearchAuditEntriesQueryHandler,
)

__all__ = [
    # Queries
    "GetAuditLogQuery",
    # Handlers
    "GetAuditLogQueryHandler",
    "GetAuditReportQuery",
    "GetAuditReportQueryHandler",
    "GetComplianceReportQuery",
    "GetComplianceReportQueryHandler",
    "GetSecurityEventsQuery",
    "GetSecurityEventsQueryHandler",
    "GetUserActivityQuery",
    "GetUserActivityQueryHandler",
    "SearchAuditEntriesQuery",
    "SearchAuditEntriesQueryHandler",
]
