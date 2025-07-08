"""GraphQL query resolvers for audit module."""

from .analytics_queries import AnalyticsQueries
from .audit_queries import AuditQueries
from .compliance_queries import ComplianceQueries
from .report_queries import ReportQueries
from .search_queries import SearchQueries

__all__ = [
    "AnalyticsQueries",
    "AuditQueries",
    "ComplianceQueries",
    "ReportQueries",
    "SearchQueries",
]
