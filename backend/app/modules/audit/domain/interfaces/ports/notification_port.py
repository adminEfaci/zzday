"""Notification port interface for audit domain.

This module defines the contract for integrating with the Notification module,
following the Dependency Inversion Principle.
"""

from abc import ABC, abstractmethod
from typing import Any
from uuid import UUID

from app.modules.audit.domain.entities.audit_entry import AuditEntry
from app.modules.audit.domain.entities.audit_report import AuditReport
from app.modules.audit.domain.enums.audit_enums import AuditSeverity


class INotificationPort(ABC):
    """
    Port interface for Notification module integration.
    
    This interface defines the contract for audit domain to send
    notifications without direct dependencies.
    """

    @abstractmethod
    async def send_security_alert(
        self,
        audit_entry: AuditEntry,
        recipients: list[UUID],
        severity: AuditSeverity,
        additional_context: dict[str, Any] | None = None,
    ) -> bool:
        """
        Send security alert notification.
        
        Args:
            audit_entry: Audit entry that triggered the alert
            recipients: List of user IDs to notify
            severity: Alert severity level
            additional_context: Additional context for the alert
            
        Returns:
            True if notification was sent successfully
        """

    @abstractmethod
    async def send_compliance_notification(
        self,
        audit_report: AuditReport,
        recipients: list[UUID],
        compliance_type: str,
        findings: list[dict[str, Any]],
    ) -> bool:
        """
        Send compliance-related notification.
        
        Args:
            audit_report: Report that triggered the notification
            recipients: List of user IDs to notify
            compliance_type: Type of compliance (GDPR, SOX, etc.)
            findings: List of compliance findings
            
        Returns:
            True if notification was sent successfully
        """

    @abstractmethod
    async def send_audit_failure_alert(
        self,
        error_details: dict[str, Any],
        recipients: list[UUID],
        system_component: str,
    ) -> bool:
        """
        Send audit system failure alert.
        
        Args:
            error_details: Details about the failure
            recipients: List of user IDs to notify
            system_component: Component that failed
            
        Returns:
            True if notification was sent successfully
        """

    @abstractmethod
    async def send_retention_policy_notification(
        self,
        policy_change: dict[str, Any],
        affected_records: int,
        recipients: list[UUID],
    ) -> bool:
        """
        Send retention policy change notification.
        
        Args:
            policy_change: Details of policy change
            affected_records: Number of records affected
            recipients: List of user IDs to notify
            
        Returns:
            True if notification was sent successfully
        """

    @abstractmethod
    async def send_report_completion_notification(
        self,
        audit_report: AuditReport,
        recipients: list[UUID],
        download_url: str | None = None,
    ) -> bool:
        """
        Send report completion notification.
        
        Args:
            audit_report: Completed report
            recipients: List of user IDs to notify
            download_url: Optional download URL
            
        Returns:
            True if notification was sent successfully
        """

    @abstractmethod
    async def send_anomaly_detection_alert(
        self,
        anomalies: list[dict[str, Any]],
        recipients: list[UUID],
        detection_time: str,
        confidence_score: float,
    ) -> bool:
        """
        Send anomaly detection alert.
        
        Args:
            anomalies: List of detected anomalies
            recipients: List of user IDs to notify
            detection_time: When anomalies were detected
            confidence_score: Confidence in detection (0.0-1.0)
            
        Returns:
            True if notification was sent successfully
        """
