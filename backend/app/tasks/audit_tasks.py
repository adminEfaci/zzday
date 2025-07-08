"""Audit-related background tasks."""
import csv
import io
import json
from datetime import datetime, timedelta
from typing import Any

from celery import Task
from sqlalchemy import and_, func

from app.core.config import settings
from app.core.database import get_db
from app.core.logging import get_logger
from app.models.audit import AuditLog
from app.services.email import EmailService
from app.services.storage import StorageService
from app.tasks import celery_app

logger = get_logger(__name__)


class AuditTask(Task):
    """Base class for audit tasks with common functionality."""

    def on_failure(self, exc, task_id, args, kwargs, einfo):
        """Called when task fails."""
        logger.error(f"Audit task {task_id} failed: {exc}")

    def on_success(self, retval, task_id, args, kwargs):
        """Called when task succeeds."""
        logger.info(f"Audit task {task_id} completed successfully")


@celery_app.task(
    bind=True, base=AuditTask, name="app.tasks.audit_tasks.generate_daily_report"
)
def generate_daily_report(self, date: str | None = None) -> dict[str, Any]:
    """Generate daily audit report."""
    try:
        db = next(get_db())

        # Use provided date or yesterday
        if date:
            target_date = datetime.fromisoformat(date).date()
        else:
            target_date = (datetime.utcnow() - timedelta(days=1)).date()

        start_time = datetime.combine(target_date, datetime.min.time())
        end_time = datetime.combine(target_date, datetime.max.time())

        # Gather audit statistics
        stats = {}

        # Total events
        stats["total_events"] = (
            db.query(AuditLog)
            .filter(
                and_(AuditLog.timestamp >= start_time, AuditLog.timestamp <= end_time)
            )
            .count()
        )

        # Events by action
        action_stats = (
            db.query(AuditLog.action, func.count(AuditLog.id).label("count"))
            .filter(
                and_(AuditLog.timestamp >= start_time, AuditLog.timestamp <= end_time)
            )
            .group_by(AuditLog.action)
            .all()
        )

        stats["actions"] = dict(action_stats)

        # Events by resource type
        resource_stats = (
            db.query(AuditLog.resource_type, func.count(AuditLog.id).label("count"))
            .filter(
                and_(AuditLog.timestamp >= start_time, AuditLog.timestamp <= end_time)
            )
            .group_by(AuditLog.resource_type)
            .all()
        )

        stats["resource_types"] = dict(resource_stats)

        # Active users
        active_users = (
            db.query(func.count(func.distinct(AuditLog.user_id)))
            .filter(
                and_(
                    AuditLog.timestamp >= start_time,
                    AuditLog.timestamp <= end_time,
                    AuditLog.user_id.isnot(None),
                )
            )
            .scalar()
        )

        stats["active_users"] = active_users

        # Security events
        security_actions = [
            "LOGIN_FAILED",
            "LOGIN_SUCCESS",
            "LOGOUT",
            "PASSWORD_CHANGED",
            "MFA_ENABLED",
            "MFA_DISABLED",
            "ACCOUNT_LOCKED",
            "PERMISSION_DENIED",
        ]

        security_events = (
            db.query(AuditLog)
            .filter(
                and_(
                    AuditLog.timestamp >= start_time,
                    AuditLog.timestamp <= end_time,
                    AuditLog.action.in_(security_actions),
                )
            )
            .count()
        )

        stats["security_events"] = security_events

        # Failed login attempts
        failed_logins = (
            db.query(AuditLog)
            .filter(
                and_(
                    AuditLog.timestamp >= start_time,
                    AuditLog.timestamp <= end_time,
                    AuditLog.action == "LOGIN_FAILED",
                )
            )
            .count()
        )

        stats["failed_logins"] = failed_logins

        # Generate report content
        report_data = {
            "date": target_date.isoformat(),
            "generated_at": datetime.utcnow().isoformat(),
            "statistics": stats,
            "summary": {
                "total_events": stats["total_events"],
                "active_users": stats["active_users"],
                "security_events": stats["security_events"],
                "failed_logins": stats["failed_logins"],
            },
        }

        # Save report to storage
        storage_service = StorageService()
        report_filename = f"audit_reports/daily/{target_date.isoformat()}.json"

        storage_service.save_file(
            filename=report_filename,
            content=json.dumps(report_data, indent=2),
            content_type="application/json",
        )

        # Send report to administrators (if configured)
        if settings.AUDIT_REPORT_RECIPIENTS:
            await send_audit_report_email.delay(
                recipients=settings.AUDIT_REPORT_RECIPIENTS,
                report_type="daily",
                report_date=target_date.isoformat(),
                report_data=report_data,
            )

        logger.info(f"Daily audit report generated for {target_date}")
        return {
            "status": "success",
            "date": target_date.isoformat(),
            "total_events": stats["total_events"],
            "report_filename": report_filename,
        }

    except Exception as exc:
        logger.exception(f"Failed to generate daily audit report: {exc}")
        return {"status": "failed", "error": str(exc)}


@celery_app.task(
    bind=True,
    base=AuditTask,
    name="app.tasks.audit_tasks.generate_compliance_report",
    max_retries=3,
    default_retry_delay=300,
)
def generate_compliance_report(
    self, start_date: str, end_date: str, compliance_type: str = "gdpr"
) -> dict[str, Any]:
    """Generate compliance report (GDPR, SOX, etc.)."""
    try:
        db = next(get_db())

        start_time = datetime.fromisoformat(start_date)
        end_time = datetime.fromisoformat(end_date)

        # Gather compliance-relevant data
        compliance_data = {}

        if compliance_type.lower() == "gdpr":
            # GDPR-specific reporting
            compliance_data = {
                "data_access_requests": db.query(AuditLog)
                .filter(
                    and_(
                        AuditLog.timestamp >= start_time,
                        AuditLog.timestamp <= end_time,
                        AuditLog.action == "DATA_ACCESS_REQUEST",
                    )
                )
                .count(),
                "data_deletions": db.query(AuditLog)
                .filter(
                    and_(
                        AuditLog.timestamp >= start_time,
                        AuditLog.timestamp <= end_time,
                        AuditLog.action == "DATA_DELETION",
                    )
                )
                .count(),
                "consent_changes": db.query(AuditLog)
                .filter(
                    and_(
                        AuditLog.timestamp >= start_time,
                        AuditLog.timestamp <= end_time,
                        AuditLog.action.in_(["CONSENT_GRANTED", "CONSENT_REVOKED"]),
                    )
                )
                .count(),
                "data_exports": db.query(AuditLog)
                .filter(
                    and_(
                        AuditLog.timestamp >= start_time,
                        AuditLog.timestamp <= end_time,
                        AuditLog.action == "DATA_EXPORT",
                    )
                )
                .count(),
            }

        elif compliance_type.lower() == "sox":
            # SOX compliance reporting
            compliance_data = {
                "financial_data_access": db.query(AuditLog)
                .filter(
                    and_(
                        AuditLog.timestamp >= start_time,
                        AuditLog.timestamp <= end_time,
                        AuditLog.resource_type.in_(["FINANCIAL_RECORD", "TRANSACTION"]),
                    )
                )
                .count(),
                "privileged_actions": db.query(AuditLog)
                .filter(
                    and_(
                        AuditLog.timestamp >= start_time,
                        AuditLog.timestamp <= end_time,
                        AuditLog.action.in_(["ADMIN_ACTION", "PRIVILEGED_ACCESS"]),
                    )
                )
                .count(),
            }

        # Generate detailed event log for the period
        events = (
            db.query(AuditLog)
            .filter(
                and_(AuditLog.timestamp >= start_time, AuditLog.timestamp <= end_time)
            )
            .order_by(AuditLog.timestamp.desc())
            .limit(10000)
            .all()
        )

        # Create CSV export of events
        csv_buffer = io.StringIO()
        csv_writer = csv.writer(csv_buffer)

        # Write headers
        csv_writer.writerow(
            [
                "Timestamp",
                "User ID",
                "Action",
                "Resource Type",
                "Resource ID",
                "IP Address",
                "Details",
            ]
        )

        # Write data
        for event in events:
            csv_writer.writerow(
                [
                    event.timestamp.isoformat(),
                    event.user_id or "",
                    event.action,
                    event.resource_type or "",
                    event.resource_id or "",
                    event.ip_address or "",
                    json.dumps(event.details) if event.details else "",
                ]
            )

        # Save CSV to storage
        storage_service = StorageService()
        csv_filename = (
            f"compliance_reports/{compliance_type}/{start_date}_{end_date}_events.csv"
        )

        storage_service.save_file(
            filename=csv_filename,
            content=csv_buffer.getvalue(),
            content_type="text/csv",
        )

        # Generate summary report
        report_data = {
            "compliance_type": compliance_type,
            "period": {"start": start_date, "end": end_date},
            "generated_at": datetime.utcnow().isoformat(),
            "summary": compliance_data,
            "total_events": len(events),
            "csv_export": csv_filename,
        }

        # Save JSON report
        json_filename = (
            f"compliance_reports/{compliance_type}/{start_date}_{end_date}_report.json"
        )
        storage_service.save_file(
            filename=json_filename,
            content=json.dumps(report_data, indent=2),
            content_type="application/json",
        )

        logger.info(
            f"Compliance report generated: {compliance_type} for {start_date} to {end_date}"
        )
        return {
            "status": "success",
            "compliance_type": compliance_type,
            "period": f"{start_date} to {end_date}",
            "total_events": len(events),
            "json_report": json_filename,
            "csv_export": csv_filename,
        }

    except Exception as exc:
        logger.exception(f"Failed to generate compliance report: {exc}")
        raise self.retry(exc=exc)


@celery_app.task(
    bind=True, base=AuditTask, name="app.tasks.audit_tasks.archive_old_logs"
)
def archive_old_logs(self, days_to_keep: int = 90) -> dict[str, Any]:
    """Archive audit logs older than specified days."""
    try:
        db = next(get_db())

        cutoff_date = datetime.utcnow() - timedelta(days=days_to_keep)

        # Get logs to archive
        logs_to_archive = (
            db.query(AuditLog).filter(AuditLog.timestamp < cutoff_date).all()
        )

        if not logs_to_archive:
            logger.info("No logs to archive")
            return {"status": "success", "archived_count": 0}

        # Convert logs to archive format
        archive_data = []
        for log in logs_to_archive:
            archive_data.append(
                {
                    "id": log.id,
                    "timestamp": log.timestamp.isoformat(),
                    "user_id": log.user_id,
                    "action": log.action,
                    "resource_type": log.resource_type,
                    "resource_id": log.resource_id,
                    "details": log.details,
                    "ip_address": log.ip_address,
                }
            )

        # Save to archive storage
        storage_service = StorageService()
        archive_filename = (
            f"audit_archives/{cutoff_date.strftime('%Y%m%d')}_archive.json"
        )

        storage_service.save_file(
            filename=archive_filename,
            content=json.dumps(archive_data, indent=2),
            content_type="application/json",
        )

        # Delete archived logs from database
        archived_count = len(logs_to_archive)
        for log in logs_to_archive:
            db.delete(log)

        db.commit()

        logger.info(
            f"Archived {archived_count} audit logs older than {days_to_keep} days"
        )
        return {
            "status": "success",
            "archived_count": archived_count,
            "archive_filename": archive_filename,
            "cutoff_date": cutoff_date.isoformat(),
        }

    except Exception as exc:
        logger.exception(f"Failed to archive old audit logs: {exc}")
        db.rollback()
        return {"status": "failed", "error": str(exc)}


@celery_app.task(
    bind=True,
    base=AuditTask,
    name="app.tasks.audit_tasks.send_audit_report_email",
    max_retries=3,
    default_retry_delay=60,
)
def send_audit_report_email(
    self,
    recipients: list[str],
    report_type: str,
    report_date: str,
    report_data: dict[str, Any],
) -> dict[str, Any]:
    """Send audit report via email."""
    try:
        email_service = EmailService()

        # Generate email content
        subject = f"Audit Report - {report_type.title()} - {report_date}"

        # Create HTML summary
        html_content = f"""
        <h2>Audit Report Summary</h2>
        <p><strong>Report Type:</strong> {report_type.title()}</p>
        <p><strong>Date:</strong> {report_date}</p>
        <p><strong>Generated:</strong> {report_data.get('generated_at', 'Unknown')}</p>
        
        <h3>Summary Statistics</h3>
        <ul>
            <li>Total Events: {report_data.get('summary', {}).get('total_events', 0)}</li>
            <li>Active Users: {report_data.get('summary', {}).get('active_users', 0)}</li>
            <li>Security Events: {report_data.get('summary', {}).get('security_events', 0)}</li>
            <li>Failed Logins: {report_data.get('summary', {}).get('failed_logins', 0)}</li>
        </ul>
        
        <p>Full report data is available in the attached file.</p>
        """

        # Send email to each recipient
        results = []
        for recipient in recipients:
            result = email_service.send_audit_report(
                email=recipient,
                subject=subject,
                html_content=html_content,
                report_data=report_data,
            )
            results.append({"recipient": recipient, "result": result})

        logger.info(f"Audit report emails sent for {report_type} - {report_date}")
        return {"status": "success", "recipients": len(recipients), "results": results}

    except Exception as exc:
        logger.exception(f"Failed to send audit report emails: {exc}")
        raise self.retry(exc=exc)


@celery_app.task(
    bind=True, base=AuditTask, name="app.tasks.audit_tasks.detect_anomalies"
)
def detect_anomalies(self, hours_to_analyze: int = 24) -> dict[str, Any]:
    """Detect anomalous patterns in audit logs."""
    try:
        db = next(get_db())

        start_time = datetime.utcnow() - timedelta(hours=hours_to_analyze)

        anomalies = []

        # Detect excessive failed login attempts
        failed_login_threshold = 10  # per user per hour

        failed_logins = (
            db.query(AuditLog.user_id, func.count(AuditLog.id).label("count"))
            .filter(
                and_(
                    AuditLog.timestamp >= start_time,
                    AuditLog.action == "LOGIN_FAILED",
                    AuditLog.user_id.isnot(None),
                )
            )
            .group_by(AuditLog.user_id)
            .having(func.count(AuditLog.id) > failed_login_threshold)
            .all()
        )

        for user_id, count in failed_logins:
            anomalies.append(
                {
                    "type": "excessive_failed_logins",
                    "user_id": user_id,
                    "count": count,
                    "threshold": failed_login_threshold,
                }
            )

        # Detect unusual access patterns
        # This is a simplified example - in practice, you'd want more sophisticated analysis
        unusual_access = (
            db.query(
                AuditLog.user_id,
                func.count(func.distinct(AuditLog.ip_address)).label("ip_count"),
            )
            .filter(
                and_(
                    AuditLog.timestamp >= start_time,
                    AuditLog.action == "LOGIN_SUCCESS",
                    AuditLog.user_id.isnot(None),
                )
            )
            .group_by(AuditLog.user_id)
            .having(func.count(func.distinct(AuditLog.ip_address)) > 5)
            .all()
        )

        for user_id, ip_count in unusual_access:
            anomalies.append(
                {
                    "type": "multiple_ip_access",
                    "user_id": user_id,
                    "ip_count": ip_count,
                    "threshold": 5,
                }
            )

        # Log anomalies
        if anomalies:
            for anomaly in anomalies:
                audit_log = AuditLog(
                    action="ANOMALY_DETECTED",
                    resource_type="SECURITY",
                    details=anomaly,
                    timestamp=datetime.utcnow(),
                )
                db.add(audit_log)

            db.commit()

            # Send security alerts for high-severity anomalies
            high_severity = [
                a for a in anomalies if a["type"] == "excessive_failed_logins"
            ]
            if high_severity and settings.SECURITY_ALERT_RECIPIENTS:
                await send_security_alert_email.delay(
                    recipients=settings.SECURITY_ALERT_RECIPIENTS,
                    anomalies=high_severity,
                )

        logger.info(f"Anomaly detection completed: {len(anomalies)} anomalies found")
        return {
            "status": "success",
            "hours_analyzed": hours_to_analyze,
            "anomalies_count": len(anomalies),
            "anomalies": anomalies,
        }

    except Exception as exc:
        logger.exception(f"Failed to detect anomalies: {exc}")
        return {"status": "failed", "error": str(exc)}


@celery_app.task(
    bind=True,
    base=AuditTask,
    name="app.tasks.audit_tasks.send_security_alert_email",
    max_retries=3,
    default_retry_delay=30,
)
def send_security_alert_email(
    self, recipients: list[str], anomalies: list[dict[str, Any]]
) -> dict[str, Any]:
    """Send security alert email for detected anomalies."""
    try:
        email_service = EmailService()

        subject = "Security Alert - Anomalous Activity Detected"

        # Create alert content
        html_content = f"""
        <h2>Security Alert</h2>
        <p>Anomalous activity has been detected in the system:</p>
        
        <h3>Detected Anomalies ({len(anomalies)})</h3>
        <ul>
        """

        for anomaly in anomalies:
            html_content += f"""
            <li>
                <strong>{anomaly['type'].replace('_', ' ').title()}:</strong>
                User ID {anomaly['user_id']} - {anomaly['count']} occurrences
                (threshold: {anomaly['threshold']})
            </li>
            """

        html_content += """
        </ul>
        
        <p>Please review these activities and take appropriate action if necessary.</p>
        <p>This alert was generated automatically by the audit system.</p>
        """

        # Send to security team
        results = []
        for recipient in recipients:
            result = email_service.send_security_alert(
                email=recipient,
                subject=subject,
                html_content=html_content,
                anomalies=anomalies,
            )
            results.append({"recipient": recipient, "result": result})

        logger.warning(f"Security alert sent for {len(anomalies)} anomalies")
        return {"status": "success", "recipients": len(recipients), "results": results}

    except Exception as exc:
        logger.exception(f"Failed to send security alert: {exc}")
        raise self.retry(exc=exc)
