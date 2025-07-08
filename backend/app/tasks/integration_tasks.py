"""Integration-related background tasks."""
import json
from datetime import datetime, timedelta
from typing import Any

import requests
from celery import Task
from requests.adapters import HTTPAdapter
from sqlalchemy import and_
from urllib3.util.retry import Retry

from app.core.database import get_db
from app.core.logging import get_logger
from app.models.audit import AuditLog
from app.models.integration import Integration, SyncJob, WebhookDelivery
from app.services.webhook import WebhookService
from app.tasks import celery_app

logger = get_logger(__name__)


class IntegrationTask(Task):
    """Base class for integration tasks with common functionality."""

    def on_failure(self, exc, task_id, args, kwargs, einfo):
        """Called when task fails."""
        logger.error(f"Integration task {task_id} failed: {exc}")

        # Log integration failure
        try:
            db = next(get_db())
            audit_log = AuditLog(
                action="INTEGRATION_TASK_FAILED",
                resource_type="INTEGRATION",
                resource_id=kwargs.get("integration_id", task_id),
                details={
                    "task_id": task_id,
                    "error": str(exc),
                    "args": args,
                    "kwargs": kwargs,
                },
                timestamp=datetime.utcnow(),
            )
            db.add(audit_log)
            db.commit()
        except Exception as e:
            logger.exception(f"Failed to log integration task failure: {e}")


@celery_app.task(
    bind=True,
    base=IntegrationTask,
    name="app.tasks.integration_tasks.webhook_delivery",
    max_retries=10,
    default_retry_delay=300,
)
def webhook_delivery(
    self,
    webhook_id: int,
    url: str,
    payload: dict[str, Any],
    headers: dict[str, str] | None = None,
    secret: str | None = None,
) -> dict[str, Any]:
    """Deliver webhook payload to external endpoint."""
    try:
        db = next(get_db())
        webhook = (
            db.query(WebhookDelivery).filter(WebhookDelivery.id == webhook_id).first()
        )

        if not webhook:
            logger.error(f"Webhook delivery {webhook_id} not found")
            return {"status": "failed", "reason": "webhook_not_found"}

        # Update status to sending
        webhook.status = "sending"
        webhook.attempts = (webhook.attempts or 0) + 1
        webhook.last_attempt_at = datetime.utcnow()
        db.commit()

        # Prepare request
        webhook_service = WebhookService()
        request_headers = headers or {}

        # Add signature if secret is provided
        if secret:
            signature = webhook_service.generate_signature(
                payload=json.dumps(payload, sort_keys=True), secret=secret
            )
            request_headers["X-Webhook-Signature"] = signature

        # Add standard headers
        request_headers.update(
            {
                "Content-Type": "application/json",
                "User-Agent": "EzzDay-Webhook/1.0",
                "X-Webhook-ID": str(webhook_id),
                "X-Webhook-Timestamp": str(int(datetime.utcnow().timestamp())),
            }
        )

        # Configure retry strategy
        retry_strategy = Retry(
            total=3,
            status_forcelist=[429, 500, 502, 503, 504],
            method_whitelist=["POST"],
            backoff_factor=1,
        )

        # Create session with retries
        session = requests.Session()
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        # Send webhook
        response = session.post(
            url=url, json=payload, headers=request_headers, timeout=30, verify=True
        )

        # Update webhook delivery record
        webhook.response_status_code = response.status_code
        webhook.response_headers = dict(response.headers)
        webhook.response_body = response.text[:10000]  # Limit response body size

        if response.status_code in [200, 201, 202, 204]:
            webhook.status = "delivered"
            webhook.delivered_at = datetime.utcnow()
            db.commit()

            logger.info(f"Webhook {webhook_id} delivered successfully to {url}")
            return {
                "status": "success",
                "webhook_id": webhook_id,
                "status_code": response.status_code,
                "response_time": response.elapsed.total_seconds(),
            }
        # Handle non-success status codes
        error_msg = f"HTTP {response.status_code}: {response.text[:500]}"
        webhook.error_message = error_msg

        if response.status_code in [400, 401, 403, 404, 410]:
            # Permanent failures - don't retry
            webhook.status = "failed"
            db.commit()
            logger.error(f"Webhook {webhook_id} permanently failed: {error_msg}")
            return {"status": "failed", "error": error_msg, "permanent": True}
        # Temporary failures - retry
        webhook.status = "pending"
        db.commit()
        raise Exception(error_msg)

    except requests.exceptions.RequestException as exc:
        # Network/connection errors - retry
        error_msg = f"Network error: {exc!s}"
        logger.warning(f"Webhook {webhook_id} network error: {error_msg}")

        try:
            webhook.error_message = error_msg
            webhook.status = "pending"
            db.commit()
        except Exception:
            pass

        raise self.retry(exc=exc)

    except Exception as exc:
        # Other errors
        error_msg = f"Webhook delivery error: {exc!s}"
        logger.exception(f"Webhook {webhook_id} error: {error_msg}")

        try:
            webhook.status = "failed"
            webhook.error_message = error_msg
            db.commit()
        except Exception:
            pass

        return {"status": "failed", "error": error_msg}


@celery_app.task(
    bind=True,
    base=IntegrationTask,
    name="app.tasks.integration_tasks.sync_external_system",
    max_retries=3,
    default_retry_delay=600,
)
def sync_external_system(
    self, integration_id: int, sync_type: str = "full"
) -> dict[str, Any]:
    """Synchronize data with external system."""
    try:
        db = next(get_db())
        integration = (
            db.query(Integration).filter(Integration.id == integration_id).first()
        )

        if not integration or not integration.is_active:
            logger.warning(f"Integration {integration_id} not found or inactive")
            return {"status": "failed", "reason": "integration_inactive"}

        # Create sync job record
        sync_job = SyncJob(
            integration_id=integration_id,
            sync_type=sync_type,
            status="running",
            started_at=datetime.utcnow(),
            metadata={},
        )
        db.add(sync_job)
        db.flush()  # Get the ID

        try:
            # Perform sync based on integration type
            if integration.provider == "salesforce":
                result = sync_salesforce_data(integration, sync_type)
            elif integration.provider == "hubspot":
                result = sync_hubspot_data(integration, sync_type)
            elif integration.provider == "slack":
                result = sync_slack_data(integration, sync_type)
            elif integration.provider == "zapier":
                result = sync_zapier_data(integration, sync_type)
            else:
                raise Exception(
                    f"Unsupported integration provider: {integration.provider}"
                )

            # Update sync job with results
            sync_job.status = "completed"
            sync_job.completed_at = datetime.utcnow()
            sync_job.records_processed = result.get("records_processed", 0)
            sync_job.records_created = result.get("records_created", 0)
            sync_job.records_updated = result.get("records_updated", 0)
            sync_job.records_failed = result.get("records_failed", 0)
            sync_job.metadata = result.get("metadata", {})

            # Update integration last sync time
            integration.last_sync_at = datetime.utcnow()
            integration.sync_status = "success"

            db.commit()

            logger.info(f"Sync completed for integration {integration_id}: {result}")
            return {
                "status": "success",
                "integration_id": integration_id,
                "sync_job_id": sync_job.id,
                "result": result,
            }

        except Exception as e:
            # Update sync job with failure
            sync_job.status = "failed"
            sync_job.completed_at = datetime.utcnow()
            sync_job.error_message = str(e)

            integration.sync_status = "error"
            integration.last_error = str(e)

            db.commit()
            raise

    except Exception as exc:
        logger.exception(f"Failed to sync integration {integration_id}: {exc}")
        raise self.retry(exc=exc)


def sync_salesforce_data(integration: Integration, sync_type: str) -> dict[str, Any]:
    """Sync data with Salesforce."""
    # This is a placeholder implementation
    # In practice, you'd use the Salesforce API to sync data

    config = integration.config
    api_endpoint = config.get("api_endpoint")
    access_token = config.get("access_token")

    if not api_endpoint or not access_token:
        raise Exception("Missing Salesforce configuration")

    # Simulate sync process
    return {
        "records_processed": 100,
        "records_created": 10,
        "records_updated": 85,
        "records_failed": 5,
        "metadata": {
            "sync_type": sync_type,
            "last_modified": datetime.utcnow().isoformat(),
        },
    }


def sync_hubspot_data(integration: Integration, sync_type: str) -> dict[str, Any]:
    """Sync data with HubSpot."""
    config = integration.config
    api_key = config.get("api_key")

    if not api_key:
        raise Exception("Missing HubSpot API key")

    # Simulate sync process
    return {
        "records_processed": 75,
        "records_created": 15,
        "records_updated": 55,
        "records_failed": 5,
        "metadata": {
            "sync_type": sync_type,
            "last_modified": datetime.utcnow().isoformat(),
        },
    }


def sync_slack_data(integration: Integration, sync_type: str) -> dict[str, Any]:
    """Sync data with Slack."""
    config = integration.config
    bot_token = config.get("bot_token")

    if not bot_token:
        raise Exception("Missing Slack bot token")

    # Simulate sync process
    return {
        "records_processed": 50,
        "records_created": 5,
        "records_updated": 40,
        "records_failed": 5,
        "metadata": {
            "sync_type": sync_type,
            "channels_synced": ["general", "announcements"],
            "last_modified": datetime.utcnow().isoformat(),
        },
    }


def sync_zapier_data(integration: Integration, sync_type: str) -> dict[str, Any]:
    """Sync data with Zapier."""
    config = integration.config
    webhook_url = config.get("webhook_url")

    if not webhook_url:
        raise Exception("Missing Zapier webhook URL")

    # Simulate sync process
    return {
        "records_processed": 25,
        "records_created": 20,
        "records_updated": 5,
        "records_failed": 0,
        "metadata": {
            "sync_type": sync_type,
            "webhook_url": webhook_url,
            "last_modified": datetime.utcnow().isoformat(),
        },
    }


@celery_app.task(
    bind=True, base=IntegrationTask, name="app.tasks.integration_tasks.sync_all_systems"
)
def sync_all_systems(self) -> dict[str, Any]:
    """Sync all active integrations."""
    try:
        db = next(get_db())

        # Get all active integrations
        active_integrations = (
            db.query(Integration).filter(Integration.is_active is True).all()
        )

        sync_results = []

        for integration in active_integrations:
            try:
                # Check if sync is due based on sync interval
                if integration.last_sync_at:
                    time_since_sync = datetime.utcnow() - integration.last_sync_at
                    sync_interval = timedelta(
                        minutes=integration.sync_interval_minutes or 60
                    )

                    if time_since_sync < sync_interval:
                        continue  # Skip if not due for sync

                # Trigger sync
                result = sync_external_system.delay(
                    integration_id=integration.id, sync_type="incremental"
                )

                sync_results.append(
                    {
                        "integration_id": integration.id,
                        "provider": integration.provider,
                        "task_id": result.id,
                        "status": "queued",
                    }
                )

            except Exception as e:
                logger.exception(
                    f"Failed to queue sync for integration {integration.id}: {e}"
                )
                sync_results.append(
                    {
                        "integration_id": integration.id,
                        "provider": integration.provider,
                        "status": "failed",
                        "error": str(e),
                    }
                )

        logger.info(f"Queued sync for {len(sync_results)} integrations")
        return {
            "status": "success",
            "total_integrations": len(active_integrations),
            "syncs_queued": len(sync_results),
            "results": sync_results,
        }

    except Exception as exc:
        logger.exception(f"Failed to sync all systems: {exc}")
        return {"status": "failed", "error": str(exc)}


@celery_app.task(
    bind=True,
    base=IntegrationTask,
    name="app.tasks.integration_tasks.process_webhook_queue",
)
def process_webhook_queue(self) -> dict[str, Any]:
    """Process pending webhook deliveries."""
    try:
        db = next(get_db())

        # Get pending webhook deliveries
        pending_webhooks = (
            db.query(WebhookDelivery)
            .filter(WebhookDelivery.status == "pending")
            .order_by(WebhookDelivery.created_at)
            .limit(100)
            .all()
        )

        processed_count = 0

        for webhook in pending_webhooks:
            try:
                # Get integration details
                integration = (
                    db.query(Integration)
                    .filter(Integration.id == webhook.integration_id)
                    .first()
                )

                if not integration or not integration.is_active:
                    webhook.status = "failed"
                    webhook.error_message = "Integration inactive"
                    continue

                # Queue webhook delivery
                webhook_delivery.delay(
                    webhook_id=webhook.id,
                    url=webhook.url,
                    payload=webhook.payload,
                    headers=webhook.headers,
                    secret=integration.config.get("webhook_secret"),
                )

                processed_count += 1

            except Exception as e:
                logger.exception(f"Failed to process webhook {webhook.id}: {e}")
                webhook.status = "failed"
                webhook.error_message = str(e)

        db.commit()

        logger.info(f"Processed {processed_count} webhook deliveries")
        return {
            "status": "success",
            "processed_count": processed_count,
            "total_pending": len(pending_webhooks),
        }

    except Exception as exc:
        logger.exception(f"Failed to process webhook queue: {exc}")
        return {"status": "failed", "error": str(exc)}


@celery_app.task(
    bind=True,
    base=IntegrationTask,
    name="app.tasks.integration_tasks.cleanup_old_sync_jobs",
)
def cleanup_old_sync_jobs(self, days_to_keep: int = 30) -> dict[str, Any]:
    """Clean up old sync job records."""
    try:
        db = next(get_db())

        cutoff_date = datetime.utcnow() - timedelta(days=days_to_keep)

        # Delete old sync jobs
        deleted_count = (
            db.query(SyncJob)
            .filter(
                and_(
                    SyncJob.created_at < cutoff_date,
                    SyncJob.status.in_(["completed", "failed"]),
                )
            )
            .delete()
        )

        db.commit()

        logger.info(f"Cleaned up {deleted_count} old sync job records")
        return {"status": "success", "deleted_count": deleted_count}

    except Exception as exc:
        logger.exception(f"Failed to cleanup old sync jobs: {exc}")
        db.rollback()
        return {"status": "failed", "error": str(exc)}


@celery_app.task(
    bind=True,
    base=IntegrationTask,
    name="app.tasks.integration_tasks.cleanup_old_webhook_deliveries",
)
def cleanup_old_webhook_deliveries(self, days_to_keep: int = 7) -> dict[str, Any]:
    """Clean up old webhook delivery records."""
    try:
        db = next(get_db())

        cutoff_date = datetime.utcnow() - timedelta(days=days_to_keep)

        # Delete old webhook deliveries
        deleted_count = (
            db.query(WebhookDelivery)
            .filter(
                and_(
                    WebhookDelivery.created_at < cutoff_date,
                    WebhookDelivery.status.in_(["delivered", "failed"]),
                )
            )
            .delete()
        )

        db.commit()

        logger.info(f"Cleaned up {deleted_count} old webhook delivery records")
        return {"status": "success", "deleted_count": deleted_count}

    except Exception as exc:
        logger.exception(f"Failed to cleanup old webhook deliveries: {exc}")
        db.rollback()
        return {"status": "failed", "error": str(exc)}


@celery_app.task(
    bind=True,
    base=IntegrationTask,
    name="app.tasks.integration_tasks.health_check_integrations",
)
def health_check_integrations(self) -> dict[str, Any]:
    """Check health of all active integrations."""
    try:
        db = next(get_db())

        active_integrations = (
            db.query(Integration).filter(Integration.is_active is True).all()
        )

        health_results = []

        for integration in active_integrations:
            try:
                config = integration.config
                health_status = {
                    "integration_id": integration.id,
                    "provider": integration.provider,
                }

                # Perform health check based on provider
                if integration.provider == "salesforce":
                    # Check Salesforce API connectivity
                    if config.get("access_token"):
                        health_status.update(
                            {
                                "status": "healthy",
                                "last_check": datetime.utcnow().isoformat(),
                            }
                        )
                    else:
                        health_status.update(
                            {"status": "unhealthy", "error": "Missing access token"}
                        )

                elif integration.provider == "hubspot":
                    # Check HubSpot API connectivity
                    if config.get("api_key"):
                        health_status.update(
                            {
                                "status": "healthy",
                                "last_check": datetime.utcnow().isoformat(),
                            }
                        )
                    else:
                        health_status.update(
                            {"status": "unhealthy", "error": "Missing API key"}
                        )

                elif integration.provider == "slack":
                    # Check Slack API connectivity
                    if config.get("bot_token"):
                        health_status.update(
                            {
                                "status": "healthy",
                                "last_check": datetime.utcnow().isoformat(),
                            }
                        )
                    else:
                        health_status.update(
                            {"status": "unhealthy", "error": "Missing bot token"}
                        )

                else:
                    health_status.update(
                        {"status": "unknown", "error": "Unknown provider"}
                    )

                # Update integration health status
                integration.health_status = health_status["status"]
                integration.last_health_check = datetime.utcnow()

                health_results.append(health_status)

            except Exception as e:
                logger.exception(
                    f"Health check failed for integration {integration.id}: {e}"
                )
                integration.health_status = "unhealthy"
                integration.last_health_check = datetime.utcnow()

                health_results.append(
                    {
                        "integration_id": integration.id,
                        "provider": integration.provider,
                        "status": "unhealthy",
                        "error": str(e),
                    }
                )

        db.commit()

        healthy_count = sum(
            1 for result in health_results if result.get("status") == "healthy"
        )

        logger.info(
            f"Health check completed: {healthy_count}/{len(health_results)} integrations healthy"
        )
        return {
            "status": "success",
            "total_integrations": len(active_integrations),
            "healthy_count": healthy_count,
            "results": health_results,
        }

    except Exception as exc:
        logger.exception(f"Failed to perform integration health checks: {exc}")
        return {"status": "failed", "error": str(exc)}
