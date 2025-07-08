"""Task monitoring and health check functions."""
from datetime import datetime, timedelta
from typing import Any

from celery import Task
from sqlalchemy import and_

from app.core.database import get_db
from app.core.logging import get_logger
from app.models.audit import AuditLog
from app.tasks import celery_app

logger = get_logger(__name__)


class MonitoringTask(Task):
    """Base class for monitoring tasks."""

    def on_failure(self, exc, task_id, args, kwargs, einfo):
        """Called when monitoring task fails."""
        logger.error(f"Monitoring task {task_id} failed: {exc}")


@celery_app.task(
    bind=True, base=MonitoringTask, name="app.tasks.monitoring.health_check_workers"
)
def health_check_workers(self) -> dict[str, Any]:
    """Check the health of all Celery workers."""
    try:
        inspect = celery_app.control.inspect()

        # Get worker stats
        stats = inspect.stats()
        ping_results = celery_app.control.ping(timeout=10)
        active_tasks = inspect.active()
        reserved_tasks = inspect.reserved()

        # Compile health information
        worker_health = {}

        if stats:
            for worker_name, worker_stats in stats.items():
                # Check if worker responded to ping
                worker_responsive = any(
                    worker_name in str(result) for result in ping_results
                )

                # Get task counts
                active_count = len(active_tasks.get(worker_name, []))
                reserved_count = len(reserved_tasks.get(worker_name, []))
                total_tasks = worker_stats.get("total", {})

                # Determine health status
                if not worker_responsive:
                    health_status = "unhealthy"
                    health_message = "Worker not responding to ping"
                elif active_count > 50:  # High load threshold
                    health_status = "warning"
                    health_message = f"High load: {active_count} active tasks"
                else:
                    health_status = "healthy"
                    health_message = "Operating normally"

                worker_health[worker_name] = {
                    "status": health_status,
                    "message": health_message,
                    "responsive": worker_responsive,
                    "active_tasks": active_count,
                    "reserved_tasks": reserved_count,
                    "total_tasks_completed": total_tasks,
                    "pool_implementation": worker_stats.get("pool", {}).get(
                        "implementation"
                    ),
                    "processes": worker_stats.get("pool", {}).get("processes"),
                    "last_check": datetime.utcnow().isoformat(),
                }

        # Overall system health
        total_workers = len(worker_health)
        healthy_workers = sum(
            1 for w in worker_health.values() if w["status"] == "healthy"
        )

        if total_workers == 0:
            system_status = "critical"
            system_message = "No workers available"
        elif healthy_workers / total_workers < 0.5:
            system_status = "critical"
            system_message = (
                f"Less than 50% of workers healthy ({healthy_workers}/{total_workers})"
            )
        elif healthy_workers / total_workers < 0.8:
            system_status = "warning"
            system_message = (
                f"Some workers unhealthy ({healthy_workers}/{total_workers})"
            )
        else:
            system_status = "healthy"
            system_message = "All workers healthy"

        health_report = {
            "system_status": system_status,
            "system_message": system_message,
            "total_workers": total_workers,
            "healthy_workers": healthy_workers,
            "workers": worker_health,
            "timestamp": datetime.utcnow().isoformat(),
        }

        # Log critical issues
        if system_status == "critical":
            logger.critical(f"Worker health critical: {system_message}")

            # Create audit log for critical issues
            try:
                db = next(get_db())
                audit_log = AuditLog(
                    action="WORKER_HEALTH_CRITICAL",
                    resource_type="CELERY_SYSTEM",
                    details=health_report,
                    timestamp=datetime.utcnow(),
                )
                db.add(audit_log)
                db.commit()
            except Exception as e:
                logger.exception(f"Failed to log worker health critical event: {e}")

        logger.info(f"Worker health check completed: {system_status}")
        return health_report

    except Exception as exc:
        logger.exception(f"Failed to check worker health: {exc}")
        return {
            "system_status": "unknown",
            "system_message": f"Health check failed: {exc!s}",
            "error": str(exc),
            "timestamp": datetime.utcnow().isoformat(),
        }


@celery_app.task(
    bind=True, base=MonitoringTask, name="app.tasks.monitoring.queue_monitoring"
)
def queue_monitoring(self) -> dict[str, Any]:
    """Monitor queue lengths and processing rates."""
    try:
        inspect = celery_app.control.inspect()

        # Get active and reserved tasks
        active_tasks = inspect.active() or {}
        reserved_tasks = inspect.reserved() or {}
        scheduled_tasks = inspect.scheduled() or {}

        # Calculate queue statistics
        queue_stats = {}

        # Predefined queues to monitor
        monitored_queues = [
            "celery",
            "high_priority",
            "medium_priority",
            "low_priority",
            "identity",
            "audit",
            "notifications",
            "integrations",
            "dead_letter",
        ]

        for queue_name in monitored_queues:
            queue_stats[queue_name] = {
                "active_tasks": 0,
                "reserved_tasks": 0,
                "scheduled_tasks": 0,
                "total_pending": 0,
                "workers": [],
            }

        # Count tasks by queue across all workers
        all_workers = set()
        if active_tasks:
            all_workers.update(active_tasks.keys())
        if reserved_tasks:
            all_workers.update(reserved_tasks.keys())
        if scheduled_tasks:
            all_workers.update(scheduled_tasks.keys())

        for worker in all_workers:
            # Count active tasks
            for task in active_tasks.get(worker, []):
                queue_name = task.get("delivery_info", {}).get("routing_key", "unknown")
                if queue_name in queue_stats:
                    queue_stats[queue_name]["active_tasks"] += 1
                    if worker not in queue_stats[queue_name]["workers"]:
                        queue_stats[queue_name]["workers"].append(worker)

            # Count reserved tasks
            for task in reserved_tasks.get(worker, []):
                queue_name = task.get("delivery_info", {}).get("routing_key", "unknown")
                if queue_name in queue_stats:
                    queue_stats[queue_name]["reserved_tasks"] += 1
                    if worker not in queue_stats[queue_name]["workers"]:
                        queue_stats[queue_name]["workers"].append(worker)

            # Count scheduled tasks
            for task in scheduled_tasks.get(worker, []):
                queue_name = task.get("delivery_info", {}).get("routing_key", "unknown")
                if queue_name in queue_stats:
                    queue_stats[queue_name]["scheduled_tasks"] += 1
                    if worker not in queue_stats[queue_name]["workers"]:
                        queue_stats[queue_name]["workers"].append(worker)

        # Calculate totals and identify issues
        alerts = []
        total_pending = 0

        for queue_name, stats in queue_stats.items():
            stats["total_pending"] = stats["reserved_tasks"] + stats["scheduled_tasks"]
            total_pending += stats["total_pending"]

            # Generate alerts for high queue lengths
            if queue_name == "high_priority" and stats["total_pending"] > 50:
                alerts.append(
                    {
                        "severity": "critical",
                        "queue": queue_name,
                        "message": f"High priority queue has {stats['total_pending']} pending tasks",
                    }
                )
            elif (
                queue_name in ["medium_priority", "notifications"]
                and stats["total_pending"] > 100
            ):
                alerts.append(
                    {
                        "severity": "warning",
                        "queue": queue_name,
                        "message": f"Queue {queue_name} has {stats['total_pending']} pending tasks",
                    }
                )
            elif stats["total_pending"] > 500:
                alerts.append(
                    {
                        "severity": "warning",
                        "queue": queue_name,
                        "message": f"Queue {queue_name} has high load: {stats['total_pending']} pending tasks",
                    }
                )

            # Check for dead letter queue issues
            if queue_name == "dead_letter" and stats["total_pending"] > 10:
                alerts.append(
                    {
                        "severity": "critical",
                        "queue": queue_name,
                        "message": f"Dead letter queue has {stats['total_pending']} failed tasks",
                    }
                )

        # Determine overall queue health
        if any(alert["severity"] == "critical" for alert in alerts):
            queue_health = "critical"
        elif any(alert["severity"] == "warning" for alert in alerts):
            queue_health = "warning"
        else:
            queue_health = "healthy"

        monitoring_report = {
            "queue_health": queue_health,
            "total_pending_tasks": total_pending,
            "queue_statistics": queue_stats,
            "alerts": alerts,
            "total_workers": len(all_workers),
            "timestamp": datetime.utcnow().isoformat(),
        }

        # Log critical queue issues
        if queue_health == "critical":
            logger.critical(
                f"Queue monitoring critical: {len([a for a in alerts if a['severity'] == 'critical'])} critical alerts"
            )

            # Create audit log for critical queue issues
            try:
                db = next(get_db())
                audit_log = AuditLog(
                    action="QUEUE_HEALTH_CRITICAL",
                    resource_type="CELERY_QUEUES",
                    details=monitoring_report,
                    timestamp=datetime.utcnow(),
                )
                db.add(audit_log)
                db.commit()
            except Exception as e:
                logger.exception(f"Failed to log queue health critical event: {e}")

        logger.info(
            f"Queue monitoring completed: {queue_health}, {total_pending} total pending"
        )
        return monitoring_report

    except Exception as exc:
        logger.exception(f"Failed to monitor queues: {exc}")
        return {
            "queue_health": "unknown",
            "error": str(exc),
            "timestamp": datetime.utcnow().isoformat(),
        }


@celery_app.task(
    bind=True,
    base=MonitoringTask,
    name="app.tasks.monitoring.task_performance_analysis",
)
def task_performance_analysis(self, hours_to_analyze: int = 24) -> dict[str, Any]:
    """Analyze task performance over the specified time period."""
    try:
        # This would typically require a result backend that stores task history
        # For now, we'll create a placeholder analysis based on audit logs

        db = next(get_db())
        start_time = datetime.utcnow() - timedelta(hours=hours_to_analyze)

        # Analyze task failures from audit logs
        task_failures = (
            db.query(AuditLog)
            .filter(
                and_(
                    AuditLog.timestamp >= start_time,
                    AuditLog.action.in_(
                        [
                            "INTEGRATION_TASK_FAILED",
                            "TASK_FAILURE",
                            "WORKER_HEALTH_CRITICAL",
                            "QUEUE_HEALTH_CRITICAL",
                        ]
                    ),
                )
            )
            .all()
        )

        # Analyze patterns
        failure_patterns = {}
        for failure in task_failures:
            task_type = (
                failure.details.get("task_name", "unknown")
                if failure.details
                else "unknown"
            )
            if task_type not in failure_patterns:
                failure_patterns[task_type] = {
                    "count": 0,
                    "latest_failure": None,
                    "error_types": {},
                }

            failure_patterns[task_type]["count"] += 1
            failure_patterns[task_type][
                "latest_failure"
            ] = failure.timestamp.isoformat()

            error_type = (
                failure.details.get("error", "unknown")[:100]
                if failure.details
                else "unknown"
            )
            if error_type not in failure_patterns[task_type]["error_types"]:
                failure_patterns[task_type]["error_types"][error_type] = 0
            failure_patterns[task_type]["error_types"][error_type] += 1

        # Generate recommendations
        recommendations = []

        for task_type, pattern in failure_patterns.items():
            if pattern["count"] > 10:
                recommendations.append(
                    {
                        "priority": "high",
                        "task_type": task_type,
                        "issue": f"High failure rate: {pattern['count']} failures in {hours_to_analyze} hours",
                        "recommendation": "Investigate task logic and increase retry delays",
                    }
                )
            elif pattern["count"] > 5:
                recommendations.append(
                    {
                        "priority": "medium",
                        "task_type": task_type,
                        "issue": f"Moderate failure rate: {pattern['count']} failures",
                        "recommendation": "Monitor closely and consider optimizations",
                    }
                )

        # Check for resource constraints
        if len(task_failures) > 50:
            recommendations.append(
                {
                    "priority": "high",
                    "task_type": "system",
                    "issue": f"High overall failure rate: {len(task_failures)} failures",
                    "recommendation": "Consider scaling workers or investigating infrastructure issues",
                }
            )

        performance_report = {
            "analysis_period_hours": hours_to_analyze,
            "total_failures": len(task_failures),
            "failure_patterns": failure_patterns,
            "recommendations": recommendations,
            "analysis_timestamp": datetime.utcnow().isoformat(),
        }

        logger.info(
            f"Task performance analysis completed: {len(task_failures)} failures analyzed"
        )
        return performance_report

    except Exception as exc:
        logger.exception(f"Failed to analyze task performance: {exc}")
        return {"error": str(exc), "analysis_timestamp": datetime.utcnow().isoformat()}


@celery_app.task(
    bind=True,
    base=MonitoringTask,
    name="app.tasks.monitoring.cleanup_task_monitoring_data",
)
def cleanup_task_monitoring_data(self, days_to_keep: int = 7) -> dict[str, Any]:
    """Clean up old task monitoring data."""
    try:
        db = next(get_db())
        cutoff_date = datetime.utcnow() - timedelta(days=days_to_keep)

        # Clean up monitoring-related audit logs
        monitoring_actions = [
            "WORKER_HEALTH_CRITICAL",
            "QUEUE_HEALTH_CRITICAL",
            "TASK_FAILURE",
            "INTEGRATION_TASK_FAILED",
        ]

        deleted_count = (
            db.query(AuditLog)
            .filter(
                and_(
                    AuditLog.timestamp < cutoff_date,
                    AuditLog.action.in_(monitoring_actions),
                )
            )
            .delete()
        )

        db.commit()

        logger.info(f"Cleaned up {deleted_count} task monitoring audit records")
        return {
            "status": "success",
            "deleted_records": deleted_count,
            "cutoff_date": cutoff_date.isoformat(),
        }

    except Exception as exc:
        logger.exception(f"Failed to cleanup task monitoring data: {exc}")
        db.rollback()
        return {"status": "failed", "error": str(exc)}


@celery_app.task(
    bind=True, base=MonitoringTask, name="app.tasks.monitoring.generate_task_metrics"
)
def generate_task_metrics(self) -> dict[str, Any]:
    """Generate comprehensive task system metrics."""
    try:
        # Get current system state
        inspect = celery_app.control.inspect()

        # Basic metrics
        stats = inspect.stats() or {}
        active_tasks = inspect.active() or {}
        reserved_tasks = inspect.reserved() or {}

        # Calculate metrics
        total_workers = len(stats)
        total_active_tasks = sum(len(tasks) for tasks in active_tasks.values())
        total_reserved_tasks = sum(len(tasks) for tasks in reserved_tasks.values())

        # Worker utilization
        worker_utilization = {}
        for worker_name, worker_stats in stats.items():
            max_concurrency = worker_stats.get("pool", {}).get("max-concurrency", 1)
            active_count = len(active_tasks.get(worker_name, []))
            utilization = (
                (active_count / max_concurrency) * 100 if max_concurrency > 0 else 0
            )

            worker_utilization[worker_name] = {
                "utilization_percent": round(utilization, 2),
                "active_tasks": active_count,
                "max_concurrency": max_concurrency,
            }

        # Task type distribution
        task_distribution = {}
        for worker_tasks in active_tasks.values():
            for task in worker_tasks:
                task_name = task.get("name", "unknown")
                if task_name not in task_distribution:
                    task_distribution[task_name] = 0
                task_distribution[task_name] += 1

        metrics = {
            "system_overview": {
                "total_workers": total_workers,
                "total_active_tasks": total_active_tasks,
                "total_reserved_tasks": total_reserved_tasks,
                "total_pending_tasks": total_active_tasks + total_reserved_tasks,
            },
            "worker_utilization": worker_utilization,
            "task_distribution": task_distribution,
            "average_utilization": round(
                sum(w["utilization_percent"] for w in worker_utilization.values())
                / len(worker_utilization)
                if worker_utilization
                else 0,
                2,
            ),
            "timestamp": datetime.utcnow().isoformat(),
        }

        logger.info(
            f"Task metrics generated: {total_workers} workers, {total_active_tasks} active tasks"
        )
        return metrics

    except Exception as exc:
        logger.exception(f"Failed to generate task metrics: {exc}")
        return {"error": str(exc), "timestamp": datetime.utcnow().isoformat()}
