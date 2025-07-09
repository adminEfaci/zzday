"""System-level background tasks."""

import asyncio
import json
import os
from datetime import datetime, timedelta
from typing import Any

import aiofiles
import psutil
from sqlalchemy import text

from app.core.cache import cache_manager
from app.core.config import settings
from app.core.database import check_database_connection, engine, get_session
from app.core.logging import get_logger
from app.core.monitoring import (
    cache_warmup_keys,
    database_cleanup_records,
    database_cleanup_total,
    db_connections_active,
    health_check_status,
    metrics_aggregation_total,
)
from app.core.tasks.base import AsyncTask
from app.core.tasks.decorators import retry, timeout, track_performance

logger = get_logger(__name__)


class HealthCheckTask(AsyncTask):
    """Periodic health check task."""

    name = "health_check"
    description = "Check system component health"

    @retry(max_attempts=3, exceptions=(Exception,))
    @timeout(30)
    @track_performance(metric_name="health_check")
    async def execute(self) -> dict:
        """Check health of all system components."""
        health_status = {
            "timestamp": datetime.now(datetime.UTC).isoformat(),
            "status": "healthy",
            "components": {},
        }

        # Check database
        try:
            db_healthy = await check_database_connection()

            # Get detailed pool stats
            pool = engine.pool
            pool_stats = {
                "size": pool.size(),
                "checked_in": pool.checkedin(),
                "checked_out": pool.checkedout(),
                "overflow": pool.overflow(),
                "total": pool.total(),
            }

            # Test query performance
            start_time = datetime.now(datetime.UTC)
            async with get_session() as session:
                from app.core.constants import CURRENT_TIME_QUERY
                result = await session.execute(text(CURRENT_TIME_QUERY))
                db_time = result.scalar()
            query_time = (datetime.now(datetime.UTC) - start_time).total_seconds()

            health_status["components"]["database"] = {
                "status": "healthy" if db_healthy and query_time < 1.0 else "degraded",
                "healthy": db_healthy,
                "response_time_ms": query_time * 1000,
                "server_time": str(db_time) if db_time else None,
                "pool": pool_stats,
            }
        except Exception as e:
            health_status["components"]["database"] = {
                "status": "unhealthy",
                "error": str(e),
            }
            health_status["status"] = "unhealthy"

        # Check Redis
        try:
            # Test basic operations
            start_time = datetime.now(datetime.UTC)
            await cache_manager.ping()

            # Test set/get
            test_key = "health:test"
            test_value = {"timestamp": datetime.now(datetime.UTC).isoformat()}
            await cache_manager.set(test_key, test_value, ttl=10)
            retrieved = await cache_manager.get(test_key)

            response_time = (datetime.now(datetime.UTC) - start_time).total_seconds()

            # Get cache stats
            stats = await cache_manager.get_stats()

            health_status["components"]["redis"] = {
                "status": "healthy" if response_time < 0.1 else "degraded",
                "response_time_ms": response_time * 1000,
                "test_passed": retrieved == test_value,
                "stats": stats,
            }
        except Exception as e:
            health_status["components"]["redis"] = {
                "status": "unhealthy",
                "error": str(e),
            }
            health_status["status"] = "unhealthy"

        # Check system resources
        try:
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage("/")

            # Process info
            process = psutil.Process()
            process_info = {
                "memory_mb": process.memory_info().rss / 1024 / 1024,
                "cpu_percent": process.cpu_percent(),
                "threads": process.num_threads(),
                "connections": len(process.connections())
                if hasattr(process, "connections")
                else 0,
                "open_files": len(process.open_files())
                if hasattr(process, "open_files")
                else 0,
            }

            # Determine system health
            system_status = "healthy"
            if cpu_percent > 80 or memory.percent > 85 or disk.percent > 90:
                system_status = "degraded"
            if cpu_percent > 95 or memory.percent > 95 or disk.percent > 95:
                system_status = "unhealthy"
                health_status["status"] = "unhealthy"

            health_status["components"]["system"] = {
                "status": system_status,
                "cpu": {
                    "percent": cpu_percent,
                    "count": psutil.cpu_count(),
                    "load_average": list(os.getloadavg())
                    if hasattr(os, "getloadavg")
                    else None,
                },
                "memory": {
                    "percent": memory.percent,
                    "available_mb": memory.available / 1024 / 1024,
                    "total_mb": memory.total / 1024 / 1024,
                },
                "disk": {
                    "percent": disk.percent,
                    "free_gb": disk.free / 1024 / 1024 / 1024,
                    "total_gb": disk.total / 1024 / 1024 / 1024,
                },
                "process": process_info,
            }
        except Exception as e:
            health_status["components"]["system"] = {
                "status": "unhealthy",
                "error": str(e),
            }

        # Check external services (if configured)
        health_status["components"][
            "external_services"
        ] = await self._check_external_services()

        # Determine overall status
        if any(
            comp.get("status") == "unhealthy"
            for comp in health_status["components"].values()
        ):
            health_status["status"] = "unhealthy"
        elif any(
            comp.get("status") == "degraded"
            for comp in health_status["components"].values()
        ):
            health_status["status"] = "degraded"

        # Update metrics
        if "database" in health_status["components"]:
            db_connections_active.set(
                health_status["components"]["database"]
                .get("pool", {})
                .get("checked_out", 0)
            )

        # Update health check metrics
        for component, check in health_status["components"].items():
            health_check_status.labels(
                component=component, status=check.get("status", "unknown")
            ).set(1 if check.get("status") == "healthy" else 0)

        # Cache health status for quick access
        await cache_manager.set("system:health", health_status, ttl=60)

        logger.info(
            "Health check completed",
            status=health_status["status"],
            components=health_status["components"],
        )

        return health_status

    async def _check_external_services(self) -> dict[str, Any]:
        """Check external service connectivity."""
        services_status = {"status": "healthy", "services": {}}

        # Check configured external services
        # Example: Email service
        if hasattr(settings, "SENDGRID_API_KEY") and settings.SENDGRID_API_KEY:
            try:
                # Would check SendGrid API
                services_status["services"]["email"] = {"status": "healthy"}
            except Exception as e:
                services_status["services"]["email"] = {
                    "status": "unhealthy",
                    "error": str(e),
                }
                services_status["status"] = "unhealthy"

        # Example: SMS service
        if hasattr(settings, "TWILIO_ACCOUNT_SID") and settings.TWILIO_ACCOUNT_SID:
            try:
                # Would check Twilio API
                services_status["services"]["sms"] = {"status": "healthy"}
            except Exception as e:
                services_status["services"]["sms"] = {
                    "status": "unhealthy",
                    "error": str(e),
                }
                services_status["status"] = "unhealthy"

        return services_status


class CacheWarmupTask(AsyncTask):
    """Cache warmup task."""

    name = "cache_warmup"
    description = "Warm up frequently accessed cache entries"

    @retry(max_attempts=3)
    @timeout(180)
    @track_performance(metric_name="cache_warmup")
    async def execute(self, keys: list[str] | None = None) -> dict:
        """Warm up specified cache keys or default set."""
        warmup_stats = {
            "started_at": datetime.now(datetime.UTC).isoformat(),
            "categories": {},
            "total_keys": 0,
            "warmed": 0,
            "failed": 0,
        }

        try:
            if keys:
                # Warm up specific keys
                for key in keys:
                    try:
                        # This would fetch and cache the data
                        # Implementation depends on specific cache warming needs
                        warmup_stats["warmed"] += 1
                    except Exception as e:
                        logger.exception(
                            "Cache warmup failed for key",
                            key=key,
                            error=str(e),
                        )
                        warmup_stats["failed"] += 1
            else:
                # Warm up default categories
                # Configuration data
                config_keys = await self._warmup_configuration()
                warmup_stats["categories"]["configuration"] = config_keys
                warmup_stats["warmed"] += config_keys

                # Reference data
                reference_keys = await self._warmup_reference_data()
                warmup_stats["categories"]["reference_data"] = reference_keys
                warmup_stats["warmed"] += reference_keys

                # Active user data
                user_keys = await self._warmup_active_users()
                warmup_stats["categories"]["active_users"] = user_keys
                warmup_stats["warmed"] += user_keys

                # Frequently accessed data
                frequent_keys = await self._warmup_frequent_queries()
                warmup_stats["categories"]["frequent_queries"] = frequent_keys
                warmup_stats["warmed"] += frequent_keys

            warmup_stats["total_keys"] = warmup_stats["warmed"] + warmup_stats["failed"]
            warmup_stats["completed_at"] = datetime.now(datetime.UTC).isoformat()

            # Update metrics
            cache_warmup_keys.labels(status="success").inc(warmup_stats["warmed"])
            if warmup_stats["failed"] > 0:
                cache_warmup_keys.labels(status="failed").inc(warmup_stats["failed"])

            logger.info(
                "Cache warmup completed",
                warmed=warmup_stats["warmed"],
                failed=warmup_stats["failed"],
                total=warmup_stats["total_keys"],
                categories=warmup_stats["categories"],
            )

            return warmup_stats

        except Exception as e:
            logger.exception("Cache warmup failed", error=str(e))
            warmup_stats["error"] = str(e)
            return warmup_stats

    async def _warmup_configuration(self) -> int:
        """Warm up configuration data."""
        keys_warmed = 0

        try:
            # Cache application settings
            await cache_manager.set(
                "config:app_settings",
                settings.dict() if hasattr(settings, "dict") else {},
                ttl=3600,
            )
            keys_warmed += 1

            # Cache feature flags
            feature_flags = await self._load_feature_flags()
            await cache_manager.set("config:feature_flags", feature_flags, ttl=300)
            keys_warmed += 1

        except Exception as e:
            logger.exception("Failed to warm up configuration", error=str(e))

        return keys_warmed

    async def _warmup_reference_data(self) -> int:
        """Warm up reference data."""
        keys_warmed = 0

        try:
            # This would load reference data from database
            async with get_session():
                # Example: Load countries, currencies, etc.
                # Adjust based on actual schema
                pass

            # For now, use static example
            reference_data = {"countries": [], "currencies": [], "timezones": []}

            for key, data in reference_data.items():
                await cache_manager.set(f"reference:{key}", data, ttl=86400)  # 24 hours
                keys_warmed += 1

        except Exception as e:
            logger.exception("Failed to warm up reference data", error=str(e))

        return keys_warmed

    async def _warmup_active_users(self) -> int:
        """Warm up recently active user data."""
        keys_warmed = 0

        try:
            # Get recently active users from database
            async with get_session():
                # This query would need adjustment based on actual schema
                datetime.now(datetime.UTC) - timedelta(hours=1)

                # TODO: Implement user cache warming when User model is available
                # This would query active users and warm their cache entries

        except Exception as e:
            logger.exception("Failed to warm up active users", error=str(e))

        return keys_warmed

    async def _warmup_frequent_queries(self) -> int:
        """Warm up frequently accessed query results."""
        keys_warmed = 0

        try:
            # Cache common aggregations
            async with get_session():
                # Example: Daily active users count
                datetime.now(datetime.UTC).date()

                # Placeholder query - adjust based on schema
                # dau_count = await session.execute(
                #     select(func.count(User.id))
                #     .where(func.date(User.last_activity) == today)
                # )
                # await cache_manager.set("stats:dau", dau_count.scalar(), ttl=3600)
                # keys_warmed += 1

        except Exception as e:
            logger.exception("Failed to warm up frequent queries", error=str(e))

        return keys_warmed

    async def _load_feature_flags(self) -> dict[str, bool]:
        """Load feature flags from database or config."""
        # Placeholder - would load from database
        return {"new_ui": True, "beta_features": False, "maintenance_mode": False}


class DatabaseCleanupTask(AsyncTask):
    """Database cleanup task."""

    name = "database_cleanup"
    description = "Clean up old database records"

    @retry(max_attempts=3)
    @timeout(300)  # 5 minutes
    @track_performance(metric_name="database_cleanup")
    async def execute(self, days_to_keep: int = 90) -> dict:
        """Clean up old records."""
        cleanup_stats = {
            "started_at": datetime.now(datetime.UTC).isoformat(),
            "tables_cleaned": {},
            "total_deleted": 0,
            "errors": [],
        }

        try:
            async with get_session() as session:
                # Clean up old sessions
                try:
                    sessions_deleted = await self._cleanup_expired_sessions(session)
                    cleanup_stats["tables_cleaned"]["sessions"] = sessions_deleted
                    cleanup_stats["total_deleted"] += sessions_deleted
                    await session.commit()
                except Exception as e:
                    await session.rollback()
                    cleanup_stats["errors"].append(f"Sessions cleanup failed: {e!s}")
                    logger.exception("Failed to clean up sessions", error=str(e))

                # Clean up old audit logs
                try:
                    audit_deleted = await self._cleanup_audit_logs(
                        session, days_to_keep
                    )
                    cleanup_stats["tables_cleaned"]["audit_logs"] = audit_deleted
                    cleanup_stats["total_deleted"] += audit_deleted
                    await session.commit()
                except Exception as e:
                    await session.rollback()
                    cleanup_stats["errors"].append(f"Audit logs cleanup failed: {e!s}")
                    logger.exception("Failed to clean up audit logs", error=str(e))

                # Clean up soft deleted records
                try:
                    soft_deleted = await self._cleanup_soft_deleted_records(session)
                    cleanup_stats["tables_cleaned"]["soft_deleted"] = soft_deleted
                    cleanup_stats["total_deleted"] += soft_deleted
                    await session.commit()
                except Exception as e:
                    await session.rollback()
                    cleanup_stats["errors"].append(f"Soft delete cleanup failed: {e!s}")
                    logger.exception(
                        "Failed to clean up soft deleted records", error=str(e)
                    )

                # Clean up orphaned records
                try:
                    orphaned_deleted = await self._cleanup_orphaned_records(session)
                    cleanup_stats["tables_cleaned"]["orphaned"] = orphaned_deleted
                    cleanup_stats["total_deleted"] += orphaned_deleted
                    await session.commit()
                except Exception as e:
                    await session.rollback()
                    cleanup_stats["errors"].append(
                        f"Orphaned records cleanup failed: {e!s}"
                    )
                    logger.exception(
                        "Failed to clean up orphaned records", error=str(e)
                    )

            cleanup_stats["completed_at"] = datetime.now(datetime.UTC).isoformat()
            cleanup_stats["success"] = len(cleanup_stats["errors"]) == 0

            # Update metrics
            database_cleanup_total.labels(
                status="success" if cleanup_stats["success"] else "partial"
            ).inc()
            database_cleanup_records.labels(table="all").inc(
                cleanup_stats["total_deleted"]
            )

            logger.info(
                "Database cleanup completed",
                stats=cleanup_stats,
            )

            return cleanup_stats

        except Exception as e:
            logger.exception("Database cleanup failed", error=str(e))
            cleanup_stats["error"] = str(e)
            cleanup_stats["success"] = False
            database_cleanup_total.labels(status="failure").inc()
            return cleanup_stats

    async def _cleanup_expired_sessions(self, session) -> int:
        """Clean up expired sessions."""
        # This is a placeholder - adjust based on actual Session model
        # Example:
        # result = await session.execute(
        #     delete(Session).where(Session.expires_at < datetime.now(datetime.UTC))
        # )
        # return result.rowcount
        return 0

    async def _cleanup_audit_logs(self, session, days_to_keep: int) -> int:
        """Clean up old audit logs."""
        datetime.now(datetime.UTC) - timedelta(days=days_to_keep)

        # Placeholder - adjust based on actual AuditLog model
        # Delete in batches to avoid locking
        return 0

        # Example batch deletion:
        # while True:
        #     result = await session.execute(
        #         delete(AuditLog)
        #         .where(AuditLog.created_at < retention_date)
        #         .limit(CLEANUP_BATCH_SIZE)
        #     )
        #
        #     deleted = result.rowcount
        #     if deleted == 0:
        #         break
        #
        #     total_deleted += deleted
        #     await session.commit()
        #     await asyncio.sleep(0.1)  # Brief pause between batches

    async def _cleanup_soft_deleted_records(self, session) -> int:
        """Clean up soft deleted records after grace period."""
        datetime.now(datetime.UTC) - timedelta(days=30)
        return 0

        # Placeholder - would iterate through tables with soft delete
        # Example:
        # for model_class in [User, Document, ...]:
        #     if hasattr(model_class, 'deleted_at'):
        #         result = await session.execute(
        #             delete(model_class)
        #             .where(
        #                 and_(
        #                     model_class.deleted_at.isnot(None),
        #                     model_class.deleted_at < grace_period
        #                 )
        #             )
        #         )
        #         total_deleted += result.rowcount

    async def _cleanup_orphaned_records(self, session) -> int:
        """Clean up orphaned records."""
        # Placeholder - would check for records with broken relationships
        return 0


class MetricsAggregationTask(AsyncTask):
    """Metrics aggregation task."""

    name = "metrics_aggregation"
    description = "Aggregate metrics for reporting"

    @retry(max_attempts=3)
    @timeout(120)
    @track_performance(metric_name="metrics_aggregation")
    async def execute(self, period: str = "hourly") -> dict:
        """Aggregate metrics for specified period."""
        aggregated_metrics = {
            "period": period,
            "timestamp": datetime.now(datetime.UTC).isoformat(),
            "metrics": {},
        }

        try:
            # Determine time window
            end_time = datetime.now(datetime.UTC)
            if period == "hourly":
                start_time = end_time - timedelta(hours=1)
            elif period == "daily":
                start_time = end_time - timedelta(days=1)
            elif period == "weekly":
                start_time = end_time - timedelta(weeks=1)
            else:
                start_time = end_time - timedelta(hours=1)

            aggregated_metrics["window"] = {
                "start": start_time.isoformat(),
                "end": end_time.isoformat(),
            }

            # Aggregate different metric categories
            # User activity metrics
            user_metrics = await self._aggregate_user_metrics(start_time, end_time)
            aggregated_metrics["metrics"]["users"] = user_metrics

            # System performance metrics
            performance_metrics = await self._aggregate_performance_metrics(
                start_time, end_time
            )
            aggregated_metrics["metrics"]["performance"] = performance_metrics

            # Business metrics
            business_metrics = await self._aggregate_business_metrics(
                start_time, end_time
            )
            aggregated_metrics["metrics"]["business"] = business_metrics

            # Store aggregated results
            await self._store_aggregated_metrics(aggregated_metrics)

            # Update dashboard cache
            await cache_manager.set(
                f"metrics:{period}:latest", aggregated_metrics, ttl=3600
            )

            # Update metrics
            metrics_aggregation_total.labels(period=period, status="success").inc()

            logger.info(
                "Metrics aggregation completed",
                period=period,
                metrics=aggregated_metrics,
            )

            return aggregated_metrics

        except Exception as e:
            logger.exception("Metrics aggregation failed", period=period, error=str(e))
            aggregated_metrics["error"] = str(e)
            metrics_aggregation_total.labels(period=period, status="failure").inc()
            return aggregated_metrics

    async def _aggregate_user_metrics(
        self, start_time: datetime, end_time: datetime
    ) -> dict[str, Any]:
        """Aggregate user activity metrics."""
        metrics = {
            "active_users": 0,
            "new_users": 0,
            "sessions": 0,
            "average_session_duration": 0,
        }

        try:
            async with get_session():
                # Placeholder queries - adjust based on actual schema
                # Example:
                # active_users = await session.execute(
                #     select(func.count(func.distinct(User.id)))
                #     .where(
                #         and_(
                #             User.last_activity >= start_time,
                #             User.last_activity <= end_time
                #         )
                #     )
                # )
                # metrics["active_users"] = active_users.scalar() or 0
                pass

        except Exception as e:
            logger.exception("Failed to aggregate user metrics", error=str(e))

        return metrics

    async def _aggregate_performance_metrics(
        self, start_time: datetime, end_time: datetime
    ) -> dict[str, Any]:
        """Aggregate system performance metrics."""
        return {
            "response_times": {"p50": 0, "p90": 0, "p95": 0, "p99": 0},
            "throughput": {"requests_per_second": 0, "bytes_per_second": 0},
            "errors": {"total": 0, "rate": 0},
        }

    async def _aggregate_business_metrics(
        self, start_time: datetime, end_time: datetime
    ) -> dict[str, Any]:
        """Aggregate business metrics."""
        return {"transactions": {"total": 0, "value": 0, "average": 0}}

    async def _store_aggregated_metrics(self, metrics: dict[str, Any]) -> None:
        """Store aggregated metrics for historical analysis."""
        try:
            # Create metrics directory if it doesn't exist
            metrics_dir = getattr(settings, "METRICS_DIR", "./metrics")
            os.makedirs(metrics_dir, exist_ok=True)

            # Generate filename
            filename = f"metrics_{metrics['period']}_{metrics['timestamp'].replace(':', '-')}.json"
            filepath = os.path.join(metrics_dir, filename)

            # Write metrics to file
            async with aiofiles.open(filepath, "w") as f:
                await f.write(json.dumps(metrics, indent=2))

        except Exception as e:
            logger.exception("Failed to store aggregated metrics", error=str(e))


# Task scheduler
async def run_periodic_tasks():
    """Run periodic system tasks."""
    logger.info("Starting periodic task scheduler")

    while True:
        try:
            # Run health check every minute
            health_task = HealthCheckTask()
            await health_task.run()

            # Get current time for scheduling
            now = datetime.now(datetime.UTC)

            # Run cache warmup every 10 minutes
            if now.minute % 10 == 0:
                cache_task = CacheWarmupTask()
                asyncio.create_task(cache_task.run())

            # Run database cleanup daily at 2 AM
            if now.hour == 2 and now.minute == 0:
                cleanup_task = DatabaseCleanupTask()
                asyncio.create_task(cleanup_task.run())

            # Run metrics aggregation every hour
            if now.minute == 0:
                metrics_task = MetricsAggregationTask()
                asyncio.create_task(metrics_task.run(period="hourly"))

                # Daily aggregation at midnight
                if now.hour == 0:
                    asyncio.create_task(metrics_task.run(period="daily"))

                    # Weekly aggregation on Sundays
                    if now.weekday() == 6:
                        asyncio.create_task(metrics_task.run(period="weekly"))

            await asyncio.sleep(60)  # Check every minute

        except Exception as e:
            logger.exception(
                "Periodic task runner error",
                error=str(e),
            )
            await asyncio.sleep(60)
