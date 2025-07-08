#!/usr/bin/env python3
"""Celery worker entry point."""
import os
import sys
from pathlib import Path

# Add the project directory to Python path
project_dir = Path(__file__).parent
sys.path.insert(0, str(project_dir))

from app.core.logging import get_logger
from app.tasks import celery_app

logger = get_logger(__name__)

if __name__ == "__main__":
    # Configure worker
    worker_name = os.getenv("CELERY_WORKER_NAME", "worker")
    log_level = os.getenv("CELERY_LOG_LEVEL", "INFO")
    concurrency = int(os.getenv("CELERY_WORKER_CONCURRENCY", "4"))

    logger.info(f"Starting Celery worker: {worker_name}")
    logger.info(f"Log level: {log_level}")
    logger.info(f"Concurrency: {concurrency}")

    # Start worker
    celery_app.worker_main(
        [
            "worker",
            f"--hostname={worker_name}@%h",
            f"--loglevel={log_level}",
            f"--concurrency={concurrency}",
            "--without-gossip",
            "--without-mingle",
            "--without-heartbeat",
            "--pool=prefork",
        ]
    )
