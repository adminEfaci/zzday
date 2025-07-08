#!/usr/bin/env python3
"""Celery beat scheduler entry point."""
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
    # Configure beat scheduler
    log_level = os.getenv("CELERY_LOG_LEVEL", "INFO")
    schedule_file = os.getenv("CELERY_BEAT_SCHEDULE", "celerybeat-schedule")

    logger.info("Starting Celery beat scheduler")
    logger.info(f"Log level: {log_level}")
    logger.info(f"Schedule file: {schedule_file}")

    # Start beat scheduler
    celery_app.worker_main(
        [
            "beat",
            f"--loglevel={log_level}",
            f"--schedule={schedule_file}",
            "--pidfile=/tmp/celerybeat.pid",
        ]
    )
