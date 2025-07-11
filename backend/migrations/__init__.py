"""
Database Migrations Package

This package contains database migrations for the EzzDay application.
Migrations are used to apply schema changes, optimize indexes, and
improve database performance.

Available migrations:
- 20250109_optimize_database_indexes: Analyzes and creates optimal database indexes

Usage:
    python migrations/runner.py --list
    python migrations/runner.py --run all
    python migrations/runner.py --status
"""

from .runner import MigrationRunner

__all__ = ["MigrationRunner"]