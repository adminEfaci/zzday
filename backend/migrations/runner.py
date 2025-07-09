#!/usr/bin/env python3
"""
Database Migration Runner

Manages database migrations including schema changes, index optimizations,
and performance improvements.

Features:
- Run all pending migrations
- Run specific migrations
- Rollback migrations
- Migration status tracking
- Dry run capabilities

Usage:
    python migrations/runner.py --list
    python migrations/runner.py --run all
    python migrations/runner.py --run 20250109_optimize_database_indexes
    python migrations/runner.py --rollback 20250109_optimize_database_indexes
    python migrations/runner.py --status
"""

import argparse
import asyncio
import importlib.util
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_async_session
from app.core.logging import get_logger

logger = get_logger(__name__)


class MigrationRunner:
    """Database migration runner and manager."""
    
    def __init__(self):
        self.migrations_dir = Path(__file__).parent
        self.migration_tracking_table = "migration_history"
        
    async def ensure_migration_tracking(self, session: AsyncSession):
        """Ensure migration tracking table exists."""
        create_table_sql = f"""
        CREATE TABLE IF NOT EXISTS {self.migration_tracking_table} (
            id SERIAL PRIMARY KEY,
            migration_name VARCHAR(255) NOT NULL UNIQUE,
            applied_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            rollback_at TIMESTAMP WITH TIME ZONE,
            status VARCHAR(50) DEFAULT 'applied',
            execution_time_ms INTEGER,
            metadata JSONB
        );
        
        CREATE INDEX IF NOT EXISTS idx_migration_history_name 
        ON {self.migration_tracking_table}(migration_name);
        
        CREATE INDEX IF NOT EXISTS idx_migration_history_applied_at 
        ON {self.migration_tracking_table}(applied_at);
        """
        
        await session.execute(text(create_table_sql))
        await session.commit()
    
    async def record_migration(
        self, 
        session: AsyncSession, 
        migration_name: str, 
        status: str = "applied",
        execution_time_ms: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """Record migration in tracking table."""
        insert_sql = f"""
        INSERT INTO {self.migration_tracking_table} 
        (migration_name, status, execution_time_ms, metadata)
        VALUES (:migration_name, :status, :execution_time_ms, :metadata)
        ON CONFLICT (migration_name) 
        DO UPDATE SET 
            status = :status,
            applied_at = NOW(),
            execution_time_ms = :execution_time_ms,
            metadata = :metadata
        """
        
        await session.execute(text(insert_sql), {
            "migration_name": migration_name,
            "status": status,
            "execution_time_ms": execution_time_ms,
            "metadata": metadata
        })
        await session.commit()
    
    async def record_rollback(self, session: AsyncSession, migration_name: str):
        """Record migration rollback."""
        update_sql = f"""
        UPDATE {self.migration_tracking_table}
        SET rollback_at = NOW(), status = 'rolled_back'
        WHERE migration_name = :migration_name
        """
        
        await session.execute(text(update_sql), {"migration_name": migration_name})
        await session.commit()
    
    async def get_migration_status(self, session: AsyncSession) -> List[Dict[str, Any]]:
        """Get status of all migrations."""
        query_sql = f"""
        SELECT migration_name, applied_at, rollback_at, status, execution_time_ms, metadata
        FROM {self.migration_tracking_table}
        ORDER BY applied_at DESC
        """
        
        result = await session.execute(text(query_sql))
        return [dict(row._mapping) for row in result.fetchall()]
    
    def discover_migrations(self) -> List[str]:
        """Discover all migration files."""
        migrations = []
        
        for file in self.migrations_dir.glob("*.py"):
            if file.name.startswith("2025") and file.name != "runner.py":
                migrations.append(file.stem)
        
        return sorted(migrations)
    
    async def load_migration_module(self, migration_name: str):
        """Load migration module dynamically."""
        migration_file = self.migrations_dir / f"{migration_name}.py"
        
        if not migration_file.exists():
            raise FileNotFoundError(f"Migration file not found: {migration_file}")
        
        spec = importlib.util.spec_from_file_location(migration_name, migration_file)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        return module
    
    async def run_migration(self, migration_name: str, dry_run: bool = False) -> bool:
        """Run a specific migration."""
        logger.info(f"Running migration: {migration_name}")
        
        start_time = datetime.now()
        
        try:
            # Load migration module
            module = await self.load_migration_module(migration_name)
            
            if dry_run:
                # Run analysis only
                if hasattr(module, 'DatabaseIndexMigration'):
                    migration = module.DatabaseIndexMigration()
                    result = await migration.run_analysis_only()
                    logger.info(f"Dry run completed for {migration_name}")
                    return True
                else:
                    logger.warning(f"Dry run not supported for {migration_name}")
                    return False
            
            # Run actual migration
            async with get_async_session() as session:
                await self.ensure_migration_tracking(session)
                
                # Check if already applied
                status = await self.get_migration_status(session)
                applied_migrations = [m["migration_name"] for m in status if m["status"] == "applied"]
                
                if migration_name in applied_migrations:
                    logger.info(f"Migration {migration_name} already applied")
                    return True
                
                # Execute migration
                if hasattr(module, 'DatabaseIndexMigration'):
                    migration = module.DatabaseIndexMigration()
                    success = await migration.apply_optimization()
                else:
                    logger.error(f"No migration class found in {migration_name}")
                    return False
                
                # Record result
                execution_time = int((datetime.now() - start_time).total_seconds() * 1000)
                await self.record_migration(
                    session, 
                    migration_name, 
                    "applied" if success else "failed",
                    execution_time
                )
                
                return success
                
        except Exception as e:
            logger.error(f"Migration {migration_name} failed: {e}")
            
            # Record failure
            try:
                async with get_async_session() as session:
                    await self.ensure_migration_tracking(session)
                    execution_time = int((datetime.now() - start_time).total_seconds() * 1000)
                    await self.record_migration(
                        session, 
                        migration_name, 
                        "failed",
                        execution_time,
                        {"error": str(e)}
                    )
            except:
                pass
            
            return False
    
    async def rollback_migration(self, migration_name: str) -> bool:
        """Rollback a specific migration."""
        logger.info(f"Rolling back migration: {migration_name}")
        
        try:
            # Load migration module
            module = await self.load_migration_module(migration_name)
            
            # Execute rollback
            if hasattr(module, 'DatabaseIndexMigration'):
                migration = module.DatabaseIndexMigration()
                success = await migration.rollback_optimization()
            else:
                logger.error(f"No migration class found in {migration_name}")
                return False
            
            # Record rollback
            async with get_async_session() as session:
                await self.ensure_migration_tracking(session)
                await self.record_rollback(session, migration_name)
            
            return success
            
        except Exception as e:
            logger.error(f"Migration rollback {migration_name} failed: {e}")
            return False
    
    async def run_all_migrations(self, dry_run: bool = False) -> Dict[str, bool]:
        """Run all pending migrations."""
        logger.info("Running all pending migrations")
        
        migrations = self.discover_migrations()
        results = {}
        
        async with get_async_session() as session:
            await self.ensure_migration_tracking(session)
            status = await self.get_migration_status(session)
            applied_migrations = [m["migration_name"] for m in status if m["status"] == "applied"]
        
        for migration_name in migrations:
            if migration_name not in applied_migrations:
                logger.info(f"Running pending migration: {migration_name}")
                results[migration_name] = await self.run_migration(migration_name, dry_run)
            else:
                logger.info(f"Skipping already applied migration: {migration_name}")
                results[migration_name] = True
        
        return results
    
    async def list_migrations(self) -> Dict[str, Any]:
        """List all migrations and their status."""
        migrations = self.discover_migrations()
        
        async with get_async_session() as session:
            await self.ensure_migration_tracking(session)
            status = await self.get_migration_status(session)
        
        status_dict = {m["migration_name"]: m for m in status}
        
        result = {
            "total_migrations": len(migrations),
            "applied_migrations": len([m for m in status if m["status"] == "applied"]),
            "failed_migrations": len([m for m in status if m["status"] == "failed"]),
            "migrations": []
        }
        
        for migration_name in migrations:
            migration_info = {
                "name": migration_name,
                "status": "pending"
            }
            
            if migration_name in status_dict:
                migration_status = status_dict[migration_name]
                migration_info.update({
                    "status": migration_status["status"],
                    "applied_at": migration_status["applied_at"].isoformat() if migration_status["applied_at"] else None,
                    "rollback_at": migration_status["rollback_at"].isoformat() if migration_status["rollback_at"] else None,
                    "execution_time_ms": migration_status["execution_time_ms"]
                })
            
            result["migrations"].append(migration_info)
        
        return result
    
    async def get_status(self) -> Dict[str, Any]:
        """Get comprehensive migration status."""
        async with get_async_session() as session:
            await self.ensure_migration_tracking(session)
            return await self.list_migrations()


async def main():
    """Main migration runner."""
    parser = argparse.ArgumentParser(description="Database Migration Runner")
    parser.add_argument("--list", action="store_true", help="List all migrations")
    parser.add_argument("--run", help="Run migration (use 'all' for all pending)")
    parser.add_argument("--rollback", help="Rollback specific migration")
    parser.add_argument("--status", action="store_true", help="Show migration status")
    parser.add_argument("--dry-run", action="store_true", help="Run in dry-run mode")
    
    args = parser.parse_args()
    
    runner = MigrationRunner()
    
    if args.list:
        result = await runner.list_migrations()
        print(f"Total migrations: {result['total_migrations']}")
        print(f"Applied: {result['applied_migrations']}")
        print(f"Failed: {result['failed_migrations']}")
        print("\nMigrations:")
        for migration in result["migrations"]:
            print(f"  {migration['name']}: {migration['status']}")
    
    elif args.run:
        if args.run == "all":
            results = await runner.run_all_migrations(args.dry_run)
            success_count = sum(1 for success in results.values() if success)
            print(f"Completed {success_count}/{len(results)} migrations")
            for name, success in results.items():
                status = "✓" if success else "✗"
                print(f"  {status} {name}")
        else:
            success = await runner.run_migration(args.run, args.dry_run)
            print(f"Migration {args.run}: {'Success' if success else 'Failed'}")
            exit(0 if success else 1)
    
    elif args.rollback:
        success = await runner.rollback_migration(args.rollback)
        print(f"Rollback {args.rollback}: {'Success' if success else 'Failed'}")
        exit(0 if success else 1)
    
    elif args.status:
        result = await runner.get_status()
        print(f"Migration Status:")
        print(f"  Total: {result['total_migrations']}")
        print(f"  Applied: {result['applied_migrations']}")
        print(f"  Failed: {result['failed_migrations']}")
        print(f"  Pending: {result['total_migrations'] - result['applied_migrations']}")
    
    else:
        parser.print_help()


if __name__ == "__main__":
    asyncio.run(main())