#!/usr/bin/env python3
"""
Database Index Optimization Migration

This migration analyzes the database for missing indexes and creates
optimal indexes to improve query performance.

Features:
- Analyzes slow queries from pg_stat_statements
- Finds missing indexes on foreign keys
- Creates indexes for date/timestamp columns
- Generates composite indexes for common query patterns
- Provides rollback capability

Usage:
    python migrations/20250109_optimize_database_indexes.py --apply
    python migrations/20250109_optimize_database_indexes.py --rollback
"""

import argparse
import asyncio
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_async_session
from app.core.infrastructure.database_optimizer import DatabaseOptimizer, IndexRecommendation
from app.core.logging import get_logger

logger = get_logger(__name__)


class DatabaseIndexMigration:
    """Database index optimization migration handler."""
    
    def __init__(self):
        self.migration_name = "20250109_optimize_database_indexes"
        self.migration_dir = Path(__file__).parent
        self.applied_indexes: List[str] = []
        
    async def analyze_database(self, session: AsyncSession) -> Dict[str, Any]:
        """Analyze database for optimization opportunities."""
        logger.info("Starting database analysis for index optimization")
        
        optimizer = DatabaseOptimizer(session)
        
        # Generate comprehensive optimization report
        stats = await optimizer.generate_optimization_report()
        
        logger.info(
            "Database analysis complete",
            total_tables=stats.total_tables,
            total_indexes=stats.total_indexes,
            slow_queries=len(stats.slow_queries),
            missing_indexes=len(stats.missing_indexes),
            database_size_mb=stats.total_size_mb
        )
        
        return {
            "stats": stats,
            "recommendations": stats.missing_indexes,
            "slow_queries": stats.slow_queries
        }
    
    async def generate_migration_sql(self, recommendations: List[IndexRecommendation]) -> str:
        """Generate SQL migration script from recommendations."""
        
        # Group recommendations by priority
        high_priority = [r for r in recommendations if r.estimated_benefit >= 0.8]
        medium_priority = [r for r in recommendations if 0.5 <= r.estimated_benefit < 0.8]
        low_priority = [r for r in recommendations if r.estimated_benefit < 0.5]
        
        sql_parts = [
            "-- Database Index Optimization Migration",
            f"-- Generated on: {datetime.now().isoformat()}",
            f"-- Total recommendations: {len(recommendations)}",
            "",
            "BEGIN;",
            "",
            "-- Create extension if not exists",
            "CREATE EXTENSION IF NOT EXISTS pg_stat_statements;",
            "",
        ]
        
        # High priority indexes (foreign keys, heavily used columns)
        if high_priority:
            sql_parts.extend([
                "-- HIGH PRIORITY INDEXES",
                "-- These indexes provide the most significant performance improvements",
                ""
            ])
            
            for rec in high_priority:
                sql_parts.extend([
                    f"-- {rec.reason}",
                    f"-- Estimated benefit: {rec.estimated_benefit:.1%}",
                    f"-- Table: {rec.table_name}, Columns: {', '.join(rec.columns)}",
                    rec.migration_sql,
                    ""
                ])
        
        # Medium priority indexes
        if medium_priority:
            sql_parts.extend([
                "-- MEDIUM PRIORITY INDEXES",
                "-- These indexes provide moderate performance improvements",
                ""
            ])
            
            for rec in medium_priority:
                sql_parts.extend([
                    f"-- {rec.reason}",
                    f"-- Estimated benefit: {rec.estimated_benefit:.1%}",
                    rec.migration_sql,
                    ""
                ])
        
        # Low priority indexes
        if low_priority:
            sql_parts.extend([
                "-- LOW PRIORITY INDEXES",
                "-- These indexes provide minor performance improvements",
                ""
            ])
            
            for rec in low_priority:
                sql_parts.extend([
                    f"-- {rec.reason}",
                    f"-- Estimated benefit: {rec.estimated_benefit:.1%}",
                    rec.migration_sql,
                    ""
                ])
        
        # Add statistics update
        sql_parts.extend([
            "-- Update table statistics after index creation",
            "ANALYZE;",
            "",
            "COMMIT;"
        ])
        
        return "\n".join(sql_parts)
    
    async def generate_rollback_sql(self, recommendations: List[IndexRecommendation]) -> str:
        """Generate rollback SQL script."""
        
        sql_parts = [
            "-- Database Index Optimization Rollback",
            f"-- Generated on: {datetime.now().isoformat()}",
            "",
            "BEGIN;",
            ""
        ]
        
        for rec in recommendations:
            # Extract index name from migration SQL
            index_name = self._extract_index_name(rec.migration_sql)
            if index_name:
                sql_parts.append(f"DROP INDEX IF EXISTS {index_name};")
        
        sql_parts.extend([
            "",
            "COMMIT;"
        ])
        
        return "\n".join(sql_parts)
    
    def _extract_index_name(self, migration_sql: str) -> str:
        """Extract index name from migration SQL."""
        # Parse "CREATE INDEX idx_name ON table(column);"
        import re
        match = re.search(r'CREATE INDEX\s+(\w+)\s+ON', migration_sql, re.IGNORECASE)
        return match.group(1) if match else ""
    
    async def apply_migration(self, session: AsyncSession, migration_sql: str) -> bool:
        """Apply migration SQL to database."""
        try:
            logger.info("Applying database index optimization migration")
            
            # Split SQL into individual statements
            statements = [s.strip() for s in migration_sql.split(';') if s.strip()]
            
            for statement in statements:
                if statement.upper().startswith(('CREATE INDEX', 'CREATE EXTENSION', 'ANALYZE')):
                    logger.debug(f"Executing: {statement[:100]}...")
                    await session.execute(text(statement))
            
            await session.commit()
            logger.info("Migration applied successfully")
            return True
            
        except Exception as e:
            logger.error(f"Migration failed: {e}")
            await session.rollback()
            return False
    
    async def rollback_migration(self, session: AsyncSession, rollback_sql: str) -> bool:
        """Rollback migration."""
        try:
            logger.info("Rolling back database index optimization migration")
            
            statements = [s.strip() for s in rollback_sql.split(';') if s.strip()]
            
            for statement in statements:
                if statement.upper().startswith('DROP INDEX'):
                    logger.debug(f"Executing: {statement}")
                    await session.execute(text(statement))
            
            await session.commit()
            logger.info("Migration rollback completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Migration rollback failed: {e}")
            await session.rollback()
            return False
    
    async def save_migration_files(self, migration_sql: str, rollback_sql: str) -> Dict[str, str]:
        """Save migration and rollback SQL files."""
        
        migration_file = self.migration_dir / f"{self.migration_name}_up.sql"
        rollback_file = self.migration_dir / f"{self.migration_name}_down.sql"
        
        # Save migration SQL
        migration_file.write_text(migration_sql)
        logger.info(f"Migration SQL saved to {migration_file}")
        
        # Save rollback SQL
        rollback_file.write_text(rollback_sql)
        logger.info(f"Rollback SQL saved to {rollback_file}")
        
        return {
            "migration_file": str(migration_file),
            "rollback_file": str(rollback_file)
        }
    
    async def run_analysis_only(self) -> Dict[str, Any]:
        """Run analysis without applying changes."""
        logger.info("Running database analysis (dry run)")
        
        async with get_async_session() as session:
            analysis = await self.analyze_database(session)
            
            # Generate migration files for review
            migration_sql = await self.generate_migration_sql(analysis["recommendations"])
            rollback_sql = await self.generate_rollback_sql(analysis["recommendations"])
            
            # Save files for review
            files = await self.save_migration_files(migration_sql, rollback_sql)
            
            return {
                "analysis": analysis,
                "migration_sql": migration_sql,
                "rollback_sql": rollback_sql,
                "files": files
            }
    
    async def apply_optimization(self) -> bool:
        """Apply database optimization migration."""
        logger.info("Applying database index optimization")
        
        async with get_async_session() as session:
            try:
                # Analyze database
                analysis = await self.analyze_database(session)
                
                if not analysis["recommendations"]:
                    logger.info("No index recommendations found - database is already optimized")
                    return True
                
                # Generate migration SQL
                migration_sql = await self.generate_migration_sql(analysis["recommendations"])
                rollback_sql = await self.generate_rollback_sql(analysis["recommendations"])
                
                # Save migration files
                await self.save_migration_files(migration_sql, rollback_sql)
                
                # Apply migration
                success = await self.apply_migration(session, migration_sql)
                
                if success:
                    logger.info(
                        "Database optimization completed successfully",
                        indexes_created=len(analysis["recommendations"])
                    )
                    
                    # Run post-migration analysis
                    await self.post_migration_analysis(session)
                
                return success
                
            except Exception as e:
                logger.error(f"Database optimization failed: {e}")
                return False
    
    async def rollback_optimization(self) -> bool:
        """Rollback database optimization."""
        logger.info("Rolling back database index optimization")
        
        rollback_file = self.migration_dir / f"{self.migration_name}_down.sql"
        
        if not rollback_file.exists():
            logger.error("Rollback file not found")
            return False
        
        rollback_sql = rollback_file.read_text()
        
        async with get_async_session() as session:
            return await self.rollback_migration(session, rollback_sql)
    
    async def post_migration_analysis(self, session: AsyncSession):
        """Run analysis after migration to verify improvements."""
        logger.info("Running post-migration analysis")
        
        optimizer = DatabaseOptimizer(session)
        
        # Update table statistics
        await session.execute(text("ANALYZE;"))
        
        # Check if there are still missing indexes
        remaining_recommendations = await optimizer.find_missing_indexes()
        
        if remaining_recommendations:
            logger.warning(
                "Some index recommendations remain after migration",
                remaining_count=len(remaining_recommendations)
            )
        else:
            logger.info("All critical indexes have been created")
        
        # Run maintenance tasks
        maintenance_results = await optimizer.execute_maintenance_tasks()
        logger.info("Post-migration maintenance completed", results=maintenance_results)


async def main():
    """Main migration script."""
    parser = argparse.ArgumentParser(description="Database Index Optimization Migration")
    parser.add_argument("--apply", action="store_true", help="Apply the migration")
    parser.add_argument("--rollback", action="store_true", help="Rollback the migration")
    parser.add_argument("--analyze", action="store_true", help="Analyze only (dry run)")
    
    args = parser.parse_args()
    
    migration = DatabaseIndexMigration()
    
    if args.apply:
        success = await migration.apply_optimization()
        exit(0 if success else 1)
    
    elif args.rollback:
        success = await migration.rollback_optimization()
        exit(0 if success else 1)
    
    elif args.analyze:
        result = await migration.run_analysis_only()
        print(f"Analysis complete. Found {len(result['analysis']['recommendations'])} recommendations.")
        print(f"Migration files saved to: {result['files']['migration_file']}")
        exit(0)
    
    else:
        parser.print_help()
        exit(1)


if __name__ == "__main__":
    asyncio.run(main())