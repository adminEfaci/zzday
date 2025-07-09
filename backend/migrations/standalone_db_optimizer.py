#!/usr/bin/env python3
"""
Standalone Database Optimizer

This script can run database optimization without requiring the full application context.
Useful for running migrations in production environments or CI/CD pipelines.

Usage:
    python migrations/standalone_db_optimizer.py --analyze
    python migrations/standalone_db_optimizer.py --apply
    python migrations/standalone_db_optimizer.py --rollback
"""

import argparse
import asyncio
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

import asyncpg
from dataclasses import dataclass

# Add the backend directory to the path
sys.path.insert(0, str(Path(__file__).parent.parent))


@dataclass
class IndexRecommendation:
    """Index recommendation."""
    table_name: str
    columns: List[str]
    index_type: str = "btree"
    reason: str = ""
    estimated_benefit: float = 0.0
    migration_sql: str = ""


class StandaloneDatabaseOptimizer:
    """Standalone database optimizer that works without the full app context."""
    
    def __init__(self, connection_string: str):
        self.connection_string = connection_string
        self.applied_indexes: List[str] = []
        
    async def get_connection(self) -> asyncpg.Connection:
        """Get database connection."""
        return await asyncpg.connect(self.connection_string)
    
    async def analyze_slow_queries(self, conn: asyncpg.Connection, limit: int = 50) -> List[Dict[str, Any]]:
        """Analyze slow queries from pg_stat_statements."""
        try:
            query = """
                SELECT 
                    query,
                    mean_exec_time,
                    calls,
                    rows,
                    100.0 * shared_blks_hit / nullif(shared_blks_hit + shared_blks_read, 0) AS hit_percent
                FROM pg_stat_statements 
                WHERE query NOT LIKE '%pg_stat_statements%'
                ORDER BY mean_exec_time DESC 
                LIMIT $1
            """
            
            rows = await conn.fetch(query, limit)
            
            return [
                {
                    "query": row["query"],
                    "execution_time_ms": row["mean_exec_time"],
                    "calls": row["calls"],
                    "rows": row["rows"],
                    "hit_percent": row["hit_percent"]
                }
                for row in rows
            ]
            
        except Exception as e:
            print(f"Warning: Could not analyze slow queries: {e}")
            return []
    
    async def get_tables(self, conn: asyncpg.Connection) -> List[str]:
        """Get all user tables."""
        query = """
            SELECT tablename 
            FROM pg_tables 
            WHERE schemaname = 'public'
        """
        
        rows = await conn.fetch(query)
        return [row["tablename"] for row in rows]
    
    async def get_foreign_keys(self, conn: asyncpg.Connection, table_name: str) -> List[Dict[str, str]]:
        """Get foreign keys for a table."""
        query = """
            SELECT 
                kcu.column_name,
                ccu.table_name AS foreign_table_name,
                ccu.column_name AS foreign_column_name
            FROM information_schema.table_constraints AS tc
            JOIN information_schema.key_column_usage AS kcu
                ON tc.constraint_name = kcu.constraint_name
                AND tc.table_schema = kcu.table_schema
            JOIN information_schema.constraint_column_usage AS ccu
                ON ccu.constraint_name = tc.constraint_name
                AND ccu.table_schema = tc.table_schema
            WHERE tc.constraint_type = 'FOREIGN KEY'
                AND tc.table_name = $1
        """
        
        rows = await conn.fetch(query, table_name)
        return [
            {
                "column_name": row["column_name"],
                "foreign_table_name": row["foreign_table_name"],
                "foreign_column_name": row["foreign_column_name"]
            }
            for row in rows
        ]
    
    async def column_has_index(self, conn: asyncpg.Connection, table_name: str, column_name: str) -> bool:
        """Check if column has an index."""
        query = """
            SELECT 1
            FROM pg_indexes
            WHERE tablename = $1
                AND indexdef LIKE '%' || $2 || '%'
        """
        
        row = await conn.fetchrow(query, table_name, column_name)
        return row is not None
    
    async def get_date_columns(self, conn: asyncpg.Connection, table_name: str) -> List[str]:
        """Get date/timestamp columns for a table."""
        query = """
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = $1
                AND data_type IN ('timestamp', 'timestamptz', 'date', 'time')
        """
        
        rows = await conn.fetch(query, table_name)
        return [row["column_name"] for row in rows]
    
    async def get_common_columns(self, conn: asyncpg.Connection, table_name: str) -> List[str]:
        """Get commonly queried columns."""
        query = """
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = $1
                AND column_name IN ('id', 'user_id', 'created_at', 'updated_at', 'status', 'type', 'email')
        """
        
        rows = await conn.fetch(query, table_name)
        return [row["column_name"] for row in rows]
    
    async def find_missing_indexes(self, conn: asyncpg.Connection) -> List[IndexRecommendation]:
        """Find missing indexes."""
        recommendations = []
        tables = await self.get_tables(conn)
        
        for table_name in tables:
            # Foreign key indexes
            foreign_keys = await self.get_foreign_keys(conn, table_name)
            for fk in foreign_keys:
                column_name = fk["column_name"]
                if not await self.column_has_index(conn, table_name, column_name):
                    recommendations.append(IndexRecommendation(
                        table_name=table_name,
                        columns=[column_name],
                        reason=f"Foreign key column without index (references {fk['foreign_table_name']}.{fk['foreign_column_name']})",
                        estimated_benefit=0.8,
                        migration_sql=f"CREATE INDEX idx_{table_name}_{column_name} ON {table_name}({column_name});"
                    ))
            
            # Date column indexes
            date_columns = await self.get_date_columns(conn, table_name)
            for column_name in date_columns:
                if not await self.column_has_index(conn, table_name, column_name):
                    recommendations.append(IndexRecommendation(
                        table_name=table_name,
                        columns=[column_name],
                        reason=f"Date/timestamp column without index (useful for range queries)",
                        estimated_benefit=0.7,
                        migration_sql=f"CREATE INDEX idx_{table_name}_{column_name} ON {table_name}({column_name});"
                    ))
            
            # Common query columns
            common_columns = await self.get_common_columns(conn, table_name)
            for column_name in common_columns:
                if not await self.column_has_index(conn, table_name, column_name):
                    recommendations.append(IndexRecommendation(
                        table_name=table_name,
                        columns=[column_name],
                        reason=f"Column frequently used in WHERE clauses",
                        estimated_benefit=0.6,
                        migration_sql=f"CREATE INDEX idx_{table_name}_{column_name} ON {table_name}({column_name});"
                    ))
        
        return recommendations
    
    async def get_database_size(self, conn: asyncpg.Connection) -> float:
        """Get database size in MB."""
        query = """
            SELECT pg_database_size(current_database()) as size_bytes
        """
        
        row = await conn.fetchrow(query)
        return row["size_bytes"] / (1024 * 1024) if row else 0.0
    
    async def get_table_stats(self, conn: asyncpg.Connection) -> Dict[str, Any]:
        """Get table statistics."""
        query = """
            SELECT 
                schemaname,
                tablename,
                n_tup_ins,
                n_tup_upd,
                n_tup_del,
                n_live_tup,
                n_dead_tup,
                last_vacuum,
                last_autovacuum,
                last_analyze,
                last_autoanalyze
            FROM pg_stat_user_tables
            ORDER BY n_live_tup DESC
        """
        
        rows = await conn.fetch(query)
        stats = {}
        
        for row in rows:
            stats[row["tablename"]] = {
                "live_tuples": row["n_live_tup"],
                "dead_tuples": row["n_dead_tup"],
                "inserts": row["n_tup_ins"],
                "updates": row["n_tup_upd"],
                "deletes": row["n_tup_del"],
                "fragmentation": row["n_dead_tup"] / (row["n_live_tup"] + row["n_dead_tup"]) if (row["n_live_tup"] + row["n_dead_tup"]) > 0 else 0
            }
        
        return stats
    
    async def count_indexes(self, conn: asyncpg.Connection) -> int:
        """Count total indexes."""
        query = """
            SELECT COUNT(*) as count
            FROM pg_indexes
            WHERE schemaname = 'public'
        """
        
        row = await conn.fetchrow(query)
        return row["count"] if row else 0
    
    def generate_migration_sql(self, recommendations: List[IndexRecommendation]) -> str:
        """Generate migration SQL."""
        if not recommendations:
            return "-- No index recommendations found\n"
        
        # Group by priority
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
            "-- Enable pg_stat_statements if not already enabled",
            "CREATE EXTENSION IF NOT EXISTS pg_stat_statements;",
            "",
        ]
        
        # Add indexes by priority
        for priority_group, group_name in [
            (high_priority, "HIGH PRIORITY"),
            (medium_priority, "MEDIUM PRIORITY"),
            (low_priority, "LOW PRIORITY")
        ]:
            if priority_group:
                sql_parts.extend([
                    f"-- {group_name} INDEXES",
                    ""
                ])
                
                for rec in priority_group:
                    sql_parts.extend([
                        f"-- {rec.reason}",
                        f"-- Estimated benefit: {rec.estimated_benefit:.1%}",
                        f"-- Table: {rec.table_name}, Columns: {', '.join(rec.columns)}",
                        rec.migration_sql,
                        ""
                    ])
        
        sql_parts.extend([
            "-- Update table statistics",
            "ANALYZE;",
            "",
            "COMMIT;"
        ])
        
        return "\n".join(sql_parts)
    
    async def analyze_database(self) -> Dict[str, Any]:
        """Analyze database for optimization opportunities."""
        conn = await self.get_connection()
        
        try:
            print("Analyzing database for optimization opportunities...")
            
            # Get basic stats
            database_size = await self.get_database_size(conn)
            table_stats = await self.get_table_stats(conn)
            total_indexes = await self.count_indexes(conn)
            
            # Find missing indexes
            recommendations = await self.find_missing_indexes(conn)
            
            # Analyze slow queries
            slow_queries = await self.analyze_slow_queries(conn)
            
            analysis = {
                "database_size_mb": database_size,
                "total_tables": len(table_stats),
                "total_indexes": total_indexes,
                "table_stats": table_stats,
                "recommendations": recommendations,
                "slow_queries": slow_queries
            }
            
            print(f"Analysis complete:")
            print(f"  Database size: {database_size:.2f} MB")
            print(f"  Total tables: {len(table_stats)}")
            print(f"  Total indexes: {total_indexes}")
            print(f"  Missing indexes: {len(recommendations)}")
            print(f"  Slow queries: {len(slow_queries)}")
            
            return analysis
            
        finally:
            await conn.close()
    
    async def apply_migration(self, migration_sql: str) -> bool:
        """Apply migration SQL."""
        conn = await self.get_connection()
        
        try:
            print("Applying database optimization migration...")
            
            # Execute migration in a transaction
            async with conn.transaction():
                # Split SQL into statements
                statements = [s.strip() for s in migration_sql.split(';') if s.strip()]
                
                for statement in statements:
                    if statement.upper().startswith(('CREATE INDEX', 'CREATE EXTENSION', 'ANALYZE')):
                        print(f"Executing: {statement[:100]}...")
                        await conn.execute(statement)
            
            print("Migration applied successfully!")
            return True
            
        except Exception as e:
            print(f"Migration failed: {e}")
            return False
            
        finally:
            await conn.close()
    
    async def save_migration_files(self, migration_sql: str, analysis: Dict[str, Any]) -> Dict[str, str]:
        """Save migration files."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        migrations_dir = Path(__file__).parent
        
        # Save migration SQL
        migration_file = migrations_dir / f"{timestamp}_db_optimization_up.sql"
        migration_file.write_text(migration_sql)
        
        # Save analysis report
        report_file = migrations_dir / f"{timestamp}_db_analysis_report.txt"
        
        report_content = f"""Database Optimization Analysis Report
Generated: {datetime.now().isoformat()}

Database Statistics:
- Size: {analysis['database_size_mb']:.2f} MB
- Tables: {analysis['total_tables']}
- Indexes: {analysis['total_indexes']}
- Missing indexes: {len(analysis['recommendations'])}
- Slow queries: {len(analysis['slow_queries'])}

Index Recommendations:
"""
        
        for rec in analysis['recommendations']:
            report_content += f"\n{rec.table_name}.{', '.join(rec.columns)}"
            report_content += f"\n  Reason: {rec.reason}"
            report_content += f"\n  Benefit: {rec.estimated_benefit:.1%}"
            report_content += f"\n  SQL: {rec.migration_sql}"
            report_content += "\n"
        
        report_file.write_text(report_content)
        
        return {
            "migration_file": str(migration_file),
            "report_file": str(report_file)
        }


def get_database_url() -> str:
    """Get database URL from environment."""
    # Try different environment variable names
    for env_var in ["DATABASE_URL", "POSTGRES_URL", "DB_URL"]:
        if env_var in os.environ:
            return os.environ[env_var]
    
    # Default connection string for local development
    return "postgresql://postgres:postgres@localhost:5432/ezzday"


async def main():
    """Main function."""
    parser = argparse.ArgumentParser(description="Standalone Database Optimizer")
    parser.add_argument("--analyze", action="store_true", help="Analyze database only")
    parser.add_argument("--apply", action="store_true", help="Apply optimization")
    parser.add_argument("--db-url", help="Database URL (default: from environment)")
    
    args = parser.parse_args()
    
    # Get database URL
    db_url = args.db_url or get_database_url()
    
    if not db_url:
        print("Error: No database URL provided. Set DATABASE_URL environment variable or use --db-url")
        return 1
    
    optimizer = StandaloneDatabaseOptimizer(db_url)
    
    if args.analyze:
        analysis = await optimizer.analyze_database()
        migration_sql = optimizer.generate_migration_sql(analysis["recommendations"])
        files = await optimizer.save_migration_files(migration_sql, analysis)
        
        print(f"\nAnalysis complete. Files saved:")
        print(f"  Migration SQL: {files['migration_file']}")
        print(f"  Analysis report: {files['report_file']}")
        
        return 0
    
    elif args.apply:
        # First analyze
        analysis = await optimizer.analyze_database()
        
        if not analysis["recommendations"]:
            print("No optimization recommendations found!")
            return 0
        
        # Generate migration SQL
        migration_sql = optimizer.generate_migration_sql(analysis["recommendations"])
        
        # Save files
        files = await optimizer.save_migration_files(migration_sql, analysis)
        
        # Apply migration
        success = await optimizer.apply_migration(migration_sql)
        
        if success:
            print(f"\nOptimization applied successfully!")
            print(f"Migration SQL saved to: {files['migration_file']}")
            return 0
        else:
            print("Optimization failed!")
            return 1
    
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))