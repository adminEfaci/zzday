"""
Database Index Optimization and Performance Analysis.

Provides automated database index analysis, optimization recommendations,
and migration generation for optimal query performance.
"""

import asyncio
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple
from sqlalchemy import text, inspect
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.schema import Index

from app.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class QueryAnalysis:
    """Query analysis result."""
    query: str
    execution_time_ms: float
    rows_examined: int
    rows_returned: int
    index_used: Optional[str]
    suggested_indexes: List[str]
    cost_estimate: float


@dataclass
class IndexRecommendation:
    """Index recommendation."""
    table_name: str
    columns: List[str]
    index_type: str = "btree"
    reason: str = ""
    estimated_benefit: float = 0.0
    migration_sql: str = ""


@dataclass
class DatabaseStats:
    """Database statistics."""
    total_tables: int
    total_indexes: int
    total_size_mb: float
    fragmentation_ratio: float
    slow_queries: List[QueryAnalysis]
    missing_indexes: List[IndexRecommendation]


class DatabaseOptimizer:
    """Database performance optimizer."""
    
    def __init__(self, session: AsyncSession):
        self.session = session
        self.inspector = inspect(session.bind)
        self._query_log: List[QueryAnalysis] = []
        self._table_stats: Dict[str, Any] = {}
        
    async def analyze_slow_queries(self, limit: int = 50) -> List[QueryAnalysis]:
        """Analyze slow queries from performance schema."""
        try:
            # PostgreSQL specific query
            query = text("""
                SELECT 
                    query,
                    mean_exec_time,
                    calls,
                    rows,
                    100.0 * shared_blks_hit / nullif(shared_blks_hit + shared_blks_read, 0) AS hit_percent
                FROM pg_stat_statements 
                WHERE query NOT LIKE '%pg_stat_statements%'
                ORDER BY mean_exec_time DESC 
                LIMIT :limit
            """)
            
            result = await self.session.execute(query, {"limit": limit})
            rows = result.fetchall()
            
            analyses = []
            for row in rows:
                analysis = QueryAnalysis(
                    query=row.query,
                    execution_time_ms=row.mean_exec_time,
                    rows_examined=row.rows,
                    rows_returned=row.rows,
                    index_used=None,
                    suggested_indexes=await self._suggest_indexes_for_query(row.query),
                    cost_estimate=row.mean_exec_time * row.calls
                )
                analyses.append(analysis)
            
            return analyses
            
        except Exception as e:
            logger.warning(f"Could not analyze slow queries: {e}")
            return []
    
    async def analyze_table_stats(self) -> Dict[str, Any]:
        """Analyze table statistics."""
        try:
            query = text("""
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
            """)
            
            result = await self.session.execute(query)
            rows = result.fetchall()
            
            stats = {}
            for row in rows:
                stats[row.tablename] = {
                    "live_tuples": row.n_live_tup,
                    "dead_tuples": row.n_dead_tup,
                    "inserts": row.n_tup_ins,
                    "updates": row.n_tup_upd,
                    "deletes": row.n_tup_del,
                    "last_vacuum": row.last_vacuum,
                    "last_analyze": row.last_analyze,
                    "fragmentation": row.n_dead_tup / (row.n_live_tup + row.n_dead_tup) if (row.n_live_tup + row.n_dead_tup) > 0 else 0
                }
            
            return stats
            
        except Exception as e:
            logger.warning(f"Could not analyze table stats: {e}")
            return {}
    
    async def find_missing_indexes(self) -> List[IndexRecommendation]:
        """Find missing indexes based on common patterns."""
        recommendations = []
        
        # Get all tables
        tables = await self._get_all_tables()
        
        for table_name in tables:
            # Check foreign key columns
            fk_recommendations = await self._check_foreign_key_indexes(table_name)
            recommendations.extend(fk_recommendations)
            
            # Check frequently queried columns
            query_recommendations = await self._check_query_patterns(table_name)
            recommendations.extend(query_recommendations)
            
            # Check date/timestamp columns
            date_recommendations = await self._check_date_indexes(table_name)
            recommendations.extend(date_recommendations)
        
        return recommendations
    
    async def _get_all_tables(self) -> List[str]:
        """Get all user tables."""
        try:
            query = text("""
                SELECT tablename 
                FROM pg_tables 
                WHERE schemaname = 'public'
            """)
            
            result = await self.session.execute(query)
            return [row.tablename for row in result.fetchall()]
            
        except Exception as e:
            logger.warning(f"Could not get tables: {e}")
            return []
    
    async def _check_foreign_key_indexes(self, table_name: str) -> List[IndexRecommendation]:
        """Check for missing foreign key indexes."""
        recommendations = []
        
        try:
            # Get foreign keys
            query = text("""
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
                    AND tc.table_name = :table_name
            """)
            
            result = await self.session.execute(query, {"table_name": table_name})
            fks = result.fetchall()
            
            # Check if each FK has an index
            for fk in fks:
                has_index = await self._column_has_index(table_name, fk.column_name)
                if not has_index:
                    recommendations.append(IndexRecommendation(
                        table_name=table_name,
                        columns=[fk.column_name],
                        reason=f"Foreign key column without index (references {fk.foreign_table_name}.{fk.foreign_column_name})",
                        estimated_benefit=0.8,
                        migration_sql=f"CREATE INDEX idx_{table_name}_{fk.column_name} ON {table_name}({fk.column_name});"
                    ))
            
            return recommendations
            
        except Exception as e:
            logger.warning(f"Could not check foreign key indexes for {table_name}: {e}")
            return []
    
    async def _check_query_patterns(self, table_name: str) -> List[IndexRecommendation]:
        """Check for missing indexes based on query patterns."""
        recommendations = []
        
        # This would analyze actual query logs in production
        # For now, we'll check common patterns
        
        try:
            # Check for columns frequently used in WHERE clauses
            common_where_columns = await self._get_common_where_columns(table_name)
            
            for column in common_where_columns:
                has_index = await self._column_has_index(table_name, column)
                if not has_index:
                    recommendations.append(IndexRecommendation(
                        table_name=table_name,
                        columns=[column],
                        reason=f"Column frequently used in WHERE clauses",
                        estimated_benefit=0.6,
                        migration_sql=f"CREATE INDEX idx_{table_name}_{column} ON {table_name}({column});"
                    ))
            
            return recommendations
            
        except Exception as e:
            logger.warning(f"Could not check query patterns for {table_name}: {e}")
            return []
    
    async def _check_date_indexes(self, table_name: str) -> List[IndexRecommendation]:
        """Check for missing indexes on date/timestamp columns."""
        recommendations = []
        
        try:
            # Get date/timestamp columns
            query = text("""
                SELECT column_name, data_type
                FROM information_schema.columns
                WHERE table_name = :table_name
                    AND data_type IN ('timestamp', 'timestamptz', 'date', 'time')
            """)
            
            result = await self.session.execute(query, {"table_name": table_name})
            date_columns = result.fetchall()
            
            for column in date_columns:
                has_index = await self._column_has_index(table_name, column.column_name)
                if not has_index:
                    recommendations.append(IndexRecommendation(
                        table_name=table_name,
                        columns=[column.column_name],
                        reason=f"Date/timestamp column without index (useful for range queries)",
                        estimated_benefit=0.7,
                        migration_sql=f"CREATE INDEX idx_{table_name}_{column.column_name} ON {table_name}({column.column_name});"
                    ))
            
            return recommendations
            
        except Exception as e:
            logger.warning(f"Could not check date indexes for {table_name}: {e}")
            return []
    
    async def _column_has_index(self, table_name: str, column_name: str) -> bool:
        """Check if column has an index."""
        try:
            query = text("""
                SELECT 1
                FROM pg_indexes
                WHERE tablename = :table_name
                    AND indexdef LIKE '%' || :column_name || '%'
            """)
            
            result = await self.session.execute(query, {
                "table_name": table_name,
                "column_name": column_name
            })
            
            return result.fetchone() is not None
            
        except Exception as e:
            logger.warning(f"Could not check index for {table_name}.{column_name}: {e}")
            return False
    
    async def _get_common_where_columns(self, table_name: str) -> List[str]:
        """Get columns commonly used in WHERE clauses."""
        # This would analyze query logs in production
        # For now, return common patterns
        common_columns = []
        
        try:
            # Get all columns
            query = text("""
                SELECT column_name
                FROM information_schema.columns
                WHERE table_name = :table_name
                    AND column_name IN ('id', 'user_id', 'created_at', 'updated_at', 'status', 'type', 'email')
            """)
            
            result = await self.session.execute(query, {"table_name": table_name})
            common_columns = [row.column_name for row in result.fetchall()]
            
        except Exception as e:
            logger.warning(f"Could not get common columns for {table_name}: {e}")
        
        return common_columns
    
    async def _suggest_indexes_for_query(self, query: str) -> List[str]:
        """Suggest indexes for a specific query."""
        suggestions = []
        
        # Parse query for common patterns
        # This is a simplified implementation
        
        # Look for WHERE clause patterns
        where_match = re.search(r'WHERE\s+(\w+)', query, re.IGNORECASE)
        if where_match:
            column = where_match.group(1)
            suggestions.append(f"CREATE INDEX ON table_name({column})")
        
        # Look for JOIN patterns
        join_matches = re.findall(r'JOIN\s+\w+\s+ON\s+\w+\.(\w+)', query, re.IGNORECASE)
        for column in join_matches:
            suggestions.append(f"CREATE INDEX ON table_name({column})")
        
        # Look for ORDER BY patterns
        order_matches = re.findall(r'ORDER\s+BY\s+(\w+)', query, re.IGNORECASE)
        for column in order_matches:
            suggestions.append(f"CREATE INDEX ON table_name({column})")
        
        return suggestions
    
    async def generate_optimization_report(self) -> DatabaseStats:
        """Generate comprehensive optimization report."""
        logger.info("Generating database optimization report")
        
        # Analyze slow queries
        slow_queries = await self.analyze_slow_queries()
        
        # Analyze table stats
        table_stats = await self.analyze_table_stats()
        
        # Find missing indexes
        missing_indexes = await self.find_missing_indexes()
        
        # Calculate database size
        total_size = await self._calculate_database_size()
        
        # Calculate fragmentation
        fragmentation = await self._calculate_fragmentation()
        
        return DatabaseStats(
            total_tables=len(table_stats),
            total_indexes=await self._count_indexes(),
            total_size_mb=total_size,
            fragmentation_ratio=fragmentation,
            slow_queries=slow_queries,
            missing_indexes=missing_indexes
        )
    
    async def _calculate_database_size(self) -> float:
        """Calculate total database size in MB."""
        try:
            query = text("""
                SELECT pg_size_pretty(pg_database_size(current_database())) as size,
                       pg_database_size(current_database()) as size_bytes
            """)
            
            result = await self.session.execute(query)
            row = result.fetchone()
            
            return row.size_bytes / (1024 * 1024)  # Convert to MB
            
        except Exception as e:
            logger.warning(f"Could not calculate database size: {e}")
            return 0.0
    
    async def _calculate_fragmentation(self) -> float:
        """Calculate average fragmentation ratio."""
        try:
            table_stats = await self.analyze_table_stats()
            
            if not table_stats:
                return 0.0
            
            total_fragmentation = sum(
                stats.get("fragmentation", 0) for stats in table_stats.values()
            )
            
            return total_fragmentation / len(table_stats)
            
        except Exception as e:
            logger.warning(f"Could not calculate fragmentation: {e}")
            return 0.0
    
    async def _count_indexes(self) -> int:
        """Count total number of indexes."""
        try:
            query = text("""
                SELECT COUNT(*) as count
                FROM pg_indexes
                WHERE schemaname = 'public'
            """)
            
            result = await self.session.execute(query)
            row = result.fetchone()
            
            return row.count
            
        except Exception as e:
            logger.warning(f"Could not count indexes: {e}")
            return 0
    
    async def create_migration_file(self, recommendations: List[IndexRecommendation]) -> str:
        """Create migration file with index recommendations."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"migrations/{timestamp}_optimize_indexes.sql"
        
        migration_content = f"""-- Database Index Optimization Migration
-- Generated on: {datetime.now().isoformat()}
-- Recommendations: {len(recommendations)}

BEGIN;

"""
        
        for rec in recommendations:
            migration_content += f"""
-- {rec.reason}
-- Estimated benefit: {rec.estimated_benefit:.1%}
-- Table: {rec.table_name}, Columns: {', '.join(rec.columns)}
{rec.migration_sql}

"""
        
        migration_content += """
COMMIT;
"""
        
        return migration_content
    
    async def execute_maintenance_tasks(self) -> Dict[str, Any]:
        """Execute database maintenance tasks."""
        results = {}
        
        try:
            # Analyze tables
            await self.session.execute(text("ANALYZE;"))
            results["analyze"] = "completed"
            
            # Vacuum analyze high-fragmentation tables
            table_stats = await self.analyze_table_stats()
            for table_name, stats in table_stats.items():
                if stats.get("fragmentation", 0) > 0.2:  # 20% fragmentation
                    await self.session.execute(text(f"VACUUM ANALYZE {table_name};"))
                    results[f"vacuum_{table_name}"] = "completed"
            
            await self.session.commit()
            
        except Exception as e:
            await self.session.rollback()
            logger.error(f"Maintenance task failed: {e}")
            results["error"] = str(e)
        
        return results


__all__ = [
    "DatabaseOptimizer",
    "QueryAnalysis", 
    "IndexRecommendation",
    "DatabaseStats"
]