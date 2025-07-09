#!/usr/bin/env python3
"""
Database Optimization Analysis Script

Runs database optimization analysis and generates reports for CI/CD pipeline.
"""

import argparse
import asyncio
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Any

# Add the backend directory to the path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.core.infrastructure.database_optimizer import DatabaseOptimizer
from app.core.database import get_async_session
from app.core.logging import get_logger

logger = get_logger(__name__)


class DatabaseOptimizationRunner:
    """Database optimization analysis runner for CI/CD."""
    
    def __init__(self, output_dir: str = "db-optimization-results"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
    async def run_optimization_analysis(self) -> Dict[str, Any]:
        """Run comprehensive database optimization analysis."""
        logger.info("Starting database optimization analysis")
        
        try:
            async with get_async_session() as session:
                optimizer = DatabaseOptimizer(session)
                
                # Find missing indexes
                missing_indexes = await optimizer.find_missing_indexes()
                
                # Find slow queries
                slow_queries = await optimizer.find_slow_queries()
                
                # Generate performance stats
                stats = await optimizer.generate_optimization_report()
                
                # Create analysis report
                report = {
                    "timestamp": datetime.now().isoformat(),
                    "missing_indexes": {
                        "count": len(missing_indexes),
                        "recommendations": [
                            {
                                "table": idx.table_name,
                                "columns": idx.columns,
                                "index_type": idx.index_type,
                                "priority": idx.priority,
                                "estimated_benefit": idx.estimated_benefit
                            }
                            for idx in missing_indexes
                        ]
                    },
                    "slow_queries": {
                        "count": len(slow_queries),
                        "queries": [
                            {
                                "query_hash": query.query_hash,
                                "avg_execution_time": query.avg_execution_time,
                                "total_executions": query.total_executions,
                                "table": query.table_name,
                                "recommendation": query.recommendation
                            }
                            for query in slow_queries
                        ]
                    },
                    "performance_stats": stats,
                    "optimization_summary": {
                        "total_recommendations": len(missing_indexes) + len(slow_queries),
                        "critical_issues": len([idx for idx in missing_indexes if idx.priority == "HIGH"]),
                        "estimated_performance_gain": sum(idx.estimated_benefit for idx in missing_indexes),
                        "status": self._determine_optimization_status(missing_indexes, slow_queries)
                    }
                }
                
                # Save report
                await self._save_report(report)
                
                return report
                
        except Exception as e:
            logger.error(f"Database optimization analysis failed: {e}")
            return {
                "error": str(e),
                "timestamp": datetime.now().isoformat(),
                "status": "failed"
            }
    
    def _determine_optimization_status(self, missing_indexes, slow_queries) -> str:
        """Determine optimization status based on findings."""
        critical_indexes = len([idx for idx in missing_indexes if idx.priority == "HIGH"])
        critical_queries = len([q for q in slow_queries if q.avg_execution_time > 1000])
        
        if critical_indexes > 3 or critical_queries > 5:
            return "critical"
        elif len(missing_indexes) > 5 or len(slow_queries) > 10:
            return "warning"
        else:
            return "good"
    
    async def _save_report(self, report: Dict[str, Any]):
        """Save optimization report to files."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save JSON report
        json_file = self.output_dir / f"db_optimization_{timestamp}.json"
        with open(json_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Save summary report
        summary_file = self.output_dir / f"db_optimization_summary_{timestamp}.txt"
        with open(summary_file, 'w') as f:
            f.write("DATABASE OPTIMIZATION ANALYSIS REPORT\n")
            f.write("=" * 50 + "\n\n")
            f.write(f"Generated: {report['timestamp']}\n")
            f.write(f"Status: {report.get('optimization_summary', {}).get('status', 'unknown').upper()}\n\n")
            
            if 'missing_indexes' in report:
                f.write(f"Missing Indexes: {report['missing_indexes']['count']}\n")
                for idx in report['missing_indexes']['recommendations'][:5]:  # Top 5
                    f.write(f"  - {idx['table']}.{','.join(idx['columns'])} ({idx['priority']} priority)\n")
                f.write("\n")
            
            if 'slow_queries' in report:
                f.write(f"Slow Queries: {report['slow_queries']['count']}\n")
                for query in report['slow_queries']['queries'][:5]:  # Top 5
                    f.write(f"  - {query['table']}: {query['avg_execution_time']}ms avg\n")
                f.write("\n")
            
            if 'optimization_summary' in report:
                summary = report['optimization_summary']
                f.write(f"Total Recommendations: {summary['total_recommendations']}\n")
                f.write(f"Critical Issues: {summary['critical_issues']}\n")
                f.write(f"Estimated Performance Gain: {summary['estimated_performance_gain']:.2f}%\n")
        
        logger.info(f"Database optimization report saved to {json_file}")
    
    def print_summary(self, report: Dict[str, Any]):
        """Print optimization summary to console."""
        if "error" in report:
            print(f"❌ Database optimization analysis failed: {report['error']}")
            return
        
        status = report.get('optimization_summary', {}).get('status', 'unknown')
        status_icon = {
            'good': '✅',
            'warning': '⚠️',
            'critical': '🚨'
        }.get(status, '❓')
        
        print(f"\n{status_icon} Database Optimization Analysis")
        print("=" * 50)
        
        if 'missing_indexes' in report:
            count = report['missing_indexes']['count']
            print(f"📊 Missing Indexes: {count}")
            
        if 'slow_queries' in report:
            count = report['slow_queries']['count']
            print(f"🐌 Slow Queries: {count}")
        
        if 'optimization_summary' in report:
            summary = report['optimization_summary']
            print(f"📋 Total Recommendations: {summary['total_recommendations']}")
            print(f"🔴 Critical Issues: {summary['critical_issues']}")
            print(f"📈 Estimated Performance Gain: {summary['estimated_performance_gain']:.2f}%")
        
        print(f"📁 Reports saved to: {self.output_dir}")


async def main():
    """Main function."""
    parser = argparse.ArgumentParser(description="Run database optimization analysis")
    parser.add_argument("--output-dir", default="db-optimization-results", help="Output directory for reports")
    parser.add_argument("--fail-on-critical", action="store_true", help="Exit with error if critical issues found")
    parser.add_argument("--fail-on-warning", action="store_true", help="Exit with error if warnings found")
    
    args = parser.parse_args()
    
    runner = DatabaseOptimizationRunner(args.output_dir)
    
    try:
        report = await runner.run_optimization_analysis()
        
        # Print summary
        runner.print_summary(report)
        
        # Check exit conditions
        if "error" in report:
            sys.exit(1)
        
        status = report.get('optimization_summary', {}).get('status', 'unknown')
        
        if args.fail_on_critical and status == 'critical':
            print("\n❌ Exiting with error due to critical database optimization issues")
            sys.exit(1)
        
        if args.fail_on_warning and status in ['critical', 'warning']:
            print("\n❌ Exiting with error due to database optimization warnings")
            sys.exit(1)
        
        print("\n✅ Database optimization analysis completed successfully")
        sys.exit(0)
        
    except Exception as e:
        print(f"❌ Error running database optimization analysis: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())