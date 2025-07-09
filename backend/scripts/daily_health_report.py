#!/usr/bin/env python3
"""
Daily Infrastructure Health Report

Generates comprehensive daily health reports for infrastructure components
including database performance, security status, system metrics, and recommendations.
"""

import argparse
import asyncio
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional

# Add the backend directory to the path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.core.monitoring.metrics import get_metrics_collector, get_metrics_exporter
from app.core.security.test_suite import run_security_tests
from app.core.infrastructure.database_optimizer import DatabaseOptimizer
from app.core.database import get_async_session
from app.core.logging import get_logger

logger = get_logger(__name__)


class HealthStatus:
    """Health status levels."""
    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"


class HealthReportGenerator:
    """Generate comprehensive infrastructure health reports."""
    
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.metrics_collector = get_metrics_collector()
        self.metrics_exporter = get_metrics_exporter()
        
    async def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive health report."""
        logger.info("Starting daily infrastructure health report generation")
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "report_period": "24h",
            "overall_status": HealthStatus.HEALTHY,
            "sections": {}
        }
        
        # System metrics analysis
        report["sections"]["system_metrics"] = await self._analyze_system_metrics()
        
        # Database health
        report["sections"]["database_health"] = await self._analyze_database_health()
        
        # Security status
        report["sections"]["security_status"] = await self._analyze_security_status()
        
        # Performance analysis
        report["sections"]["performance_analysis"] = await self._analyze_performance()
        
        # Infrastructure components
        report["sections"]["infrastructure_status"] = await self._analyze_infrastructure()
        
        # Recommendations
        report["sections"]["recommendations"] = self._generate_recommendations(report)
        
        # Determine overall status
        report["overall_status"] = self._determine_overall_status(report)
        
        # Save report
        await self._save_report(report)
        
        logger.info(f"Health report generated with status: {report['overall_status']}")
        return report
    
    async def _analyze_system_metrics(self) -> Dict[str, Any]:
        """Analyze system metrics over the last 24 hours."""
        since = datetime.now() - timedelta(hours=24)
        
        # CPU metrics
        cpu_metrics = self.metrics_collector.get_summary("system.cpu.usage", since)
        
        # Memory metrics
        memory_metrics = self.metrics_collector.get_summary("system.memory.usage", since)
        
        # Disk metrics
        disk_metrics = self.metrics_collector.get_summary("system.disk.usage", since)
        
        # Network metrics
        network_sent = self.metrics_collector.get_summary("system.network.bytes_sent", since)
        network_recv = self.metrics_collector.get_summary("system.network.bytes_recv", since)
        
        analysis = {
            "status": HealthStatus.HEALTHY,
            "cpu": self._analyze_metric_summary(cpu_metrics, "CPU", 80, 95),
            "memory": self._analyze_metric_summary(memory_metrics, "Memory", 85, 95),
            "disk": self._analyze_metric_summary(disk_metrics, "Disk", 80, 90),
            "network": {
                "bytes_sent": network_sent.sum if network_sent else 0,
                "bytes_received": network_recv.sum if network_recv else 0,
                "status": HealthStatus.HEALTHY
            }
        }
        
        # Determine section status
        if (analysis["cpu"]["status"] == HealthStatus.CRITICAL or 
            analysis["memory"]["status"] == HealthStatus.CRITICAL or
            analysis["disk"]["status"] == HealthStatus.CRITICAL):
            analysis["status"] = HealthStatus.CRITICAL
        elif (analysis["cpu"]["status"] == HealthStatus.WARNING or 
              analysis["memory"]["status"] == HealthStatus.WARNING or
              analysis["disk"]["status"] == HealthStatus.WARNING):
            analysis["status"] = HealthStatus.WARNING
        
        return analysis
    
    async def _analyze_database_health(self) -> Dict[str, Any]:
        """Analyze database health and performance."""
        since = datetime.now() - timedelta(hours=24)
        
        # Query performance
        query_duration = self.metrics_collector.get_summary("database.query.duration", since)
        slow_queries = self.metrics_collector.get_summary("database.slow_query.count", since)
        
        # Connection pool
        active_connections = self.metrics_collector.get_summary("database.connections.active", since)
        
        # Cache performance
        cache_hits = self.metrics_collector.get_metrics("database.cache.requests", since)
        cache_hit_rate = self._calculate_cache_hit_rate(cache_hits)
        
        # Database optimization analysis
        db_optimization = await self._run_database_optimization_check()
        
        analysis = {
            "status": HealthStatus.HEALTHY,
            "query_performance": {
                "avg_duration": query_duration.avg if query_duration else 0,
                "p95_duration": query_duration.p95 if query_duration else 0,
                "slow_query_count": slow_queries.sum if slow_queries else 0,
                "status": self._assess_query_performance(query_duration, slow_queries)
            },
            "connection_pool": {
                "avg_active_connections": active_connections.avg if active_connections else 0,
                "max_active_connections": active_connections.max if active_connections else 0,
                "status": self._assess_connection_pool(active_connections)
            },
            "cache_performance": {
                "hit_rate": cache_hit_rate,
                "status": HealthStatus.HEALTHY if cache_hit_rate > 0.8 else HealthStatus.WARNING
            },
            "optimization": db_optimization
        }
        
        # Determine section status
        statuses = [
            analysis["query_performance"]["status"],
            analysis["connection_pool"]["status"],
            analysis["cache_performance"]["status"],
            analysis["optimization"]["status"]
        ]
        
        if HealthStatus.CRITICAL in statuses:
            analysis["status"] = HealthStatus.CRITICAL
        elif HealthStatus.WARNING in statuses:
            analysis["status"] = HealthStatus.WARNING
        
        return analysis
    
    async def _analyze_security_status(self) -> Dict[str, Any]:
        """Analyze security status."""
        try:
            # Run security tests
            security_report = await run_security_tests("http://localhost:8000")
            
            analysis = {
                "status": HealthStatus.HEALTHY,
                "total_tests": security_report.total_tests,
                "passed_tests": security_report.passed_tests,
                "failed_tests": security_report.failed_tests,
                "critical_failures": security_report.critical_failures,
                "high_failures": security_report.high_failures,
                "medium_failures": security_report.medium_failures,
                "low_failures": security_report.low_failures,
                "execution_time": security_report.execution_time
            }
            
            # Determine security status
            if security_report.critical_failures > 0:
                analysis["status"] = HealthStatus.CRITICAL
            elif security_report.high_failures > 0:
                analysis["status"] = HealthStatus.WARNING
            elif security_report.medium_failures > 5:
                analysis["status"] = HealthStatus.WARNING
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error running security analysis: {e}")
            return {
                "status": HealthStatus.WARNING,
                "error": str(e),
                "message": "Security tests could not be executed"
            }
    
    async def _analyze_performance(self) -> Dict[str, Any]:
        """Analyze overall performance metrics."""
        since = datetime.now() - timedelta(hours=24)
        
        # API performance
        api_duration = self.metrics_collector.get_summary("api.request.duration", since)
        api_errors = self.metrics_collector.get_summary("api.request.errors", since)
        api_requests = self.metrics_collector.get_summary("api.request.count", since)
        
        # Infrastructure performance
        cache_ops = self.metrics_collector.get_summary("infrastructure.cache.operations", since)
        background_tasks = self.metrics_collector.get_summary("infrastructure.background_task.duration", since)
        
        analysis = {
            "status": HealthStatus.HEALTHY,
            "api_performance": {
                "avg_response_time": api_duration.avg if api_duration else 0,
                "p95_response_time": api_duration.p95 if api_duration else 0,
                "total_requests": api_requests.count if api_requests else 0,
                "error_count": api_errors.sum if api_errors else 0,
                "error_rate": self._calculate_error_rate(api_errors, api_requests),
                "status": self._assess_api_performance(api_duration, api_errors, api_requests)
            },
            "infrastructure_performance": {
                "cache_operations": cache_ops.count if cache_ops else 0,
                "background_task_avg_duration": background_tasks.avg if background_tasks else 0,
                "status": HealthStatus.HEALTHY
            }
        }
        
        # Determine section status
        if analysis["api_performance"]["status"] == HealthStatus.CRITICAL:
            analysis["status"] = HealthStatus.CRITICAL
        elif analysis["api_performance"]["status"] == HealthStatus.WARNING:
            analysis["status"] = HealthStatus.WARNING
        
        return analysis
    
    async def _analyze_infrastructure(self) -> Dict[str, Any]:
        """Analyze infrastructure component health."""
        since = datetime.now() - timedelta(hours=24)
        
        # Circuit breaker status
        circuit_breaker_events = self.metrics_collector.get_metrics("infrastructure.circuit_breaker.state_changes", since)
        
        # Retry attempts
        retry_attempts = self.metrics_collector.get_summary("infrastructure.retry.attempts", since)
        
        analysis = {
            "status": HealthStatus.HEALTHY,
            "circuit_breakers": {
                "state_changes": len(circuit_breaker_events),
                "status": HealthStatus.WARNING if len(circuit_breaker_events) > 10 else HealthStatus.HEALTHY
            },
            "retry_mechanisms": {
                "total_attempts": retry_attempts.count if retry_attempts else 0,
                "avg_attempts": retry_attempts.avg if retry_attempts else 0,
                "status": HealthStatus.WARNING if retry_attempts and retry_attempts.avg > 2 else HealthStatus.HEALTHY
            }
        }
        
        # Determine section status
        if (analysis["circuit_breakers"]["status"] == HealthStatus.CRITICAL or 
            analysis["retry_mechanisms"]["status"] == HealthStatus.CRITICAL):
            analysis["status"] = HealthStatus.CRITICAL
        elif (analysis["circuit_breakers"]["status"] == HealthStatus.WARNING or 
              analysis["retry_mechanisms"]["status"] == HealthStatus.WARNING):
            analysis["status"] = HealthStatus.WARNING
        
        return analysis
    
    def _generate_recommendations(self, report: Dict[str, Any]) -> List[Dict[str, str]]:
        """Generate actionable recommendations based on report."""
        recommendations = []
        
        # System recommendations
        system_metrics = report["sections"]["system_metrics"]
        if system_metrics["cpu"]["status"] == HealthStatus.CRITICAL:
            recommendations.append({
                "priority": "HIGH",
                "category": "System",
                "issue": "High CPU usage detected",
                "recommendation": "Consider scaling horizontally or optimizing CPU-intensive operations"
            })
        
        if system_metrics["memory"]["status"] == HealthStatus.CRITICAL:
            recommendations.append({
                "priority": "HIGH", 
                "category": "System",
                "issue": "High memory usage detected",
                "recommendation": "Review memory usage patterns and consider increasing memory allocation"
            })
        
        # Database recommendations
        db_health = report["sections"]["database_health"]
        if db_health["optimization"]["missing_indexes"]:
            recommendations.append({
                "priority": "MEDIUM",
                "category": "Database",
                "issue": f"Missing {len(db_health['optimization']['missing_indexes'])} database indexes",
                "recommendation": "Run database optimization migration to create missing indexes"
            })
        
        if db_health["query_performance"]["status"] == HealthStatus.WARNING:
            recommendations.append({
                "priority": "MEDIUM",
                "category": "Database", 
                "issue": "Slow query performance detected",
                "recommendation": "Review slow queries and optimize database queries"
            })
        
        # Security recommendations
        security_status = report["sections"]["security_status"]
        if security_status.get("critical_failures", 0) > 0:
            recommendations.append({
                "priority": "CRITICAL",
                "category": "Security",
                "issue": f"{security_status['critical_failures']} critical security issues found",
                "recommendation": "Address critical security vulnerabilities immediately"
            })
        
        if security_status.get("high_failures", 0) > 0:
            recommendations.append({
                "priority": "HIGH",
                "category": "Security",
                "issue": f"{security_status['high_failures']} high severity security issues found",
                "recommendation": "Address high severity security issues within 24 hours"
            })
        
        # Performance recommendations  
        performance = report["sections"]["performance_analysis"]
        if performance["api_performance"]["error_rate"] > 0.05:
            recommendations.append({
                "priority": "MEDIUM",
                "category": "Performance",
                "issue": f"API error rate is {performance['api_performance']['error_rate']:.2%}",
                "recommendation": "Investigate and fix API errors to improve reliability"
            })
        
        return recommendations
    
    def _determine_overall_status(self, report: Dict[str, Any]) -> str:
        """Determine overall health status."""
        statuses = [section["status"] for section in report["sections"].values()]
        
        if HealthStatus.CRITICAL in statuses:
            return HealthStatus.CRITICAL
        elif HealthStatus.WARNING in statuses:
            return HealthStatus.WARNING
        else:
            return HealthStatus.HEALTHY
    
    def _analyze_metric_summary(self, summary, name: str, warning_threshold: float, critical_threshold: float) -> Dict[str, Any]:
        """Analyze a metric summary against thresholds."""
        if not summary:
            return {"status": HealthStatus.HEALTHY, "message": f"No {name} metrics available"}
        
        status = HealthStatus.HEALTHY
        if summary.avg > critical_threshold:
            status = HealthStatus.CRITICAL
        elif summary.avg > warning_threshold:
            status = HealthStatus.WARNING
        
        return {
            "status": status,
            "average": summary.avg,
            "max": summary.max,
            "p95": summary.p95,
            "message": f"{name} average: {summary.avg:.1f}%, max: {summary.max:.1f}%"
        }
    
    def _calculate_cache_hit_rate(self, cache_metrics: List) -> float:
        """Calculate cache hit rate."""
        if not cache_metrics:
            return 0.0
        
        hits = sum(1 for m in cache_metrics if m.labels.get("result") == "hit")
        total = len(cache_metrics)
        
        return hits / total if total > 0 else 0.0
    
    def _calculate_error_rate(self, errors_summary, requests_summary) -> float:
        """Calculate API error rate."""
        if not errors_summary or not requests_summary:
            return 0.0
        
        return errors_summary.sum / requests_summary.count if requests_summary.count > 0 else 0.0
    
    def _assess_query_performance(self, query_duration, slow_queries) -> str:
        """Assess database query performance."""
        if not query_duration:
            return HealthStatus.HEALTHY
        
        if query_duration.avg > 1.0 or (slow_queries and slow_queries.sum > 100):
            return HealthStatus.CRITICAL
        elif query_duration.avg > 0.5 or (slow_queries and slow_queries.sum > 50):
            return HealthStatus.WARNING
        else:
            return HealthStatus.HEALTHY
    
    def _assess_connection_pool(self, active_connections) -> str:
        """Assess database connection pool health."""
        if not active_connections:
            return HealthStatus.HEALTHY
        
        if active_connections.max > 80:
            return HealthStatus.CRITICAL
        elif active_connections.max > 60:
            return HealthStatus.WARNING
        else:
            return HealthStatus.HEALTHY
    
    def _assess_api_performance(self, duration, errors, requests) -> str:
        """Assess API performance."""
        if not duration:
            return HealthStatus.HEALTHY
        
        error_rate = self._calculate_error_rate(errors, requests)
        
        if duration.p95 > 5.0 or error_rate > 0.1:
            return HealthStatus.CRITICAL
        elif duration.p95 > 2.0 or error_rate > 0.05:
            return HealthStatus.WARNING
        else:
            return HealthStatus.HEALTHY
    
    async def _run_database_optimization_check(self) -> Dict[str, Any]:
        """Run database optimization analysis."""
        try:
            async with get_async_session() as session:
                optimizer = DatabaseOptimizer(session)
                missing_indexes = await optimizer.find_missing_indexes()
                slow_queries = await optimizer.find_slow_queries()
                
                return {
                    "status": HealthStatus.WARNING if missing_indexes or slow_queries else HealthStatus.HEALTHY,
                    "missing_indexes": len(missing_indexes),
                    "slow_queries": len(slow_queries),
                    "recommendations": len(missing_indexes) + len(slow_queries)
                }
        except Exception as e:
            logger.error(f"Database optimization check failed: {e}")
            return {
                "status": HealthStatus.WARNING,
                "error": str(e),
                "message": "Database optimization check failed"
            }
    
    async def _save_report(self, report: Dict[str, Any]):
        """Save report to file."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save JSON report
        json_file = self.output_dir / f"health_report_{timestamp}.json"
        with open(json_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Save HTML report
        html_file = self.output_dir / f"health_report_{timestamp}.html"
        html_content = self._generate_html_report(report)
        with open(html_file, 'w') as f:
            f.write(html_content)
        
        logger.info(f"Health report saved to {json_file} and {html_file}")
    
    def _generate_html_report(self, report: Dict[str, Any]) -> str:
        """Generate HTML report."""
        status_colors = {
            HealthStatus.HEALTHY: "#28a745",
            HealthStatus.WARNING: "#ffc107",
            HealthStatus.CRITICAL: "#dc3545"
        }
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Infrastructure Health Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .status {{ padding: 5px 10px; border-radius: 3px; color: white; }}
        .healthy {{ background-color: {status_colors[HealthStatus.HEALTHY]}; }}
        .warning {{ background-color: {status_colors[HealthStatus.WARNING]}; }}
        .critical {{ background-color: {status_colors[HealthStatus.CRITICAL]}; }}
        .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; }}
        .recommendations {{ background-color: #f8f9fa; padding: 15px; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <h1>Infrastructure Health Report</h1>
    <p><strong>Generated:</strong> {report['timestamp']}</p>
    <p><strong>Overall Status:</strong> <span class="status {report['overall_status']}">{report['overall_status'].upper()}</span></p>
    
    <div class="section">
        <h2>System Metrics</h2>
        <p><strong>Status:</strong> <span class="status {report['sections']['system_metrics']['status']}">{report['sections']['system_metrics']['status'].upper()}</span></p>
        <table>
            <tr><th>Metric</th><th>Average</th><th>Max</th><th>P95</th><th>Status</th></tr>
            <tr><td>CPU Usage</td><td>{report['sections']['system_metrics']['cpu']['average']:.1f}%</td><td>{report['sections']['system_metrics']['cpu']['max']:.1f}%</td><td>{report['sections']['system_metrics']['cpu']['p95']:.1f}%</td><td><span class="status {report['sections']['system_metrics']['cpu']['status']}">{report['sections']['system_metrics']['cpu']['status'].upper()}</span></td></tr>
            <tr><td>Memory Usage</td><td>{report['sections']['system_metrics']['memory']['average']:.1f}%</td><td>{report['sections']['system_metrics']['memory']['max']:.1f}%</td><td>{report['sections']['system_metrics']['memory']['p95']:.1f}%</td><td><span class="status {report['sections']['system_metrics']['memory']['status']}">{report['sections']['system_metrics']['memory']['status'].upper()}</span></td></tr>
            <tr><td>Disk Usage</td><td>{report['sections']['system_metrics']['disk']['average']:.1f}%</td><td>{report['sections']['system_metrics']['disk']['max']:.1f}%</td><td>{report['sections']['system_metrics']['disk']['p95']:.1f}%</td><td><span class="status {report['sections']['system_metrics']['disk']['status']}">{report['sections']['system_metrics']['disk']['status'].upper()}</span></td></tr>
        </table>
    </div>
    
    <div class="section">
        <h2>Database Health</h2>
        <p><strong>Status:</strong> <span class="status {report['sections']['database_health']['status']}">{report['sections']['database_health']['status'].upper()}</span></p>
        <p><strong>Query Performance:</strong> Avg: {report['sections']['database_health']['query_performance']['avg_duration']:.3f}s, P95: {report['sections']['database_health']['query_performance']['p95_duration']:.3f}s</p>
        <p><strong>Slow Queries:</strong> {report['sections']['database_health']['query_performance']['slow_query_count']}</p>
        <p><strong>Cache Hit Rate:</strong> {report['sections']['database_health']['cache_performance']['hit_rate']:.1%}</p>
        <p><strong>Missing Indexes:</strong> {report['sections']['database_health']['optimization']['missing_indexes']}</p>
    </div>
    
    <div class="section">
        <h2>Security Status</h2>
        <p><strong>Status:</strong> <span class="status {report['sections']['security_status']['status']}">{report['sections']['security_status']['status'].upper()}</span></p>
        <p><strong>Tests:</strong> {report['sections']['security_status']['total_tests']} total, {report['sections']['security_status']['passed_tests']} passed, {report['sections']['security_status']['failed_tests']} failed</p>
        <p><strong>Failures:</strong> {report['sections']['security_status']['critical_failures']} critical, {report['sections']['security_status']['high_failures']} high, {report['sections']['security_status']['medium_failures']} medium</p>
    </div>
    
    <div class="section">
        <h2>Performance Analysis</h2>
        <p><strong>Status:</strong> <span class="status {report['sections']['performance_analysis']['status']}">{report['sections']['performance_analysis']['status'].upper()}</span></p>
        <p><strong>API Response Time:</strong> Avg: {report['sections']['performance_analysis']['api_performance']['avg_response_time']:.3f}s, P95: {report['sections']['performance_analysis']['api_performance']['p95_response_time']:.3f}s</p>
        <p><strong>API Error Rate:</strong> {report['sections']['performance_analysis']['api_performance']['error_rate']:.2%}</p>
        <p><strong>Total Requests:</strong> {report['sections']['performance_analysis']['api_performance']['total_requests']}</p>
    </div>
    
    <div class="recommendations">
        <h2>Recommendations</h2>
        {''.join(f'<p><strong>[{rec["priority"]}]</strong> {rec["category"]}: {rec["issue"]} - {rec["recommendation"]}</p>' for rec in report['sections']['recommendations'])}
    </div>
</body>
</html>"""
        
        return html


async def main():
    """Main function."""
    parser = argparse.ArgumentParser(description="Generate daily infrastructure health report")
    parser.add_argument("--output-dir", default="reports", help="Output directory for reports")
    parser.add_argument("--format", choices=["json", "html", "both"], default="both", help="Report format")
    
    args = parser.parse_args()
    
    generator = HealthReportGenerator(args.output_dir)
    
    try:
        report = await generator.generate_report()
        
        print(f"✅ Health report generated successfully")
        print(f"📊 Overall Status: {report['overall_status'].upper()}")
        print(f"📁 Reports saved to: {args.output_dir}")
        
        # Return appropriate exit code
        if report['overall_status'] == HealthStatus.CRITICAL:
            sys.exit(2)
        elif report['overall_status'] == HealthStatus.WARNING:
            sys.exit(1)
        else:
            sys.exit(0)
            
    except Exception as e:
        print(f"❌ Error generating health report: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())