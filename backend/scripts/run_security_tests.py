#!/usr/bin/env python3
"""
Security Test Runner

Comprehensive security testing runner for the application.
Executes all security tests and generates detailed reports.

Usage:
    python scripts/run_security_tests.py
    python scripts/run_security_tests.py --base-url http://localhost:8000
    python scripts/run_security_tests.py --output-dir reports/
    python scripts/run_security_tests.py --format html,json
    python scripts/run_security_tests.py --categories sql,auth,xss
    python scripts/run_security_tests.py --severity critical,high
"""

import argparse
import asyncio
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional

# Add the backend directory to the path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.core.security.test_suite import SecurityTestSuite, run_security_tests


class SecurityTestRunner:
    """Security test runner with comprehensive reporting."""
    
    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        output_dir: str = "reports",
        formats: List[str] = ["html", "json"],
        categories: Optional[List[str]] = None,
        severity_filter: Optional[List[str]] = None
    ):
        self.base_url = base_url
        self.output_dir = Path(output_dir)
        self.formats = formats
        self.categories = categories or []
        self.severity_filter = severity_filter or []
        
        # Create output directory
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    async def run_tests(self) -> dict:
        """Run security tests and generate reports."""
        print(f"🔒 Starting security test suite against {self.base_url}")
        print(f"📊 Output directory: {self.output_dir}")
        print(f"📋 Report formats: {', '.join(self.formats)}")
        
        if self.categories:
            print(f"🏷️  Testing categories: {', '.join(self.categories)}")
        
        if self.severity_filter:
            print(f"⚠️  Severity filter: {', '.join(self.severity_filter)}")
        
        print("-" * 60)
        
        try:
            # Run security tests
            report = await run_security_tests(self.base_url)
            
            # Filter results if needed
            if self.categories or self.severity_filter:
                report = self._filter_report(report)
            
            # Generate reports
            report_files = await self._generate_reports(report)
            
            # Print summary
            self._print_summary(report)
            
            # Print report file locations
            print("\n📁 Generated Reports:")
            for file_path in report_files:
                print(f"   {file_path}")
            
            return {
                "report": report,
                "report_files": report_files,
                "success": report.critical_failures == 0 and report.high_failures == 0
            }
        
        except Exception as e:
            print(f"❌ Error running security tests: {e}")
            return {
                "error": str(e),
                "success": False
            }
    
    def _filter_report(self, report):
        """Filter report results based on categories and severity."""
        filtered_results = []
        
        for result in report.results:
            # Filter by category
            if self.categories and result.category.lower() not in [c.lower() for c in self.categories]:
                continue
            
            # Filter by severity
            if self.severity_filter and result.severity.lower() not in [s.lower() for s in self.severity_filter]:
                continue
            
            filtered_results.append(result)
        
        # Update report with filtered results
        report.results = filtered_results
        report.total_tests = len(filtered_results)
        report.passed_tests = sum(1 for r in filtered_results if r.passed)
        report.failed_tests = report.total_tests - report.passed_tests
        report.critical_failures = sum(1 for r in filtered_results if not r.passed and r.severity == "CRITICAL")
        report.high_failures = sum(1 for r in filtered_results if not r.passed and r.severity == "HIGH")
        report.medium_failures = sum(1 for r in filtered_results if not r.passed and r.severity == "MEDIUM")
        report.low_failures = sum(1 for r in filtered_results if not r.passed and r.severity == "LOW")
        
        return report
    
    async def _generate_reports(self, report) -> List[str]:
        """Generate reports in specified formats."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_files = []
        
        # Generate HTML report
        if "html" in self.formats:
            html_file = self.output_dir / f"security_report_{timestamp}.html"
            html_content = SecurityTestSuite().generate_html_report(report)
            html_file.write_text(html_content)
            report_files.append(str(html_file))
        
        # Generate JSON report
        if "json" in self.formats:
            json_file = self.output_dir / f"security_report_{timestamp}.json"
            json_content = self._generate_json_report(report)
            json_file.write_text(json_content)
            report_files.append(str(json_file))
        
        # Generate text report
        if "text" in self.formats:
            text_file = self.output_dir / f"security_report_{timestamp}.txt"
            text_content = self._generate_text_report(report)
            text_file.write_text(text_content)
            report_files.append(str(text_file))
        
        # Generate CSV report
        if "csv" in self.formats:
            csv_file = self.output_dir / f"security_report_{timestamp}.csv"
            csv_content = self._generate_csv_report(report)
            csv_file.write_text(csv_content)
            report_files.append(str(csv_file))
        
        return report_files
    
    def _generate_json_report(self, report) -> str:
        """Generate JSON report."""
        report_data = {
            "timestamp": report.timestamp.isoformat(),
            "execution_time": report.execution_time,
            "summary": {
                "total_tests": report.total_tests,
                "passed_tests": report.passed_tests,
                "failed_tests": report.failed_tests,
                "critical_failures": report.critical_failures,
                "high_failures": report.high_failures,
                "medium_failures": report.medium_failures,
                "low_failures": report.low_failures
            },
            "results": []
        }
        
        for result in report.results:
            report_data["results"].append({
                "test_name": result.test_name,
                "category": result.category,
                "passed": result.passed,
                "severity": result.severity,
                "description": result.description,
                "details": result.details,
                "remediation": result.remediation,
                "execution_time": result.execution_time
            })
        
        return json.dumps(report_data, indent=2)
    
    def _generate_text_report(self, report) -> str:
        """Generate text report."""
        lines = [
            "=" * 60,
            "SECURITY TEST REPORT",
            "=" * 60,
            f"Generated: {report.timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
            f"Execution Time: {report.execution_time:.2f} seconds",
            "",
            "SUMMARY",
            "-" * 20,
            f"Total Tests: {report.total_tests}",
            f"Passed: {report.passed_tests}",
            f"Failed: {report.failed_tests}",
            f"Critical Failures: {report.critical_failures}",
            f"High Failures: {report.high_failures}",
            f"Medium Failures: {report.medium_failures}",
            f"Low Failures: {report.low_failures}",
            "",
            "DETAILED RESULTS",
            "-" * 20
        ]
        
        # Group by category
        categories = {}
        for result in report.results:
            if result.category not in categories:
                categories[result.category] = []
            categories[result.category].append(result)
        
        for category, results in categories.items():
            lines.append(f"\n{category.upper()}")
            lines.append("-" * len(category))
            
            for result in results:
                status = "✓ PASS" if result.passed else "✗ FAIL"
                lines.append(f"{status} [{result.severity}] {result.test_name}")
                lines.append(f"    {result.description}")
                
                if result.details:
                    lines.append(f"    Details: {result.details}")
                
                if result.remediation:
                    lines.append(f"    Remediation: {result.remediation}")
                
                lines.append(f"    Execution Time: {result.execution_time:.3f}s")
                lines.append("")
        
        return "\n".join(lines)
    
    def _generate_csv_report(self, report) -> str:
        """Generate CSV report."""
        lines = [
            "Test Name,Category,Status,Severity,Description,Details,Remediation,Execution Time"
        ]
        
        for result in report.results:
            status = "PASS" if result.passed else "FAIL"
            details = (result.details or "").replace(",", ";").replace("\n", " ")
            remediation = (result.remediation or "").replace(",", ";").replace("\n", " ")
            description = result.description.replace(",", ";").replace("\n", " ")
            
            lines.append(
                f'"{result.test_name}","{result.category}","{status}","{result.severity}",'
                f'"{description}","{details}","{remediation}",{result.execution_time:.3f}'
            )
        
        return "\n".join(lines)
    
    def _print_summary(self, report):
        """Print test summary to console."""
        print("\n" + "=" * 60)
        print("SECURITY TEST SUMMARY")
        print("=" * 60)
        
        # Overall status
        if report.critical_failures > 0:
            print("🚨 CRITICAL SECURITY ISSUES FOUND")
        elif report.high_failures > 0:
            print("⚠️  HIGH SEVERITY ISSUES FOUND")
        elif report.medium_failures > 0:
            print("⚠️  MEDIUM SEVERITY ISSUES FOUND")
        elif report.low_failures > 0:
            print("⚠️  LOW SEVERITY ISSUES FOUND")
        else:
            print("✅ ALL SECURITY TESTS PASSED")
        
        print()
        
        # Detailed counts
        print(f"📊 Total Tests: {report.total_tests}")
        print(f"✅ Passed: {report.passed_tests}")
        print(f"❌ Failed: {report.failed_tests}")
        print()
        
        if report.failed_tests > 0:
            print("📋 Failure Breakdown:")
            if report.critical_failures > 0:
                print(f"   🔴 Critical: {report.critical_failures}")
            if report.high_failures > 0:
                print(f"   🟠 High: {report.high_failures}")
            if report.medium_failures > 0:
                print(f"   🟡 Medium: {report.medium_failures}")
            if report.low_failures > 0:
                print(f"   🟢 Low: {report.low_failures}")
            print()
        
        # Category breakdown
        categories = {}
        for result in report.results:
            if result.category not in categories:
                categories[result.category] = {"passed": 0, "failed": 0}
            
            if result.passed:
                categories[result.category]["passed"] += 1
            else:
                categories[result.category]["failed"] += 1
        
        print("📂 Category Breakdown:")
        for category, stats in categories.items():
            total = stats["passed"] + stats["failed"]
            print(f"   {category}: {stats['passed']}/{total} passed")
        
        print(f"\n⏱️  Execution Time: {report.execution_time:.2f} seconds")
        
        # Failed test details
        if report.failed_tests > 0:
            print("\n❌ FAILED TESTS:")
            print("-" * 40)
            
            failed_tests = [r for r in report.results if not r.passed]
            # Sort by severity
            severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            failed_tests.sort(key=lambda x: severity_order.get(x.severity, 4))
            
            for result in failed_tests:
                severity_icon = {
                    "CRITICAL": "🔴",
                    "HIGH": "🟠", 
                    "MEDIUM": "🟡",
                    "LOW": "🟢"
                }.get(result.severity, "⚪")
                
                print(f"{severity_icon} [{result.severity}] {result.test_name}")
                print(f"   {result.description}")
                if result.remediation:
                    print(f"   💡 {result.remediation}")
                print()


def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description="Run comprehensive security tests",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        "--base-url",
        default="http://localhost:8000",
        help="Base URL for the application (default: http://localhost:8000)"
    )
    
    parser.add_argument(
        "--output-dir",
        default="reports",
        help="Output directory for reports (default: reports)"
    )
    
    parser.add_argument(
        "--format",
        default="html,json",
        help="Report formats (comma-separated): html,json,text,csv (default: html,json)"
    )
    
    parser.add_argument(
        "--categories",
        help="Test categories to run (comma-separated): sql,auth,xss,csrf,etc"
    )
    
    parser.add_argument(
        "--severity",
        help="Severity filter (comma-separated): critical,high,medium,low"
    )
    
    parser.add_argument(
        "--fail-on-high",
        action="store_true",
        help="Exit with error code if high or critical issues found"
    )
    
    parser.add_argument(
        "--fail-on-medium",
        action="store_true", 
        help="Exit with error code if medium, high, or critical issues found"
    )
    
    args = parser.parse_args()
    
    # Parse arguments
    formats = [f.strip() for f in args.format.split(",")]
    categories = [c.strip() for c in args.categories.split(",")] if args.categories else None
    severity_filter = [s.strip() for s in args.severity.split(",")] if args.severity else None
    
    # Create runner
    runner = SecurityTestRunner(
        base_url=args.base_url,
        output_dir=args.output_dir,
        formats=formats,
        categories=categories,
        severity_filter=severity_filter
    )
    
    # Run tests
    async def run_async():
        return await runner.run_tests()
    
    result = asyncio.run(run_async())
    
    if "error" in result:
        sys.exit(1)
    
    # Check exit conditions
    report = result["report"]
    
    if args.fail_on_high and (report.critical_failures > 0 or report.high_failures > 0):
        print("\n❌ Exiting with error due to high/critical security issues")
        sys.exit(1)
    
    if args.fail_on_medium and (report.critical_failures > 0 or report.high_failures > 0 or report.medium_failures > 0):
        print("\n❌ Exiting with error due to medium/high/critical security issues")
        sys.exit(1)
    
    print("\n✅ Security test execution completed successfully")
    sys.exit(0)


if __name__ == "__main__":
    main()