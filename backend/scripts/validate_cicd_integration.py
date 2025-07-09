#!/usr/bin/env python3
"""
CI/CD Integration Validation Script

Validates that all Agent 3 infrastructure components are properly integrated 
with the CI/CD pipeline and ready for automated testing.
"""

import json
import sys
import subprocess
from pathlib import Path
from typing import Dict, List, Any
import importlib.util


class CICDIntegrationValidator:
    """Validates CI/CD integration for Agent 3 infrastructure components."""
    
    def __init__(self):
        self.backend_dir = Path(__file__).parent.parent
        self.validation_results = []
        
    def validate_all_components(self) -> Dict[str, Any]:
        """Run all validation checks."""
        print("Starting CI/CD integration validation")
        
        # Core infrastructure validation
        self._validate_security_test_suite()
        self._validate_database_optimizer()
        self._validate_performance_monitoring()
        self._validate_health_reporting()
        self._validate_ci_cd_workflow()
        
        # Generate summary
        passed = sum(1 for r in self.validation_results if r['status'] == 'passed')
        failed = sum(1 for r in self.validation_results if r['status'] == 'failed')
        
        summary = {
            "total_checks": len(self.validation_results),
            "passed": passed,
            "failed": failed,
            "success_rate": (passed / len(self.validation_results)) * 100 if self.validation_results else 0,
            "results": self.validation_results
        }
        
        print(f"Validation completed: {passed}/{len(self.validation_results)} checks passed")
        return summary
    
    def _validate_security_test_suite(self):
        """Validate security test suite integration."""
        print("Validating security test suite integration")
        
        try:
            # Check if security test script exists
            script_path = self.backend_dir / "scripts" / "run_security_tests.py"
            if not script_path.exists():
                self._add_result("security_test_script", "failed", "Security test script not found")
                return
            
            # Test script execution (dry run)
            result = subprocess.run([
                sys.executable, str(script_path), "--help"
            ], capture_output=True, text=True, cwd=self.backend_dir)
            
            if result.returncode != 0:
                self._add_result("security_test_script", "failed", f"Script execution failed: {result.stderr}")
                return
            
            # Check if required modules exist as files
            security_suite_path = self.backend_dir / "app" / "core" / "security" / "test_suite.py"
            if security_suite_path.exists():
                self._add_result("security_test_imports", "passed", "Security test modules found")
            else:
                self._add_result("security_test_imports", "failed", "Security test modules not found")
                return
            
            # Check if security config exists
            config_path = self.backend_dir / "app" / "core" / "security" / "config.py"
            if config_path.exists():
                self._add_result("security_config", "passed", "Security configuration found")
            else:
                self._add_result("security_config", "failed", "Security configuration missing")
            
            self._add_result("security_test_suite", "passed", "Security test suite integration validated")
            
        except Exception as e:
            self._add_result("security_test_suite", "failed", f"Validation error: {e}")
    
    def _validate_database_optimizer(self):
        """Validate database optimizer integration."""
        print("Validating database optimizer integration")
        
        try:
            # Check if database optimizer script exists
            script_path = self.backend_dir / "scripts" / "run_database_optimization.py"
            if not script_path.exists():
                self._add_result("database_optimizer_script", "failed", "Database optimizer script not found")
                return
            
            # Test script execution (dry run)
            result = subprocess.run([
                sys.executable, str(script_path), "--help"
            ], capture_output=True, text=True, cwd=self.backend_dir)
            
            if result.returncode != 0:
                self._add_result("database_optimizer_script", "failed", f"Script execution failed: {result.stderr}")
                return
            
            # Check if required modules exist as files
            optimizer_path = self.backend_dir / "app" / "core" / "infrastructure" / "database_optimizer.py"
            if optimizer_path.exists():
                self._add_result("database_optimizer_imports", "passed", "Database optimizer modules found")
            else:
                self._add_result("database_optimizer_imports", "failed", "Database optimizer modules not found")
                return
            
            # Check if migration scripts exist
            migration_dir = self.backend_dir / "migrations"
            if migration_dir.exists():
                self._add_result("database_migrations", "passed", "Database migration directory found")
            else:
                self._add_result("database_migrations", "failed", "Database migration directory missing")
            
            self._add_result("database_optimizer", "passed", "Database optimizer integration validated")
            
        except Exception as e:
            self._add_result("database_optimizer", "failed", f"Validation error: {e}")
    
    def _validate_performance_monitoring(self):
        """Validate performance monitoring integration."""
        print("Validating performance monitoring integration")
        
        try:
            # Check if performance monitoring modules exist as files
            metrics_path = self.backend_dir / "app" / "core" / "monitoring" / "metrics.py"
            perf_tests_path = self.backend_dir / "app" / "core" / "infrastructure" / "performance_tests.py"
            
            if metrics_path.exists() and perf_tests_path.exists():
                self._add_result("performance_monitoring_imports", "passed", "Performance monitoring modules found")
            else:
                self._add_result("performance_monitoring_imports", "failed", "Performance monitoring modules not found")
                return
            
            # Check if monitoring configuration exists
            monitoring_dir = self.backend_dir / "app" / "core" / "monitoring"
            if monitoring_dir.exists():
                self._add_result("monitoring_config", "passed", "Monitoring configuration found")
            else:
                self._add_result("monitoring_config", "failed", "Monitoring configuration missing")
            
            self._add_result("performance_monitoring", "passed", "Performance monitoring integration validated")
            
        except Exception as e:
            self._add_result("performance_monitoring", "failed", f"Validation error: {e}")
    
    def _validate_health_reporting(self):
        """Validate health reporting integration."""
        print("Validating health reporting integration")
        
        try:
            # Check if health reporting script exists
            script_path = self.backend_dir / "scripts" / "daily_health_report.py"
            if not script_path.exists():
                self._add_result("health_reporting_script", "failed", "Health reporting script not found")
                return
            
            # Test script execution (dry run)
            result = subprocess.run([
                sys.executable, str(script_path), "--help"
            ], capture_output=True, text=True, cwd=self.backend_dir)
            
            if result.returncode != 0:
                self._add_result("health_reporting_script", "failed", f"Script execution failed: {result.stderr}")
                return
            
            self._add_result("health_reporting", "passed", "Health reporting integration validated")
            
        except Exception as e:
            self._add_result("health_reporting", "failed", f"Validation error: {e}")
    
    def _validate_ci_cd_workflow(self):
        """Validate CI/CD workflow configuration."""
        print("Validating CI/CD workflow configuration")
        
        try:
            # Check if CI/CD workflow exists
            workflow_path = self.backend_dir / ".github" / "workflows" / "ci-cd.yml"
            if not workflow_path.exists():
                self._add_result("cicd_workflow", "failed", "CI/CD workflow file not found")
                return
            
            # Read and validate workflow content
            with open(workflow_path, 'r') as f:
                workflow_content = f.read()
            
            # Check for Agent 3 integration points
            required_components = [
                "Run Agent 3 Security Test Suite",
                "Run Database Optimization Analysis",
                "Run Performance Tests with Locust",
                "Daily Health Monitoring",
                "Generate Daily Health Report"
            ]
            
            missing_components = []
            for component in required_components:
                if component not in workflow_content:
                    missing_components.append(component)
            
            if missing_components:
                self._add_result("cicd_workflow", "failed", f"Missing components: {missing_components}")
                return
            
            # Check for scheduled jobs
            if "schedule:" in workflow_content and "cron:" in workflow_content:
                self._add_result("cicd_schedule", "passed", "Scheduled jobs configured")
            else:
                self._add_result("cicd_schedule", "failed", "Scheduled jobs not configured")
            
            self._add_result("cicd_workflow", "passed", "CI/CD workflow integration validated")
            
        except Exception as e:
            self._add_result("cicd_workflow", "failed", f"Validation error: {e}")
    
    def _add_result(self, check_name: str, status: str, message: str):
        """Add validation result."""
        self.validation_results.append({
            "check": check_name,
            "status": status,
            "message": message
        })
        
        status_icon = "✅" if status == "passed" else "❌"
        print(f"{status_icon} {check_name}: {message}")
    
    def print_summary(self, summary: Dict[str, Any]):
        """Print validation summary."""
        print("\n" + "=" * 60)
        print("CI/CD INTEGRATION VALIDATION SUMMARY")
        print("=" * 60)
        
        print(f"📊 Total Checks: {summary['total_checks']}")
        print(f"✅ Passed: {summary['passed']}")
        print(f"❌ Failed: {summary['failed']}")
        print(f"📈 Success Rate: {summary['success_rate']:.1f}%")
        
        if summary['failed'] > 0:
            print("\n❌ FAILED CHECKS:")
            for result in summary['results']:
                if result['status'] == 'failed':
                    print(f"   • {result['check']}: {result['message']}")
        
        print("\n✅ PASSED CHECKS:")
        for result in summary['results']:
            if result['status'] == 'passed':
                print(f"   • {result['check']}: {result['message']}")
        
        if summary['success_rate'] == 100:
            print("\n🎉 All CI/CD integration checks passed!")
        else:
            print(f"\n⚠️  {summary['failed']} checks failed - please address before deployment")


def main():
    """Main function."""
    validator = CICDIntegrationValidator()
    
    try:
        summary = validator.validate_all_components()
        validator.print_summary(summary)
        
        # Save validation report
        report_path = Path("cicd_validation_report.json")
        with open(report_path, 'w') as f:
            json.dump(summary, f, indent=2)
        
        print(f"\n📁 Validation report saved to: {report_path}")
        
        # Exit with appropriate code
        if summary['failed'] > 0:
            sys.exit(1)
        else:
            sys.exit(0)
            
    except Exception as e:
        print(f"❌ Validation failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()