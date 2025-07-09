#!/usr/bin/env python3
"""
Quality gates enforcement for CI/CD pipeline
"""

import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path


class QualityGates:
    """Enforce quality standards across the codebase"""
    
    THRESHOLDS = {
        'coverage': {
            'total': 80,
            'domain': 95,
            'application': 85,
            'infrastructure': 75,
            'presentation': 70
        },
        'complexity': {
            'max_cyclomatic': 10,
            'max_cognitive': 15
        },
        'duplication': {
            'max_percentage': 5
        },
        'technical_debt': {
            'max_ratio': 0.05  # 5% of codebase
        },
        'security': {
            'max_high_severity': 0,
            'max_medium_severity': 5
        }
    }
    
    def __init__(self, project_root: Path = None):
        self.project_root = project_root or Path.cwd()
        self.reports_dir = self.project_root / "ci" / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)
    
    def check_coverage(self) -> tuple[bool, dict]:
        """Check test coverage meets thresholds"""
        try:
            # Run pytest with coverage
            cmd = [
                "python", "-m", "pytest", 
                "--cov=app", 
                "--cov-report=json",
                "--cov-report=term-missing",
                "--quiet",
                "--tb=no"
            ]
            
            result = subprocess.run(
                cmd, 
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=300, check=False
            )
            
            coverage_file = self.project_root / "coverage.json"
            
            if not coverage_file.exists():
                return False, {
                    "error": "Coverage file not generated",
                    "output": result.stdout,
                    "stderr": result.stderr
                }
            
            with open(coverage_file) as f:
                coverage_data = json.load(f)
            
            total_coverage = coverage_data.get('totals', {}).get('percent_covered', 0)
            
            # Check module-specific coverage
            failures = []
            
            # Check total coverage
            if total_coverage < self.THRESHOLDS['coverage']['total']:
                failures.append(f"Total coverage {total_coverage:.1f}% < {self.THRESHOLDS['coverage']['total']}%")
            
            # Check module coverage (if we have enough data)
            files_coverage = coverage_data.get('files', {})
            module_coverage = self._analyze_module_coverage(files_coverage)
            
            for module, coverage in module_coverage.items():
                threshold = self.THRESHOLDS['coverage'].get(module, 80)
                if coverage < threshold:
                    failures.append(f"{module} coverage {coverage:.1f}% < {threshold}%")
            
            return len(failures) == 0, {
                "total_coverage": total_coverage,
                "module_coverage": module_coverage,
                "failures": failures,
                "raw_data": coverage_data
            }
            
        except subprocess.TimeoutExpired:
            return False, {"error": "Coverage check timed out"}
        except Exception as e:
            return False, {"error": f"Coverage check failed: {e!s}"}
    
    def _analyze_module_coverage(self, files_coverage: dict) -> dict[str, float]:
        """Analyze coverage by module type"""
        module_stats = {
            'domain': {'lines': 0, 'covered': 0},
            'application': {'lines': 0, 'covered': 0},
            'infrastructure': {'lines': 0, 'covered': 0},
            'presentation': {'lines': 0, 'covered': 0}
        }
        
        for file_path, file_data in files_coverage.items():
            total_lines = file_data.get('summary', {}).get('num_statements', 0)
            covered_lines = file_data.get('summary', {}).get('covered_lines', 0)
            
            if 'domain' in file_path:
                module_stats['domain']['lines'] += total_lines
                module_stats['domain']['covered'] += covered_lines
            elif 'application' in file_path:
                module_stats['application']['lines'] += total_lines
                module_stats['application']['covered'] += covered_lines
            elif 'infrastructure' in file_path:
                module_stats['infrastructure']['lines'] += total_lines
                module_stats['infrastructure']['covered'] += covered_lines
            elif 'presentation' in file_path:
                module_stats['presentation']['lines'] += total_lines
                module_stats['presentation']['covered'] += covered_lines
        
        # Calculate coverage percentages
        module_coverage = {}
        for module, stats in module_stats.items():
            if stats['lines'] > 0:
                module_coverage[module] = (stats['covered'] / stats['lines']) * 100
            else:
                module_coverage[module] = 100  # No code = 100% coverage
        
        return module_coverage
    
    def check_code_quality(self) -> tuple[bool, dict]:
        """Check code quality with ruff"""
        try:
            # Run ruff linter
            cmd = ["python", "-m", "ruff", "check", "app", "--format", "json"]
            result = subprocess.run(
                cmd,
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=60, check=False
            )
            
            violations = []
            if result.stdout:
                try:
                    violations = json.loads(result.stdout)
                except json.JSONDecodeError:
                    # If JSON parsing fails, treat as text output
                    violations = [{"message": result.stdout}]
            
            # Check ruff formatter
            fmt_cmd = ["python", "-m", "ruff", "format", "app", "--check"]
            fmt_result = subprocess.run(
                fmt_cmd,
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=60, check=False
            )
            
            format_violations = []
            if fmt_result.returncode != 0:
                format_violations = [{"message": "Code formatting issues found"}]
            
            all_violations = violations + format_violations
            
            return len(all_violations) == 0, {
                "violations": all_violations,
                "total_violations": len(all_violations),
                "ruff_output": result.stdout,
                "format_output": fmt_result.stdout
            }
            
        except subprocess.TimeoutExpired:
            return False, {"error": "Code quality check timed out"}
        except Exception as e:
            return False, {"error": f"Code quality check failed: {e!s}"}
    
    def check_type_safety(self) -> tuple[bool, dict]:
        """Check type safety with mypy"""
        try:
            cmd = ["python", "-m", "mypy", "app", "--config-file", "mypy.ini"]
            result = subprocess.run(
                cmd,
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=120, check=False
            )
            
            # MyPy returns 0 for success, non-zero for type errors
            type_errors = []
            if result.returncode != 0:
                # Parse mypy output for errors
                lines = result.stdout.split('\n')
                for line in lines:
                    if ':' in line and ('error:' in line or 'warning:' in line):
                        type_errors.append(line.strip())
            
            return len(type_errors) == 0, {
                "type_errors": type_errors,
                "total_errors": len(type_errors),
                "mypy_output": result.stdout
            }
            
        except subprocess.TimeoutExpired:
            return False, {"error": "Type checking timed out"}
        except FileNotFoundError:
            return False, {"error": "MyPy configuration not found"}
        except Exception as e:
            return False, {"error": f"Type checking failed: {e!s}"}
    
    def check_security(self) -> tuple[bool, dict]:
        """Check security with bandit"""
        try:
            cmd = ["python", "-m", "bandit", "-r", "app", "-f", "json"]
            result = subprocess.run(
                cmd,
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=60, check=False
            )
            
            security_issues = []
            if result.stdout:
                try:
                    bandit_data = json.loads(result.stdout)
                    security_issues = bandit_data.get('results', [])
                except json.JSONDecodeError:
                    pass
            
            # Count issues by severity
            high_severity = len([i for i in security_issues if i.get('issue_severity') == 'HIGH'])
            medium_severity = len([i for i in security_issues if i.get('issue_severity') == 'MEDIUM'])
            
            security_passed = (
                high_severity <= self.THRESHOLDS['security']['max_high_severity'] and
                medium_severity <= self.THRESHOLDS['security']['max_medium_severity']
            )
            
            return security_passed, {
                "security_issues": security_issues,
                "high_severity": high_severity,
                "medium_severity": medium_severity,
                "total_issues": len(security_issues),
                "bandit_output": result.stdout
            }
            
        except subprocess.TimeoutExpired:
            return False, {"error": "Security check timed out"}
        except Exception as e:
            return False, {"error": f"Security check failed: {e!s}"}
    
    def check_dependencies(self) -> tuple[bool, dict]:
        """Check dependency security with safety"""
        try:
            cmd = ["python", "-m", "safety", "check", "--json"]
            result = subprocess.run(
                cmd,
                cwd=self.project_root,
                capture_output=True,
                text=True,
                timeout=60, check=False
            )
            
            vulnerabilities = []
            if result.stdout:
                try:
                    safety_data = json.loads(result.stdout)
                    vulnerabilities = safety_data if isinstance(safety_data, list) else []
                except json.JSONDecodeError:
                    pass
            
            # For now, we'll be permissive with dependency vulnerabilities
            # In production, you might want to be stricter
            critical_vulns = [v for v in vulnerabilities if v.get('severity', '').lower() == 'critical']
            
            return len(critical_vulns) == 0, {
                "vulnerabilities": vulnerabilities,
                "total_vulnerabilities": len(vulnerabilities),
                "critical_vulnerabilities": len(critical_vulns),
                "safety_output": result.stdout
            }
            
        except subprocess.TimeoutExpired:
            return False, {"error": "Dependency check timed out"}
        except Exception as e:
            return False, {"error": f"Dependency check failed: {e!s}"}
    
    def run_all_checks(self) -> dict:
        """Run all quality gate checks"""
        print("🔍 Running Quality Gate Checks...")
        print("=" * 50)
        
        # Run all checks
        coverage_pass, coverage_results = self.check_coverage()
        quality_pass, quality_results = self.check_code_quality()
        type_pass, type_results = self.check_type_safety()
        security_pass, security_results = self.check_security()
        deps_pass, deps_results = self.check_dependencies()
        
        # Compile overall results
        all_passed = all([coverage_pass, quality_pass, type_pass, security_pass, deps_pass])
        
        results = {
            'overall_passed': all_passed,
            'timestamp': datetime.now().isoformat(),
            'checks': {
                'coverage': {
                    'passed': coverage_pass,
                    'results': coverage_results
                },
                'code_quality': {
                    'passed': quality_pass,
                    'results': quality_results
                },
                'type_safety': {
                    'passed': type_pass,
                    'results': type_results
                },
                'security': {
                    'passed': security_pass,
                    'results': security_results
                },
                'dependencies': {
                    'passed': deps_pass,
                    'results': deps_results
                }
            }
        }
        
        # Print summary
        self._print_summary(results)
        
        # Generate reports
        self.generate_report(results)
        
        return results
    
    def _print_summary(self, results: dict) -> None:
        """Print quality gate summary"""
        checks = results['checks']
        
        print("\n📊 Quality Gate Results:")
        print("-" * 30)
        
        for check_name, check_data in checks.items():
            status = "✅ PASSED" if check_data['passed'] else "❌ FAILED"
            print(f"{check_name.replace('_', ' ').title()}: {status}")
            
            if not check_data['passed']:
                error = check_data['results'].get('error')
                if error:
                    print(f"  Error: {error}")
                
                failures = check_data['results'].get('failures', [])
                for failure in failures[:3]:  # Show first 3 failures
                    print(f"  - {failure}")
        
        overall_status = "✅ PASSED" if results['overall_passed'] else "❌ FAILED"
        print(f"\n🎯 Overall Quality Gate: {overall_status}")
        
        if not results['overall_passed']:
            print("\n💡 To pass quality gates:")
            if not checks['coverage']['passed']:
                print("  - Increase test coverage (target: 80%)")
            if not checks['code_quality']['passed']:
                print("  - Fix code quality issues with: ruff check app --fix")
            if not checks['type_safety']['passed']:
                print("  - Fix type annotations")
            if not checks['security']['passed']:
                print("  - Address security issues")
            if not checks['dependencies']['passed']:
                print("  - Update vulnerable dependencies")
    
    def generate_report(self, results: dict) -> None:
        """Generate quality gate report"""
        report_path = self.reports_dir / "quality_gates.json"
        
        with open(report_path, 'w') as f:
            json.dump(results, f, indent=2)
        
        # Generate markdown report
        md_report = self._generate_markdown_report(results)
        with open(self.reports_dir / "quality_gates.md", 'w') as f:
            f.write(md_report)
        
        print("\n📄 Reports generated:")
        print(f"  - JSON: {report_path}")
        print(f"  - Markdown: {self.reports_dir / 'quality_gates.md'}")
    
    def _generate_markdown_report(self, results: dict) -> str:
        """Generate markdown formatted report"""
        status = "✅ PASSED" if results['overall_passed'] else "❌ FAILED"
        
        report = f"""# Quality Gates Report

**Status**: {status}  
**Date**: {results['timestamp']}  
**Generated by**: Agent 0 (CI/CD Pipeline)

## Summary

| Check | Status | Details |
|-------|--------|---------|
"""
        
        for check_name, check_data in results['checks'].items():
            status_icon = "✅" if check_data['passed'] else "❌"
            check_title = check_name.replace('_', ' ').title()
            
            # Add summary details
            details = ""
            if check_name == 'coverage':
                total_cov = check_data['results'].get('total_coverage', 0)
                details = f"{total_cov:.1f}% coverage"
            elif check_name == 'code_quality':
                violations = check_data['results'].get('total_violations', 0)
                details = f"{violations} violations"
            elif check_name == 'type_safety':
                errors = check_data['results'].get('total_errors', 0)
                details = f"{errors} type errors"
            elif check_name == 'security':
                issues = check_data['results'].get('total_issues', 0)
                details = f"{issues} security issues"
            elif check_name == 'dependencies':
                vulns = check_data['results'].get('total_vulnerabilities', 0)
                details = f"{vulns} vulnerabilities"
            
            report += f"| {check_title} | {status_icon} | {details} |\n"
        
        report += f"""
## Quality Thresholds

- **Test Coverage**: {self.THRESHOLDS['coverage']['total']}% minimum
- **Code Quality**: 0 violations
- **Type Safety**: 0 type errors
- **Security**: {self.THRESHOLDS['security']['max_high_severity']} high severity issues max
- **Dependencies**: 0 critical vulnerabilities

## Actions Required

"""
        
        if not results['overall_passed']:
            report += "The following issues must be addressed:\n\n"
            
            for check_name, check_data in results['checks'].items():
                if not check_data['passed']:
                    report += f"### {check_name.replace('_', ' ').title()}\n"
                    
                    failures = check_data['results'].get('failures', [])
                    for failure in failures:
                        report += f"- {failure}\n"
                    
                    error = check_data['results'].get('error')
                    if error:
                        report += f"- Error: {error}\n"
                    
                    report += "\n"
        else:
            report += "All quality gates passed! 🎉\n"
        
        report += f"""
---
*Generated by Agent 0 CI/CD Pipeline*  
*Report Path: {self.reports_dir / 'quality_gates.md'}*
"""
        
        return report

def main():
    """Main entry point"""
    gates = QualityGates()
    results = gates.run_all_checks()
    
    # Exit with appropriate code
    sys.exit(0 if results['overall_passed'] else 1)

if __name__ == "__main__":
    main()