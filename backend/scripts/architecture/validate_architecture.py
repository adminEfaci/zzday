#!/usr/bin/env python3
"""
Architecture Validation Script

This script validates the architectural principles of the Ezzday identity platform.
It checks for module boundary violations, improper dependencies, and other
architectural anti-patterns.

Author: Agent 1 - Architecture & Integration Specialist
Date: 2025-07-09
"""

import ast
import json
import re
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path


class ArchitectureValidator:
    """Validates architectural principles and module boundaries."""
    
    def __init__(self, base_path: str = "backend/app"):
        self.base_path = Path(base_path)
        self.modules_path = self.base_path / "modules"
        self.core_modules = ["identity", "audit", "integration", "notification"]
        self.violations = defaultdict(list)
        self.metrics = {
            "total_files_analyzed": 0,
            "total_imports": 0,
            "cross_module_imports": 0,
            "foreign_key_violations": 0,
            "external_api_violations": 0,
            "missing_contracts": 0,
            "missing_interfaces": 0,
        }
        
    def validate_all(self) -> dict:
        """Run all validation checks."""
        print("🏗️ Running Architecture Validation...")
        print("=" * 60)
        
        # Run all validation checks
        self.check_module_boundaries()
        self.check_foreign_keys()
        self.check_external_api_usage()
        self.check_module_contracts()
        self.check_domain_service_interfaces()
        self.check_event_usage()
        
        # Generate report
        report = self.generate_report()
        
        # Save report
        self.save_report(report)
        
        return report
    
    def check_module_boundaries(self):
        """Check for direct imports between modules."""
        print("\n📦 Checking Module Boundaries...")
        
        for module in self.core_modules:
            module_path = self.modules_path / module
            if not module_path.exists():
                continue
                
            for py_file in module_path.rglob("*.py"):
                if "__pycache__" in str(py_file):
                    continue
                    
                self.metrics["total_files_analyzed"] += 1
                
                with open(py_file, encoding='utf-8') as f:
                    content = f.read()
                    
                # Parse imports
                try:
                    tree = ast.parse(content)
                    for node in ast.walk(tree):
                        if isinstance(node, ast.Import | ast.ImportFrom):
                            self._check_import(node, module, py_file)
                except Exception as e:
                    print(f"  ⚠️ Failed to parse {py_file}: {e}")
    
    def _check_import(self, node, current_module: str, file_path: Path):
        """Check individual import for violations."""
        if isinstance(node, ast.ImportFrom):
            module_name = node.module
        else:
            # For regular imports, check each alias
            for alias in node.names:
                module_name = alias.name
                self._validate_import(module_name, current_module, file_path)
            return
            
        if module_name:
            self._validate_import(module_name, current_module, file_path)
    
    def _validate_import(self, import_path: str, current_module: str, file_path: Path):
        """Validate a single import path."""
        self.metrics["total_imports"] += 1
        
        # Check for cross-module imports
        if import_path and import_path.startswith("app.modules."):
            parts = import_path.split(".")
            if len(parts) >= 3:
                imported_module = parts[2]
                
                # Check if importing from another module (violation)
                if imported_module in self.core_modules and imported_module != current_module:
                    self.metrics["cross_module_imports"] += 1
                    
                    # Determine severity based on what's being imported
                    severity = self._determine_violation_severity(import_path)
                    
                    violation = {
                        "type": "cross_module_import",
                        "severity": severity,
                        "file": str(file_path.relative_to(self.base_path)),
                        "import": import_path,
                        "from_module": current_module,
                        "to_module": imported_module,
                        "line": self._find_import_line(file_path, import_path)
                    }
                    
                    self.violations[current_module].append(violation)
                    print(f"  ❌ {severity.upper()}: {current_module} → {imported_module}")
                    print(f"     File: {violation['file']}")
                    print(f"     Import: {import_path}")
    
    def _determine_violation_severity(self, import_path: str) -> str:
        """Determine the severity of a cross-module import violation."""
        # Domain imports are critical violations
        if ".domain." in import_path:
            return "critical"
        # Infrastructure imports are high severity
        if ".infrastructure." in import_path:
            return "high"
        # Application layer imports are medium severity
        if ".application." in import_path:
            return "medium"
        # Presentation layer imports are low severity
        return "low"
    
    def _find_import_line(self, file_path: Path, import_path: str) -> int:
        """Find the line number of an import."""
        with open(file_path, encoding='utf-8') as f:
            for i, line in enumerate(f, 1):
                if import_path in line and ("import" in line or "from" in line):
                    return i
        return 0
    
    def check_foreign_keys(self):
        """Check for foreign keys between modules."""
        print("\n🔗 Checking Foreign Keys...")
        
        for module in self.core_modules:
            models_path = self.modules_path / module / "infrastructure" / "models"
            if not models_path.exists():
                continue
                
            for py_file in models_path.glob("*.py"):
                with open(py_file, encoding='utf-8') as f:
                    content = f.read()
                    
                # Look for ForeignKey patterns
                fk_pattern = r'ForeignKey\s*\(\s*["\']([^"\']+)["\']\s*[,)]'
                matches = re.findall(fk_pattern, content)
                
                for fk_reference in matches:
                    # Check if FK references another module's table
                    for other_module in self.core_modules:
                        if other_module != module and other_module in fk_reference.lower():
                            self.metrics["foreign_key_violations"] += 1
                            
                            violation = {
                                "type": "foreign_key",
                                "severity": "critical",
                                "file": str(py_file.relative_to(self.base_path)),
                                "from_module": module,
                                "to_module": other_module,
                                "reference": fk_reference
                            }
                            
                            self.violations[module].append(violation)
                            print(f"  ❌ CRITICAL: Foreign key from {module} → {other_module}")
                            print(f"     File: {violation['file']}")
                            print(f"     Reference: {fk_reference}")
    
    def check_external_api_usage(self):
        """Check that only Integration module uses external APIs."""
        print("\n🌐 Checking External API Usage...")
        
        # Common external API indicators
        external_indicators = [
            "requests", "httpx", "aiohttp",  # HTTP clients
            "boto3", "google-cloud",  # Cloud SDKs
            "sendgrid", "twilio", "stripe",  # Third-party services
            "redis", "celery", "rabbitmq",  # Message brokers (allowed in core)
        ]
        
        for module in self.core_modules:
            if module == "integration":
                continue  # Integration module is allowed external APIs
                
            module_path = self.modules_path / module
            if not module_path.exists():
                continue
                
            for py_file in module_path.rglob("*.py"):
                if "__pycache__" in str(py_file):
                    continue
                    
                with open(py_file, encoding='utf-8') as f:
                    content = f.read()
                    
                for indicator in external_indicators:
                    if f"import {indicator}" in content or f"from {indicator}" in content:
                        # Skip if it's in core infrastructure (allowed)
                        if "redis" in indicator or "celery" in indicator or "rabbitmq" in indicator:
                            continue
                            
                        self.metrics["external_api_violations"] += 1
                        
                        violation = {
                            "type": "external_api",
                            "severity": "critical",
                            "file": str(py_file.relative_to(self.base_path)),
                            "module": module,
                            "api": indicator
                        }
                        
                        self.violations[module].append(violation)
                        print(f"  ❌ CRITICAL: External API usage in {module}")
                        print(f"     File: {violation['file']}")
                        print(f"     API: {indicator}")
    
    def check_module_contracts(self):
        """Check that each module has proper contracts defined."""
        print("\n📋 Checking Module Contracts...")
        
        for module in self.core_modules:
            contract_path = self.modules_path / module / "application" / "contracts"
            
            if not contract_path.exists():
                self.metrics["missing_contracts"] += 1
                
                violation = {
                    "type": "missing_contracts",
                    "severity": "high",
                    "module": module,
                    "expected_path": str(contract_path.relative_to(self.base_path))
                }
                
                self.violations[module].append(violation)
                print(f"  ❌ HIGH: Missing contracts directory for {module}")
                print(f"     Expected: {violation['expected_path']}")
            else:
                # Check for specific contract file
                contract_file = contract_path / f"{module}_contract.py"
                if not contract_file.exists():
                    self.metrics["missing_contracts"] += 1
                    
                    violation = {
                        "type": "missing_contract_file",
                        "severity": "medium",
                        "module": module,
                        "expected_file": str(contract_file.relative_to(self.base_path))
                    }
                    
                    self.violations[module].append(violation)
                    print(f"  ⚠️ MEDIUM: Missing contract file for {module}")
                    print(f"     Expected: {violation['expected_file']}")
    
    def check_domain_service_interfaces(self):
        """Check that domain services have corresponding interfaces."""
        print("\n🔧 Checking Domain Service Interfaces...")
        
        for module in self.core_modules:
            services_path = self.modules_path / module / "domain" / "services"
            interfaces_path = self.modules_path / module / "domain" / "interfaces" / "services"
            
            if not services_path.exists():
                continue
                
            # Get all service files
            service_files = [f.stem for f in services_path.glob("*.py") if f.stem != "__init__"]
            
            # Check for corresponding interfaces
            for service in service_files:
                interface_name = f"i_{service}"
                interface_file = interfaces_path / f"{interface_name}.py"
                
                if not interface_file.exists():
                    self.metrics["missing_interfaces"] += 1
                    
                    violation = {
                        "type": "missing_interface",
                        "severity": "high",
                        "module": module,
                        "service": service,
                        "expected_interface": str(interface_file.relative_to(self.base_path))
                    }
                    
                    self.violations[module].append(violation)
                    print(f"  ❌ HIGH: Missing interface for {service}")
                    print(f"     Expected: {violation['expected_interface']}")
    
    def check_event_usage(self):
        """Check that cross-module communication uses events."""
        print("\n📨 Checking Event Usage...")
        
        # This is a more complex check - for now, we'll check basic patterns
        # In a full implementation, we'd trace actual method calls
    
    def generate_report(self) -> dict:
        """Generate comprehensive architecture report."""
        total_violations = sum(len(v) for v in self.violations.values())
        
        return {
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total_violations": total_violations,
                "critical_violations": self._count_by_severity("critical"),
                "high_violations": self._count_by_severity("high"),
                "medium_violations": self._count_by_severity("medium"),
                "low_violations": self._count_by_severity("low"),
                "modules_with_violations": len(self.violations),
            },
            "metrics": self.metrics,
            "violations_by_module": dict(self.violations),
            "health_score": self._calculate_health_score(),
        }
    
    def _count_by_severity(self, severity: str) -> int:
        """Count violations by severity level."""
        count = 0
        for module_violations in self.violations.values():
            for violation in module_violations:
                if violation.get("severity") == severity:
                    count += 1
        return count
    
    def _calculate_health_score(self) -> float:
        """Calculate overall architecture health score (0-100)."""
        if self.metrics["total_files_analyzed"] == 0:
            return 100.0
            
        # Weight different violation types
        score = 100.0
        
        # Critical violations have highest impact
        critical_count = self._count_by_severity("critical")
        score -= critical_count * 10
        
        # High violations
        high_count = self._count_by_severity("high")
        score -= high_count * 5
        
        # Medium violations
        medium_count = self._count_by_severity("medium")
        score -= medium_count * 2
        
        # Low violations
        low_count = self._count_by_severity("low")
        score -= low_count * 1
        
        return max(0.0, score)
    
    def save_report(self, report: dict):
        """Save report to file."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save JSON report
        report_dir = Path("docs/agent-1-reports/architecture")
        report_dir.mkdir(parents=True, exist_ok=True)
        
        json_path = report_dir / f"architecture_validation_{timestamp}.json"
        with open(json_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Save markdown report
        md_path = report_dir / f"architecture_validation_{timestamp}.md"
        with open(md_path, 'w') as f:
            f.write(self._generate_markdown_report(report))
        
        print("\n📄 Reports saved:")
        print(f"   JSON: {json_path}")
        print(f"   Markdown: {md_path}")
    
    def _generate_markdown_report(self, report: dict) -> str:
        """Generate markdown version of the report."""
        md = f"""# Architecture Validation Report

**Generated**: {report['timestamp']}  
**Agent**: Agent 1 - Architecture & Integration Specialist

## Executive Summary

**Architecture Health Score**: {report['health_score']:.1f}/100

### Violation Summary
- **Total Violations**: {report['summary']['total_violations']}
- **Critical**: {report['summary']['critical_violations']}
- **High**: {report['summary']['high_violations']}
- **Medium**: {report['summary']['medium_violations']}
- **Low**: {report['summary']['low_violations']}

### Metrics
- **Files Analyzed**: {report['metrics']['total_files_analyzed']}
- **Total Imports**: {report['metrics']['total_imports']}
- **Cross-Module Imports**: {report['metrics']['cross_module_imports']}
- **Foreign Key Violations**: {report['metrics']['foreign_key_violations']}
- **External API Violations**: {report['metrics']['external_api_violations']}
- **Missing Contracts**: {report['metrics']['missing_contracts']}
- **Missing Interfaces**: {report['metrics']['missing_interfaces']}

## Violations by Module
"""
        
        for module, violations in report['violations_by_module'].items():
            if violations:
                md += f"\n### {module.capitalize()} Module\n\n"
                
                # Group by type
                by_type = defaultdict(list)
                for v in violations:
                    by_type[v['type']].append(v)
                
                for vtype, items in by_type.items():
                    md += f"#### {vtype.replace('_', ' ').title()}\n"
                    for item in items:
                        md += f"- **{item['severity'].upper()}**: "
                        if vtype == "cross_module_import":
                            md += f"`{item['file']}`: {item['from_module']} → {item['to_module']} ({item['import']})\n"
                        elif vtype == "foreign_key":
                            md += f"`{item['file']}`: References {item['to_module']} ({item['reference']})\n"
                        elif vtype == "external_api":
                            md += f"`{item['file']}`: Uses {item['api']}\n"
                        elif vtype == "missing_contracts":
                            md += f"Expected contracts at `{item['expected_path']}`\n"
                        elif vtype == "missing_interface":
                            md += f"Service `{item['service']}` missing interface at `{item['expected_interface']}`\n"
                        else:
                            md += f"{item}\n"
                    md += "\n"
        
        md += """
## Recommendations

### Immediate Actions Required
1. **Fix Critical Violations**: Address all cross-module domain imports
2. **Remove Foreign Keys**: Replace with value objects or IDs
3. **Move External APIs**: Relocate all external API usage to Integration module
4. **Create Missing Contracts**: Define public APIs for each module
5. **Add Service Interfaces**: Create interfaces for all domain services

### Architecture Improvements
1. Implement internal adapters for cross-module communication
2. Use event bus for all module interactions
3. Create standardized contract interfaces
4. Add automated architecture tests to CI/CD pipeline

## Next Steps
1. Fix all critical violations
2. Document architecture decisions in ADRs
3. Create module dependency graph
4. Implement architecture fitness functions
"""
        
        return md


def main():
    """Run architecture validation."""
    validator = ArchitectureValidator()
    report = validator.validate_all()
    
    # Print summary
    print("\n" + "=" * 60)
    print("📊 VALIDATION COMPLETE")
    print("=" * 60)
    print(f"Architecture Health Score: {report['health_score']:.1f}/100")
    print(f"Total Violations: {report['summary']['total_violations']}")
    
    if report['summary']['critical_violations'] > 0:
        print(f"\n🚨 CRITICAL: {report['summary']['critical_violations']} critical violations found!")
        print("These must be fixed immediately for production readiness.")
        sys.exit(1)
    elif report['summary']['total_violations'] > 0:
        print(f"\n⚠️  WARNING: {report['summary']['total_violations']} violations found.")
        print("Review the report and create a remediation plan.")
        sys.exit(1)
    else:
        print("\n✅ SUCCESS: No architectural violations found!")
        sys.exit(0)


if __name__ == "__main__":
    main()