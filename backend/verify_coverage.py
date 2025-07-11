#!/usr/bin/env python3
"""
Interface Coverage Verification Script

Verifies that all domain services have corresponding interfaces and that 
service implementations properly use dependency injection with Protocol interfaces.
"""

import ast
import os
import re
from pathlib import Path
from typing import Dict, List, Set, Tuple


class InterfaceCoverageVerifier:
    """Verifies interface coverage and proper implementation patterns."""
    
    def __init__(self, root_path: str):
        self.root_path = Path(root_path)
        self.interfaces: Dict[str, Path] = {}
        self.services: Dict[str, Path] = {}
        self.interface_usage: Dict[str, List[str]] = {}
        self.missing_interfaces: List[str] = []
        self.unused_interfaces: List[str] = []
        self.verification_results = {}
        
    def find_all_interfaces(self) -> Dict[str, Path]:
        """Find all Protocol interfaces in domain/interfaces/services/."""
        interfaces = {}
        modules_path = self.root_path / "app" / "modules"
        
        for module_dir in modules_path.iterdir():
            if module_dir.is_dir() and module_dir.name not in ["__pycache__"]:
                services_path = module_dir / "domain" / "interfaces" / "services"
                if services_path.exists():
                    for py_file in services_path.rglob("*.py"):
                        if py_file.name != "__init__.py":
                            interface_name = self._extract_interface_name(py_file)
                            if interface_name:
                                interfaces[interface_name] = py_file
        
        self.interfaces = interfaces
        return interfaces
    
    def find_all_services(self) -> Dict[str, Path]:
        """Find all domain service implementations."""
        services = {}
        modules_path = self.root_path / "app" / "modules"
        
        # Domain services
        for module_dir in modules_path.iterdir():
            if module_dir.is_dir() and module_dir.name not in ["__pycache__"]:
                domain_services_path = module_dir / "domain" / "services"
                if domain_services_path.exists():
                    for py_file in domain_services_path.rglob("*.py"):
                        if py_file.name != "__init__.py":
                            service_name = self._extract_service_name(py_file)
                            if service_name:
                                services[f"domain.{service_name}"] = py_file
                
                # Application services
                app_services_path = module_dir / "application" / "services"
                if app_services_path.exists():
                    for py_file in app_services_path.rglob("*.py"):
                        if py_file.name != "__init__.py":
                            service_name = self._extract_service_name(py_file)
                            if service_name:
                                services[f"application.{service_name}"] = py_file
                
                # Infrastructure services
                infra_services_path = module_dir / "infrastructure" / "services"
                if infra_services_path.exists():
                    for py_file in infra_services_path.rglob("*.py"):
                        if py_file.name != "__init__.py":
                            service_name = self._extract_service_name(py_file)
                            if service_name:
                                services[f"infrastructure.{service_name}"] = py_file
        
        self.services = services
        return services
    
    def _extract_interface_name(self, file_path: Path) -> str | None:
        """Extract interface name from file."""
        try:
            content = file_path.read_text()
            # Look for class I...Service(Protocol):
            match = re.search(r'class (I\w+(?:Service|Port))\(Protocol\):', content)
            if match:
                return match.group(1)
        except Exception:
            pass
        return None
    
    def _extract_service_name(self, file_path: Path) -> str | None:
        """Extract service class name from file."""
        try:
            content = file_path.read_text()
            # Look for class ...Service:
            match = re.search(r'class (\w+Service)(?:\([^)]*\))?:', content)
            if match:
                return match.group(1)
        except Exception:
            pass
        return None
    
    def analyze_interface_usage(self) -> Dict[str, List[str]]:
        """Analyze which services use which interfaces."""
        usage = {}
        
        # Check all Python files for interface imports
        modules_path = self.root_path / "app" / "modules"
        
        for module_dir in modules_path.iterdir():
            if module_dir.is_dir() and module_dir.name not in ["__pycache__"]:
                for py_file in module_dir.rglob("*.py"):
                    if py_file.name != "__init__.py":
                        try:
                            content = py_file.read_text()
                            # Find interface imports
                            interface_imports = re.findall(
                                r'from.*interfaces.*import.*?(I\w+(?:Service|Port))',
                                content
                            )
                            
                            for interface_name in interface_imports:
                                if interface_name not in usage:
                                    usage[interface_name] = []
                                relative_path = str(py_file.relative_to(self.root_path))
                                usage[interface_name].append(relative_path)
                                
                        except Exception:
                            pass
        
        self.interface_usage = usage
        return usage
    
    def verify_service_interface_pairs(self) -> Dict[str, any]:
        """Verify that each service has a corresponding interface."""
        missing_interfaces = []
        extra_interfaces = []
        
        # Expected interface names based on services
        expected_interfaces = set()
        for service_name in self.services.keys():
            # Extract base name and create expected interface name
            base_name = service_name.split('.')[-1]  # Get just the service name
            if base_name.endswith('Service'):
                interface_name = f"I{base_name}"
                expected_interfaces.add(interface_name)
        
        # Find missing interfaces
        actual_interfaces = set(self.interfaces.keys())
        missing = expected_interfaces - actual_interfaces
        unused = actual_interfaces - expected_interfaces
        
        # Check if services that should have interfaces actually use them
        for service_name, service_path in self.services.items():
            base_name = service_name.split('.')[-1]
            expected_interface = f"I{base_name}"
            
            if expected_interface in actual_interfaces:
                # Check if the service file imports this interface
                if not self._service_uses_interface(service_path, expected_interface):
                    missing_interfaces.append({
                        'service': service_name,
                        'expected_interface': expected_interface,
                        'issue': 'Service exists but does not import/use its interface'
                    })
        
        return {
            'expected_interfaces': list(expected_interfaces),
            'actual_interfaces': list(actual_interfaces),
            'missing_interfaces': list(missing),
            'unused_interfaces': list(unused),
            'service_interface_mismatches': missing_interfaces
        }
    
    def _service_uses_interface(self, service_path: Path, interface_name: str) -> bool:
        """Check if a service file imports and uses its interface."""
        try:
            content = service_path.read_text()
            # Check for interface import
            import_pattern = rf'from.*interfaces.*import.*{interface_name}'
            return bool(re.search(import_pattern, content))
        except Exception:
            return False
    
    def check_protocol_compliance(self) -> Dict[str, any]:
        """Verify all interfaces are Protocol-based."""
        abc_interfaces = []
        protocol_interfaces = []
        
        for interface_name, interface_path in self.interfaces.items():
            try:
                content = interface_path.read_text()
                if "from abc import" in content or "(ABC)" in content:
                    abc_interfaces.append(interface_name)
                elif "Protocol" in content and "(Protocol)" in content:
                    protocol_interfaces.append(interface_name)
            except Exception:
                pass
        
        return {
            'total_interfaces': len(self.interfaces),
            'protocol_interfaces': protocol_interfaces,
            'abc_interfaces': abc_interfaces,
            'protocol_compliance': len(abc_interfaces) == 0
        }
    
    def generate_coverage_report(self) -> Dict[str, any]:
        """Generate comprehensive coverage report."""
        print("🔍 Analyzing interface coverage...")
        
        # Find all interfaces and services
        self.find_all_interfaces()
        self.find_all_services()
        self.analyze_interface_usage()
        
        # Run verification checks
        service_interface_verification = self.verify_service_interface_pairs()
        protocol_compliance = self.check_protocol_compliance()
        
        report = {
            'summary': {
                'total_interfaces': len(self.interfaces),
                'total_services': len(self.services),
                'interfaces_used': len(self.interface_usage),
                'protocol_compliance': protocol_compliance['protocol_compliance']
            },
            'interfaces': list(self.interfaces.keys()),
            'services': list(self.services.keys()),
            'interface_usage': self.interface_usage,
            'service_interface_verification': service_interface_verification,
            'protocol_compliance': protocol_compliance
        }
        
        self.verification_results = report
        return report
    
    def print_detailed_report(self):
        """Print a detailed verification report."""
        if not self.verification_results:
            self.generate_coverage_report()
        
        report = self.verification_results
        
        print("\n" + "="*80)
        print("🔍 INTERFACE COVERAGE VERIFICATION REPORT")
        print("="*80)
        
        # Summary
        summary = report['summary']
        print(f"\n📊 SUMMARY:")
        print(f"   Total Interfaces: {summary['total_interfaces']}")
        print(f"   Total Services: {summary['total_services']}")
        print(f"   Interfaces Used: {summary['interfaces_used']}")
        print(f"   Protocol Compliance: {'✅' if summary['protocol_compliance'] else '❌'}")
        
        # Protocol compliance
        protocol_info = report['protocol_compliance']
        print(f"\n🔧 PROTOCOL COMPLIANCE:")
        print(f"   Protocol Interfaces: {len(protocol_info['protocol_interfaces'])}")
        print(f"   ABC Interfaces: {len(protocol_info['abc_interfaces'])}")
        
        if protocol_info['abc_interfaces']:
            print(f"   ❌ Remaining ABC interfaces:")
            for abc_interface in protocol_info['abc_interfaces']:
                print(f"      - {abc_interface}")
        else:
            print(f"   ✅ All interfaces are Protocol-based!")
        
        # Interface usage
        print(f"\n📈 INTERFACE USAGE:")
        if report['interface_usage']:
            for interface, usage_files in report['interface_usage'].items():
                print(f"   {interface}: {len(usage_files)} files")
                for file_path in usage_files[:3]:  # Show first 3
                    print(f"      - {file_path}")
                if len(usage_files) > 3:
                    print(f"      ... and {len(usage_files) - 3} more")
        
        # Service-interface verification
        verification = report['service_interface_verification']
        print(f"\n🔍 SERVICE-INTERFACE VERIFICATION:")
        print(f"   Expected Interfaces: {len(verification['expected_interfaces'])}")
        print(f"   Actual Interfaces: {len(verification['actual_interfaces'])}")
        print(f"   Missing Interfaces: {len(verification['missing_interfaces'])}")
        print(f"   Unused Interfaces: {len(verification['unused_interfaces'])}")
        
        if verification['missing_interfaces']:
            print(f"\n   ❌ Missing Interfaces:")
            for missing in verification['missing_interfaces']:
                print(f"      - {missing}")
        
        if verification['unused_interfaces']:
            print(f"\n   ⚠️  Unused Interfaces:")
            for unused in verification['unused_interfaces']:
                print(f"      - {unused}")
        
        if verification['service_interface_mismatches']:
            print(f"\n   ⚠️  Service-Interface Mismatches:")
            for mismatch in verification['service_interface_mismatches']:
                print(f"      - {mismatch['service']}: {mismatch['issue']}")
        
        # Overall assessment
        print(f"\n🎯 OVERALL ASSESSMENT:")
        if (summary['protocol_compliance'] and 
            len(verification['missing_interfaces']) == 0 and
            len(verification['service_interface_mismatches']) == 0):
            print("   ✅ EXCELLENT: All interfaces are Protocol-based with proper coverage!")
        elif summary['protocol_compliance']:
            print("   ✅ GOOD: All interfaces are Protocol-based")
            if verification['missing_interfaces'] or verification['service_interface_mismatches']:
                print("   ⚠️  Some service-interface coverage issues detected")
        else:
            print("   ❌ NEEDS WORK: Protocol conversion incomplete")
        
        print("\n" + "="*80)


def main():
    """Main verification function."""
    root_path = "/Users/neuro/workspace2/app-codebase/ezzday/backend"
    
    print("🔧 Interface Coverage Verification")
    print("=" * 50)
    print(f"📂 Root path: {root_path}")
    
    verifier = InterfaceCoverageVerifier(root_path)
    verifier.print_detailed_report()
    
    return verifier.verification_results


if __name__ == "__main__":
    main()
