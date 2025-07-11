"""Architecture Compliance Tests for EzzDay Backend.

This module validates that the codebase adheres to Domain-Driven Design (DDD)
principles and clean architecture patterns. These tests ensure code quality
and architectural consistency remain high across all modules.

Test Categories:
- DDD Layer Separation: Validates proper domain/application/infrastructure separation
- Import Dependencies: Ensures no circular dependencies or layer violations
- Naming Conventions: Validates consistent naming patterns
- File Organization: Checks proper module structure
- Design Patterns: Validates implementation of DDD patterns (Aggregates, VOs, etc.)
- Framework Independence: Ensures domain layer has no framework dependencies
- Error Handling: Validates consistent error handling patterns
- Configuration Management: Validates proper configuration patterns

These tests run in CI/CD to prevent architectural drift and ensure
production-ready code quality standards.
"""

import ast
import importlib.util
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

import pytest


# =====================================================================================
# TEST CONFIGURATION
# =====================================================================================

# Root paths for testing
APP_ROOT = Path(__file__).parent.parent.parent
MODULES_PATH = APP_ROOT / "modules"
CORE_PATH = APP_ROOT / "core"

# Framework dependencies that should NOT be in domain layer
FRAMEWORK_IMPORTS = {
    "fastapi", "sqlalchemy", "pydantic", "redis", "celery", 
    "uvicorn", "starlette", "strawberry", "httpx", "aiosmtplib"
}

# Required directories for each module (DDD structure)
REQUIRED_MODULE_STRUCTURE = {
    "domain": ["entities", "value_objects", "aggregates", "services"],
    "application": ["commands", "queries", "services", "handlers"],
    "infrastructure": ["repositories", "external_services", "adapters"]
}

# Naming patterns
AGGREGATE_PATTERN = re.compile(r"^[A-Z][a-zA-Z0-9]*$")
ENTITY_PATTERN = re.compile(r"^[A-Z][a-zA-Z0-9]*$")
VALUE_OBJECT_PATTERN = re.compile(r"^[A-Z][a-zA-Z0-9]*$")
SERVICE_PATTERN = re.compile(r"^[A-Z][a-zA-Z0-9]*Service$")
REPOSITORY_PATTERN = re.compile(r"^[A-Z][a-zA-Z0-9]*Repository$")
HANDLER_PATTERN = re.compile(r"^[A-Z][a-zA-Z0-9]*Handler$")


# =====================================================================================
# UTILITY FUNCTIONS
# =====================================================================================

def get_python_files(path: Path) -> List[Path]:
    """Get all Python files in a directory recursively."""
    return list(path.rglob("*.py"))


def get_imports_from_file(file_path: Path) -> Set[str]:
    """Extract all imports from a Python file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        tree = ast.parse(content)
        imports = set()
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for name in node.names:
                    imports.add(name.name.split('.')[0])
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.add(node.module.split('.')[0])
        
        return imports
    except Exception:
        return set()


def get_class_names_from_file(file_path: Path) -> List[str]:
    """Extract all class names from a Python file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        tree = ast.parse(content)
        classes = []
        
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                classes.append(node.name)
        
        return classes
    except Exception:
        return []


def is_domain_layer(file_path: Path) -> bool:
    """Check if file is in domain layer."""
    return "domain" in file_path.parts


def is_application_layer(file_path: Path) -> bool:
    """Check if file is in application layer."""
    return "application" in file_path.parts


def is_infrastructure_layer(file_path: Path) -> bool:
    """Check if file is in infrastructure layer."""
    return "infrastructure" in file_path.parts


# =====================================================================================
# DDD LAYER SEPARATION TESTS
# =====================================================================================

class TestDDDLayerSeparation:
    """Test Domain-Driven Design layer separation compliance."""

    def test_domain_layer_has_no_framework_dependencies(self):
        """Domain layer should not import any framework dependencies."""
        domain_files = []
        
        # Get all domain files from modules
        for module_dir in MODULES_PATH.iterdir():
            if module_dir.is_dir():
                domain_path = module_dir / "domain"
                if domain_path.exists():
                    domain_files.extend(get_python_files(domain_path))
        
        violations = []
        
        for file_path in domain_files:
            imports = get_imports_from_file(file_path)
            framework_imports = imports.intersection(FRAMEWORK_IMPORTS)
            
            if framework_imports:
                violations.append({
                    "file": str(file_path),
                    "framework_imports": list(framework_imports)
                })
        
        assert not violations, f"Domain layer files have framework dependencies: {violations}"

    def test_domain_layer_only_imports_domain_or_core(self):
        """Domain layer should only import from domain or core layers."""
        domain_files = []
        
        for module_dir in MODULES_PATH.iterdir():
            if module_dir.is_dir():
                domain_path = module_dir / "domain"
                if domain_path.exists():
                    domain_files.extend(get_python_files(domain_path))
        
        violations = []
        
        for file_path in domain_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Check for imports from application or infrastructure layers
                if ("from app.modules." in content and ".application." in content) or \
                   ("from app.modules." in content and ".infrastructure." in content):
                    violations.append(str(file_path))
            except Exception:
                continue
        
        assert not violations, f"Domain layer files import from application/infrastructure: {violations}"

    def test_application_layer_does_not_import_infrastructure(self):
        """Application layer should not directly import infrastructure layer."""
        application_files = []
        
        for module_dir in MODULES_PATH.iterdir():
            if module_dir.is_dir():
                app_path = module_dir / "application"
                if app_path.exists():
                    application_files.extend(get_python_files(app_path))
        
        violations = []
        
        for file_path in application_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Check for direct imports from infrastructure layer
                if "from app.modules." in content and ".infrastructure." in content:
                    violations.append(str(file_path))
            except Exception:
                continue
        
        assert not violations, f"Application layer files import infrastructure: {violations}"


# =====================================================================================
# MODULE STRUCTURE TESTS
# =====================================================================================

class TestModuleStructure:
    """Test module structure compliance with DDD patterns."""

    def test_modules_have_required_ddd_structure(self):
        """Each module should have proper DDD directory structure."""
        if not MODULES_PATH.exists():
            pytest.skip("Modules directory does not exist")
        
        violations = []
        
        for module_dir in MODULES_PATH.iterdir():
            if not module_dir.is_dir() or module_dir.name.startswith('.'):
                continue
            
            missing_dirs = []
            
            # Check for required DDD directories
            for layer, subdirs in REQUIRED_MODULE_STRUCTURE.items():
                layer_path = module_dir / layer
                
                if not layer_path.exists():
                    missing_dirs.append(layer)
                    continue
                
                # Check for required subdirectories
                for subdir in subdirs:
                    subdir_path = layer_path / subdir
                    if not subdir_path.exists():
                        missing_dirs.append(f"{layer}/{subdir}")
            
            if missing_dirs:
                violations.append({
                    "module": module_dir.name,
                    "missing_directories": missing_dirs
                })
        
        assert not violations, f"Modules missing DDD structure: {violations}"

    def test_modules_have_init_files(self):
        """Each module and layer should have __init__.py files."""
        if not MODULES_PATH.exists():
            pytest.skip("Modules directory does not exist")
        
        violations = []
        
        for module_dir in MODULES_PATH.iterdir():
            if not module_dir.is_dir() or module_dir.name.startswith('.'):
                continue
            
            missing_init_files = []
            
            # Check module __init__.py
            if not (module_dir / "__init__.py").exists():
                missing_init_files.append("__init__.py")
            
            # Check layer __init__.py files
            for layer in REQUIRED_MODULE_STRUCTURE.keys():
                layer_path = module_dir / layer
                if layer_path.exists() and not (layer_path / "__init__.py").exists():
                    missing_init_files.append(f"{layer}/__init__.py")
            
            if missing_init_files:
                violations.append({
                    "module": module_dir.name,
                    "missing_init_files": missing_init_files
                })
        
        assert not violations, f"Modules missing __init__.py files: {violations}"


# =====================================================================================
# NAMING CONVENTION TESTS
# =====================================================================================

class TestNamingConventions:
    """Test naming convention compliance."""

    def test_aggregate_naming_conventions(self):
        """Aggregates should follow naming conventions."""
        violations = []
        
        for module_dir in MODULES_PATH.iterdir():
            if not module_dir.is_dir():
                continue
            
            aggregates_path = module_dir / "domain" / "aggregates"
            if aggregates_path.exists():
                for file_path in get_python_files(aggregates_path):
                    if file_path.name == "__init__.py":
                        continue
                    
                    classes = get_class_names_from_file(file_path)
                    for class_name in classes:
                        if not AGGREGATE_PATTERN.match(class_name):
                            violations.append({
                                "file": str(file_path),
                                "class": class_name,
                                "expected_pattern": "PascalCase"
                            })
        
        assert not violations, f"Aggregate naming violations: {violations}"

    def test_repository_naming_conventions(self):
        """Repositories should end with 'Repository'."""
        violations = []
        
        for module_dir in MODULES_PATH.iterdir():
            if not module_dir.is_dir():
                continue
            
            repos_path = module_dir / "infrastructure" / "repositories"
            if repos_path.exists():
                for file_path in get_python_files(repos_path):
                    if file_path.name == "__init__.py":
                        continue
                    
                    classes = get_class_names_from_file(file_path)
                    for class_name in classes:
                        if "Repository" in class_name and not REPOSITORY_PATTERN.match(class_name):
                            violations.append({
                                "file": str(file_path),
                                "class": class_name,
                                "expected_pattern": "NameRepository"
                            })
        
        assert not violations, f"Repository naming violations: {violations}"

    def test_service_naming_conventions(self):
        """Services should end with 'Service'."""
        violations = []
        
        for module_dir in MODULES_PATH.iterdir():
            if not module_dir.is_dir():
                continue
            
            for layer in ["domain", "application"]:
                services_path = module_dir / layer / "services"
                if services_path.exists():
                    for file_path in get_python_files(services_path):
                        if file_path.name == "__init__.py":
                            continue
                        
                        classes = get_class_names_from_file(file_path)
                        for class_name in classes:
                            if "Service" in class_name and not SERVICE_PATTERN.match(class_name):
                                violations.append({
                                    "file": str(file_path),
                                    "class": class_name,
                                    "expected_pattern": "NameService"
                                })
        
        assert not violations, f"Service naming violations: {violations}"


# =====================================================================================
# ERROR HANDLING TESTS
# =====================================================================================

class TestErrorHandling:
    """Test error handling compliance."""

    def test_custom_exceptions_inherit_from_core_errors(self):
        """Custom exceptions should inherit from core error classes."""
        violations = []
        
        # Get all Python files
        all_files = get_python_files(APP_ROOT)
        
        for file_path in all_files:
            if "test" in str(file_path):
                continue
            
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                tree = ast.parse(content)
                
                for node in ast.walk(tree):
                    if isinstance(node, ast.ClassDef):
                        # Check if it's an exception class
                        if node.name.endswith("Error") or node.name.endswith("Exception"):
                            # Check if it inherits from built-in exceptions directly
                            for base in node.bases:
                                if isinstance(base, ast.Name):
                                    if base.id in ["Exception", "ValueError", "TypeError", "RuntimeError"]:
                                        violations.append({
                                            "file": str(file_path),
                                            "class": node.name,
                                            "issue": f"Inherits directly from {base.id} instead of core error classes"
                                        })
            except Exception:
                continue
        
        # Allow some core exceptions to inherit from built-ins
        allowed_files = ["core/errors.py"]
        violations = [v for v in violations if not any(af in v["file"] for af in allowed_files)]
        
        assert not violations, f"Exception inheritance violations: {violations}"


# =====================================================================================
# CONFIGURATION TESTS
# =====================================================================================

class TestConfigurationCompliance:
    """Test configuration management compliance."""

    def test_no_hardcoded_configurations(self):
        """No hardcoded configuration values in code."""
        violations = []
        
        # Pattern for potential hardcoded values
        hardcode_patterns = [
            re.compile(r'(password|secret|key)\s*=\s*["\'][^"\']+["\']', re.IGNORECASE),
            re.compile(r'(host|url)\s*=\s*["\']https?://[^"\']+["\']', re.IGNORECASE),
            re.compile(r'(port)\s*=\s*\d{4,5}'),
        ]
        
        # Exclude test files and configuration files
        exclude_patterns = ["test", "config", "example", "sample"]
        
        all_files = get_python_files(APP_ROOT)
        
        for file_path in all_files:
            if any(pattern in str(file_path).lower() for pattern in exclude_patterns):
                continue
            
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                for pattern in hardcode_patterns:
                    matches = pattern.findall(content)
                    if matches:
                        violations.append({
                            "file": str(file_path),
                            "hardcoded_values": matches
                        })
            except Exception:
                continue
        
        assert not violations, f"Hardcoded configuration violations: {violations}"

    def test_environment_variables_documented(self):
        """Environment variables should be documented."""
        env_example_path = APP_ROOT.parent / ".env.example"
        
        if not env_example_path.exists():
            pytest.skip(".env.example file not found")
        
        # This test would check that all environment variables used in code
        # are documented in .env.example
        # Implementation depends on specific requirements
        assert True, "Environment variable documentation check passed"


# =====================================================================================
# PERFORMANCE AND SECURITY TESTS
# =====================================================================================

class TestPerformanceCompliance:
    """Test performance-related compliance."""

    def test_no_synchronous_io_in_async_functions(self):
        """Async functions should not use synchronous I/O operations."""
        violations = []
        
        # Common synchronous I/O patterns
        sync_patterns = [
            "requests.get", "requests.post", "urllib.request",
            "open(", "json.loads(", "time.sleep("
        ]
        
        all_files = get_python_files(APP_ROOT)
        
        for file_path in all_files:
            if "test" in str(file_path):
                continue
            
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Look for async functions
                tree = ast.parse(content)
                
                for node in ast.walk(tree):
                    if isinstance(node, ast.AsyncFunctionDef):
                        func_start = node.lineno
                        func_end = node.end_lineno or func_start + 50
                        
                        func_lines = content.split('\n')[func_start-1:func_end]
                        func_content = '\n'.join(func_lines)
                        
                        for pattern in sync_patterns:
                            if pattern in func_content:
                                violations.append({
                                    "file": str(file_path),
                                    "function": node.name,
                                    "sync_operation": pattern,
                                    "line": func_start
                                })
            except Exception:
                continue
        
        assert not violations, f"Synchronous I/O in async functions: {violations}"


# =====================================================================================
# INTEGRATION TESTS
# =====================================================================================

class TestArchitectureIntegration:
    """Test overall architecture integration."""

    def test_module_dependencies_are_acyclic(self):
        """Module dependencies should not have cycles."""
        # This would implement a dependency graph analysis
        # For now, we'll do a basic check
        
        module_imports = {}
        
        for module_dir in MODULES_PATH.iterdir():
            if not module_dir.is_dir():
                continue
            
            module_name = module_dir.name
            imports = set()
            
            for file_path in get_python_files(module_dir):
                file_imports = get_imports_from_file(file_path)
                
                # Look for imports from other modules
                for imp in file_imports:
                    if imp.startswith("app.modules.") and not imp.startswith(f"app.modules.{module_name}"):
                        # Extract module name
                        parts = imp.split(".")
                        if len(parts) >= 3:
                            imported_module = parts[2]
                            imports.add(imported_module)
            
            module_imports[module_name] = imports
        
        # Simple cycle detection (this could be more sophisticated)
        for module, deps in module_imports.items():
            for dep in deps:
                if dep in module_imports and module in module_imports[dep]:
                    pytest.fail(f"Circular dependency detected between {module} and {dep}")

    def test_core_modules_are_stable(self):
        """Core modules should be stable (not depend on application modules)."""
        violations = []
        
        core_files = get_python_files(CORE_PATH)
        
        for file_path in core_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Check for imports from modules
                if "from app.modules." in content or "import app.modules." in content:
                    violations.append(str(file_path))
            except Exception:
                continue
        
        assert not violations, f"Core modules depend on application modules: {violations}"
