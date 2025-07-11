"""Simplified Architecture Compliance Tests for EzzDay Backend.

This module validates that the codebase adheres to Domain-Driven Design (DDD)
principles and clean architecture patterns without requiring full app loading.

These tests focus on static analysis of the codebase structure and imports.
"""

import ast
import os
import re
from pathlib import Path
from typing import List, Set

import pytest


# =====================================================================================
# TEST CONFIGURATION
# =====================================================================================

# Root paths for testing
APP_ROOT = Path(__file__).parent.parent / "app"
MODULES_PATH = APP_ROOT / "modules"
CORE_PATH = APP_ROOT / "core"

# Framework dependencies that should NOT be in domain layer
FRAMEWORK_IMPORTS = {
    "fastapi", "sqlalchemy", "pydantic", "redis", "celery", 
    "uvicorn", "starlette", "strawberry", "httpx", "aiosmtplib"
}


# =====================================================================================
# UTILITY FUNCTIONS
# =====================================================================================

def get_python_files(path: Path) -> List[Path]:
    """Get all Python files in a directory recursively."""
    if not path.exists():
        return []
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


# =====================================================================================
# CORE ARCHITECTURE TESTS
# =====================================================================================

class TestCoreArchitecture:
    """Test core architecture principles."""

    def test_core_files_exist_and_are_valid(self):
        """Test that core infrastructure files exist and are valid Python."""
        required_core_files = [
            "errors.py",
            "config.py", 
            "database.py",
            "logging.py"
        ]
        
        missing_files = []
        invalid_files = []
        
        for file_name in required_core_files:
            file_path = CORE_PATH / file_name
            
            if not file_path.exists():
                missing_files.append(file_name)
                continue
            
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                ast.parse(content)
            except Exception as e:
                invalid_files.append(f"{file_name}: {str(e)}")
        
        assert not missing_files, f"Missing core files: {missing_files}"
        assert not invalid_files, f"Invalid core files: {invalid_files}"

    def test_domain_layer_has_no_framework_dependencies(self):
        """Domain layer should not import any framework dependencies."""
        if not MODULES_PATH.exists():
            pytest.skip("Modules directory does not exist")
        
        domain_files = []
        
        # Get all domain files from modules
        for module_dir in MODULES_PATH.iterdir():
            if module_dir.is_dir() and not module_dir.name.startswith('.'):
                domain_path = module_dir / "domain"
                if domain_path.exists():
                    domain_files.extend(get_python_files(domain_path))
        
        if not domain_files:
            pytest.skip("No domain files found")
        
        violations = []
        
        for file_path in domain_files:
            imports = get_imports_from_file(file_path)
            framework_imports = imports.intersection(FRAMEWORK_IMPORTS)
            
            if framework_imports:
                violations.append({
                    "file": str(file_path.relative_to(APP_ROOT)),
                    "framework_imports": list(framework_imports)
                })
        
        assert not violations, f"Domain layer files have framework dependencies: {violations}"

    def test_modules_have_ddd_structure(self):
        """Test that modules follow DDD structure."""
        if not MODULES_PATH.exists():
            pytest.skip("Modules directory does not exist")
        
        ddd_layers = ["domain", "application", "infrastructure"]
        module_dirs = [d for d in MODULES_PATH.iterdir() if d.is_dir() and not d.name.startswith('.')]
        
        if not module_dirs:
            pytest.skip("No module directories found")
        
        structure_issues = []
        
        for module_dir in module_dirs:
            missing_layers = []
            
            for layer in ddd_layers:
                layer_path = module_dir / layer
                if not layer_path.exists():
                    missing_layers.append(layer)
            
            if missing_layers:
                structure_issues.append({
                    "module": module_dir.name,
                    "missing_layers": missing_layers
                })
        
        # Allow some modules to not have all layers if they're small/specialized
        critical_modules = ["identity", "audit"]  # These should definitely have full structure
        
        critical_issues = [issue for issue in structure_issues if issue["module"] in critical_modules]
        
        assert not critical_issues, f"Critical modules missing DDD layers: {critical_issues}"

    def test_domain_layer_import_restrictions(self):
        """Domain layer should only import from domain or core layers."""
        if not MODULES_PATH.exists():
            pytest.skip("Modules directory does not exist")
        
        domain_files = []
        
        for module_dir in MODULES_PATH.iterdir():
            if module_dir.is_dir() and not module_dir.name.startswith('.'):
                domain_path = module_dir / "domain"
                if domain_path.exists():
                    domain_files.extend(get_python_files(domain_path))
        
        if not domain_files:
            pytest.skip("No domain files found")
        
        violations = []
        
        for file_path in domain_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Check for imports from application or infrastructure layers
                if ("from app.modules." in content and ".application." in content) or \
                   ("from app.modules." in content and ".infrastructure." in content):
                    violations.append(str(file_path.relative_to(APP_ROOT)))
            except Exception:
                continue
        
        assert not violations, f"Domain layer files import from application/infrastructure: {violations}"

    def test_naming_conventions(self):
        """Test basic naming conventions."""
        if not MODULES_PATH.exists():
            pytest.skip("Modules directory does not exist")
        
        violations = []
        
        # Test repository naming
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
                        if "Repository" in class_name and not class_name.endswith("Repository"):
                            violations.append({
                                "file": str(file_path.relative_to(APP_ROOT)),
                                "class": class_name,
                                "issue": "Repository classes should end with 'Repository'"
                            })
        
        assert not violations, f"Naming convention violations: {violations}"

    def test_no_hardcoded_secrets(self):
        """Test that there are no hardcoded secrets or credentials."""
        # Simple regex patterns for potential secrets
        secret_patterns = [
            re.compile(r'password\s*=\s*["\'][^"\']+["\']', re.IGNORECASE),
            re.compile(r'secret\s*=\s*["\'][^"\']+["\']', re.IGNORECASE),
            re.compile(r'api_key\s*=\s*["\'][^"\']+["\']', re.IGNORECASE),
            re.compile(r'token\s*=\s*["\'][^"\']+["\']', re.IGNORECASE),
        ]
        
        violations = []
        
        # Check all Python files except tests and examples
        all_files = get_python_files(APP_ROOT)
        
        for file_path in all_files:
            if any(exclude in str(file_path).lower() for exclude in ["test", "example", "sample"]):
                continue
            
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                for pattern in secret_patterns:
                    matches = pattern.findall(content)
                    if matches:
                        violations.append({
                            "file": str(file_path.relative_to(APP_ROOT)),
                            "potential_secrets": matches
                        })
            except Exception:
                continue
        
        assert not violations, f"Potential hardcoded secrets found: {violations}"

    def test_core_error_hierarchy_exists(self):
        """Test that core error hierarchy is properly implemented."""
        errors_file = CORE_PATH / "errors.py"
        
        if not errors_file.exists():
            pytest.fail("Core errors.py file is missing")
        
        classes = get_class_names_from_file(errors_file)
        
        required_error_classes = [
            "EzzDayError",  # Base error
            "DomainError",
            "ApplicationError", 
            "InfrastructureError",
            "ValidationError"
        ]
        
        missing_classes = [cls for cls in required_error_classes if cls not in classes]
        
        assert not missing_classes, f"Missing required error classes: {missing_classes}"

    def test_database_configuration_exists(self):
        """Test that database configuration is properly implemented."""
        config_file = CORE_PATH / "config.py"
        database_file = CORE_PATH / "database.py"
        
        if not config_file.exists():
            pytest.fail("Core config.py file is missing")
        
        if not database_file.exists():
            pytest.fail("Core database.py file is missing")
        
        config_classes = get_class_names_from_file(config_file)
        database_classes = get_class_names_from_file(database_file)
        
        # Check for key configuration classes
        required_config_classes = ["DatabaseConfig"]
        required_database_classes = ["ConnectionManager", "SessionManager"]
        
        missing_config = [cls for cls in required_config_classes if cls not in config_classes]
        missing_database = [cls for cls in required_database_classes if cls not in database_classes]
        
        assert not missing_config, f"Missing configuration classes: {missing_config}"
        assert not missing_database, f"Missing database classes: {missing_database}"


# =====================================================================================
# QUALITY METRICS
# =====================================================================================

class TestQualityMetrics:
    """Test code quality metrics."""

    def test_python_files_are_valid(self):
        """All Python files should be syntactically valid."""
        invalid_files = []
        
        all_files = get_python_files(APP_ROOT)
        
        for file_path in all_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                ast.parse(content)
            except Exception as e:
                invalid_files.append(f"{file_path.relative_to(APP_ROOT)}: {str(e)}")
        
        assert not invalid_files, f"Invalid Python files found: {invalid_files}"

    def test_reasonable_file_sizes(self):
        """Files should not be excessively large."""
        large_files = []
        max_lines = 2000  # Reasonable limit for maintainability
        
        all_files = get_python_files(APP_ROOT)
        
        for file_path in all_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    lines = len(f.readlines())
                
                if lines > max_lines:
                    large_files.append(f"{file_path.relative_to(APP_ROOT)}: {lines} lines")
            except Exception:
                continue
        
        # Allow some flexibility for configuration and generated files
        assert len(large_files) <= 5, f"Too many large files (>{max_lines} lines): {large_files}"

    def test_modules_have_init_files(self):
        """Important directories should have __init__.py files."""
        if not MODULES_PATH.exists():
            pytest.skip("Modules directory does not exist")
        
        missing_init = []
        
        for module_dir in MODULES_PATH.iterdir():
            if not module_dir.is_dir() or module_dir.name.startswith('.'):
                continue
            
            # Check module __init__.py
            if not (module_dir / "__init__.py").exists():
                missing_init.append(f"{module_dir.name}/__init__.py")
            
            # Check layer __init__.py files
            for layer in ["domain", "application", "infrastructure"]:
                layer_path = module_dir / layer
                if layer_path.exists() and not (layer_path / "__init__.py").exists():
                    missing_init.append(f"{module_dir.name}/{layer}/__init__.py")
        
        assert not missing_init, f"Missing __init__.py files: {missing_init}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
