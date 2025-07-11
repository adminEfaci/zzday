#!/usr/bin/env python3
"""
Simple Repository Contract Fixes

This script fixes repository contract implementations without requiring app imports.
"""

import re
from pathlib import Path
from typing import Dict, List


class RepositoryFixer:
    """Fixes repository contract implementations."""
    
    def __init__(self, backend_path: Path):
        self.backend_path = backend_path
        self.fixes_applied = 0
        
    def fix_all_repositories(self) -> Dict[str, List[str]]:
        """Fix all repository implementations."""
        results = {
            "fixed_files": [],
            "errors": [],
            "summary": []
        }
        
        # Find all repository files
        repository_files = self._find_repository_files()
        
        print(f"Found {len(repository_files)} repository files to fix")
        
        for file_path in repository_files:
            try:
                fixes = self._fix_repository_file(file_path)
                if fixes:
                    results["fixed_files"].append(str(file_path))
                    results["summary"].extend(fixes)
                    
            except Exception as e:
                error_msg = f"Error fixing {file_path}: {e}"
                results["errors"].append(error_msg)
                print(error_msg)
        
        print(f"Fixed {len(results['fixed_files'])} repository files")
        return results
    
    def _find_repository_files(self) -> List[Path]:
        """Find all repository implementation files."""
        repository_files = []
        
        # Common repository file patterns
        patterns = [
            "**/repositories/*.py",
            "**/infrastructure/repositories/*.py",
            "**/*repository.py",
            "**/*_repository.py"
        ]
        
        for pattern in patterns:
            for file_path in self.backend_path.glob(pattern):
                if file_path.is_file() and not file_path.name.startswith("__"):
                    repository_files.append(file_path)
        
        return list(set(repository_files))  # Remove duplicates
    
    def _fix_repository_file(self, file_path: Path) -> List[str]:
        """Fix a single repository file."""
        fixes = []
        
        try:
            content = file_path.read_text()
            original_content = content
            
            # Fix 1: SQLRepository imports - change to BaseRepository
            if "from app.core.infrastructure.repository import SQLRepository" in content:
                content = content.replace(
                    "from app.core.infrastructure.repository import SQLRepository",
                    "from app.core.infrastructure.repository import BaseRepository"
                )
                fixes.append(f"Fixed SQLRepository import in {file_path.name}")
            
            # Fix 2: SQLRepository class inheritance
            content = re.sub(
                r'class\s+(\w+Repository)\s*\(\s*SQLRepository\[([^\]]+)\]\s*,\s*([^)]+)\s*\)',
                r'class \1(BaseRepository[\2], \3)',
                content
            )
            
            # Fix 3: Simple inheritance pattern
            content = re.sub(
                r'class\s+(\w+Repository)\s*\(\s*SQLRepository\[([^\]]+)\]\s*\)',
                r'class \1(BaseRepository[\2])',
                content
            )
            
            # Fix 4: BaseRepository import if missing
            if "BaseRepository" in content and "from app.core.infrastructure.repository import BaseRepository" not in content:
                # Add import after other imports
                import_line = "from app.core.infrastructure.repository import BaseRepository"
                if import_line not in content:
                    content = self._add_import_after_existing(content, import_line)
                    fixes.append(f"Added BaseRepository import to {file_path.name}")
            
            # Fix 5: Method signatures - ensure async
            methods_to_make_async = [
                "find_by_id", "find_by_name", "save", "delete", "find_many",
                "count", "exists", "create", "update", "get_by_id", "list"
            ]
            
            for method in methods_to_make_async:
                # Find method definitions that aren't async
                pattern = rf'(\s+)def ({method}\([^)]*\):)'
                replacement = rf'\1async def \2'
                if re.search(pattern, content):
                    content = re.sub(pattern, replacement, content)
                    fixes.append(f"Made {method} async in {file_path.name}")
            
            # Fix 6: Add proper type hints imports
            type_imports = [
                "from typing import List, Optional, Dict, Any",
                "from uuid import UUID"
            ]
            
            for import_line in type_imports:
                if import_line not in content and ("List[" in content or "Optional[" in content or "Dict[" in content):
                    content = self._add_import_after_existing(content, import_line)
                    fixes.append(f"Added type imports to {file_path.name}")
            
            # Fix 7: Constructor pattern
            if "def __init__(self, session:" in content:
                content = re.sub(
                    r'def __init__\(self, session: ([^)]+)\):\s*\n\s*self\.session = session',
                    r'def __init__(self, session: \1):\n        super().__init__(session)\n        self.session = session',
                    content
                )
                fixes.append(f"Fixed constructor in {file_path.name}")
            
            # Only write if changes were made
            if content != original_content:
                file_path.write_text(content)
                self.fixes_applied += 1
                print(f"Applied fixes to {file_path.name}")
            
            return fixes
            
        except Exception as e:
            print(f"Error fixing {file_path}: {e}")
            return []
    
    def _add_import_after_existing(self, content: str, import_line: str) -> str:
        """Add import after existing imports."""
        lines = content.split('\n')
        
        # Find the last import line
        last_import_index = -1
        for i, line in enumerate(lines):
            if line.strip().startswith('from ') or line.strip().startswith('import '):
                last_import_index = i
        
        if last_import_index >= 0:
            # Insert after the last import
            lines.insert(last_import_index + 1, import_line)
        else:
            # Add at the beginning after docstrings
            insert_index = 0
            for i, line in enumerate(lines):
                if line.strip().startswith('"""') or line.strip().startswith("'''"):
                    # Find the end of the docstring
                    quote_type = '"""' if line.strip().startswith('"""') else "'''"
                    quote_count = line.count(quote_type)
                    if quote_count == 1:  # Opening docstring
                        for j in range(i + 1, len(lines)):
                            if quote_type in lines[j]:
                                insert_index = j + 1
                                break
                    elif quote_count == 2:  # Single line docstring
                        insert_index = i + 1
                    break
                elif line.strip():
                    insert_index = i
                    break
            
            lines.insert(insert_index, import_line)
        
        return '\n'.join(lines)
    
    def create_enhanced_base_class(self) -> str:
        """Create enhanced base class."""
        return '''"""
Enhanced Repository Base Class for All Modules

This base class provides consistent interface and performance optimizations
for all repository implementations across the application.
"""

from abc import ABC, abstractmethod
from typing import Generic, TypeVar, List, Optional, Dict, Any
from uuid import UUID

from app.core.domain.base import Entity
from app.core.domain.specification import Specification
from app.core.infrastructure.repository import BaseRepository

TEntity = TypeVar("TEntity", bound=Entity)
TId = TypeVar("TId")


class EnhancedRepositoryBase(BaseRepository[TEntity, TId], ABC):
    """Enhanced base repository with consistent interface."""
    
    @abstractmethod
    async def find_by_id(self, id: TId) -> Optional[TEntity]:
        """Find entity by ID."""
        pass
    
    @abstractmethod
    async def save(self, entity: TEntity) -> TEntity:
        """Save entity."""
        pass
    
    @abstractmethod
    async def delete(self, id: TId) -> bool:
        """Delete entity by ID."""
        pass
    
    @abstractmethod
    async def find_many(
        self,
        specification: Optional[Specification] = None,
        offset: int = 0,
        limit: int = 100,
        order_by: Optional[str] = None
    ) -> List[TEntity]:
        """Find entities matching specification."""
        pass
    
    @abstractmethod
    async def count(self, specification: Optional[Specification] = None) -> int:
        """Count entities matching specification."""
        pass
    
    async def exists(self, id: TId) -> bool:
        """Check if entity exists."""
        entity = await self.find_by_id(id)
        return entity is not None
    
    async def find_all(self, limit: int = 1000) -> List[TEntity]:
        """Find all entities."""
        return await self.find_many(limit=limit)
    
    async def create(self, entity: TEntity) -> TEntity:
        """Create new entity."""
        return await self.save(entity)
    
    async def update(self, entity: TEntity) -> TEntity:
        """Update existing entity."""
        return await self.save(entity)
    
    async def delete_many(self, ids: List[TId]) -> int:
        """Delete multiple entities."""
        deleted_count = 0
        for id in ids:
            if await self.delete(id):
                deleted_count += 1
        return deleted_count
'''


def main():
    """Main function to fix repository contracts."""
    backend_path = Path(__file__).parent.parent
    fixer = RepositoryFixer(backend_path)
    
    print("Starting repository contract fixes...")
    
    # Generate enhanced base class
    base_class_content = fixer.create_enhanced_base_class()
    base_class_file = backend_path / "app" / "core" / "repositories" / "enhanced_base.py"
    base_class_file.parent.mkdir(parents=True, exist_ok=True)
    base_class_file.write_text(base_class_content)
    print(f"Generated enhanced base class: {base_class_file}")
    
    # Fix all repositories
    results = fixer.fix_all_repositories()
    
    # Print summary
    print(f"\n=== Repository Contract Fix Summary ===")
    print(f"Files fixed: {len(results['fixed_files'])}")
    print(f"Errors encountered: {len(results['errors'])}")
    print(f"Total fixes applied: {fixer.fixes_applied}")
    
    if results['errors']:
        print("\nErrors:")
        for error in results['errors']:
            print(f"  - {error}")
    
    if results['fixed_files']:
        print("\nFixed files:")
        for file in results['fixed_files']:
            print(f"  - {file}")
    
    print("\n=== Fix Details ===")
    for fix in results['summary']:
        print(f"  - {fix}")
    
    return len(results['errors']) == 0


if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)