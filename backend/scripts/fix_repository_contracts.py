#!/usr/bin/env python3
"""
Repository Contract Fixes

This script fixes repository contract implementations across all modules to ensure
consistent interfaces and proper inheritance from base repository classes.

Issues addressed:
1. SQLRepository imports that should be BaseRepository or OptimizedSQLRepository
2. Inconsistent method signatures
3. Missing proper inheritance
4. Import errors and inconsistencies
"""

import ast
import re
from pathlib import Path
from typing import Dict, List, Tuple

from app.core.logging import get_logger

logger = get_logger(__name__)


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
        
        logger.info(f"Found {len(repository_files)} repository files to fix")
        
        for file_path in repository_files:
            try:
                fixes = self._fix_repository_file(file_path)
                if fixes:
                    results["fixed_files"].append(str(file_path))
                    results["summary"].extend(fixes)
                    
            except Exception as e:
                error_msg = f"Error fixing {file_path}: {e}"
                results["errors"].append(error_msg)
                logger.error(error_msg)
        
        logger.info(f"Fixed {len(results['fixed_files'])} repository files")
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
            
            # Fix 1: SQLRepository imports
            if "from app.core.infrastructure.repository import SQLRepository" in content:
                content = content.replace(
                    "from app.core.infrastructure.repository import SQLRepository",
                    "from app.core.infrastructure.repository import BaseRepository"
                )
                fixes.append(f"Fixed SQLRepository import in {file_path}")
            
            # Fix 2: SQLRepository class inheritance
            content = re.sub(
                r'class\s+(\w+Repository)\s*\(\s*SQLRepository\[([^\]]+)\]\s*,\s*([^)]+)\s*\)',
                r'class \1(BaseRepository[\2], \3)',
                content
            )
            
            # Fix 3: Session parameter in __init__ for SQL repositories
            if "def __init__(self, session:" in content:
                content = self._fix_repository_init(content)
                fixes.append(f"Fixed __init__ method in {file_path}")
            
            # Fix 4: Add proper async methods
            if "class " in content and "Repository" in content:
                content = self._ensure_async_methods(content)
                fixes.append(f"Ensured async methods in {file_path}")
            
            # Fix 5: Import BaseRepository from optimized repository if needed
            if "BaseRepository" in content and "from app.core.infrastructure.repository import BaseRepository" not in content:
                if "from app.core.infrastructure.optimized_sql_repository import" in content:
                    content = content.replace(
                        "from app.core.infrastructure.optimized_sql_repository import",
                        "from app.core.infrastructure.optimized_sql_repository import BaseRepository,"
                    )
                else:
                    # Add import at the top
                    import_line = "from app.core.infrastructure.repository import BaseRepository\n"
                    content = self._add_import_at_top(content, import_line)
                    fixes.append(f"Added BaseRepository import to {file_path}")
            
            # Fix 6: Fix method signatures to match base repository
            content = self._fix_method_signatures(content)
            
            # Fix 7: Add missing type hints
            content = self._add_type_hints(content)
            
            # Only write if changes were made
            if content != original_content:
                file_path.write_text(content)
                self.fixes_applied += 1
                logger.info(f"Applied fixes to {file_path}")
            
            return fixes
            
        except Exception as e:
            logger.error(f"Error fixing {file_path}: {e}")
            return []
    
    def _fix_repository_init(self, content: str) -> str:
        """Fix repository __init__ method."""
        # Pattern to match __init__ method
        init_pattern = r'def __init__\(self, session: (\w+)\):'
        
        # Replace with proper initialization
        def replace_init(match):
            session_type = match.group(1)
            return f"""def __init__(self, session: {session_type}):
        super().__init__(session)
        self.session = session"""
        
        content = re.sub(init_pattern, replace_init, content)
        return content
    
    def _ensure_async_methods(self, content: str) -> str:
        """Ensure repository methods are async."""
        # Common repository methods that should be async
        methods_to_make_async = [
            "find_by_id", "find_by_name", "save", "delete", "find_many",
            "count", "exists", "create", "update", "get_by_id", "list"
        ]
        
        for method in methods_to_make_async:
            # Find method definitions that aren't async
            pattern = rf'def ({method}\([^)]*\):[^a])'
            replacement = rf'async def \1'
            content = re.sub(pattern, replacement, content)
        
        return content
    
    def _fix_method_signatures(self, content: str) -> str:
        """Fix method signatures to match base repository."""
        # Common signature fixes
        fixes = {
            r'def find_by_id\(self, id: (\w+)\)': r'async def find_by_id(self, id: \1)',
            r'def save\(self, entity: (\w+)\)': r'async def save(self, entity: \1) -> \1',
            r'def delete\(self, id: (\w+)\)': r'async def delete(self, id: \1) -> bool',
            r'def find_many\(self,': r'async def find_many(self,',
            r'def count\(self,': r'async def count(self,',
            r'def exists\(self,': r'async def exists(self,',
        }
        
        for pattern, replacement in fixes.items():
            content = re.sub(pattern, replacement, content)
        
        return content
    
    def _add_type_hints(self, content: str) -> str:
        """Add proper type hints to repository methods."""
        # Add common imports for type hints
        imports_to_add = [
            "from typing import List, Optional, Dict, Any",
            "from uuid import UUID"
        ]
        
        for import_line in imports_to_add:
            if import_line not in content:
                content = self._add_import_at_top(content, import_line + "\n")
        
        return content
    
    def _add_import_at_top(self, content: str, import_line: str) -> str:
        """Add import at the top of the file."""
        lines = content.split('\n')
        
        # Find where to insert the import
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
            elif line.strip().startswith('from ') or line.strip().startswith('import '):
                # After other imports
                insert_index = i + 1
            elif line.strip() == '':
                continue
            else:
                insert_index = i
                break
        
        # Insert the import
        lines.insert(insert_index, import_line.rstrip())
        return '\n'.join(lines)
    
    def generate_repository_base_class(self) -> str:
        """Generate a consistent repository base class."""
        base_class = '''"""
Enhanced Repository Base Class for All Modules

This base class provides consistent interface and performance optimizations
for all repository implementations across the application.
"""

from abc import ABC, abstractmethod
from typing import Generic, TypeVar, List, Optional, Dict, Any
from uuid import UUID

from app.core.domain.base import Entity
from app.core.domain.specification import Specification
from app.core.infrastructure.optimized_sql_repository import OptimizedSQLRepository

TEntity = TypeVar("TEntity", bound=Entity)
TId = TypeVar("TId")


class EnhancedRepositoryBase(OptimizedSQLRepository[TEntity, TId], ABC):
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
    
    async def batch_save(self, entities: List[TEntity]) -> List[TEntity]:
        """Save multiple entities in batch."""
        return await self.save_batch(entities)
'''
        
        return base_class
    
    def create_repository_migration_guide(self) -> str:
        """Create migration guide for repository implementations."""
        guide = '''# Repository Contract Migration Guide

## Overview
This guide helps migrate repository implementations to use consistent contracts and base classes.

## Common Issues Fixed

### 1. SQLRepository Import
**Before:**
```python
from app.core.infrastructure.repository import SQLRepository
```

**After:**
```python
from app.core.infrastructure.repository import BaseRepository
```

### 2. Class Inheritance
**Before:**
```python
class UserRepository(SQLRepository[User, UserModel], IUserRepository):
```

**After:**
```python
class UserRepository(BaseRepository[User, UserModel], IUserRepository):
```

### 3. Method Signatures
**Before:**
```python
def find_by_id(self, id: UUID) -> User | None:
```

**After:**
```python
async def find_by_id(self, id: UUID) -> User | None:
```

### 4. Constructor Pattern
**Before:**
```python
def __init__(self, session: Session):
    self.session = session
```

**After:**
```python
def __init__(self, session: Session):
    super().__init__(session)
    self.session = session
```

## Benefits
1. Consistent interface across all repositories
2. Performance optimizations from base classes
3. Proper async/await support
4. Enhanced caching and query optimization
5. Better error handling and monitoring

## Migration Steps
1. Update imports to use BaseRepository or OptimizedSQLRepository
2. Ensure all CRUD methods are async
3. Add proper type hints
4. Update method signatures to match base class
5. Test repository functionality
'''
        
        return guide


def main():
    """Main function to fix repository contracts."""
    backend_path = Path(__file__).parent.parent
    fixer = RepositoryFixer(backend_path)
    
    print("Starting repository contract fixes...")
    
    # Generate enhanced base class
    base_class_content = fixer.generate_repository_base_class()
    base_class_file = backend_path / "app" / "core" / "repositories" / "enhanced_base.py"
    base_class_file.parent.mkdir(parents=True, exist_ok=True)
    base_class_file.write_text(base_class_content)
    print(f"Generated enhanced base class: {base_class_file}")
    
    # Create migration guide
    guide_content = fixer.create_repository_migration_guide()
    guide_file = backend_path / "docs" / "REPOSITORY_MIGRATION_GUIDE.md"
    guide_file.parent.mkdir(parents=True, exist_ok=True)
    guide_file.write_text(guide_content)
    print(f"Created migration guide: {guide_file}")
    
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