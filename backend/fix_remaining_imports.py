#!/usr/bin/env python3
"""
Fix remaining critical import issues in integration and notification modules.
"""

import os
import re
from pathlib import Path

def fix_any_imports(file_path):
    """Fix missing Any imports."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Check if Any is used but not imported
        if ('Any' in content and 
            'from typing import' in content and 
            'Any' not in content.split('from typing import')[1].split('\n')[0]):
            
            # Add Any to existing typing import
            typing_pattern = r'(from typing import )([^)\n]+)'
            match = re.search(typing_pattern, content)
            if match:
                existing_imports = match.group(2).strip()
                if 'Any' not in existing_imports:
                    new_imports = f"{existing_imports}, Any"
                    content = content.replace(match.group(0), f"from typing import {new_imports}")
                    
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(content)
                    return True
                    
        elif 'Any' in content and 'from typing import' not in content:
            # Add new typing import
            lines = content.split('\n')
            insert_idx = 0
            for i, line in enumerate(lines):
                if line.startswith('from ') and 'import' in line:
                    insert_idx = i + 1
            
            lines.insert(insert_idx, 'from typing import Any')
            content = '\n'.join(lines)
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
            
    except Exception as e:
        print(f"Error fixing Any imports in {file_path}: {e}")
    
    return False

def fix_datetime_imports(file_path):
    """Fix missing datetime and timedelta imports."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        changed = False
        
        # Fix datetime imports
        if 'datetime' in content and 'from datetime import' in content:
            datetime_pattern = r'(from datetime import )([^)\n]+)'
            match = re.search(datetime_pattern, content)
            if match:
                existing_imports = match.group(2).strip()
                missing_imports = []
                
                if 'datetime' in content and 'datetime' not in existing_imports:
                    missing_imports.append('datetime')
                if 'timedelta' in content and 'timedelta' not in existing_imports:
                    missing_imports.append('timedelta')
                if 'timezone' in content and 'timezone' not in existing_imports:
                    missing_imports.append('timezone')
                
                if missing_imports:
                    new_imports = f"{existing_imports}, {', '.join(missing_imports)}"
                    content = content.replace(match.group(0), f"from datetime import {new_imports}")
                    changed = True
                    
        elif ('datetime' in content or 'timedelta' in content) and 'from datetime import' not in content:
            # Add new datetime import
            imports_needed = []
            if 'datetime' in content:
                imports_needed.append('datetime')
            if 'timedelta' in content:
                imports_needed.append('timedelta')
            if 'timezone' in content:
                imports_needed.append('timezone')
                
            if imports_needed:
                lines = content.split('\n')
                insert_idx = 0
                for i, line in enumerate(lines):
                    if line.startswith('from ') and 'import' in line:
                        insert_idx = i + 1
                
                lines.insert(insert_idx, f"from datetime import {', '.join(imports_needed)}")
                content = '\n'.join(lines)
                changed = True
        
        if changed:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
            
    except Exception as e:
        print(f"Error fixing datetime imports in {file_path}: {e}")
    
    return False

def fix_sqlalchemy_imports(file_path):
    """Fix missing SQLAlchemy imports."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        changed = False
        missing_imports = []
        
        # Check for SQLAlchemy types
        if 'Boolean' in content and 'from sqlalchemy import' not in content:
            missing_imports.append('Boolean')
        if 'Text' in content and 'from sqlalchemy import' not in content:
            missing_imports.append('Text')
        if 'Float' in content and 'from sqlalchemy import' not in content:
            missing_imports.append('Float')
        if 'IntegrityError' in content and 'from sqlalchemy.exc import' not in content:
            missing_imports.append('IntegrityError')
        
        if missing_imports:
            lines = content.split('\n')
            insert_idx = 0
            for i, line in enumerate(lines):
                if line.startswith('from ') and 'import' in line:
                    insert_idx = i + 1
            
            if 'IntegrityError' in missing_imports:
                lines.insert(insert_idx, 'from sqlalchemy.exc import IntegrityError')
                missing_imports.remove('IntegrityError')
                insert_idx += 1
                
            if missing_imports:
                lines.insert(insert_idx, f"from sqlalchemy import {', '.join(missing_imports)}")
            
            content = '\n'.join(lines)
            changed = True
        
        if changed:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
            
    except Exception as e:
        print(f"Error fixing SQLAlchemy imports in {file_path}: {e}")
    
    return False

def fix_json_imports(file_path):
    """Fix missing json imports."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        if 'json' in content and 'import json' not in content:
            lines = content.split('\n')
            insert_idx = 0
            for i, line in enumerate(lines):
                if line.startswith('import ') or (line.startswith('from ') and 'import' in line):
                    insert_idx = i + 1
            
            lines.insert(insert_idx, 'import json')
            content = '\n'.join(lines)
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
            
    except Exception as e:
        print(f"Error fixing json imports in {file_path}: {e}")
    
    return False

def fix_asyncio_imports(file_path):
    """Fix missing asyncio imports."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        if 'asyncio' in content and 'import asyncio' not in content:
            lines = content.split('\n')
            insert_idx = 0
            for i, line in enumerate(lines):
                if line.startswith('import ') or (line.startswith('from ') and 'import' in line):
                    insert_idx = i + 1
            
            lines.insert(insert_idx, 'import asyncio')
            content = '\n'.join(lines)
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
            
    except Exception as e:
        print(f"Error fixing asyncio imports in {file_path}: {e}")
    
    return False

def fix_service_interface_imports_in_dtos(file_path):
    """Fix missing service interface imports in DTO files."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        interfaces_needed = []
        interface_map = {
            'ITokenRepository': 'ITokenRepository',
            'ISecurityEventRepository': 'ISecurityEventRepository', 
            'IAuditService': 'IAuditService'
        }
        
        for interface_name in interface_map.keys():
            if interface_name in content:
                interfaces_needed.append(interface_name)
        
        if interfaces_needed:
            lines = content.split('\n')
            insert_idx = 0
            for i, line in enumerate(lines):
                if line.startswith('from ') and 'import' in line:
                    insert_idx = i + 1
            
            import_line = f"from app.modules.identity.domain.interfaces.services import (\n"
            for interface in interfaces_needed:
                import_line += f"    {interface},\n"
            import_line += ")"
            
            lines.insert(insert_idx, import_line)
            content = '\n'.join(lines)
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
            
    except Exception as e:
        print(f"Error fixing service interface imports in {file_path}: {e}")
    
    return False

def main():
    """Main function to fix remaining imports."""
    print("🔧 Fixing remaining critical import issues...")
    
    # Target specific files that need fixes
    target_files = [
        # Integration module
        "backend/app/modules/integration/application/commands/disconnect_integration.py",
        "backend/app/modules/integration/application/commands/refresh_credentials.py", 
        "backend/app/modules/integration/application/queries/get_integration.py",
        "backend/app/modules/integration/application/queries/get_integration_health.py",
        "backend/app/modules/integration/application/queries/get_mappings.py",
        "backend/app/modules/integration/application/queries/get_sync_status.py",
        "backend/app/modules/integration/application/queries/get_webhook_history.py",
        "backend/app/modules/integration/application/queries/list_integrations.py",
        "backend/app/modules/integration/infrastructure/models/mapping.py",
        "backend/app/modules/integration/infrastructure/models/webhook_event.py",
        "backend/app/modules/integration/infrastructure/repositories/credential.py",
        "backend/app/modules/integration/infrastructure/repositories/mapping.py",
        "backend/app/modules/integration/infrastructure/repositories/webhook_endpoint.py",
        "backend/app/modules/integration/presentation/graphql/data_loaders.py",
        "backend/app/modules/integration/presentation/graphql/resolvers/queries/mapping_queries.py",
        "backend/app/modules/integration/presentation/graphql/resolvers/subscriptions/health_subscriptions.py",
        
        # Notification module
        "backend/app/modules/notification/domain/entities/notification_recipient.py",
        "backend/app/modules/notification/infrastructure/adapters/in_app_adapter.py",
        
        # Identity module DTOs and misc
        "backend/app/modules/identity/application/dtos/command_params.py",
        "backend/app/modules/identity/domain/services/role/role_factory.py",
    ]
    
    fixed_count = 0
    
    for file_path in target_files:
        if os.path.exists(file_path):
            print(f"Processing: {file_path}")
            
            changed = False
            changed |= fix_any_imports(file_path)
            changed |= fix_datetime_imports(file_path) 
            changed |= fix_sqlalchemy_imports(file_path)
            changed |= fix_json_imports(file_path)
            changed |= fix_asyncio_imports(file_path)
            changed |= fix_service_interface_imports_in_dtos(file_path)
            
            if changed:
                fixed_count += 1
                print(f"  ✓ Fixed imports")
            else:
                print(f"  - No changes needed")
    
    print(f"\n📊 Results: Fixed imports in {fixed_count} files")

if __name__ == "__main__":
    main() 