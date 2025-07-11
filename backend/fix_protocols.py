#!/usr/bin/env python3
"""
Quick fix for Protocol interface formatting
"""

import re
from pathlib import Path


def fix_protocol_formatting(file_path: Path):
    """Fix the ordering of ... and docstrings in Protocol methods."""
    content = file_path.read_text()
    
    # Pattern to match method with wrong ordering: ... followed by docstring
    pattern = r'(    async def \w+\([^)]*\)[^:]*:)\n(        \.\.\.)\n(        """[\s\S]*?""")'
    
    def replacement(match):
        method_def = match.group(1)
        ellipsis = match.group(2)
        docstring = match.group(3)
        return f"{method_def}\n{docstring}\n{ellipsis}"
    
    # Also handle non-async methods
    pattern2 = r'(    def \w+\([^)]*\)[^:]*:)\n(        \.\.\.)\n(        """[\s\S]*?""")'
    
    content = re.sub(pattern, replacement, content)
    content = re.sub(pattern2, replacement, content)
    
    # Remove any leftover ABC imports
    content = re.sub(r'from abc import.*\n', '', content)
    
    file_path.write_text(content)


def main():
    """Fix all Protocol interface files."""
    root = Path("/Users/neuro/workspace2/app-codebase/ezzday/backend")
    modules_path = root / "app" / "modules"
    
    fixed_count = 0
    
    for module_dir in modules_path.iterdir():
        if module_dir.is_dir() and module_dir.name not in ["__pycache__"]:
            services_path = module_dir / "domain" / "interfaces" / "services"
            if services_path.exists():
                for py_file in services_path.rglob("*.py"):
                    if py_file.name != "__init__.py":
                        try:
                            content = py_file.read_text()
                            if "Protocol" in content and "..." in content:
                                fix_protocol_formatting(py_file)
                                fixed_count += 1
                                print(f"✅ Fixed: {py_file.relative_to(root)}")
                        except Exception as e:
                            print(f"❌ Error fixing {py_file}: {e}")
    
    print(f"\n🎉 Fixed {fixed_count} Protocol interface files")


if __name__ == "__main__":
    main()
