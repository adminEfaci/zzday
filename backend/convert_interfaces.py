#!/usr/bin/env python3
"""
ABC to Protocol Interface Converter

Systematically converts ABC-based domain service interfaces to Protocol-based interfaces.
Handles the complete identity domain with its sophisticated security-first design.
"""

import os
import re
from pathlib import Path
from typing import Dict, List, Set


class InterfaceConverter:
    """Converts ABC-based interfaces to Protocol-based interfaces."""
    
    def __init__(self, root_path: str):
        self.root_path = Path(root_path)
        self.converted_files: List[Path] = []
        self.failed_files: List[tuple[Path, str]] = []
        self.interface_files: List[Path] = []
        
    def find_interface_files(self) -> List[Path]:
        """Find all interface files in domain/interfaces/services/ directories."""
        interface_files = []
        
        # Search pattern for domain service interfaces
        modules_path = self.root_path / "app" / "modules"
        
        for module_dir in modules_path.iterdir():
            if module_dir.is_dir() and module_dir.name not in ["__pycache__"]:
                services_path = module_dir / "domain" / "interfaces" / "services"
                if services_path.exists():
                    # Recursively find all .py files in services
                    for py_file in services_path.rglob("*.py"):
                        if py_file.name != "__init__.py":
                            interface_files.append(py_file)
        
        self.interface_files = interface_files
        return interface_files
    
    def is_abc_interface(self, file_path: Path) -> bool:
        """Check if file contains ABC-based interface."""
        try:
            content = file_path.read_text(encoding='utf-8')
            return (
                "from abc import ABC, abstractmethod" in content or
                "from abc import abstractmethod, ABC" in content or
                "class I" in content and "(ABC)" in content
            )
        except Exception:
            return False
    
    def convert_file_to_protocol(self, file_path: Path) -> bool:
        """Convert a single ABC interface file to Protocol."""
        try:
            content = file_path.read_text(encoding='utf-8')
            
            # Check if already converted
            if "from typing import" in content and "Protocol" in content:
                print(f"✓ Already Protocol-based: {file_path.relative_to(self.root_path)}")
                return True
            
            # Perform ABC to Protocol conversion
            converted_content = self._perform_conversion(content)
            
            # Write back the converted content
            file_path.write_text(converted_content, encoding='utf-8')
            
            self.converted_files.append(file_path)
            print(f"✅ Converted: {file_path.relative_to(self.root_path)}")
            return True
            
        except Exception as e:
            self.failed_files.append((file_path, str(e)))
            print(f"❌ Failed: {file_path.relative_to(self.root_path)} - {e}")
            return False
    
    def _perform_conversion(self, content: str) -> str:
        """Perform the actual ABC to Protocol conversion."""
        lines = content.split('\n')
        converted_lines = []
        in_import_section = True
        protocol_imported = False
        
        for line in lines:
            # Handle imports
            if in_import_section:
                if line.strip() == "":
                    converted_lines.append(line)
                    continue
                    
                # Remove ABC imports
                if "from abc import" in line:
                    # Skip ABC import line
                    continue
                
                # Add Protocol import if not already there
                if line.startswith("from typing import") and not protocol_imported:
                    if "Protocol" not in line:
                        # Add Protocol to existing typing import
                        line = line.rstrip() + ", Protocol"
                    protocol_imported = True
                elif line.startswith("from typing import") and "Protocol" in line:
                    protocol_imported = True
                elif line.startswith("from uuid import") or line.startswith("if TYPE_CHECKING"):
                    # Add Protocol import before these if not added yet
                    if not protocol_imported:
                        converted_lines.append("from typing import Protocol")
                        protocol_imported = True
                        
                converted_lines.append(line)
                
                # Check if we're leaving import section
                if not line.startswith(("from ", "import ", "#", '"""', "'''")) and line.strip():
                    in_import_section = False
            else:
                # Handle class definition
                if re.match(r'class I\w+\(ABC\):', line):
                    line = re.sub(r'\(ABC\)', '(Protocol)', line)
                
                # Remove @abstractmethod decorators
                if line.strip() == "@abstractmethod":
                    continue
                
                # Handle method definitions - add ... body
                if self._is_method_definition(line) and not self._has_implementation(lines, converted_lines):
                    converted_lines.append(line)
                    # Add ... body for protocol methods
                    indent = self._get_indent(line)
                    converted_lines.append(f"{indent}    ...")
                    continue
                
                # Update docstring from "Port" to "Protocol"
                if "Port for" in line:
                    line = line.replace("Port for", "Protocol for")
                
                converted_lines.append(line)
        
        # Ensure Protocol is imported if we found ABC classes
        if not protocol_imported and any("class I" in line and "(Protocol)" in line for line in converted_lines):
            # Insert Protocol import after typing imports
            for i, line in enumerate(converted_lines):
                if line.startswith("from typing import"):
                    if "Protocol" not in line:
                        converted_lines[i] = line.rstrip() + ", Protocol"
                    break
            else:
                # No typing import found, add it
                for i, line in enumerate(converted_lines):
                    if line.startswith("from uuid import") or line.startswith("if TYPE_CHECKING"):
                        converted_lines.insert(i, "from typing import Protocol")
                        break
        
        return '\n'.join(converted_lines)
    
    def _is_method_definition(self, line: str) -> bool:
        """Check if line is a method definition."""
        stripped = line.strip()
        return (
            stripped.startswith("async def ") or
            stripped.startswith("def ")
        ) and ":" in stripped
    
    def _has_implementation(self, all_lines: List[str], current_lines: List[str]) -> bool:
        """Check if method already has implementation (not just pass or ...)."""
        # For Protocol conversion, we always want to add ... bodies
        return False
    
    def _get_indent(self, line: str) -> str:
        """Get the indentation of a line."""
        return line[:len(line) - len(line.lstrip())]
    
    def convert_all_interfaces(self) -> Dict[str, any]:
        """Convert all ABC interfaces to Protocol interfaces."""
        print("🔍 Finding interface files...")
        interface_files = self.find_interface_files()
        
        print(f"📁 Found {len(interface_files)} interface files")
        
        abc_files = [f for f in interface_files if self.is_abc_interface(f)]
        print(f"🔄 Found {len(abc_files)} ABC-based interfaces to convert")
        
        if not abc_files:
            print("✅ All interfaces are already Protocol-based!")
            return {
                "total_files": len(interface_files),
                "abc_files_found": 0,
                "converted": 0,
                "failed": 0,
                "already_protocol": len(interface_files)
            }
        
        print("\n🚀 Starting conversion process...")
        
        for file_path in abc_files:
            self.convert_file_to_protocol(file_path)
        
        print(f"\n📊 Conversion Summary:")
        print(f"✅ Successfully converted: {len(self.converted_files)}")
        print(f"❌ Failed conversions: {len(self.failed_files)}")
        print(f"📁 Total interface files: {len(interface_files)}")
        
        if self.failed_files:
            print(f"\n❌ Failed Files:")
            for file_path, error in self.failed_files:
                print(f"  - {file_path.relative_to(self.root_path)}: {error}")
        
        return {
            "total_files": len(interface_files),
            "abc_files_found": len(abc_files),
            "converted": len(self.converted_files),
            "failed": len(self.failed_files),
            "converted_files": [str(f.relative_to(self.root_path)) for f in self.converted_files],
            "failed_files": [(str(f.relative_to(self.root_path)), e) for f, e in self.failed_files]
        }


def main():
    """Main conversion function."""
    # Set the root path for the EzzDay backend
    root_path = "/Users/neuro/workspace2/app-codebase/ezzday/backend"
    
    print("🔧 ABC to Protocol Interface Converter")
    print("=" * 50)
    print(f"📂 Root path: {root_path}")
    print()
    
    converter = InterfaceConverter(root_path)
    results = converter.convert_all_interfaces()
    
    print("\n" + "=" * 50)
    print("🎉 Conversion Complete!")
    
    return results


if __name__ == "__main__":
    main()
