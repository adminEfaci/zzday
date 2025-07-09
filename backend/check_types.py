#!/usr/bin/env python3
"""
Script to check type annotations in specific files.
"""
import subprocess
import sys


def check_file_types(filepath):
    """Check types for a specific file."""
    try:
        # Use mypy directly on the file with minimal configuration
        result = subprocess.run([
            sys.executable, '-m', 'mypy', 
            filepath,
            '--ignore-missing-imports',
            '--no-strict-optional',
            '--show-error-codes',
            '--explicit-package-bases'
        ], capture_output=True, text=True, cwd='.', check=False)
        
        if result.returncode == 0:
            print(f"✓ {filepath}: No type errors found")
            return True
        print(f"✗ {filepath}: Type errors found")
        print(result.stdout)
        return False
    except Exception as e:
        print(f"Error checking {filepath}: {e}")
        return False

def main():
    """Check all the files we fixed."""
    files_to_check = [
        'app/modules/identity/domain/value_objects/username.py',
        'app/modules/identity/domain/value_objects/phone_number.py', 
        'app/modules/identity/domain/rules/base.py',
        'app/modules/identity/domain/interfaces/services/communication/notification_service.py',
        'app/modules/identity/domain/entities/user/user_enums.py'
    ]
    
    print("Checking type annotations for fixed files...\n")
    
    passed = 0
    total = len(files_to_check)
    
    for filepath in files_to_check:
        if check_file_types(filepath):
            passed += 1
        print()
    
    print(f"Results: {passed}/{total} files passed type checking")
    
    if passed == total:
        print("🎉 All assigned files have proper type annotations!")
        return 0
    print("❌ Some files still have type errors")
    return 1

if __name__ == "__main__":
    sys.exit(main())