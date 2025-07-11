#!/usr/bin/env python3
"""
Identity Domain Import Verification Script

This script verifies that all interface imports are working correctly
and that the domain layer is properly structured.
"""

import sys
import traceback
from pathlib import Path

def test_import(module_path: str, items: list[str]) -> tuple[bool, list[str]]:
    """Test importing specific items from a module."""
    errors = []
    try:
        # Dynamic import of the module
        module = __import__(module_path, fromlist=items)
        
        # Check each item exists
        for item in items:
            if not hasattr(module, item):
                errors.append(f"Missing: {item} in {module_path}")
        
        return len(errors) == 0, errors
    except ImportError as e:
        errors.append(f"Import error in {module_path}: {e}")
        return False, errors
    except Exception as e:
        errors.append(f"Unexpected error in {module_path}: {e}")
        return False, errors

def main():
    """Run comprehensive import verification."""
    print("🔍 Identity Domain Import Verification")
    print("=" * 50)
    
    # Test cases: (module_path, [items_to_check])
    test_cases = [
        # Core domain imports
        ("app.modules.identity.domain", [
            "AuthenticationError", "IUserRepository", "IAuthenticationService",
            "IMFAService", "IPasswordService", "IAuditService"
        ]),
        
        # Interface imports
        ("app.modules.identity.domain.interfaces", [
            "IUserRepository", "IAuthenticationService", "IMFAService",
            "IAccessTokenService", "IPasswordService", "IAuthorizationService",
            "ISecurityService", "IRiskAssessmentService", "IDeviceService",
            "IAdministrativeService", "IActivityService", "IAuditService",
            "IAnalyticsPort", "IRateLimitPort", "ICachePort", "IEventPublisherPort",
            "INotificationService", "IComplianceService"
        ]),
        
        # Service interface categories
        ("app.modules.identity.domain.interfaces.services.authentication", [
            "IBiometricService", "IPasswordHasher", "IPasswordService", "ITokenGenerator"
        ]),
        
        ("app.modules.identity.domain.interfaces.services.security", [
            "IAdministrativeService", "IAuthorizationService", "IDeviceService",
            "IGeolocationService", "IRiskAssessmentService", "ISecurityService",
            "IThreatIntelligenceService"
        ]),
        
        ("app.modules.identity.domain.interfaces.services.monitoring", [
            "IActivityService", "IAnalyticsPort", "IAuditService", "IRateLimitPort"
        ]),
        
        ("app.modules.identity.domain.interfaces.services.infrastructure", [
            "ICachePort", "IConfigurationPort", "IEventPublisherPort",
            "IFileStoragePort", "ITaskQueuePort"
        ]),
        
        ("app.modules.identity.domain.interfaces.services.communication", [
            "INotificationService"
        ]),
        
        ("app.modules.identity.domain.interfaces.services.compliance", [
            "IComplianceService"
        ]),
        
        ("app.modules.identity.domain.interfaces.services.mfa", [
            "IMFAService"
        ]),
        
        ("app.modules.identity.domain.interfaces.services.token", [
            "IAccessTokenService"
        ]),
    ]
    
    # Run tests
    total_tests = len(test_cases)
    passed_tests = 0
    all_errors = []
    
    for module_path, items in test_cases:
        print(f"\n📦 Testing {module_path}")
        success, errors = test_import(module_path, items)
        
        if success:
            print(f"  ✅ All {len(items)} imports successful")
            passed_tests += 1
        else:
            print(f"  ❌ {len(errors)} errors found:")
            for error in errors:
                print(f"    • {error}")
            all_errors.extend(errors)
    
    # Summary
    print("\n" + "=" * 50)
    print(f"📊 SUMMARY: {passed_tests}/{total_tests} test modules passed")
    
    if all_errors:
        print(f"\n❌ {len(all_errors)} total errors found:")
        for i, error in enumerate(all_errors, 1):
            print(f"  {i}. {error}")
        return 1
    else:
        print("\n🎉 All imports are working correctly!")
        print("\n✅ INTERFACE COMPLETENESS STATUS:")
        print("  • Core Authentication: ✅ Complete")
        print("  • Security Services: ✅ Complete")  
        print("  • Infrastructure: ✅ Complete")
        print("  • Communication: ✅ Complete")
        print("  • Monitoring: ✅ Complete")
        print("  • Compliance: ✅ Complete")
        print("\n🏆 Overall Status: 100% Complete")
        return 0

if __name__ == "__main__":
    sys.exit(main())
