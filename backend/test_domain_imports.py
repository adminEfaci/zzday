#!/usr/bin/env python3
"""
Domain Layer Import Verification Script

Tests all critical imports in the identity domain layer to ensure
all __init__.py files and import paths are working correctly.
"""

import sys
import os
sys.path.append('.')

def test_imports():
    """Test all critical domain imports."""
    success_count = 0
    total_tests = 0
    
    tests = [
        # Core domain imports
        ("app.modules.identity.domain.enums", "MfaMethod, RiskLevel, UserStatus"),
        ("app.modules.identity.domain.constants", "DefaultValues, SecurityLimits"),
        
        # Entity imports
        ("app.modules.identity.domain.entities.shared", "IdentityEntity, AuditableEntity"),
        ("app.modules.identity.domain.entities.session", "PartialSession, SecurityEvent"),
        ("app.modules.identity.domain.entities.user", "UserProfile, EmergencyContact"),
        ("app.modules.identity.domain.entities.group", "Group, GroupMember"),
        
        # Service interface imports  
        ("app.modules.identity.domain.interfaces.services.mfa", "IMFAService"),
        ("app.modules.identity.domain.interfaces.services.token", "IAccessTokenService"),
        ("app.modules.identity.domain.interfaces.services.authentication", "IPasswordHasher"),
        
        # Service imports
        ("app.modules.identity.domain.services.access_token", "AccessTokenService"),
        ("app.modules.identity.domain.services.mfa", "MFAService"),
        ("app.modules.identity.domain.services.user", "AuthenticationService"),
        
        # Value object imports
        ("app.modules.identity.domain.value_objects", "Email, Password, Username"),
        
        # Repository interface imports
        ("app.modules.identity.domain.interfaces.repositories", "IUserRepository"),
        
        # Error imports
        ("app.modules.identity.domain.errors", "IdentityDomainError, AuthenticationError"),
    ]
    
    for module_path, items in tests:
        total_tests += 1
        try:
            exec(f"from {module_path} import {items}")
            print(f"✅ {module_path} - {items}")
            success_count += 1
        except Exception as e:
            print(f"❌ {module_path} - {items}: {e}")
    
    print(f"\n🎯 Test Results: {success_count}/{total_tests} imports successful")
    
    if success_count == total_tests:
        print("🎉 All domain layer imports are working perfectly!")
        return True
    else:
        print("⚠️  Some imports still need attention")
        return False

if __name__ == "__main__":
    test_imports()
