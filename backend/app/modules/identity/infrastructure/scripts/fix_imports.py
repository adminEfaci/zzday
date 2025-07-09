#!/usr/bin/env python3
"""
Script to fix imports from application.contracts.ports to domain.interfaces
"""

import re
from pathlib import Path

# Mapping of interfaces to their domain locations
INTERFACE_MAPPINGS = {
    "IUserRepository": "from app.modules.identity.domain.interfaces.repositories.user_repository import IUserRepository",
    "ISessionRepository": "from app.modules.identity.domain.interfaces.repositories.session_repository import ISessionRepository",
    "IRoleRepository": "from app.modules.identity.domain.interfaces.repositories.role_repository import IRoleRepository",
    "IPermissionRepository": "from app.modules.identity.domain.interfaces.repositories.permission_repository import IPermissionRepository",
    "IAuditRepository": "from app.modules.identity.domain.interfaces.repositories.audit_repository import IAuditRepository",
    "IMFARepository": "from app.modules.identity.domain.interfaces.repositories.mfa_repository import IMFARepository",
    "IDeviceRepository": "from app.modules.identity.domain.interfaces.repositories.device_registration_repository import IDeviceRepository",
    "ISecurityRepository": "from app.modules.identity.domain.interfaces.repositories.security_event_repository import ISecurityRepository",
    "IEmergencyContactRepository": "from app.modules.identity.domain.interfaces.repositories.emergency_contact_repository import IEmergencyContactRepository",
    "IPasswordHistoryRepository": "from app.modules.identity.domain.interfaces.repositories.password_history_repository import IPasswordHistoryRepository",
    "IUserProfileRepository": "from app.modules.identity.domain.interfaces.repositories.user_profile_repository import IUserProfileRepository",
    "IGroupRepository": "from app.modules.identity.domain.interfaces.repositories.group_repository import IGroupRepository",
    "INotificationSettingRepository": "from app.modules.identity.domain.interfaces.repositories.notification_setting_repository import INotificationSettingRepository",
    "IUserPreferenceRepository": "from app.modules.identity.domain.interfaces.repositories.user_preference_repository import IUserPreferenceRepository",
    "IAccessTokenRepository": "from app.modules.identity.domain.interfaces.repositories.access_token_repository import IAccessTokenRepository",
    "ILoginAttemptRepository": "from app.modules.identity.domain.interfaces.repositories.login_attempt_repository import ILoginAttemptRepository",
    "IMFADeviceRepository": "from app.modules.identity.domain.interfaces.repositories.mfa_device_repository import IMFADeviceRepository",
    "IMFAChallengeRepository": "from app.modules.identity.domain.interfaces.repositories.mfa_challenge_repository import IMFAChallengeRepository",
    "ICacheService": "from app.modules.identity.domain.interfaces.services.infrastructure.cache_port import ICachePort as ICacheService",
    "IEmailService": "from app.modules.identity.domain.interfaces.services.communication.notification_service import IEmailService",
    "ISMSService": "from app.modules.identity.domain.interfaces.services.communication.notification_service import ISMSService",
    "INotificationService": "from app.modules.identity.domain.interfaces.services.communication.notification_service import INotificationService",
    "ITokenService": "from app.modules.identity.domain.interfaces.services.authentication.token_generator import ITokenGenerator as ITokenService",
    "IPasswordBreachService": "from app.modules.identity.domain.interfaces.services.security.password_breach_service import IPasswordBreachService",
    "IThreatIntelligenceService": "from app.modules.identity.domain.interfaces.services.security.threat_intelligence_service import IThreatIntelligenceService",
    "IGeolocationService": "from app.modules.identity.domain.interfaces.services.security.geolocation_service import IGeolocationService",
    "IStorageService": "from app.modules.identity.domain.interfaces.services.infrastructure.file_storage_port import IFileStoragePort as IStorageService",
    "IEventBus": "from app.modules.identity.domain.interfaces.services.infrastructure.event_publisher_port import IEventPublisherPort as IEventBus",
}

# Method name mappings
METHOD_MAPPINGS = {
    "get_by_id": "find_by_id",
    "get_by_email": "find_by_email", 
    "get_by_username": "find_by_username",
    "get_by_name": "find_by_name",
    "get_user_roles": "find_by_user",
    "get_active_sessions": "find_active_by_user",
    "get_by_token": "find_by_token",
    "get_by_refresh_token": "find_by_refresh_token",
    "get_user_devices": "find_by_user",
    "get_device": "find_by_id",
    "get_user_permissions": "find_by_user",
    "get_direct_permissions": "find_direct_by_user",
    "get_role_permissions": "find_by_role",
}


def fix_imports_in_file(file_path: Path) -> bool:
    """Fix imports in a single file."""
    with open(file_path) as f:
        content = f.read()
    
    original_content = content
    
    # Check if file imports from application.contracts.ports
    if "from app.modules.identity.application.contracts.ports import" not in content:
        return False
    
    # Extract the import statement
    import_match = re.search(
        r'from app\.modules\.identity\.application\.contracts\.ports import \((.*?)\)',
        content,
        re.DOTALL
    )
    
    if not import_match:
        # Try single line import
        import_match = re.search(
            r'from app\.modules\.identity\.application\.contracts\.ports import (.+?)$',
            content,
            re.MULTILINE
        )
    
    if not import_match:
        return False
    
    # Get imported interfaces
    imported_items = import_match.group(1)
    imported_items = [item.strip() for item in imported_items.split(',')]
    
    # Build new imports
    new_imports = []
    for item in imported_items:
        if item in INTERFACE_MAPPINGS:
            new_imports.append(INTERFACE_MAPPINGS[item])
        else:
            print(f"Warning: No mapping for {item} in {file_path}")
    
    # Replace the old import with new imports
    old_import = import_match.group(0)
    new_import_block = '\n'.join(new_imports)
    content = content.replace(old_import, new_import_block)
    
    # Fix method calls
    for old_method, new_method in METHOD_MAPPINGS.items():
        content = re.sub(
            rf'\.{old_method}\b',
            f'.{new_method}',
            content
        )
    
    # Write back if changed
    if content != original_content:
        with open(file_path, 'w') as f:
            f.write(content)
        return True
    
    return False


def main():
    """Main function to fix all imports."""
    identity_path = Path("backend/app/modules/identity")
    
    if not identity_path.exists():
        print("Error: Identity module not found!")
        return
    
    fixed_count = 0
    for py_file in identity_path.glob("**/*.py"):
        if fix_imports_in_file(py_file):
            print(f"Fixed: {py_file}")
            fixed_count += 1
    
    print(f"\nTotal files fixed: {fixed_count}")


if __name__ == "__main__":
    main()