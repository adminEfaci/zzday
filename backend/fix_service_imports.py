#!/usr/bin/env python3
"""
Script to fix missing service interface imports in identity command files.
This script systematically adds the required imports to all files that need them.
"""

import os
import re
from pathlib import Path

def add_service_interface_imports(file_path):
    """Add missing service interface imports to a file."""
    
    # Read the file
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Define the imports to add
    service_imports = """
# Service interface imports
from app.modules.identity.domain.interfaces.services import (
    IAuditService,
    ITokenBlocklistService,
    IDeviceFingerprintService,
    IRateLimitService,
    IEmailVerificationTokenRepository,
    IUserRoleRepository,
    IUserPermissionRepository,
    ITemplateRepository,
    IEscalationRepository,
    IIncidentRepository,
    ICallService,
    INotificationHistoryRepository,
    IBackupService,
    IContactTestRepository,
    IVerificationRepository,
    ILocationHistoryRepository,
    IRiskAssessmentRepository,
    IDevicePolicyRepository,
    ITokenRepository,
    IPolicyTemplateRepository,
    IComplianceRepository,
    IDeviceManagementService,
    ITrustAssessmentRepository,
    IRemoteWipeService,
    IFileStorageService,
    IPasswordResetTokenRepository,
    IPasswordResetAttemptRepository,
    IPasswordPolicyRepository,
    IBreachDetectionService,
    IAccessRepository,
    IMonitoringRepository,
    IKeyRepository,
    ICertificateRepository,
    IEncryptionRepository,
    IForensicsRepository,
    IEvidenceRepository,
    IMfaRepository,
    IBackupCodeRepository,
    IPasswordRepository,
    IBreachRepository,
    IRiskRepository,
    IPolicyRepository,
    IRuleRepository,
    IThreatRepository,
    IAvatarGenerationService,
    IAuditLogRepository,
    IImageProcessingService,
    IDataOwnershipRepository,
    IPhoneService,
    IUserPreferencesRepository,
    IFeatureFlagService,
    ISecurityEventRepository,
    IConfigurationPort,
    ICachePort,
    IAuthorizationRepository,
    IPreferencesRepository,
)"""
    
    # Skip if imports already exist
    if "from app.modules.identity.domain.interfaces.services import" in content:
        return False
    
    # Find the import section
    import_section_pattern = r'(from app\.modules\.identity\.domain\.errors import.*?\n)'
    match = re.search(import_section_pattern, content, re.DOTALL)
    
    if match:
        # Add the service imports after the errors import
        new_content = content.replace(
            match.group(1),
            match.group(1) + service_imports + '\n'
        )
        
        # Write back to file
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(new_content)
        
        return True
    
    return False

def fix_missing_any_imports(file_path):
    """Fix missing Any imports in files."""
    
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Check if Any is used but not imported
    if ': Any' in content or 'Any]' in content or 'Any,' in content:
        if 'from typing import' in content:
            # Add Any to existing typing import
            typing_import_pattern = r'from typing import ([^)]+)'
            match = re.search(typing_import_pattern, content)
            if match and 'Any' not in match.group(1):
                new_import = f"from typing import {match.group(1)}, Any"
                content = content.replace(match.group(0), new_import)
        else:
            # Add new typing import
            first_import_pattern = r'(from [^)]+import[^)]+\n)'
            match = re.search(first_import_pattern, content)
            if match:
                content = content.replace(
                    match.group(1),
                    match.group(1) + 'from typing import Any\n'
                )
    
    # Write back to file
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)

def fix_missing_timedelta_imports(file_path):
    """Fix missing timedelta imports in files."""
    
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Check if timedelta is used but not imported
    if 'timedelta(' in content or 'timedelta ' in content:
        if 'from datetime import' in content:
            # Add timedelta to existing datetime import
            datetime_import_pattern = r'from datetime import ([^)]+)'
            match = re.search(datetime_import_pattern, content)
            if match and 'timedelta' not in match.group(1):
                new_import = f"from datetime import {match.group(1)}, timedelta"
                content = content.replace(match.group(0), new_import)
        else:
            # Add new datetime import
            first_import_pattern = r'(from [^)]+import[^)]+\n)'
            match = re.search(first_import_pattern, content)
            if match:
                content = content.replace(
                    match.group(1),
                    match.group(1) + 'from datetime import timedelta\n'
                )
    
    # Write back to file
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)

def main():
    """Main function to process all files."""
    
    base_path = Path("backend/app/modules/identity/application/commands")
    query_path = Path("backend/app/modules/identity/application/queries")
    
    # Process command files
    if base_path.exists():
        for file_path in base_path.rglob("*.py"):
            if file_path.is_file():
                print(f"Processing {file_path}")
                add_service_interface_imports(file_path)
                fix_missing_any_imports(file_path)
                fix_missing_timedelta_imports(file_path)
    
    # Process query files
    if query_path.exists():
        for file_path in query_path.rglob("*.py"):
            if file_path.is_file():
                print(f"Processing {file_path}")
                add_service_interface_imports(file_path)
                fix_missing_any_imports(file_path)
                fix_missing_timedelta_imports(file_path)
    
    # Process other files with Any/timedelta issues
    audit_files = [
        "backend/app/modules/audit/application/commands/update_retention_policy_command.py",
        "backend/app/modules/audit/application/queries/get_audit_log_query.py",
        "backend/app/modules/audit/application/queries/get_audit_report_query.py",
        "backend/app/modules/audit/infrastructure/models/audit_models.py",
        "backend/app/modules/audit/presentation/graphql/schemas/inputs/audit_search_input.py",
        "backend/app/modules/identity/domain/services/role/role_factory.py",
    ]
    
    for file_path in audit_files:
        if os.path.exists(file_path):
            print(f"Processing {file_path}")
            fix_missing_any_imports(file_path)
            fix_missing_timedelta_imports(file_path)

if __name__ == "__main__":
    main() 