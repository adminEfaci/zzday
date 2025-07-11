#!/usr/bin/env python3
"""
Agent 0 Pipeline: Systematic Service Interface Import Fixer

This script implements an automated pipeline to systematically fix missing
service interface imports in the identity module command and query files.
"""

import os
import re
from pathlib import Path
from typing import Dict, List, Set

class ServiceInterfaceImportFixer:
    """Agent 0 pipeline for fixing service interface imports."""
    
    def __init__(self):
        self.base_import_path = "from app.modules.identity.domain.interfaces.services import ("
        self.service_interfaces_map = {
            'IAuditService': 'IAuditService',
            'ITokenBlocklistService': 'ITokenBlocklistService', 
            'IDeviceFingerprintService': 'IDeviceFingerprintService',
            'IRateLimitService': 'IRateLimitService',
            'IEmailVerificationTokenRepository': 'IEmailVerificationTokenRepository',
            'IUserRoleRepository': 'IUserRoleRepository',
            'IUserPermissionRepository': 'IUserPermissionRepository',
            'ITemplateRepository': 'ITemplateRepository',
            'IEscalationRepository': 'IEscalationRepository',
            'IIncidentRepository': 'IIncidentRepository',
            'ICallService': 'ICallService',
            'INotificationHistoryRepository': 'INotificationHistoryRepository',
            'IBackupService': 'IBackupService',
            'IContactTestRepository': 'IContactTestRepository',
            'IVerificationRepository': 'IVerificationRepository',
            'ILocationHistoryRepository': 'ILocationHistoryRepository',
            'IRiskAssessmentRepository': 'IRiskAssessmentRepository',
            'IDevicePolicyRepository': 'IDevicePolicyRepository',
            'ITokenRepository': 'ITokenRepository',
            'IPolicyTemplateRepository': 'IPolicyTemplateRepository',
            'IComplianceRepository': 'IComplianceRepository',
            'IDeviceManagementService': 'IDeviceManagementService',
            'ITrustAssessmentRepository': 'ITrustAssessmentRepository',
            'IRemoteWipeService': 'IRemoteWipeService',
            'IFileStorageService': 'IFileStorageService',
            'IPasswordResetTokenRepository': 'IPasswordResetTokenRepository',
            'IPasswordResetAttemptRepository': 'IPasswordResetAttemptRepository',
            'IPasswordPolicyRepository': 'IPasswordPolicyRepository',
            'IBreachDetectionService': 'IBreachDetectionService',
            'IAccessRepository': 'IAccessRepository',
            'IMonitoringRepository': 'IMonitoringRepository',
            'IKeyRepository': 'IKeyRepository',
            'ICertificateRepository': 'ICertificateRepository',
            'IEncryptionRepository': 'IEncryptionRepository',
            'IForensicsRepository': 'IForensicsRepository',
            'IEvidenceRepository': 'IEvidenceRepository',
            'IMfaRepository': 'IMfaRepository',
            'IBackupCodeRepository': 'IBackupCodeRepository',
            'IPasswordRepository': 'IPasswordRepository',
            'IBreachRepository': 'IBreachRepository',
            'IRiskRepository': 'IRiskRepository',
            'IPolicyRepository': 'IPolicyRepository',
            'IRuleRepository': 'IRuleRepository',
            'IThreatRepository': 'IThreatRepository',
            'IAvatarGenerationService': 'IAvatarGenerationService',
            'IAuditLogRepository': 'IAuditLogRepository',
            'IImageProcessingService': 'IImageProcessingService',
            'IDataOwnershipRepository': 'IDataOwnershipRepository',
            'IPhoneService': 'IPhoneService',
            'IUserPreferencesRepository': 'IUserPreferencesRepository',
            'IFeatureFlagService': 'IFeatureFlagService',
            'ISecurityEventRepository': 'ISecurityEventRepository',
            'IConfigurationPort': 'IConfigurationPort',
            'ICachePort': 'ICachePort',
            'IAuthorizationRepository': 'IAuthorizationRepository',
            'IPreferencesRepository': 'IPreferencesRepository',
        }
    
    def scan_file_for_missing_interfaces(self, file_path: str) -> Set[str]:
        """Scan a file for missing service interface imports."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            missing_interfaces = set()
            
            # Check for usage of each interface
            for interface_name in self.service_interfaces_map.keys():
                # Look for type annotations and variable usage
                patterns = [
                    rf'\b{interface_name}\b',  # Direct usage
                    rf': {interface_name}',    # Type annotation
                    rf'{interface_name}\]',    # List/Optional type
                    rf'{interface_name},',     # In parameter list
                ]
                
                for pattern in patterns:
                    if re.search(pattern, content):
                        # Check if it's already imported
                        if f"from app.modules.identity.domain.interfaces.services import" not in content or interface_name not in content.split("from app.modules.identity.domain.interfaces.services import")[0]:
                            missing_interfaces.add(interface_name)
                        break
            
            return missing_interfaces
            
        except Exception as e:
            print(f"Error scanning {file_path}: {e}")
            return set()
    
    def add_missing_imports(self, file_path: str, missing_interfaces: Set[str]) -> bool:
        """Add missing service interface imports to a file."""
        if not missing_interfaces:
            return False
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Check if we already have service interface imports
            if "from app.modules.identity.domain.interfaces.services import (" in content:
                # Update existing import
                import_pattern = r'(from app\.modules\.identity\.domain\.interfaces\.services import \()(.*?)(\))'
                match = re.search(import_pattern, content, re.DOTALL)
                
                if match:
                    existing_imports = set()
                    import_content = match.group(2)
                    for line in import_content.split('\n'):
                        line = line.strip().replace(',', '')
                        if line and not line.startswith('#'):
                            existing_imports.add(line)
                    
                    # Add missing interfaces
                    all_imports = existing_imports.union(missing_interfaces)
                    sorted_imports = sorted(all_imports)
                    
                    # Format new import block
                    new_import_content = "from app.modules.identity.domain.interfaces.services import (\n"
                    for interface in sorted_imports:
                        new_import_content += f"    {interface},\n"
                    new_import_content += ")"
                    
                    # Replace the import block
                    content = content.replace(match.group(0), new_import_content)
                
            else:
                # Add new import block
                sorted_interfaces = sorted(missing_interfaces)
                new_import = "from app.modules.identity.domain.interfaces.services import (\n"
                for interface in sorted_interfaces:
                    new_import += f"    {interface},\n"
                new_import += ")\n"
                
                # Find the best place to insert - after domain imports
                domain_import_pattern = r'(from app\.modules\.identity\.domain\..*?\n)'
                matches = list(re.finditer(domain_import_pattern, content))
                
                if matches:
                    # Insert after the last domain import
                    last_match = matches[-1]
                    insert_pos = last_match.end()
                    content = content[:insert_pos] + new_import + content[insert_pos:]
                else:
                    # Insert after any import section
                    import_section_pattern = r'(from .*? import .*?\n)'
                    matches = list(re.finditer(import_section_pattern, content))
                    if matches:
                        last_match = matches[-1]
                        insert_pos = last_match.end()
                        content = content[:insert_pos] + new_import + content[insert_pos:]
            
            # Write updated content
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            return True
            
        except Exception as e:
            print(f"Error updating {file_path}: {e}")
            return False
    
    def process_file(self, file_path: str) -> bool:
        """Process a single file."""
        print(f"Processing: {file_path}")
        
        missing_interfaces = self.scan_file_for_missing_interfaces(file_path)
        if missing_interfaces:
            print(f"  Found missing interfaces: {', '.join(sorted(missing_interfaces))}")
            success = self.add_missing_imports(file_path, missing_interfaces)
            if success:
                print(f"  ✓ Successfully added imports")
                return True
            else:
                print(f"  ✗ Failed to add imports")
                return False
        else:
            print(f"  ✓ No missing interfaces found")
            return True
    
    def run_pipeline(self) -> Dict[str, int]:
        """Run the Agent 0 pipeline."""
        print("🤖 Agent 0 Pipeline: Service Interface Import Fixer")
        print("=" * 60)
        
        results = {
            'total_files': 0,
            'processed_files': 0,
            'updated_files': 0,
            'failed_files': 0
        }
        
        # Target directories
        target_dirs = [
            "backend/app/modules/identity/application/commands",
            "backend/app/modules/identity/application/queries",
        ]
        
        for target_dir in target_dirs:
            if not os.path.exists(target_dir):
                continue
                
            print(f"\n📁 Processing directory: {target_dir}")
            
            for file_path in Path(target_dir).rglob("*.py"):
                if file_path.is_file() and not file_path.name.startswith('__'):
                    results['total_files'] += 1
                    
                    if self.process_file(str(file_path)):
                        results['processed_files'] += 1
                        # Check if file was actually updated
                        missing_before = self.scan_file_for_missing_interfaces(str(file_path))
                        if not missing_before:  # No more missing interfaces
                            results['updated_files'] += 1
                    else:
                        results['failed_files'] += 1
        
        print("\n" + "=" * 60)
        print("📊 Pipeline Results:")
        print(f"  Total files: {results['total_files']}")
        print(f"  Processed files: {results['processed_files']}")
        print(f"  Updated files: {results['updated_files']}")
        print(f"  Failed files: {results['failed_files']}")
        
        return results

def main():
    """Main entry point."""
    fixer = ServiceInterfaceImportFixer()
    results = fixer.run_pipeline()
    
    if results['failed_files'] == 0:
        print("\n✅ Agent 0 Pipeline completed successfully!")
    else:
        print(f"\n⚠️  Agent 0 Pipeline completed with {results['failed_files']} failures")
    
    return 0 if results['failed_files'] == 0 else 1

if __name__ == "__main__":
    exit(main()) 