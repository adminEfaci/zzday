#!/usr/bin/env python3
"""
Agent scope validation script
Ensures agents only modify files within their designated scope
"""

import re
import subprocess
import sys
from pathlib import Path


class AgentScopeValidator:
    """Validates that agents only modify files within their designated scope"""
    
    AGENT_SCOPES = {
        0: {
            'name': 'CI/CD & Build Engineering',
            'allowed_patterns': [
                r'\.github/.*',
                r'ci/.*',
                r'docs/agent-0-reports/.*',
                r'\.pre-commit-config\.yaml',
                r'Makefile',
                r'docker-compose\..*\.yml',
                r'\.env\..*',
                r'requirements.*\.txt',
                r'pyproject\.toml',
                r'pytest\.ini',
                r'mypy\.ini',
                r'\.flake8',
                r'\.ruff\.toml',
            ]
        },
        1: {
            'name': 'Core Architecture & Identity Foundation',
            'allowed_patterns': [
                r'app/core/.*',
                r'app/modules/identity/.*',
                r'app/bootstrap/identity_bootstrap\.py',
                r'app/alembic/versions/.*identity.*\.py',
                r'docs/agent-1-reports/.*',
            ]
        },
        2: {
            'name': 'Domain Models & Business Logic',
            'allowed_patterns': [
                r'app/modules/.*/domain/.*',
                r'app/shared/value_objects/.*',
                r'app/modules/audit/domain/.*',
                r'app/modules/identity/domain/.*',
                r'app/modules/notification/domain/.*',
                r'app/modules/integration/domain/.*',
                r'docs/agent-2-reports/.*',
            ]
        },
        3: {
            'name': 'Infrastructure & Data Layer',
            'allowed_patterns': [
                r'app/modules/.*/infrastructure/.*',
                r'app/alembic/.*',
                r'app/infrastructure/.*',
                r'app/core/database\.py',
                r'app/core/cache\.py',
                r'app/core/repositories/.*',
                r'app/bootstrap/.*_bootstrap\.py',
                r'docs/agent-3-reports/.*',
            ]
        },
        4: {
            'name': 'API & Presentation Layer',
            'allowed_patterns': [
                r'app/modules/.*/presentation/.*',
                r'app/presentation/.*',
                r'app/core/api_docs\.py',
                r'app/config/api_docs\.py',
                r'app/modules/notification/presentation/.*',
                r'docs/agent-4-reports/.*',
            ]
        },
        5: {
            'name': 'Testing & Quality Assurance',
            'allowed_patterns': [
                r'app/tests/.*',
                r'tests/.*',
                r'app/utils/testing\.py',
                r'conftest\.py',
                r'pytest\.ini',
                r'\.coveragerc',
                r'docs/agent-5-reports/.*',
            ]
        },
        6: {
            'name': 'Documentation & Deployment',
            'allowed_patterns': [
                r'docs/.*',
                r'README\.md',
                r'CHANGELOG\.md',
                r'app/config/deployment/.*',
                r'app/config/monitoring/.*',
                r'app/config/scripts/.*',
                r'docs/agent-6-reports/.*',
            ]
        }
    }
    
    def __init__(self):
        self.project_root = Path.cwd()
        self.current_branch = self._get_current_branch()
        self.agent_number = self._extract_agent_number()
    
    def _get_current_branch(self) -> str:
        """Get current git branch"""
        try:
            result = subprocess.run(
                ['git', 'rev-parse', '--abbrev-ref', 'HEAD'],
                capture_output=True,
                text=True,
                cwd=self.project_root, check=False
            )
            return result.stdout.strip()
        except subprocess.SubprocessError:
            return "unknown"
    
    def _extract_agent_number(self) -> int | None:
        """Extract agent number from branch name"""
        if not self.current_branch:
            return None
        
        # Pattern: agent-N-something
        match = re.search(r'agent-(\d+)-', self.current_branch)
        if match:
            return int(match.group(1))
        
        # Pattern: agent-N
        match = re.search(r'agent-(\d+)$', self.current_branch)
        if match:
            return int(match.group(1))
        
        return None
    
    def _get_changed_files(self) -> list[str]:
        """Get list of changed files compared to master"""
        try:
            # Get files changed in current branch vs master
            result = subprocess.run(
                ['git', 'diff', '--name-only', 'origin/master...HEAD'],
                capture_output=True,
                text=True,
                cwd=self.project_root, check=False
            )
            
            if result.returncode != 0:
                # Fallback to just staged files
                result = subprocess.run(
                    ['git', 'diff', '--name-only', '--cached'],
                    capture_output=True,
                    text=True,
                    cwd=self.project_root, check=False
                )
            
            files = [f.strip() for f in result.stdout.split('\n') if f.strip()]
            return files
        except subprocess.SubprocessError:
            return []
    
    def validate_agent_scope(self) -> dict:
        """Validate that changed files are within agent scope"""
        if self.agent_number is None:
            return {
                'valid': True,
                'agent_number': None,
                'message': 'No agent number detected in branch name - allowing all changes',
                'violations': []
            }
        
        if self.agent_number not in self.AGENT_SCOPES:
            return {
                'valid': False,
                'agent_number': self.agent_number,
                'message': f'Unknown agent number: {self.agent_number}',
                'violations': []
            }
        
        agent_config = self.AGENT_SCOPES[self.agent_number]
        changed_files = self._get_changed_files()
        
        violations = []
        allowed_patterns = agent_config['allowed_patterns']
        
        for file_path in changed_files:
            if not self._is_file_allowed(file_path, allowed_patterns):
                violations.append(file_path)
        
        is_valid = len(violations) == 0
        
        return {
            'valid': is_valid,
            'agent_number': self.agent_number,
            'agent_name': agent_config['name'],
            'branch': self.current_branch,
            'changed_files': changed_files,
            'violations': violations,
            'allowed_patterns': allowed_patterns,
            'message': self._generate_message(is_valid, violations, agent_config)
        }
    
    def _is_file_allowed(self, file_path: str, allowed_patterns: list[str]) -> bool:
        """Check if file path matches any allowed pattern"""
        for pattern in allowed_patterns:
            if re.match(pattern, file_path):
                return True
        return False
    
    def _generate_message(self, is_valid: bool, violations: list[str], agent_config: dict) -> str:
        """Generate validation message"""
        if is_valid:
            return f"✅ All changes are within Agent {self.agent_number} scope"
        return f"❌ Agent {self.agent_number} ({agent_config['name']}) has {len(violations)} scope violations"
    
    def print_validation_report(self, result: dict) -> None:
        """Print detailed validation report"""
        print("=" * 60)
        print("🔍 Agent Scope Validation Report")
        print("=" * 60)
        
        print(f"Branch: {result.get('branch', 'unknown')}")
        print(f"Agent: {result.get('agent_number', 'unknown')} - {result.get('agent_name', 'unknown')}")
        print(f"Status: {result['message']}")
        
        changed_files = result.get('changed_files', [])
        if changed_files:
            print(f"\nChanged files ({len(changed_files)}):")
            for file_path in changed_files:
                status = "✅" if file_path not in result.get('violations', []) else "❌"
                print(f"  {status} {file_path}")
        
        violations = result.get('violations', [])
        if violations:
            print(f"\n❌ Scope violations ({len(violations)}):")
            for violation in violations:
                print(f"  - {violation}")
            
            print(f"\n📋 Allowed patterns for Agent {result.get('agent_number')}:")
            for pattern in result.get('allowed_patterns', []):
                print(f"  - {pattern}")
        
        print("\n" + "=" * 60)
    
    def generate_report_file(self, result: dict) -> None:
        """Generate validation report file"""
        report_dir = self.project_root / "docs" / "agent-0-reports" / "scope-validations"
        report_dir.mkdir(parents=True, exist_ok=True)
        
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        report_file = report_dir / f"agent-{self.agent_number}-scope-validation-{timestamp}.md"
        
        report_content = f"""# Agent Scope Validation Report

**Date**: {datetime.now().isoformat()}  
**Agent**: {result.get('agent_number', 'unknown')} - {result.get('agent_name', 'unknown')}  
**Branch**: {result.get('branch', 'unknown')}  
**Status**: {'✅ PASSED' if result['valid'] else '❌ FAILED'}

## Summary
{result['message']}

## Changed Files
"""
        
        changed_files = result.get('changed_files', [])
        if changed_files:
            for file_path in changed_files:
                status = "✅" if file_path not in result.get('violations', []) else "❌"
                report_content += f"- {status} `{file_path}`\n"
        else:
            report_content += "No files changed\n"
        
        violations = result.get('violations', [])
        if violations:
            report_content += f"\n## Scope Violations ({len(violations)})\n"
            for violation in violations:
                report_content += f"- ❌ `{violation}`\n"
        
        report_content += f"""
## Allowed Patterns for Agent {result.get('agent_number')}
"""
        for pattern in result.get('allowed_patterns', []):
            report_content += f"- `{pattern}`\n"
        
        report_content += """
---
*Generated by Agent 0 CI/CD Pipeline*
"""
        
        with open(report_file, 'w') as f:
            f.write(report_content)
        
        print(f"\n📄 Validation report saved: {report_file}")

def main():
    """Main entry point"""
    validator = AgentScopeValidator()
    result = validator.validate_agent_scope()
    
    # Print report
    validator.print_validation_report(result)
    
    # Generate report file
    validator.generate_report_file(result)
    
    # Exit with appropriate code
    sys.exit(0 if result['valid'] else 1)

if __name__ == "__main__":
    main()