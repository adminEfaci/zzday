#!/usr/bin/env python3
"""GraphQL API Analysis Script for Agent 4"""

import os
import re
import ast
from pathlib import Path
from collections import defaultdict
from datetime import datetime
import json

class GraphQLAnalyzer:
    def __init__(self):
        self.modules_path = Path("app/modules")
        self.presentation_path = Path("app/presentation")
        self.issues = defaultdict(list)
        self.schema_metrics = defaultdict(int)
        self.type_registry = {}
        self.resolver_registry = defaultdict(list)
        self.dataloader_usage = defaultdict(int)
        self.authorization_coverage = defaultdict(int)
        
    def analyze(self):
        print("🔍 Analyzing GraphQL API Layer...")
        
        # Analyze main schema
        self.analyze_main_schema()
        
        # Analyze each module's GraphQL implementation
        for module in self.modules_path.iterdir():
            if module.is_dir() and not module.name.startswith('__'):
                self.analyze_module_graphql(module)
        
        # Check for common issues
        self.check_common_issues()
        
        # Generate report
        self.generate_report()
    
    def analyze_main_schema(self):
        """Analyze the main GraphQL schema composition"""
        schema_file = self.presentation_path / "graphql" / "schema.py"
        if schema_file.exists():
            with open(schema_file) as f:
                content = f.read()
            
            # Check for proper error handling
            if 'try:' in content and 'except ImportError' in content:
                self.schema_metrics['error_handling'] += 1
            
            # Check for context setup
            if 'get_context' in content:
                self.schema_metrics['context_setup'] += 1
            
            # Check for subscription support
            if 'subscription=' in content:
                self.schema_metrics['subscription_support'] += 1
    
    def analyze_module_graphql(self, module_path):
        module_name = module_path.name
        graphql_path = module_path / "presentation" / "graphql"
        
        if not graphql_path.exists():
            self.issues[module_name].append("Missing GraphQL layer")
            return
        
        # Check for non-standard naming
        if module_name == "identity":
            if (graphql_path / "identity_schema.py").exists():
                self.issues[module_name].append("Non-standard schema file name: identity_schema.py (should be schema.py)")
        
        # Analyze schema types
        schemas_path = graphql_path / "schemas"
        schema_path = graphql_path / "schema"  # Identity uses 'schema' instead of 'schemas'
        
        if schemas_path.exists():
            self.analyze_schema_types(schemas_path, module_name)
        elif schema_path.exists():
            self.issues[module_name].append("Non-standard directory name: 'schema' (should be 'schemas')")
            self.analyze_schema_types(schema_path, module_name)
        
        # Analyze resolvers
        resolvers_path = graphql_path / "resolvers"
        if resolvers_path.exists():
            self.analyze_resolvers(resolvers_path, module_name)
        
        # Check for dataloaders
        if (graphql_path / "dataloaders.py").exists() or (graphql_path / "data_loaders.py").exists():
            self.dataloader_usage[module_name] += 1
        
        # Check for middleware
        if (graphql_path / "middleware.py").exists():
            self.schema_metrics['middleware_count'] += 1
    
    def analyze_schema_types(self, schemas_path, module_name):
        # Check for proper type organization
        expected_dirs = ["types", "inputs", "enums"]
        for expected in expected_dirs:
            if not (schemas_path / expected).exists() and not any(schemas_path.glob(f"{expected}.*")):
                self.issues[module_name].append(f"Missing {expected} directory/file in schema")
        
        # Analyze all Python files for type definitions
        for py_file in schemas_path.rglob("*.py"):
            if py_file.name == "__init__.py":
                continue
            
            with open(py_file) as f:
                content = f.read()
            
            # Check for strawberry decorators
            if '@strawberry.type' in content:
                self.schema_metrics['type_count'] += content.count('@strawberry.type')
            
            if '@strawberry.input' in content:
                self.schema_metrics['input_count'] += content.count('@strawberry.input')
            
            if '@strawberry.enum' in content:
                self.schema_metrics['enum_count'] += content.count('@strawberry.enum')
            
            # Check for descriptions
            if 'description=' not in content and 'description:' not in content:
                self.issues[module_name].append(f"Missing descriptions in {py_file.name}")
            
            # Extract type names
            type_classes = re.findall(r'class (\w+).*?:', content)
            for type_class in type_classes:
                if type_class in self.type_registry:
                    self.issues['schema'].append(
                        f"Duplicate type {type_class} in {module_name} and {self.type_registry[type_class]}"
                    )
                self.type_registry[type_class] = module_name
    
    def analyze_resolvers(self, resolvers_path, module_name):
        # Check resolver organization
        resolver_types = ["queries", "mutations", "subscriptions"]
        for resolver_type in resolver_types:
            resolver_dir = resolvers_path / resolver_type
            if resolver_dir.exists():
                self.resolver_registry[module_name].append(resolver_type)
                
                for resolver_file in resolver_dir.glob("*.py"):
                    if resolver_file.name == "__init__.py":
                        continue
                    
                    self.analyze_resolver_file(resolver_file, module_name, resolver_type)
    
    def analyze_resolver_file(self, file_path, module_name, resolver_type):
        with open(file_path) as f:
            content = f.read()
        
        # Check for authorization
        auth_patterns = ['@requires_permission', '@requires_auth', '@authenticated', 'check_permission', 'require_auth']
        has_auth = any(pattern in content for pattern in auth_patterns)
        
        if has_auth:
            self.authorization_coverage[module_name] += 1
        else:
            self.issues[module_name].append(f"No authorization in {file_path.name}")
        
        # Check for dataloader usage
        if 'dataloader' in content.lower() or 'loader' in content:
            self.dataloader_usage[module_name] += 1
        
        # Check for N+1 query potential
        if 'for ' in content and any(term in content for term in ['get_by_id', 'repository.get', '.query']):
            if 'dataloader' not in content.lower():
                self.issues[module_name].append(f"Potential N+1 query in {file_path.name}")
        
        # Check for async patterns
        if 'def ' in content and 'async def' not in content:
            self.issues[module_name].append(f"Non-async resolver in {file_path.name}")
        
        # Check for proper error handling
        if 'GraphQLError' not in content and resolver_type == "mutations":
            self.issues[module_name].append(f"No GraphQLError usage in mutation {file_path.name}")
        
        # Check for pagination in list queries
        if resolver_type == "queries" and ('list' in file_path.name.lower() or 'get_all' in content):
            if not any(term in content for term in ['Connection', 'first:', 'last:', 'limit', 'pagination']):
                self.issues[module_name].append(f"No pagination in list query {file_path.name}")
    
    def check_common_issues(self):
        # Check for Connection/Edge pattern
        has_connection_pattern = False
        for type_name in self.type_registry:
            if 'Connection' in type_name or 'Edge' in type_name:
                has_connection_pattern = True
                break
        
        if not has_connection_pattern:
            self.issues['schema'].append("No Connection/Edge pattern implementation found")
        
        # Check for error types
        has_error_types = any('Error' in type_name for type_name in self.type_registry)
        if not has_error_types:
            self.issues['schema'].append("No error types defined")
        
        # Check for dataloader implementation
        total_modules = len([m for m in self.modules_path.iterdir() if m.is_dir() and not m.name.startswith('__')])
        if self.dataloader_usage and len(self.dataloader_usage) < total_modules:
            self.issues['performance'].append(f"Only {len(self.dataloader_usage)}/{total_modules} modules use dataloaders")
    
    def generate_report(self):
        report_path = Path("docs/agent-4-reports/daily/graphql_analysis.md")
        report_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Also save as JSON for programmatic access
        json_report = {
            "timestamp": datetime.now().isoformat(),
            "metrics": dict(self.schema_metrics),
            "type_registry": self.type_registry,
            "resolver_coverage": {k: v for k, v in self.resolver_registry.items()},
            "dataloader_usage": dict(self.dataloader_usage),
            "authorization_coverage": dict(self.authorization_coverage),
            "issues": {k: v for k, v in self.issues.items() if v}
        }
        
        json_path = Path("docs/agent-4-reports/daily/graphql_analysis.json")
        with open(json_path, "w") as f:
            json.dump(json_report, f, indent=2)
        
        with open(report_path, "w") as f:
            f.write("# GraphQL API Analysis Report\n\n")
            f.write(f"Generated: {datetime.now()}\n\n")
            
            # Summary
            f.write("## Summary\n\n")
            f.write(f"- Total Types Defined: {self.schema_metrics.get('type_count', 0)}\n")
            f.write(f"- Total Inputs Defined: {self.schema_metrics.get('input_count', 0)}\n")
            f.write(f"- Total Enums Defined: {self.schema_metrics.get('enum_count', 0)}\n")
            f.write(f"- Modules with Dataloaders: {len(self.dataloader_usage)}\n")
            f.write(f"- Modules with Authorization: {len(self.authorization_coverage)}\n")
            f.write(f"- Total Issues: {sum(len(issues) for issues in self.issues.values())}\n\n")
            
            # Module Coverage
            f.write("## Module Coverage\n\n")
            f.write("| Module | Queries | Mutations | Subscriptions | Dataloaders | Authorization |\n")
            f.write("|--------|---------|-----------|---------------|-------------|---------------|\n")
            
            for module in ['identity', 'audit', 'notification', 'integration']:
                resolvers = self.resolver_registry.get(module, [])
                has_queries = "✅" if "queries" in resolvers else "❌"
                has_mutations = "✅" if "mutations" in resolvers else "❌"
                has_subscriptions = "✅" if "subscriptions" in resolvers else "❌"
                has_dataloaders = "✅" if module in self.dataloader_usage else "❌"
                has_auth = "✅" if module in self.authorization_coverage else "❌"
                
                f.write(f"| {module} | {has_queries} | {has_mutations} | {has_subscriptions} | {has_dataloaders} | {has_auth} |\n")
            
            # Critical Issues
            f.write("\n## Critical Issues\n\n")
            critical_issues = []
            
            for module, issues in self.issues.items():
                for issue in issues:
                    if any(term in issue.lower() for term in ['n+1', 'authorization', 'pagination', 'error']):
                        critical_issues.append(f"- **{module}**: {issue}")
            
            if critical_issues:
                f.write("\n".join(critical_issues))
            else:
                f.write("No critical issues found.\n")
            
            # All Issues by Module
            f.write("\n\n## All Issues by Module\n\n")
            for module, issues in sorted(self.issues.items()):
                if issues:
                    f.write(f"### {module}\n\n")
                    for issue in issues:
                        f.write(f"- ⚠️ {issue}\n")
                    f.write("\n")
            
            # Recommendations
            f.write("## Recommendations\n\n")
            f.write("1. **Standardization**: Rename identity_schema.py to schema.py and 'schema' directory to 'schemas'\n")
            f.write("2. **Authorization**: Implement consistent authorization decorators across all resolvers\n")
            f.write("3. **Performance**: Add dataloaders to all modules to prevent N+1 queries\n")
            f.write("4. **Pagination**: Implement Connection/Edge pattern for all list queries\n")
            f.write("5. **Error Handling**: Use GraphQLError consistently in all mutations\n")
            f.write("6. **Documentation**: Add descriptions to all types, fields, and arguments\n")
            f.write("7. **Monitoring**: Implement query complexity analysis and rate limiting\n")
            
        print(f"✅ Analysis complete! Reports saved to:")
        print(f"   - {report_path}")
        print(f"   - {json_path}")

if __name__ == "__main__":
    analyzer = GraphQLAnalyzer()
    analyzer.analyze()