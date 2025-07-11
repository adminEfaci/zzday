#!/usr/bin/env python3
"""
Build health dashboard generator
Provides real-time visibility into CI/CD pipeline health
"""

import json
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any


class BuildDashboard:
    """Generate build health dashboard for CI/CD monitoring"""
    
    def __init__(self, project_root: Path = None):
        self.project_root = project_root or Path.cwd()
        self.reports_dir = self.project_root / "ci" / "reports"
        self.dashboard_dir = self.project_root / "docs" / "agent-0-reports" / "dashboard"
        self.dashboard_dir.mkdir(parents=True, exist_ok=True)
    
    def gather_build_metrics(self) -> dict[str, Any]:
        """Gather current build and quality metrics"""
        metrics = {
            'timestamp': datetime.now().isoformat(),
            'git_info': self._get_git_info(),
            'test_metrics': self._get_test_metrics(),
            'coverage_metrics': self._get_coverage_metrics(),
            'quality_metrics': self._get_quality_metrics(),
            'security_metrics': self._get_security_metrics(),
            'build_status': self._get_build_status(),
            'agent_status': self._get_agent_status()
        }
        return metrics
    
    def _get_git_info(self) -> dict[str, Any]:
        """Get git repository information"""
        try:
            # Current branch
            branch_result = subprocess.run(
                ['git', 'rev-parse', '--abbrev-ref', 'HEAD'],
                capture_output=True, text=True, cwd=self.project_root, check=False
            )
            current_branch = branch_result.stdout.strip()
            
            # Latest commit
            commit_result = subprocess.run(
                ['git', 'log', '-1', '--format=%H|%s|%an|%ad'],
                capture_output=True, text=True, cwd=self.project_root, check=False
            )
            if commit_result.stdout:
                commit_hash, commit_msg, author, date = commit_result.stdout.strip().split('|')
            else:
                commit_hash = commit_msg = author = date = "unknown"
            
            # Get all agent branches
            branch_list_result = subprocess.run(
                ['git', 'branch', '-a'],
                capture_output=True, text=True, cwd=self.project_root, check=False
            )
            all_branches = [
                line.strip().replace('* ', '').replace('remotes/origin/', '')
                for line in branch_list_result.stdout.split('\n')
                if line.strip() and 'agent-' in line
            ]
            
            return {
                'current_branch': current_branch,
                'latest_commit': {
                    'hash': commit_hash[:8],
                    'message': commit_msg,
                    'author': author,
                    'date': date
                },
                'agent_branches': list(set(all_branches))
            }
        except Exception as e:
            return {'error': str(e)}
    
    def _get_test_metrics(self) -> dict[str, Any]:
        """Get test execution metrics"""
        try:
            # Run basic test collection
            result = subprocess.run(
                ['python', '-m', 'pytest', '--collect-only', '--quiet'],
                capture_output=True, text=True, cwd=self.project_root, timeout=30, check=False
            )
            
            # Parse test count from output
            test_count = 0
            for line in result.stdout.split('\n'):
                if 'tests collected' in line:
                    test_count = int(line.split()[0])
                    break
            
            # Try to get test results from last run
            test_status = "unknown"
            if result.returncode == 0:
                test_status = "collection_passed"
            else:
                test_status = "collection_failed"
            
            return {
                'total_tests': test_count,
                'collection_status': test_status,
                'last_run': datetime.now().isoformat()
            }
        except subprocess.TimeoutExpired:
            return {'error': 'Test collection timed out'}
        except Exception as e:
            return {'error': str(e)}
    
    def _get_coverage_metrics(self) -> dict[str, Any]:
        """Get test coverage metrics"""
        coverage_file = self.project_root / "coverage.json"
        if coverage_file.exists():
            try:
                with open(coverage_file) as f:
                    coverage_data = json.load(f)
                return {
                    'total_coverage': coverage_data.get('totals', {}).get('percent_covered', 0),
                    'lines_covered': coverage_data.get('totals', {}).get('covered_lines', 0),
                    'lines_total': coverage_data.get('totals', {}).get('num_statements', 0),
                    'last_updated': datetime.now().isoformat()
                }
            except Exception as e:
                return {'error': f'Failed to parse coverage: {e!s}'}
        
        return {'total_coverage': 0, 'status': 'no_coverage_data'}
    
    def _get_quality_metrics(self) -> dict[str, Any]:
        """Get code quality metrics"""
        try:
            # Run ruff check
            ruff_result = subprocess.run(
                ['python', '-m', 'ruff', 'check', 'app', '--format', 'json'],
                capture_output=True, text=True, cwd=self.project_root, timeout=30, check=False
            )
            
            violations = []
            if ruff_result.stdout:
                try:
                    violations = json.loads(ruff_result.stdout)
                except json.JSONDecodeError:
                    pass
            
            return {
                'ruff_violations': len(violations),
                'ruff_status': 'passed' if len(violations) == 0 else 'failed',
                'last_checked': datetime.now().isoformat()
            }
        except subprocess.TimeoutExpired:
            return {'error': 'Quality check timed out'}
        except Exception as e:
            return {'error': str(e)}
    
    def _get_security_metrics(self) -> dict[str, Any]:
        """Get security scan metrics"""
        try:
            # Run bandit security scan
            bandit_result = subprocess.run(
                ['python', '-m', 'bandit', '-r', 'app', '-f', 'json'],
                capture_output=True, text=True, cwd=self.project_root, timeout=60, check=False
            )
            
            security_issues = []
            if bandit_result.stdout:
                try:
                    bandit_data = json.loads(bandit_result.stdout)
                    security_issues = bandit_data.get('results', [])
                except json.JSONDecodeError:
                    pass
            
            high_severity = len([i for i in security_issues if i.get('issue_severity') == 'HIGH'])
            medium_severity = len([i for i in security_issues if i.get('issue_severity') == 'MEDIUM'])
            
            return {
                'total_issues': len(security_issues),
                'high_severity': high_severity,
                'medium_severity': medium_severity,
                'status': 'passed' if high_severity == 0 else 'failed',
                'last_scanned': datetime.now().isoformat()
            }
        except subprocess.TimeoutExpired:
            return {'error': 'Security scan timed out'}
        except Exception as e:
            return {'error': str(e)}
    
    def _get_build_status(self) -> dict[str, Any]:
        """Get overall build status"""
        try:
            # Try to import the app to check if it's buildable
            import_result = subprocess.run(
                ['python', '-c', 'import app; print("OK")'],
                capture_output=True, text=True, cwd=self.project_root, timeout=10, check=False
            )
            
            build_status = 'passed' if import_result.returncode == 0 else 'failed'
            
            return {
                'status': build_status,
                'last_build': datetime.now().isoformat(),
                'build_time': '< 1 min'  # Placeholder
            }
        except subprocess.TimeoutExpired:
            return {'status': 'failed', 'error': 'Build timed out'}
        except Exception as e:
            return {'status': 'failed', 'error': str(e)}
    
    def _get_agent_status(self) -> dict[str, Any]:
        """Get agent-specific status"""
        agent_status = {}
        
        # Check each agent's directory for reports
        for agent_num in range(7):  # Agents 0-6
            agent_dir = self.project_root / "docs" / f"agent-{agent_num}-reports"
            if agent_dir.exists():
                agent_status[f"agent_{agent_num}"] = {
                    'reports_available': True,
                    'last_activity': self._get_last_modified(agent_dir)
                }
            else:
                agent_status[f"agent_{agent_num}"] = {
                    'reports_available': False,
                    'last_activity': None
                }
        
        return agent_status
    
    def _get_last_modified(self, directory: Path) -> str | None:
        """Get last modified time for directory"""
        try:
            latest_time = 0
            for file_path in directory.rglob("*"):
                if file_path.is_file():
                    mtime = file_path.stat().st_mtime
                    latest_time = max(latest_time, mtime)
            
            if latest_time > 0:
                return datetime.fromtimestamp(latest_time).isoformat()
            return None
        except Exception:
            return None
    
    def generate_dashboard(self) -> str:
        """Generate HTML dashboard"""
        metrics = self.gather_build_metrics()
        
        # Generate HTML content
        html_content = self._generate_html_dashboard(metrics)
        
        # Save dashboard
        dashboard_file = self.dashboard_dir / "build-health.html"
        with open(dashboard_file, 'w') as f:
            f.write(html_content)
        
        # Save metrics as JSON
        metrics_file = self.dashboard_dir / "metrics.json"
        with open(metrics_file, 'w') as f:
            json.dump(metrics, f, indent=2)
        
        return str(dashboard_file)
    
    def _generate_html_dashboard(self, metrics: dict[str, Any]) -> str:
        """Generate HTML dashboard content"""
        git_info = metrics.get('git_info', {})
        test_metrics = metrics.get('test_metrics', {})
        coverage_metrics = metrics.get('coverage_metrics', {})
        quality_metrics = metrics.get('quality_metrics', {})
        security_metrics = metrics.get('security_metrics', {})
        build_status = metrics.get('build_status', {})
        
        # Overall health color
        health_color = self._get_health_color(metrics)
        
        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ezzday CI/CD Dashboard</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .header {{
            background: {health_color};
            color: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
        }}
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }}
        .metric-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .metric-title {{
            font-size: 18px;
            font-weight: bold;
            margin-bottom: 10px;
            color: #333;
        }}
        .metric-value {{
            font-size: 24px;
            font-weight: bold;
            margin: 10px 0;
        }}
        .status-passed {{ color: #28a745; }}
        .status-failed {{ color: #dc3545; }}
        .status-warning {{ color: #ffc107; }}
        .status-unknown {{ color: #6c757d; }}
        .progress-bar {{
            width: 100%;
            height: 20px;
            background-color: #e9ecef;
            border-radius: 10px;
            overflow: hidden;
            margin: 10px 0;
        }}
        .progress-fill {{
            height: 100%;
            background-color: #28a745;
            transition: width 0.3s ease;
        }}
        .agent-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }}
        .agent-card {{
            background: white;
            padding: 15px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .timestamp {{
            color: #6c757d;
            font-size: 12px;
            margin-top: 20px;
        }}
        .error {{
            color: #dc3545;
            font-style: italic;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🚀 Ezzday CI/CD Dashboard</h1>
        <p>Real-time build health and quality metrics</p>
        <p><strong>Branch:</strong> {git_info.get('current_branch', 'unknown')}</p>
        <p><strong>Last Updated:</strong> {metrics.get('timestamp', 'unknown')}</p>
    </div>
    
    <div class="metrics-grid">
        <div class="metric-card">
            <div class="metric-title">🏗️ Build Status</div>
            <div class="metric-value status-{build_status.get('status', 'unknown')}">
                {build_status.get('status', 'unknown').upper()}
            </div>
            <div>Last Build: {build_status.get('last_build', 'never')}</div>
            {('<div class="error">Error: ' + build_status.get('error', '') + '</div>') if build_status.get('error') else ''}
        </div>
        
        <div class="metric-card">
            <div class="metric-title">🧪 Test Coverage</div>
            <div class="metric-value">{coverage_metrics.get('total_coverage', 0):.1f}%</div>
            <div class="progress-bar">
                <div class="progress-fill" style="width: {coverage_metrics.get('total_coverage', 0)}%"></div>
            </div>
            <div>Lines: {coverage_metrics.get('lines_covered', 0)}/{coverage_metrics.get('lines_total', 0)}</div>
        </div>
        
        <div class="metric-card">
            <div class="metric-title">📊 Tests</div>
            <div class="metric-value">{test_metrics.get('total_tests', 0)}</div>
            <div class="status-{test_metrics.get('collection_status', 'unknown').replace('_', '-')}">
                Collection: {test_metrics.get('collection_status', 'unknown').replace('_', ' ').title()}
            </div>
        </div>
        
        <div class="metric-card">
            <div class="metric-title">🔍 Code Quality</div>
            <div class="metric-value status-{quality_metrics.get('ruff_status', 'unknown')}">
                {quality_metrics.get('ruff_violations', 0)} issues
            </div>
            <div>Ruff: {quality_metrics.get('ruff_status', 'unknown').title()}</div>
        </div>
        
        <div class="metric-card">
            <div class="metric-title">🔒 Security</div>
            <div class="metric-value status-{security_metrics.get('status', 'unknown')}">
                {security_metrics.get('total_issues', 0)} issues
            </div>
            <div>High: {security_metrics.get('high_severity', 0)}, Medium: {security_metrics.get('medium_severity', 0)}</div>
        </div>
        
        <div class="metric-card">
            <div class="metric-title">🌿 Git Info</div>
            <div><strong>Commit:</strong> {git_info.get('latest_commit', {}).get('hash', 'unknown')}</div>
            <div><strong>Author:</strong> {git_info.get('latest_commit', {}).get('author', 'unknown')}</div>
            <div><strong>Message:</strong> {git_info.get('latest_commit', {}).get('message', 'unknown')[:50]}...</div>
        </div>
    </div>
    
    <div class="metric-card">
        <div class="metric-title">👥 Agent Status</div>
        <div class="agent-grid">
'''
        
        # Add agent status cards
        agent_names = [
            "CI/CD & Build",
            "Core Architecture",
            "Domain Logic",
            "Infrastructure",
            "Presentation",
            "Testing",
            "Documentation"
        ]
        
        agent_status = metrics.get('agent_status', {})
        for i in range(7):
            agent_key = f"agent_{i}"
            agent_info = agent_status.get(agent_key, {})
            status = "✅" if agent_info.get('reports_available') else "⏳"
            
            html += f'''
            <div class="agent-card">
                <div><strong>Agent {i}</strong></div>
                <div>{agent_names[i]}</div>
                <div>{status}</div>
                <div style="font-size: 12px; color: #6c757d;">
                    {agent_info.get('last_activity', 'No activity')[:16] if agent_info.get('last_activity') else 'No activity'}
                </div>
            </div>
            '''
        
        html += f'''
        </div>
    </div>
    
    <div class="timestamp">
        Dashboard generated at {metrics.get('timestamp', 'unknown')}
        <br>
        Next update: Auto-refresh every 5 minutes
    </div>
    
    <script>
        // Auto-refresh every 5 minutes
        setTimeout(() => {{
            location.reload();
        }}, 300000);
    </script>
</body>
</html>'''
        
        return html
    
    def _get_health_color(self, metrics: dict[str, Any]) -> str:
        """Determine overall health color"""
        build_status = metrics.get('build_status', {}).get('status', 'unknown')
        coverage = metrics.get('coverage_metrics', {}).get('total_coverage', 0)
        quality_status = metrics.get('quality_metrics', {}).get('ruff_status', 'unknown')
        security_status = metrics.get('security_metrics', {}).get('status', 'unknown')
        
        if build_status == 'failed':
            return '#dc3545'  # Red
        if coverage < 50 or quality_status == 'failed' or security_status == 'failed':
            return '#ffc107'  # Yellow
        if build_status == 'passed' and coverage >= 80:
            return '#28a745'  # Green
        return '#17a2b8'  # Blue
    
    def generate_markdown_report(self) -> str:
        """Generate markdown build report"""
        metrics = self.gather_build_metrics()
        
        report = f"""# Build Health Report

**Generated**: {metrics.get('timestamp', 'unknown')}  
**Branch**: {metrics.get('git_info', {}).get('current_branch', 'unknown')}  

## 🏗️ Build Status

| Metric | Value | Status |
|--------|-------|--------|
| Build | {metrics.get('build_status', {}).get('status', 'unknown')} | {'✅' if metrics.get('build_status', {}).get('status') == 'passed' else '❌'} |
| Coverage | {metrics.get('coverage_metrics', {}).get('total_coverage', 0):.1f}% | {'✅' if metrics.get('coverage_metrics', {}).get('total_coverage', 0) >= 80 else '❌'} |
| Tests | {metrics.get('test_metrics', {}).get('total_tests', 0)} | {'✅' if metrics.get('test_metrics', {}).get('collection_status') == 'collection_passed' else '❌'} |
| Quality | {metrics.get('quality_metrics', {}).get('ruff_violations', 0)} violations | {'✅' if metrics.get('quality_metrics', {}).get('ruff_violations', 0) == 0 else '❌'} |
| Security | {metrics.get('security_metrics', {}).get('total_issues', 0)} issues | {'✅' if metrics.get('security_metrics', {}).get('status') == 'passed' else '❌'} |

## 👥 Agent Activity

"""
        
        agent_names = [
            "CI/CD & Build Engineering",
            "Core Architecture & Identity",
            "Domain Models & Business Logic",
            "Infrastructure & Data Layer",
            "API & Presentation Layer",
            "Testing & Quality Assurance",
            "Documentation & Deployment"
        ]
        
        agent_status = metrics.get('agent_status', {})
        for i in range(7):
            agent_key = f"agent_{i}"
            agent_info = agent_status.get(agent_key, {})
            status = "✅ Active" if agent_info.get('reports_available') else "⏳ Pending"
            
            report += f"- **Agent {i}** ({agent_names[i]}): {status}\n"
        
        report += f"""
## 📊 Detailed Metrics

### Test Coverage
- **Total Coverage**: {metrics.get('coverage_metrics', {}).get('total_coverage', 0):.1f}%
- **Lines Covered**: {metrics.get('coverage_metrics', {}).get('lines_covered', 0)}
- **Total Lines**: {metrics.get('coverage_metrics', {}).get('lines_total', 0)}

### Security
- **Total Issues**: {metrics.get('security_metrics', {}).get('total_issues', 0)}
- **High Severity**: {metrics.get('security_metrics', {}).get('high_severity', 0)}
- **Medium Severity**: {metrics.get('security_metrics', {}).get('medium_severity', 0)}

### Git Information
- **Latest Commit**: {metrics.get('git_info', {}).get('latest_commit', {}).get('hash', 'unknown')}
- **Author**: {metrics.get('git_info', {}).get('latest_commit', {}).get('author', 'unknown')}
- **Message**: {metrics.get('git_info', {}).get('latest_commit', {}).get('message', 'unknown')}

---
*Generated by Agent 0 CI/CD Pipeline*
"""
        
        # Save markdown report
        report_file = self.dashboard_dir / "build-health.md"
        with open(report_file, 'w') as f:
            f.write(report)
        
        return str(report_file)

def main():
    """Main entry point"""
    dashboard = BuildDashboard()
    
    print("📊 Generating build health dashboard...")
    
    # Generate HTML dashboard
    html_file = dashboard.generate_dashboard()
    print(f"✅ HTML dashboard: {html_file}")
    
    # Generate markdown report
    md_file = dashboard.generate_markdown_report()
    print(f"✅ Markdown report: {md_file}")
    
    print("\n🚀 Dashboard generated successfully!")
    print(f"Open {html_file} in your browser to view the dashboard")

if __name__ == "__main__":
    main()