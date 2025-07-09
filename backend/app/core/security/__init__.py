"""
Security Module

This module provides comprehensive security testing and validation
capabilities for the application.

Components:
- SecurityTestSuite: Comprehensive security testing framework
- SecurityTestResult: Individual test result representation
- SecurityTestReport: Test report generation

Usage:
    from app.core.security import SecurityTestSuite, run_security_tests
    
    # Run all security tests
    report = await run_security_tests()
    
    # Generate HTML report
    html_report = SecurityTestSuite().generate_html_report(report)
"""

from .test_suite import (
    SecurityTestSuite,
    SecurityTestResult,
    SecurityTestReport,
    run_security_tests
)

__all__ = [
    "SecurityTestSuite",
    "SecurityTestResult", 
    "SecurityTestReport",
    "run_security_tests"
]