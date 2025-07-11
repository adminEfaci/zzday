#!/bin/bash

# UV & Test Framework Master - Quick Test Runner
# Agent-2C: UV & Test Framework Master

set -e

echo "🚀 EzzDay Backend Test Runner (UV Environment)"
echo "=============================================="

# Set Python path
export PYTHONPATH="${PYTHONPATH}:/Users/neuro/workspace2/app-codebase/ezzday/backend"

# Test different scenarios based on argument
case "${1:-all}" in
    "env")
        echo "🔧 Testing UV Environment Setup..."
        uv run pytest test_uv_environment.py -v
        ;;
    "basic")
        echo "🧪 Running Basic Tests (non-app specific)..."
        uv run pytest test_uv_environment.py --cov=. --cov-report=term-missing
        ;;
    "conftest")
        echo "🔧 Testing conftest.py fixtures (collect only)..."
        uv run pytest app/tests/conftest.py --collect-only -q
        ;;
    "coverage")
        echo "📊 Running Coverage Test..."
        uv run pytest test_uv_environment.py --cov=. --cov-report=html --cov-report=xml
        echo "Coverage reports generated: htmlcov/index.html and coverage.xml"
        ;;
    "fast")
        echo "⚡ Fast Test Suite (unit tests only)..."
        uv run pytest -m "unit and not slow" --tb=short -q
        ;;
    "integration")
        echo "🔗 Integration Test Suite..."
        uv run pytest -m "integration" --tb=short
        ;;
    "performance")
        echo "🚀 Performance Test Suite..."
        uv run pytest -m "performance" --tb=short
        ;;
    "security")
        echo "🔒 Security Test Suite..."
        uv run pytest -m "security" --tb=short
        ;;
    "all")
        echo "🎯 Full Test Suite with Coverage..."
        uv run pytest --cov=app --cov-report=term-missing --cov-report=html -v
        ;;
    "help")
        echo "Available commands:"
        echo "  env         - Test UV environment setup"
        echo "  basic       - Basic functionality tests"
        echo "  conftest    - Test conftest.py fixtures"
        echo "  coverage    - Generate coverage reports"
        echo "  fast        - Fast unit tests only"
        echo "  integration - Integration tests"
        echo "  performance - Performance tests"
        echo "  security    - Security tests"
        echo "  all         - Full test suite (default)"
        echo "  help        - Show this help"
        ;;
    *)
        echo "❌ Unknown command: $1"
        echo "Run './run_tests.sh help' for available commands"
        exit 1
        ;;
esac

echo "✅ Test execution completed!"