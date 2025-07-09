#!/bin/bash
# Agent environment setup script
# Usage: ./setup-agent-environment.sh [AGENT_NUMBER]

set -e

AGENT_NUMBER=${1:-0}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "🚀 Setting up environment for Agent $AGENT_NUMBER"
echo "Project root: $PROJECT_ROOT"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}✅${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠️${NC} $1"
}

print_error() {
    echo -e "${RED}❌${NC} $1"
}

print_info() {
    echo -e "${BLUE}ℹ️${NC} $1"
}

# Check if we're in the right directory
if [ ! -f "pyproject.toml" ]; then
    print_error "Must be run from the backend directory (where pyproject.toml is located)"
    exit 1
fi

# Get current user for branch naming
CURRENT_USER=$(git config user.name 2>/dev/null || echo "developer")
BRANCH_NAME="agent-${AGENT_NUMBER}-$(echo "$CURRENT_USER" | tr ' ' '-' | tr '[:upper:]' '[:lower:]')"

print_info "Branch name: $BRANCH_NAME"

# Check if branch already exists
if git branch | grep -q "$BRANCH_NAME"; then
    print_warning "Branch $BRANCH_NAME already exists"
    git checkout "$BRANCH_NAME"
else
    print_info "Creating new branch: $BRANCH_NAME"
    git checkout -b "$BRANCH_NAME"
fi

# Install Python dependencies
print_info "Installing Python dependencies..."
python -m pip install --upgrade pip
pip install -e .[dev]

# Install pre-commit hooks
print_info "Installing pre-commit hooks..."
if [ -f ".pre-commit-config.yaml" ]; then
    pre-commit install
    print_status "Pre-commit hooks installed"
else
    print_warning "No .pre-commit-config.yaml found"
fi

# Make scripts executable
chmod +x ci/scripts/*.py
chmod +x ci/scripts/*.sh

# Create agent-specific directories
mkdir -p "docs/agent-${AGENT_NUMBER}-reports"
mkdir -p "docs/agent-${AGENT_NUMBER}-reports/scope-validations"
mkdir -p "docs/agent-${AGENT_NUMBER}-reports/build-reports"

# Create agent-specific pre-commit hook
cat > .git/hooks/pre-push << EOF
#!/bin/bash
# Agent $AGENT_NUMBER pre-push hook

echo "🔍 Running Agent $AGENT_NUMBER validation checks..."

# Run agent-specific validation
cd "\$(git rev-parse --show-toplevel)/backend"
python ci/scripts/validate_agent_scope.py

if [ \$? -ne 0 ]; then
    echo "❌ Agent scope validation failed! Fix scope violations before pushing."
    exit 1
fi

# Run quality gates
echo "🔍 Running quality gates..."
python ci/scripts/quality_gates.py

if [ \$? -ne 0 ]; then
    echo "❌ Quality gates failed! Fix issues before pushing."
    echo "💡 Run: python ci/scripts/quality_gates.py for details"
    exit 1
fi

echo "✅ All validation checks passed!"
EOF

chmod +x .git/hooks/pre-push

# Create agent-specific Makefile targets
cat >> Makefile << EOF

# Agent $AGENT_NUMBER specific targets
.PHONY: agent-$AGENT_NUMBER-setup
agent-$AGENT_NUMBER-setup:
	@echo "Setting up Agent $AGENT_NUMBER environment..."
	@./ci/scripts/setup-agent-environment.sh $AGENT_NUMBER

.PHONY: agent-$AGENT_NUMBER-validate
agent-$AGENT_NUMBER-validate:
	@echo "Validating Agent $AGENT_NUMBER work..."
	@python ci/scripts/validate_agent_scope.py
	@python ci/scripts/quality_gates.py

.PHONY: agent-$AGENT_NUMBER-test
agent-$AGENT_NUMBER-test:
	@echo "Running Agent $AGENT_NUMBER tests..."
	@python -m pytest --collect-only --quiet
	@python -m pytest app/tests/unit -x -v

.PHONY: agent-$AGENT_NUMBER-report
agent-$AGENT_NUMBER-report:
	@echo "Generating Agent $AGENT_NUMBER reports..."
	@python ci/scripts/quality_gates.py
	@echo "Reports available in docs/agent-$AGENT_NUMBER-reports/"

.PHONY: agent-$AGENT_NUMBER-clean
agent-$AGENT_NUMBER-clean:
	@echo "Cleaning Agent $AGENT_NUMBER artifacts..."
	@find . -name "*.pyc" -delete
	@find . -name "__pycache__" -type d -exec rm -rf {} +
	@rm -rf .pytest_cache/
	@rm -rf .coverage
	@rm -rf htmlcov/
	@rm -rf ci/reports/
EOF

# Create agent-specific environment validation
cat > "docs/agent-${AGENT_NUMBER}-reports/environment-setup.md" << EOF
# Agent $AGENT_NUMBER Environment Setup

**Date**: $(date)  
**Agent**: $AGENT_NUMBER  
**Branch**: $BRANCH_NAME  
**User**: $CURRENT_USER

## Setup Complete

✅ **Git branch**: $BRANCH_NAME  
✅ **Python dependencies**: Installed  
✅ **Pre-commit hooks**: Configured  
✅ **Quality gates**: Available  
✅ **Agent validation**: Configured  
✅ **Makefile targets**: Added  

## Available Commands

\`\`\`bash
# Validate your work
make agent-$AGENT_NUMBER-validate

# Run tests
make agent-$AGENT_NUMBER-test

# Generate reports
make agent-$AGENT_NUMBER-report

# Clean artifacts
make agent-$AGENT_NUMBER-clean
\`\`\`

## Next Steps

1. **Start coding** within your agent's scope
2. **Run validation** frequently: \`make agent-$AGENT_NUMBER-validate\`
3. **Check quality gates** before pushing
4. **Review reports** in \`docs/agent-$AGENT_NUMBER-reports/\`

## Agent $AGENT_NUMBER Scope

EOF

# Add agent-specific scope information
case $AGENT_NUMBER in
    0)
        cat >> "docs/agent-${AGENT_NUMBER}-reports/environment-setup.md" << EOF
**CI/CD & Build Engineering**
- GitHub Actions workflows
- Quality gates and validation
- Build scripts and automation
- Pre-commit hooks
EOF
        ;;
    1)
        cat >> "docs/agent-${AGENT_NUMBER}-reports/environment-setup.md" << EOF
**Core Architecture & Identity Foundation**
- Core framework components
- Identity domain implementation
- Module bootstrapping
- Database migrations (identity)
EOF
        ;;
    2)
        cat >> "docs/agent-${AGENT_NUMBER}-reports/environment-setup.md" << EOF
**Domain Models & Business Logic**
- Domain entities and aggregates
- Value objects and business rules
- Domain services and specifications
- Business logic validation
EOF
        ;;
    3)
        cat >> "docs/agent-${AGENT_NUMBER}-reports/environment-setup.md" << EOF
**Infrastructure & Data Layer**
- Repository implementations
- Database adapters and models
- External service adapters
- Infrastructure services
EOF
        ;;
    4)
        cat >> "docs/agent-${AGENT_NUMBER}-reports/environment-setup.md" << EOF
**API & Presentation Layer**
- GraphQL schema and resolvers
- API endpoint implementations
- Request/response mapping
- Presentation logic
EOF
        ;;
    5)
        cat >> "docs/agent-${AGENT_NUMBER}-reports/environment-setup.md" << EOF
**Testing & Quality Assurance**
- Unit, integration, and E2E tests
- Test fixtures and factories
- Testing utilities
- Quality metrics and reports
EOF
        ;;
    6)
        cat >> "docs/agent-${AGENT_NUMBER}-reports/environment-setup.md" << EOF
**Documentation & Deployment**
- Technical documentation
- API documentation
- Deployment configurations
- Monitoring and observability
EOF
        ;;
esac

cat >> "docs/agent-${AGENT_NUMBER}-reports/environment-setup.md" << EOF

---
*Generated by Agent 0 CI/CD Pipeline*
EOF

# Test the setup
print_info "Testing environment setup..."

# Test Python imports
python -c "import app; print('✅ Python imports working')" 2>/dev/null || print_warning "Python imports may have issues"

# Test linting
python -m ruff check --help > /dev/null 2>&1 && print_status "Ruff linter available" || print_warning "Ruff linter not available"

# Test mypy
python -m mypy --help > /dev/null 2>&1 && print_status "MyPy type checker available" || print_warning "MyPy type checker not available"

# Test pytest
python -m pytest --version > /dev/null 2>&1 && print_status "Pytest available" || print_warning "Pytest not available"

# Test pre-commit
pre-commit --version > /dev/null 2>&1 && print_status "Pre-commit available" || print_warning "Pre-commit not available"

# Final success message
print_status "Agent $AGENT_NUMBER environment setup complete!"
print_info "Branch: $BRANCH_NAME"
print_info "Use 'make agent-$AGENT_NUMBER-validate' to validate your work"
print_info "Use 'make agent-$AGENT_NUMBER-test' to run tests"
print_info "Documentation: docs/agent-$AGENT_NUMBER-reports/"

echo ""
echo "🎯 Agent $AGENT_NUMBER is ready to work!"
echo "📝 Remember to stay within your designated scope"
echo "🔍 Run validations frequently to catch issues early"
echo "📊 Check quality gates before pushing changes"
echo ""