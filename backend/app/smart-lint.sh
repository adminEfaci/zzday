#!/bin/bash
set -euo pipefail

# Enhanced Smart Lint Script for EzzDay Backend
# Production-ready linting with comprehensive checks and reporting

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly NC='\033[0m' # No Color

# Configuration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(cd "${SCRIPT_DIR}" && pwd)"
readonly LOG_FILE="${PROJECT_ROOT}/logs/smart-lint.log"
readonly TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
readonly SESSION_ID=$(date +%s)

# Ensure logs directory exists
mkdir -p "${PROJECT_ROOT}/logs"

# Logging functions
log_info() {
    echo -e "${CYAN}[INFO]${NC} $1" | tee -a "${LOG_FILE}"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "${LOG_FILE}"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "${LOG_FILE}"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "${LOG_FILE}"
}

log_section() {
    echo -e "\n${PURPLE}=== $1 ===${NC}" | tee -a "${LOG_FILE}"
}

# Performance tracking
start_timer() {
    echo $(date +%s%N)
}

end_timer() {
    local start_time=$1
    local end_time=$(date +%s%N)
    local duration=$(( (end_time - start_time) / 1000000 ))
    echo "${duration}ms"
}

# Initialize session
initialize_session() {
    echo -e "${WHITE}" | tee -a "${LOG_FILE}"
    echo "╔══════════════════════════════════════════════════════════════════════════════════════╗" | tee -a "${LOG_FILE}"
    echo "║                          🚀 SMART LINT SESSION START 🚀                             ║" | tee -a "${LOG_FILE}"
    echo "║                                                                                      ║" | tee -a "${LOG_FILE}"
    echo "║  Session ID: ${SESSION_ID}                                                               ║" | tee -a "${LOG_FILE}"
    echo "║  Timestamp:  ${TIMESTAMP}                                                     ║" | tee -a "${LOG_FILE}"
    echo "║  Project:    EzzDay Backend (FastAPI + DDD + Hexagonal Architecture)               ║" | tee -a "${LOG_FILE}"
    echo "║  Directory:  ${PROJECT_ROOT}  ║" | tee -a "${LOG_FILE}"
    echo "╚══════════════════════════════════════════════════════════════════════════════════════╝" | tee -a "${LOG_FILE}"
    echo -e "${NC}" | tee -a "${LOG_FILE}"
}

# Check if tools are installed
check_dependencies() {
    log_section "Dependency Check"
    local missing_tools=()
    
    local tools=("python" "ruff" "mypy" "black" "isort" "bandit" "pytest" "alembic")
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
            log_error "Missing tool: $tool"
        else
            local version
            case "$tool" in
                "python") version=$(python --version 2>&1) ;;
                "ruff") version=$(ruff --version 2>&1) ;;
                "mypy") version=$(mypy --version 2>&1) ;;
                "black") version=$(black --version 2>&1) ;;
                "isort") version=$(isort --version 2>&1) ;;
                "bandit") version=$(bandit --version 2>&1) ;;
                "pytest") version=$(pytest --version 2>&1) ;;
                "alembic") version=$(alembic --version 2>&1) ;;
            esac
            log_success "$tool: $version"
        fi
    done
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        log_error "Please install missing tools: pip install ${missing_tools[*]}"
        exit 1
    fi
}

# Enhanced Python syntax check
check_syntax() {
    log_section "Python Syntax Check"
    local timer=$(start_timer)
    local issues=0
    
    while IFS= read -r -d '' file; do
        if ! python -m py_compile "$file" 2>/dev/null; then
            log_error "Syntax error in: $file"
            python -m py_compile "$file" 2>&1 | head -5
            ((issues++))
        fi
    done < <(find . -name "*.py" -not -path "./venv/*" -not -path "./.venv/*" -not -path "./.*" -print0)
    
    local duration=$(end_timer $timer)
    
    if [ $issues -eq 0 ]; then
        log_success "All Python files have valid syntax (${duration})"
    else
        log_error "$issues syntax errors found (${duration})"
        return 1
    fi
}

# Enhanced import check
check_imports() {
    log_section "Import Validation"
    local timer=$(start_timer)
    local issues=0
    
    # Check for common import issues
    log_info "Checking for circular imports..."
    
    # Simple circular import detection
    while IFS= read -r -d '' file; do
        if python -c "
import sys
import ast
import os

def check_file_imports(filepath):
    try:
        with open(filepath, 'r') as f:
            tree = ast.parse(f.read())
        
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imports.append(node.module)
        return imports
    except Exception as e:
        print(f'Error parsing {filepath}: {e}')
        return []

imports = check_file_imports('$file')
for imp in imports:
    if 'app.modules' in imp and len(imp.split('.')) > 3:
        potential_circular = any('app.modules' in other and other != imp for other in imports)
        if potential_circular:
            print(f'Potential circular import in $file: {imp}')
" 2>/dev/null | grep -q "Potential circular"; then
            log_warning "Potential circular import detected in: $file"
            ((issues++))
        fi
    done < <(find . -name "*.py" -not -path "./venv/*" -not -path "./.venv/*" -not -path "./.*" -print0)
    
    local duration=$(end_timer $timer)
    
    if [ $issues -eq 0 ]; then
        log_success "No import issues detected (${duration})"
    else
        log_warning "$issues potential import issues found (${duration})"
    fi
}

# Enhanced code formatting with Black
run_black() {
    log_section "Code Formatting (Black)"
    local timer=$(start_timer)
    
    if black --check --diff . 2>/dev/null; then
        local duration=$(end_timer $timer)
        log_success "All code is properly formatted (${duration})"
    else
        log_warning "Code formatting issues found. Running auto-formatter..."
        if black . --line-length=88 --target-version=py312; then
            local duration=$(end_timer $timer)
            log_success "Code formatted successfully (${duration})"
        else
            local duration=$(end_timer $timer)
            log_error "Code formatting failed (${duration})"
            return 1
        fi
    fi
}

# Enhanced import sorting with isort
run_isort() {
    log_section "Import Sorting (isort)"
    local timer=$(start_timer)
    
    if isort --check-only --diff . 2>/dev/null; then
        local duration=$(end_timer $timer)
        log_success "All imports are properly sorted (${duration})"
    else
        log_warning "Import sorting issues found. Running auto-sorter..."
        if isort . --profile=black --line-length=88; then
            local duration=$(end_timer $timer)
            log_success "Imports sorted successfully (${duration})"
        else
            local duration=$(end_timer $timer)
            log_error "Import sorting failed (${duration})"
            return 1
        fi
    fi
}

# Enhanced linting with Ruff
run_ruff() {
    log_section "Linting (Ruff)"
    local timer=$(start_timer)
    
    # Run ruff check with auto-fix
    if ruff check . --fix --exit-zero > /tmp/ruff_output.txt 2>&1; then
        local warnings=$(grep -c "warning" /tmp/ruff_output.txt 2>/dev/null || echo "0")
        local errors=$(grep -c "error" /tmp/ruff_output.txt 2>/dev/null || echo "0")
        local fixed=$(grep -c "Fixed" /tmp/ruff_output.txt 2>/dev/null || echo "0")
        
        local duration=$(end_timer $timer)
        
        if [ "$errors" -eq 0 ] && [ "$warnings" -eq 0 ]; then
            log_success "No linting issues found (${duration})"
        elif [ "$errors" -eq 0 ]; then
            log_warning "$warnings warnings found, $fixed auto-fixed (${duration})"
            if [ "$fixed" -gt 0 ]; then
                log_info "View details: cat /tmp/ruff_output.txt"
            fi
        else
            log_error "$errors errors and $warnings warnings found (${duration})"
            cat /tmp/ruff_output.txt
            return 1
        fi
    else
        local duration=$(end_timer $timer)
        log_error "Ruff linting failed (${duration})"
        cat /tmp/ruff_output.txt
        return 1
    fi
}

# Enhanced type checking with MyPy
run_mypy() {
    log_section "Type Checking (MyPy)"
    local timer=$(start_timer)
    
    # Create mypy config if it doesn't exist
    if [ ! -f "mypy.ini" ] && [ ! -f "pyproject.toml" ] && [ ! -f "setup.cfg" ]; then
        log_info "Creating temporary mypy configuration..."
        cat > .mypy.ini << EOF
[mypy]
python_version = 3.12
strict = True
warn_redundant_casts = True
warn_unused_ignores = True
warn_return_any = True
warn_unreachable = True
show_error_codes = True
disallow_untyped_defs = True
disallow_any_generics = True
disallow_untyped_calls = True
disallow_incomplete_defs = True
check_untyped_defs = True
disallow_untyped_decorators = True

[mypy-tests.*]
disallow_untyped_defs = False

[mypy-alembic.*]
ignore_errors = True
EOF
    fi
    
    if mypy . --no-error-summary > /tmp/mypy_output.txt 2>&1; then
        local duration=$(end_timer $timer)
        log_success "No type errors found (${duration})"
    else
        local error_count=$(grep -c "error:" /tmp/mypy_output.txt 2>/dev/null || echo "0")
        local duration=$(end_timer $timer)
        
        if [ "$error_count" -eq 0 ]; then
            log_success "Type checking completed with warnings (${duration})"
        else
            log_error "$error_count type errors found (${duration})"
            
            # Show first 20 errors
            echo "First 20 type errors:"
            head -20 /tmp/mypy_output.txt
            
            if [ "$error_count" -gt 20 ]; then
                echo "... and $(($error_count - 20)) more errors. See /tmp/mypy_output.txt for full details."
            fi
            
            return 1
        fi
    fi
    
    # Cleanup temporary config
    [ -f ".mypy.ini" ] && rm .mypy.ini
}

# Enhanced security scanning with Bandit
run_bandit() {
    log_section "Security Scanning (Bandit)"
    local timer=$(start_timer)
    
    if bandit -r . -f json -o /tmp/bandit_output.json -ll > /dev/null 2>&1; then
        local high_severity=$(jq '.results | map(select(.issue_severity == "HIGH")) | length' /tmp/bandit_output.json 2>/dev/null || echo "0")
        local medium_severity=$(jq '.results | map(select(.issue_severity == "MEDIUM")) | length' /tmp/bandit_output.json 2>/dev/null || echo "0")
        local low_severity=$(jq '.results | map(select(.issue_severity == "LOW")) | length' /tmp/bandit_output.json 2>/dev/null || echo "0")
        
        local duration=$(end_timer $timer)
        
        if [ "$high_severity" -eq 0 ] && [ "$medium_severity" -eq 0 ]; then
            if [ "$low_severity" -eq 0 ]; then
                log_success "No security issues found (${duration})"
            else
                log_warning "$low_severity low-severity security issues found (${duration})"
            fi
        else
            log_error "Security issues found: $high_severity high, $medium_severity medium, $low_severity low (${duration})"
            bandit -r . -f txt --severity-level medium
            return 1
        fi
    else
        local duration=$(end_timer $timer)
        log_error "Security scanning failed (${duration})"
        return 1
    fi
}

# Database migration check
check_migrations() {
    log_section "Database Migration Check"
    local timer=$(start_timer)
    
    if [ -f "alembic.ini" ]; then
        # Check if migrations are up to date
        if alembic check > /dev/null 2>&1; then
            local duration=$(end_timer $timer)
            log_success "Database migrations are up to date (${duration})"
        else
            local duration=$(end_timer $timer)
            log_warning "Database migrations may be out of sync (${duration})"
            alembic check 2>&1 || true
        fi
    else
        local duration=$(end_timer $timer)
        log_info "No Alembic configuration found, skipping migration check (${duration})"
    fi
}

# GraphQL schema validation
check_graphql_schema() {
    log_section "GraphQL Schema Validation"
    local timer=$(start_timer)
    
    if python -c "
try:
    from app.presentation.graphql.schema import schema
    print('✅ GraphQL schema imported successfully')
    
    # Basic schema validation
    schema_str = str(schema)
    if 'Query' in schema_str and 'Mutation' in schema_str:
        print('✅ Query and Mutation types found')
    else:
        print('❌ Missing Query or Mutation types')
        exit(1)
        
except ImportError as e:
    print(f'❌ Cannot import GraphQL schema: {e}')
    exit(1)
except Exception as e:
    print(f'❌ GraphQL schema validation failed: {e}')
    exit(1)
" 2>/dev/null; then
        local duration=$(end_timer $timer)
        log_success "GraphQL schema validation passed (${duration})"
    else
        local duration=$(end_timer $timer)
        log_error "GraphQL schema validation failed (${duration})"
        return 1
    fi
}

# Dependency injection validation
check_dependency_injection() {
    log_section "Dependency Injection Validation"
    local timer=$(start_timer)
    
    if python -c "
try:
    from app.core.dependencies import get_container, initialize_dependencies
    
    # Initialize DI system
    initialize_dependencies()
    container = get_container()
    
    print(f'✅ DI container initialized successfully')
    
    # Check if core services can be resolved
    try:
        stats = container.get_container_stats()
        print(f'✅ Container stats: {stats}')
    except Exception as e:
        print(f'⚠️  Container stats unavailable: {e}')
        
except ImportError as e:
    print(f'❌ Cannot import DI container: {e}')
    exit(1)
except Exception as e:
    print(f'❌ DI validation failed: {e}')
    exit(1)
" 2>/dev/null; then
        local duration=$(end_timer $timer)
        log_success "Dependency injection validation passed (${duration})"
    else
        local duration=$(end_timer $timer)
        log_error "Dependency injection validation failed (${duration})"
        return 1
    fi
}

# Test coverage check
check_test_coverage() {
    log_section "Test Coverage Analysis"
    local timer=$(start_timer)
    
    if [ -d "tests" ]; then
        if pytest --co -q > /dev/null 2>&1; then
            local test_count=$(pytest --co -q | grep "^<" | wc -l)
            log_info "Found $test_count test cases"
            
            # Quick syntax check for test files
            local test_issues=0
            while IFS= read -r -d '' test_file; do
                if ! python -m py_compile "$test_file" 2>/dev/null; then
                    log_error "Test syntax error in: $test_file"
                    ((test_issues++))
                fi
            done < <(find tests -name "*.py" -print0 2>/dev/null)
            
            local duration=$(end_timer $timer)
            
            if [ $test_issues -eq 0 ]; then
                log_success "All test files have valid syntax (${duration})"
            else
                log_error "$test_issues test files have syntax errors (${duration})"
                return 1
            fi
        else
            local duration=$(end_timer $timer)
            log_warning "Test collection failed (${duration})"
        fi
    else
        local duration=$(end_timer $timer)
        log_warning "No tests directory found (${duration})"
    fi
}

# Performance metrics
generate_metrics() {
    log_section "Performance Metrics"
    
    local total_files=$(find . -name "*.py" -not -path "./venv/*" -not -path "./.venv/*" -not -path "./.*" | wc -l)
    local total_lines=$(find . -name "*.py" -not -path "./venv/*" -not -path "./.venv/*" -not -path "./.*" -exec wc -l {} + | tail -1 | awk '{print $1}')
    local test_files=$(find tests -name "*.py" 2>/dev/null | wc -l)
    
    echo "📊 Code Metrics:"
    echo "   • Python files: $total_files"
    echo "   • Total lines: $total_lines"
    echo "   • Test files: $test_files"
    echo "   • Test coverage: Run 'pytest --cov' for detailed coverage"
}

# Finalize session
finalize_session() {
    local end_time=$(date '+%Y-%m-%d %H:%M:%S')
    local exit_code=$1
    
    echo -e "\n${WHITE}" | tee -a "${LOG_FILE}"
    echo "╔══════════════════════════════════════════════════════════════════════════════════════╗" | tee -a "${LOG_FILE}"
    if [ $exit_code -eq 0 ]; then
        echo "║                          ✅ SMART LINT SESSION COMPLETED ✅                         ║" | tee -a "${LOG_FILE}"
        echo "║                                                                                      ║" | tee -a "${LOG_FILE}"
        echo "║  Status: ALL CHECKS PASSED                                                          ║" | tee -a "${LOG_FILE}"
    else
        echo "║                          ❌ SMART LINT SESSION FAILED ❌                            ║" | tee -a "${LOG_FILE}"
        echo "║                                                                                      ║" | tee -a "${LOG_FILE}"
        echo "║  Status: SOME CHECKS FAILED                                                         ║" | tee -a "${LOG_FILE}"
    fi
    echo "║  Session ID: ${SESSION_ID}                                                               ║" | tee -a "${LOG_FILE}"
    echo "║  Started:    ${TIMESTAMP}                                                     ║" | tee -a "${LOG_FILE}"
    echo "║  Completed:  ${end_time}                                                     ║" | tee -a "${LOG_FILE}"
    echo "║  Log File:   ${LOG_FILE}  ║" | tee -a "${LOG_FILE}"
    echo "╚══════════════════════════════════════════════════════════════════════════════════════╝" | tee -a "${LOG_FILE}"
    echo -e "${NC}" | tee -a "${LOG_FILE}"
}

# Main execution
main() {
    local overall_timer=$(start_timer)
    local exit_code=0
    
    # Change to project directory
    cd "${PROJECT_ROOT}"
    
    # Initialize session
    initialize_session
    
    # Run all checks
    local checks=(
        "check_dependencies"
        "check_syntax"
        "check_imports"
        "run_black"
        "run_isort" 
        "run_ruff"
        "run_mypy"
        "run_bandit"
        "check_migrations"
        "check_graphql_schema"
        "check_dependency_injection"
        "check_test_coverage"
    )
    
    local failed_checks=()
    
    for check in "${checks[@]}"; do
        if ! $check; then
            failed_checks+=("$check")
            exit_code=1
        fi
    done
    
    # Generate metrics
    generate_metrics
    
    # Report results
    local total_duration=$(end_timer $overall_timer)
    
    if [ $exit_code -eq 0 ]; then
        log_success "🎉 All quality checks passed! (Total time: ${total_duration})"
    else
        log_error "❌ ${#failed_checks[@]} checks failed: ${failed_checks[*]} (Total time: ${total_duration})"
        log_error "Please fix the issues above before proceeding."
    fi
    
    # Finalize session
    finalize_session $exit_code
    
    exit $exit_code
}

# Handle script interruption
trap 'log_error "Script interrupted by user"; finalize_session 130; exit 130' INT TERM

# Run main function
main "$@"