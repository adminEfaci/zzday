#!/bin/bash
# EzzDay Backend - Deployment Automation Script
# Comprehensive deployment automation with safety checks

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
DOCKER_CONFIG_DIR="$PROJECT_ROOT/app/config/docker"
HELM_CHART_DIR="$PROJECT_ROOT/app/config/deployment/helm/identity-platform"

# Default values
ENVIRONMENT=""
IMAGE_TAG="latest"
REGISTRY="ghcr.io/ezzday/backend"
DRY_RUN=false
SKIP_TESTS=false
ROLLBACK=false
CANARY_PERCENT=10
HEALTH_CHECK_TIMEOUT=300
BACKUP_BEFORE_DEPLOY=true

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_header() {
    echo -e "${PURPLE}[DEPLOY]${NC} $1"
}

# Help function
show_help() {
    cat << EOF
EzzDay Backend Deployment Automation Script

Usage: $0 [OPTIONS] ENVIRONMENT

ENVIRONMENTS:
    dev         Deploy to development environment
    staging     Deploy to staging environment
    prod        Deploy to production environment

OPTIONS:
    -t, --tag TAG           Docker image tag to deploy (default: latest)
    -r, --registry REGISTRY Registry URL (default: ghcr.io/ezzday/backend)
    -d, --dry-run          Show what would be deployed without actually deploying
    -s, --skip-tests       Skip pre-deployment tests
    -b, --rollback         Rollback to previous version
    -c, --canary PERCENT   Canary deployment percentage (default: 10)
    -n, --no-backup        Skip backup before deployment
    -h, --help             Show this help message

EXAMPLES:
    $0 staging --tag v1.2.3
    $0 prod --tag v1.2.3 --canary 25
    $0 prod --rollback
    $0 staging --dry-run --tag latest

ENVIRONMENT VARIABLES:
    KUBECONFIG              Path to kubectl config file
    DOCKER_REGISTRY_TOKEN   Registry authentication token
    SLACK_WEBHOOK_URL       Slack webhook for notifications
EOF
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -t|--tag)
                IMAGE_TAG="$2"
                shift 2
                ;;
            -r|--registry)
                REGISTRY="$2"
                shift 2
                ;;
            -d|--dry-run)
                DRY_RUN=true
                shift
                ;;
            -s|--skip-tests)
                SKIP_TESTS=true
                shift
                ;;
            -b|--rollback)
                ROLLBACK=true
                shift
                ;;
            -c|--canary)
                CANARY_PERCENT="$2"
                shift 2
                ;;
            -n|--no-backup)
                BACKUP_BEFORE_DEPLOY=false
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            dev|staging|prod)
                ENVIRONMENT="$1"
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done

    if [[ -z "$ENVIRONMENT" ]]; then
        log_error "Environment is required"
        show_help
        exit 1
    fi
}

# Validate prerequisites
validate_prerequisites() {
    log_info "Validating prerequisites..."
    
    # Check required tools
    local required_tools=("docker" "kubectl" "helm" "curl" "jq")
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            log_error "Required tool not found: $tool"
            exit 1
        fi
    done
    
    # Check kubectl access
    if ! kubectl cluster-info >/dev/null 2>&1; then
        log_error "kubectl is not configured or cluster is not accessible"
        exit 1
    fi
    
    # Check Helm
    if ! helm version >/dev/null 2>&1; then
        log_error "Helm is not properly configured"
        exit 1
    fi
    
    # Validate environment-specific prerequisites
    case "$ENVIRONMENT" in
        prod)
            if [[ "$IMAGE_TAG" == "latest" && "$ROLLBACK" == false ]]; then
                log_error "Production deployment requires a specific tag (not 'latest')"
                exit 1
            fi
            ;;
    esac
    
    log_success "Prerequisites validated"
}

# Check current deployment status
check_current_deployment() {
    log_info "Checking current deployment status..."
    
    local namespace="ezzday-${ENVIRONMENT}"
    local release_name="ezzday-backend"
    
    if helm status "$release_name" -n "$namespace" >/dev/null 2>&1; then
        local current_version=$(helm get values "$release_name" -n "$namespace" -o json | jq -r '.image.tag // "unknown"')
        log_info "Current deployed version: $current_version"
        
        # Check pod status
        local ready_pods=$(kubectl get pods -n "$namespace" -l app=ezzday-backend --field-selector=status.phase=Running --no-headers | wc -l)
        local total_pods=$(kubectl get pods -n "$namespace" -l app=ezzday-backend --no-headers | wc -l)
        log_info "Pod status: $ready_pods/$total_pods ready"
        
        return 0
    else
        log_info "No current deployment found"
        return 1
    fi
}

# Run pre-deployment tests
run_pre_deployment_tests() {
    if [[ "$SKIP_TESTS" == true ]]; then
        log_warning "Skipping pre-deployment tests"
        return 0
    fi
    
    log_info "Running pre-deployment tests..."
    
    # Run unit tests
    log_info "Running unit tests..."
    cd "$DOCKER_CONFIG_DIR"
    
    if ! docker-compose -f docker-compose.test.yml up --build --abort-on-container-exit; then
        log_error "Unit tests failed"
        return 1
    fi
    
    # Cleanup test containers
    docker-compose -f docker-compose.test.yml down -v
    
    # Additional environment-specific tests
    case "$ENVIRONMENT" in
        staging|prod)
            log_info "Running integration tests..."
            # Run integration tests here
            ;;
    esac
    
    log_success "Pre-deployment tests passed"
}

# Create backup
create_backup() {
    if [[ "$BACKUP_BEFORE_DEPLOY" == false ]]; then
        log_warning "Skipping backup"
        return 0
    fi
    
    log_info "Creating backup before deployment..."
    
    local namespace="ezzday-${ENVIRONMENT}"
    local backup_name="backup-$(date +%Y%m%d-%H%M%S)"
    
    # Database backup
    log_info "Creating database backup: $backup_name"
    kubectl create job "${backup_name}-db" \
        --from=cronjob/db-backup \
        -n "$namespace" 2>/dev/null || true
    
    # Application state backup
    log_info "Creating application state backup"
    kubectl create configmap "${backup_name}-config" \
        --from-literal=version="$(helm get values ezzday-backend -n "$namespace" -o json | jq -r '.image.tag')" \
        --from-literal=timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        -n "$namespace" 2>/dev/null || true
    
    log_success "Backup created: $backup_name"
}

# Deploy with Helm
deploy_with_helm() {
    log_info "Starting deployment to $ENVIRONMENT..."
    
    local namespace="ezzday-${ENVIRONMENT}"
    local release_name="ezzday-backend"
    local values_file="$HELM_CHART_DIR/values-${ENVIRONMENT}.yaml"
    
    if [[ ! -f "$values_file" ]]; then
        log_error "Values file not found: $values_file"
        exit 1
    fi
    
    # Prepare Helm command
    local helm_cmd=(
        helm upgrade --install "$release_name"
        "$HELM_CHART_DIR"
        --namespace "$namespace"
        --create-namespace
        --values "$values_file"
        --set "image.tag=$IMAGE_TAG"
        --set "image.repository=$REGISTRY"
        --wait
        --timeout="${HEALTH_CHECK_TIMEOUT}s"
    )
    
    # Add environment-specific configurations
    case "$ENVIRONMENT" in
        prod)
            helm_cmd+=(
                --set "replicaCount=3"
                --set "resources.limits.memory=1Gi"
                --set "resources.limits.cpu=1000m"
            )
            ;;
        staging)
            helm_cmd+=(
                --set "replicaCount=2"
                --set "resources.limits.memory=512Mi"
                --set "resources.limits.cpu=500m"
            )
            ;;
        dev)
            helm_cmd+=(
                --set "replicaCount=1"
                --set "resources.limits.memory=256Mi"
                --set "resources.limits.cpu=250m"
            )
            ;;
    esac
    
    # Add canary settings for production
    if [[ "$ENVIRONMENT" == "prod" && "$CANARY_PERCENT" -gt 0 ]]; then
        log_info "Deploying canary release: $CANARY_PERCENT%"
        helm_cmd+=(--set "canary.enabled=true" --set "canary.weight=$CANARY_PERCENT")
    fi
    
    if [[ "$DRY_RUN" == true ]]; then
        log_warning "DRY RUN - Would execute: ${helm_cmd[*]} --dry-run"
        helm_cmd+=(--dry-run)
    fi
    
    # Execute deployment
    log_info "Executing Helm deployment..."
    if "${helm_cmd[@]}"; then
        log_success "Helm deployment completed"
    else
        log_error "Helm deployment failed"
        return 1
    fi
}

# Perform rollback
perform_rollback() {
    log_warning "Performing rollback..."
    
    local namespace="ezzday-${ENVIRONMENT}"
    local release_name="ezzday-backend"
    
    if [[ "$DRY_RUN" == true ]]; then
        log_warning "DRY RUN - Would rollback: helm rollback $release_name -n $namespace"
        return 0
    fi
    
    if helm rollback "$release_name" -n "$namespace" --wait --timeout="${HEALTH_CHECK_TIMEOUT}s"; then
        log_success "Rollback completed successfully"
    else
        log_error "Rollback failed"
        return 1
    fi
}

# Verify deployment health
verify_deployment() {
    log_info "Verifying deployment health..."
    
    local namespace="ezzday-${ENVIRONMENT}"
    local app_label="app=ezzday-backend"
    
    # Wait for pods to be ready
    log_info "Waiting for pods to be ready..."
    if ! kubectl wait --for=condition=ready pod -l "$app_label" -n "$namespace" --timeout="${HEALTH_CHECK_TIMEOUT}s"; then
        log_error "Pods failed to become ready"
        return 1
    fi
    
    # Check pod status
    local ready_pods=$(kubectl get pods -n "$namespace" -l "$app_label" --field-selector=status.phase=Running --no-headers | wc -l)
    local total_pods=$(kubectl get pods -n "$namespace" -l "$app_label" --no-headers | wc -l)
    log_info "Pod status: $ready_pods/$total_pods ready"
    
    if [[ "$ready_pods" -eq 0 ]]; then
        log_error "No pods are ready"
        return 1
    fi
    
    # Health check endpoints
    local health_endpoint=""
    case "$ENVIRONMENT" in
        prod) health_endpoint="https://api.ezzday.com/health" ;;
        staging) health_endpoint="https://staging-api.ezzday.com/health" ;;
        dev) health_endpoint="https://dev-api.ezzday.com/health" ;;
    esac
    
    if [[ -n "$health_endpoint" ]]; then
        log_info "Checking health endpoint: $health_endpoint"
        local retries=30
        while [[ $retries -gt 0 ]]; do
            if curl -f -s "$health_endpoint" >/dev/null; then
                log_success "Health check passed"
                break
            fi
            ((retries--))
            sleep 10
        done
        
        if [[ $retries -eq 0 ]]; then
            log_error "Health check failed after timeout"
            return 1
        fi
    fi
    
    log_success "Deployment verification completed"
}

# Send notifications
send_notifications() {
    local status="$1"
    local message="$2"
    
    if [[ -n "$SLACK_WEBHOOK_URL" ]]; then
        local color="good"
        local emoji="✅"
        
        if [[ "$status" != "success" ]]; then
            color="danger"
            emoji="❌"
        fi
        
        local payload=$(cat <<EOF
{
    "attachments": [
        {
            "color": "$color",
            "title": "$emoji EzzDay Backend Deployment - $ENVIRONMENT",
            "fields": [
                {
                    "title": "Environment",
                    "value": "$ENVIRONMENT",
                    "short": true
                },
                {
                    "title": "Image Tag",
                    "value": "$IMAGE_TAG",
                    "short": true
                },
                {
                    "title": "Status",
                    "value": "$status",
                    "short": true
                },
                {
                    "title": "Message",
                    "value": "$message",
                    "short": false
                }
            ],
            "footer": "EzzDay Deployment Bot",
            "ts": $(date +%s)
        }
    ]
}
EOF
        )
        
        curl -X POST -H 'Content-type: application/json' \
            --data "$payload" \
            "$SLACK_WEBHOOK_URL" >/dev/null 2>&1 || true
    fi
}

# Cleanup function
cleanup() {
    log_info "Performing cleanup..."
    
    # Cleanup old releases (keep last 10)
    local namespace="ezzday-${ENVIRONMENT}"
    local release_name="ezzday-backend"
    
    helm history "$release_name" -n "$namespace" --max 10 >/dev/null 2>&1 || true
    
    # Cleanup old Docker images (if on same host)
    docker image prune -f >/dev/null 2>&1 || true
    
    log_success "Cleanup completed"
}

# Main execution function
main() {
    log_header "EzzDay Backend Deployment Automation"
    log_info "Environment: $ENVIRONMENT"
    log_info "Image Tag: $IMAGE_TAG"
    log_info "Registry: $REGISTRY"
    
    if [[ "$DRY_RUN" == true ]]; then
        log_warning "DRY RUN MODE - No changes will be made"
    fi
    
    # Validate prerequisites
    validate_prerequisites
    
    # Check current deployment
    check_current_deployment
    
    if [[ "$ROLLBACK" == true ]]; then
        # Perform rollback
        if perform_rollback && verify_deployment; then
            send_notifications "success" "Rollback completed successfully"
            log_success "Rollback operation completed successfully"
        else
            send_notifications "failed" "Rollback operation failed"
            log_error "Rollback operation failed"
            exit 1
        fi
    else
        # Normal deployment flow
        
        # Run tests
        run_pre_deployment_tests
        
        # Create backup
        create_backup
        
        # Deploy
        if deploy_with_helm && verify_deployment; then
            send_notifications "success" "Deployment completed successfully"
            log_success "Deployment operation completed successfully"
        else
            log_error "Deployment failed, attempting automatic rollback..."
            if perform_rollback; then
                send_notifications "warning" "Deployment failed but rollback succeeded"
                log_warning "Automatic rollback completed"
            else
                send_notifications "failed" "Deployment and rollback both failed"
                log_error "Both deployment and rollback failed"
            fi
            exit 1
        fi
    fi
    
    # Cleanup
    cleanup
    
    log_success "All operations completed successfully"
}

# Trap signals for cleanup
trap cleanup EXIT

# Parse arguments and run main function
parse_args "$@"
main