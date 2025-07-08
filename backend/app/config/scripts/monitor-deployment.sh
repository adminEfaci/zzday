#!/bin/bash
# EzzDay Backend - Deployment Monitoring Script
# Real-time monitoring of deployment health and metrics

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
ENVIRONMENT=""
NAMESPACE=""
PROMETHEUS_URL=""
GRAFANA_URL=""
APP_URL=""
MONITORING_DURATION=300  # 5 minutes default
CHECK_INTERVAL=30       # 30 seconds
ALERT_THRESHOLD_ERROR_RATE=5  # 5% error rate
ALERT_THRESHOLD_RESPONSE_TIME=2000  # 2000ms response time

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1"
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1"
}

log_metric() {
    echo -e "${CYAN}[METRIC]${NC} $(date '+%Y-%m-%d %H:%M:%S') $1"
}

log_header() {
    echo -e "${PURPLE}[MONITOR]${NC} $1"
}

# Help function
show_help() {
    cat << EOF
EzzDay Backend Deployment Monitoring Script

Usage: $0 [OPTIONS] ENVIRONMENT

ENVIRONMENTS:
    dev         Monitor development environment
    staging     Monitor staging environment
    prod        Monitor production environment

OPTIONS:
    -d, --duration SECONDS  Monitoring duration in seconds (default: 300)
    -i, --interval SECONDS  Check interval in seconds (default: 30)
    -e, --error-threshold   Error rate threshold percentage (default: 5)
    -r, --response-threshold Response time threshold in ms (default: 2000)
    -c, --continuous        Run continuous monitoring (until interrupted)
    -s, --summary-only      Show summary without detailed metrics
    -h, --help              Show this help message

EXAMPLES:
    $0 prod --duration 600
    $0 staging --continuous
    $0 dev --summary-only

ENVIRONMENT VARIABLES:
    KUBECONFIG              Path to kubectl config file
    SLACK_WEBHOOK_URL       Slack webhook for alerts
EOF
}

# Parse command line arguments
parse_args() {
    local continuous=false
    local summary_only=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -d|--duration)
                MONITORING_DURATION="$2"
                shift 2
                ;;
            -i|--interval)
                CHECK_INTERVAL="$2"
                shift 2
                ;;
            -e|--error-threshold)
                ALERT_THRESHOLD_ERROR_RATE="$2"
                shift 2
                ;;
            -r|--response-threshold)
                ALERT_THRESHOLD_RESPONSE_TIME="$2"
                shift 2
                ;;
            -c|--continuous)
                continuous=true
                MONITORING_DURATION=999999  # Very long duration
                shift
                ;;
            -s|--summary-only)
                summary_only=true
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
    
    # Set environment-specific configurations
    case "$ENVIRONMENT" in
        prod)
            NAMESPACE="ezzday-production"
            PROMETHEUS_URL="https://monitoring.ezzday.com/prometheus"
            GRAFANA_URL="https://monitoring.ezzday.com/grafana"
            APP_URL="https://api.ezzday.com"
            ;;
        staging)
            NAMESPACE="ezzday-staging"
            PROMETHEUS_URL="https://staging-monitoring.ezzday.com/prometheus"
            GRAFANA_URL="https://staging-monitoring.ezzday.com/grafana"
            APP_URL="https://staging-api.ezzday.com"
            ;;
        dev)
            NAMESPACE="ezzday-development"
            PROMETHEUS_URL="http://localhost:9090"
            GRAFANA_URL="http://localhost:3000"
            APP_URL="http://localhost:8000"
            ;;
    esac
    
    export CONTINUOUS_MODE="$continuous"
    export SUMMARY_ONLY="$summary_only"
}

# Check if tools are available
check_prerequisites() {
    local required_tools=("kubectl" "curl" "jq")
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
}

# Get pod metrics
get_pod_metrics() {
    local pod_info=$(kubectl get pods -n "$NAMESPACE" -l app=ezzday-backend -o json)
    local total_pods=$(echo "$pod_info" | jq '.items | length')
    local ready_pods=$(echo "$pod_info" | jq '[.items[] | select(.status.conditions[]? | select(.type=="Ready" and .status=="True"))] | length')
    local running_pods=$(echo "$pod_info" | jq '[.items[] | select(.status.phase=="Running")] | length')
    
    echo "PODS_TOTAL:$total_pods,PODS_READY:$ready_pods,PODS_RUNNING:$running_pods"
}

# Get application health
get_app_health() {
    local health_status="UNKNOWN"
    local response_time=0
    
    if [[ -n "$APP_URL" ]]; then
        local start_time=$(date +%s%3N)
        if curl -f -s -m 10 "$APP_URL/health" >/dev/null 2>&1; then
            local end_time=$(date +%s%3N)
            response_time=$((end_time - start_time))
            health_status="HEALTHY"
        else
            health_status="UNHEALTHY"
        fi
    fi
    
    echo "HEALTH:$health_status,RESPONSE_TIME:${response_time}ms"
}

# Query Prometheus metrics
query_prometheus() {
    local query="$1"
    local result=""
    
    if [[ -n "$PROMETHEUS_URL" ]]; then
        result=$(curl -s -G "${PROMETHEUS_URL}/api/v1/query" \
            --data-urlencode "query=$query" 2>/dev/null | \
            jq -r '.data.result[0].value[1] // "0"' 2>/dev/null || echo "0")
    fi
    
    echo "$result"
}

# Get detailed metrics from Prometheus
get_prometheus_metrics() {
    if [[ -z "$PROMETHEUS_URL" ]]; then
        echo "PROMETHEUS:UNAVAILABLE"
        return
    fi
    
    # Error rate (5xx responses in last 5 minutes)
    local error_rate=$(query_prometheus 'rate(http_requests_total{status=~"5.."}[5m]) * 100')
    
    # 95th percentile response time
    local p95_response_time=$(query_prometheus 'histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m])) * 1000')
    
    # CPU usage
    local cpu_usage=$(query_prometheus 'avg(rate(container_cpu_usage_seconds_total{pod=~"ezzday-backend.*"}[5m])) * 100')
    
    # Memory usage
    local memory_usage=$(query_prometheus 'avg(container_memory_working_set_bytes{pod=~"ezzday-backend.*"}) / 1024 / 1024')
    
    # Request rate
    local request_rate=$(query_prometheus 'rate(http_requests_total[5m])')
    
    echo "ERROR_RATE:${error_rate}%,P95_RESPONSE:${p95_response_time}ms,CPU_USAGE:${cpu_usage}%,MEMORY_USAGE:${memory_usage}MB,REQUEST_RATE:${request_rate}req/s"
}

# Get resource usage
get_resource_usage() {
    local cpu_usage="0"
    local memory_usage="0"
    local disk_usage="0"
    
    # Get pod resource usage
    local resources=$(kubectl top pods -n "$NAMESPACE" -l app=ezzday-backend --no-headers 2>/dev/null || echo "")
    
    if [[ -n "$resources" ]]; then
        cpu_usage=$(echo "$resources" | awk '{cpu+=$2} END {print cpu}' | sed 's/m$//')
        memory_usage=$(echo "$resources" | awk '{mem+=$3} END {print mem}' | sed 's/Mi$//')
    fi
    
    echo "CPU_USAGE:${cpu_usage}m,MEMORY_USAGE:${memory_usage}Mi"
}

# Check for alerts
check_alerts() {
    local metrics="$1"
    local alerts_triggered=false
    
    # Parse metrics
    local error_rate=$(echo "$metrics" | grep -o 'ERROR_RATE:[^,]*' | cut -d: -f2 | sed 's/%$//')
    local response_time=$(echo "$metrics" | grep -o 'P95_RESPONSE:[^,]*' | cut -d: -f2 | sed 's/ms$//')
    
    # Check error rate threshold
    if [[ -n "$error_rate" && $(echo "$error_rate > $ALERT_THRESHOLD_ERROR_RATE" | bc -l 2>/dev/null || echo 0) -eq 1 ]]; then
        log_error "ALERT: High error rate detected: ${error_rate}% (threshold: ${ALERT_THRESHOLD_ERROR_RATE}%)"
        alerts_triggered=true
    fi
    
    # Check response time threshold
    if [[ -n "$response_time" && $(echo "$response_time > $ALERT_THRESHOLD_RESPONSE_TIME" | bc -l 2>/dev/null || echo 0) -eq 1 ]]; then
        log_error "ALERT: High response time detected: ${response_time}ms (threshold: ${ALERT_THRESHOLD_RESPONSE_TIME}ms)"
        alerts_triggered=true
    fi
    
    # Check pod health
    local pod_metrics=$(get_pod_metrics)
    local total_pods=$(echo "$pod_metrics" | grep -o 'PODS_TOTAL:[^,]*' | cut -d: -f2)
    local ready_pods=$(echo "$pod_metrics" | grep -o 'PODS_READY:[^,]*' | cut -d: -f2)
    
    if [[ "$ready_pods" -lt "$total_pods" ]]; then
        log_warning "ALERT: Not all pods are ready: $ready_pods/$total_pods"
        alerts_triggered=true
    fi
    
    return $([ "$alerts_triggered" = true ] && echo 1 || echo 0)
}

# Send alert notification
send_alert() {
    local message="$1"
    
    if [[ -n "$SLACK_WEBHOOK_URL" ]]; then
        local payload=$(cat <<EOF
{
    "attachments": [
        {
            "color": "danger",
            "title": "🚨 EzzDay Backend Alert - $ENVIRONMENT",
            "text": "$message",
            "footer": "EzzDay Monitoring",
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

# Display metrics dashboard
display_dashboard() {
    clear
    log_header "EzzDay Backend Monitoring Dashboard - $ENVIRONMENT"
    echo "$(date '+%Y-%m-%d %H:%M:%S') | Namespace: $NAMESPACE | App URL: $APP_URL"
    echo "─────────────────────────────────────────────────────────────────────────────────"
    
    # Get all metrics
    local pod_metrics=$(get_pod_metrics)
    local app_health=$(get_app_health)
    local prometheus_metrics=$(get_prometheus_metrics)
    local resource_metrics=$(get_resource_usage)
    
    # Display pod status
    echo -e "${BLUE}📊 Pod Status:${NC}"
    local total_pods=$(echo "$pod_metrics" | grep -o 'PODS_TOTAL:[^,]*' | cut -d: -f2)
    local ready_pods=$(echo "$pod_metrics" | grep -o 'PODS_READY:[^,]*' | cut -d: -f2)
    local running_pods=$(echo "$pod_metrics" | grep -o 'PODS_RUNNING:[^,]*' | cut -d: -f2)
    
    if [[ "$ready_pods" -eq "$total_pods" ]]; then
        echo -e "  ${GREEN}●${NC} Total: $total_pods | Ready: $ready_pods | Running: $running_pods"
    else
        echo -e "  ${YELLOW}●${NC} Total: $total_pods | Ready: $ready_pods | Running: $running_pods"
    fi
    
    # Display application health
    echo -e "${BLUE}🔍 Application Health:${NC}"
    local health_status=$(echo "$app_health" | grep -o 'HEALTH:[^,]*' | cut -d: -f2)
    local response_time=$(echo "$app_health" | grep -o 'RESPONSE_TIME:[^,]*' | cut -d: -f2)
    
    if [[ "$health_status" == "HEALTHY" ]]; then
        echo -e "  ${GREEN}●${NC} Status: $health_status | Response Time: $response_time"
    else
        echo -e "  ${RED}●${NC} Status: $health_status | Response Time: $response_time"
    fi
    
    # Display Prometheus metrics (if available)
    if [[ "$prometheus_metrics" != "PROMETHEUS:UNAVAILABLE" ]]; then
        echo -e "${BLUE}📈 Application Metrics:${NC}"
        
        local error_rate=$(echo "$prometheus_metrics" | grep -o 'ERROR_RATE:[^,]*' | cut -d: -f2)
        local p95_response=$(echo "$prometheus_metrics" | grep -o 'P95_RESPONSE:[^,]*' | cut -d: -f2)
        local cpu_usage=$(echo "$prometheus_metrics" | grep -o 'CPU_USAGE:[^,]*' | cut -d: -f2)
        local memory_usage=$(echo "$prometheus_metrics" | grep -o 'MEMORY_USAGE:[^,]*' | cut -d: -f2)
        local request_rate=$(echo "$prometheus_metrics" | grep -o 'REQUEST_RATE:[^,]*' | cut -d: -f2)
        
        echo "  Error Rate: $error_rate | P95 Response: $p95_response"
        echo "  CPU Usage: $cpu_usage | Memory Usage: $memory_usage"
        echo "  Request Rate: $request_rate"
    fi
    
    # Display resource usage
    echo -e "${BLUE}💻 Resource Usage:${NC}"
    local cpu_usage=$(echo "$resource_metrics" | grep -o 'CPU_USAGE:[^,]*' | cut -d: -f2)
    local memory_usage=$(echo "$resource_metrics" | grep -o 'MEMORY_USAGE:[^,]*' | cut -d: -f2)
    echo "  CPU: $cpu_usage | Memory: $memory_usage"
    
    # Check for alerts
    if check_alerts "$prometheus_metrics"; then
        echo -e "${RED}🚨 ALERTS ACTIVE${NC}"
    else
        echo -e "${GREEN}✅ No Active Alerts${NC}"
    fi
    
    echo "─────────────────────────────────────────────────────────────────────────────────"
    echo "Monitoring for $MONITORING_DURATION seconds | Check interval: $CHECK_INTERVAL seconds"
    
    if [[ "$CONTINUOUS_MODE" == "true" ]]; then
        echo "Running in continuous mode. Press Ctrl+C to stop."
    fi
}

# Show summary only
show_summary() {
    local pod_metrics=$(get_pod_metrics)
    local app_health=$(get_app_health)
    
    local total_pods=$(echo "$pod_metrics" | grep -o 'PODS_TOTAL:[^,]*' | cut -d: -f2)
    local ready_pods=$(echo "$pod_metrics" | grep -o 'PODS_READY:[^,]*' | cut -d: -f2)
    local health_status=$(echo "$app_health" | grep -o 'HEALTH:[^,]*' | cut -d: -f2)
    
    if [[ "$ready_pods" -eq "$total_pods" && "$health_status" == "HEALTHY" ]]; then
        log_success "Environment $ENVIRONMENT is healthy: $ready_pods/$total_pods pods ready, app status: $health_status"
    else
        log_warning "Environment $ENVIRONMENT has issues: $ready_pods/$total_pods pods ready, app status: $health_status"
    fi
}

# Signal handler for graceful shutdown
signal_handler() {
    echo ""
    log_info "Monitoring stopped by user"
    exit 0
}

# Main monitoring loop
main_monitoring_loop() {
    local start_time=$(date +%s)
    local end_time=$((start_time + MONITORING_DURATION))
    
    # Set up signal handlers
    trap signal_handler SIGINT SIGTERM
    
    while [[ $(date +%s) -lt $end_time ]]; do
        if [[ "$SUMMARY_ONLY" == "true" ]]; then
            show_summary
        else
            display_dashboard
        fi
        
        # Sleep for the check interval
        sleep "$CHECK_INTERVAL"
    done
    
    log_info "Monitoring completed after $MONITORING_DURATION seconds"
}

# Main execution function
main() {
    log_header "Starting EzzDay Backend Monitoring"
    log_info "Environment: $ENVIRONMENT"
    log_info "Namespace: $NAMESPACE"
    log_info "Monitoring Duration: $MONITORING_DURATION seconds"
    
    # Check prerequisites
    check_prerequisites
    
    # Start monitoring
    main_monitoring_loop
}

# Parse arguments and run main function
parse_args "$@"
main