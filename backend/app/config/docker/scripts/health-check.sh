#!/bin/bash
# EzzDay Backend - Health Check Script
# Used by Docker and orchestrators to determine container health

set -e

# Default health check endpoint
HEALTH_ENDPOINT="${HEALTH_CHECK_PATH:-/health}"
HEALTH_PORT="${PORT:-8000}"
HEALTH_TIMEOUT="${HEALTH_CHECK_TIMEOUT:-5}"

# Perform health check
response=$(curl -sf -m $HEALTH_TIMEOUT \
    -H "User-Agent: Docker-HealthCheck/1.0" \
    "http://localhost:${HEALTH_PORT}${HEALTH_ENDPOINT}" || echo "FAILED")

# Check if the response indicates health
if [[ "$response" == "FAILED" ]]; then
    echo "Health check failed: Unable to connect to service"
    exit 1
fi

# Parse JSON response and check status
status=$(echo "$response" | python -c "
import sys, json
try:
    data = json.load(sys.stdin)
    if data.get('status') == 'healthy':
        print('OK')
    else:
        print('UNHEALTHY')
        print(f\"Status: {data.get('status', 'unknown')}\")
        if 'details' in data:
            for service, info in data['details'].items():
                print(f\"  {service}: {info.get('status', 'unknown')}\")
except Exception as e:
    print('ERROR')
    print(f\"Failed to parse response: {e}\")
" 2>&1)

if [[ "$status" == "OK" ]]; then
    echo "Health check passed"
    exit 0
else
    echo "Health check failed:"
    echo "$status"
    exit 1
fi