# EzzDay Backend - Production Dockerfile
# Multi-stage build for optimized production image

# Build stage
FROM python:3.12-slim as builder

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies for building
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    libssl-dev \
    libffi-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install UV package manager
RUN pip install uv

# Create application directory
WORKDIR /app

# Copy dependency files
COPY app/config/requirements/requirements.txt .
COPY app/config/requirements/prod.txt .

# Install Python dependencies using UV
RUN uv pip install --system -r prod.txt

# Security scanning stage
FROM aquasec/trivy:latest as scanner

# Copy the built image for scanning
COPY --from=builder / /scan

# Run Trivy vulnerability scan
RUN trivy filesystem --no-progress --severity HIGH,CRITICAL --exit-code 1 /scan || \
    (echo "Security vulnerabilities found!" && exit 1)

# Production stage
FROM python:3.12-slim as production

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/app/.local/bin:$PATH" \
    ENVIRONMENT=production

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libpq5 \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user
RUN groupadd -r ezzday && useradd -r -g ezzday -d /app -s /bin/bash ezzday

# Create application directory
WORKDIR /app

# Copy Python packages from builder stage
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY app/ ./app/
COPY app/config/docker/scripts/entrypoint.sh ./entrypoint.sh
COPY app/config/docker/scripts/health-check.sh ./health-check.sh

# Create required directories
RUN mkdir -p /app/logs /app/storage /app/tmp \
    && chown -R ezzday:ezzday /app \
    && chmod +x ./entrypoint.sh ./health-check.sh

# Security: Remove any potential sensitive files
RUN find /app -name "*.pyc" -delete \
    && find /app -name "__pycache__" -delete \
    && find /app -name ".git*" -delete

# Switch to non-root user
USER ezzday

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["./health-check.sh"]

# Set entrypoint
ENTRYPOINT ["./entrypoint.sh"]

# Default command
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]