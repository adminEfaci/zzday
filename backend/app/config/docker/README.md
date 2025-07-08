# EzzDay Backend - Docker Configuration

This directory contains all Docker-related configuration for the EzzDay backend application.

## Overview

The Docker setup is optimized for production deployment with:
- Multi-stage builds for smaller images
- Security scanning with Trivy
- Resource limits and health checks
- Comprehensive monitoring with Prometheus and Grafana
- High availability Redis with Sentinel
- Automated backups
- Zero-downtime deployments

## Directory Structure

```
docker/
├── Dockerfile              # Production Dockerfile
├── Dockerfile.ci          # CI/CD Dockerfile with security scanning
├── Dockerfile.dev         # Development Dockerfile
├── docker-compose.yml     # Development stack
├── docker-compose.prod.yml # Production stack
├── docker-compose.test.yml # Test environment
├── scripts/
│   ├── entrypoint.sh      # Container initialization
│   └── health-check.sh    # Health check script
└── README.md              # This file
```

## Quick Start

### Development

```bash
# Start development stack
docker-compose -f app/config/docker/docker-compose.yml up -d

# View logs
docker-compose -f app/config/docker/docker-compose.yml logs -f app

# Run tests
docker-compose -f app/config/docker/docker-compose.test.yml up --abort-on-container-exit
```

### Production

```bash
# Build production image
docker build -f app/config/docker/Dockerfile -t ezzday/backend:latest .

# Start production stack
docker-compose -f app/config/docker/docker-compose.prod.yml up -d

# Scale application
docker-compose -f app/config/docker/docker-compose.prod.yml up -d --scale app=3
```

## Configuration

### Environment Variables

Copy `.env.example` to `.env` and configure:

```bash
cp .env.example .env
# Edit .env with your values
```

Key variables for monitoring:
- `PROMETHEUS_MULTIPROC_DIR`: Directory for Prometheus metrics
- `GRAFANA_ADMIN_PASSWORD`: Grafana admin password
- `FLOWER_USER/FLOWER_PASSWORD`: Celery monitoring credentials

### Resource Limits

All services have configured resource limits:

| Service | CPU Limit | Memory Limit | CPU Reservation | Memory Reservation |
|---------|-----------|--------------|-----------------|-------------------|
| App | 1.0 | 512M | 0.5 | 256M |
| Nginx | 0.5 | 256M | 0.25 | 128M |
| Redis Master | 0.5 | 768M | 0.25 | 512M |
| Redis Replica | 0.5 | 768M | 0.25 | 512M |
| Prometheus | 0.5 | 1G | 0.25 | 512M |
| Grafana | 0.5 | 512M | 0.25 | 256M |

### Health Checks

All services include health checks:

```yaml
healthcheck:
  test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
  interval: 30s
  timeout: 10s
  retries: 3
  start_period: 40s
```

## Monitoring

### Prometheus

Access at: http://localhost:9090

Configured scrape targets:
- FastAPI metrics: `/metrics`
- Redis metrics via redis-exporter
- PostgreSQL metrics via postgres-exporter
- Container metrics via cAdvisor
- System metrics via node-exporter

### Grafana

Access at: http://localhost:3000

Pre-configured dashboards:
- API Performance
- Database Performance
- Container Resources

Default credentials:
- Username: `admin`
- Password: Set via `GRAFANA_ADMIN_PASSWORD`

### Alerts

Prometheus alert rules are configured for:
- High error rates (>5%)
- Slow response times (>1s p95)
- Service downtime
- Resource exhaustion
- SSL certificate expiration

## Security

### Image Scanning

The CI Dockerfile includes multiple security scanning stages:

1. **Dependency Scanning**: Using Safety for Python packages
2. **Code Scanning**: Using Bandit and Semgrep
3. **Image Scanning**: Using Trivy for vulnerabilities

To run security scans:

```bash
# Build with security scanning
docker build -f app/config/docker/Dockerfile.ci -t ezzday/backend:ci .

# Extract scan reports
docker run --rm ezzday/backend:ci cat /tmp/trivy-report.json
```

### Runtime Security

- Non-root user execution
- Read-only root filesystem
- No new privileges
- Security headers enabled
- Network isolation between services

## Deployment

### Building Images

```bash
# Production build
docker build \
  -f app/config/docker/Dockerfile \
  -t ezzday/backend:$(git rev-parse --short HEAD) \
  -t ezzday/backend:latest \
  .

# Push to registry
docker push ezzday/backend:latest
```

### Zero-Downtime Deployment

1. Build new image
2. Update `IMAGE_TAG` in environment
3. Rolling update:
   ```bash
   docker-compose -f docker-compose.prod.yml up -d --no-deps --scale app=6 app
   docker-compose -f docker-compose.prod.yml up -d --no-deps --scale app=3 app
   ```

### Backup and Recovery

Automated backups run daily at 2 AM:
- Database dumps to S3
- Redis snapshots
- Application logs

Restore procedure:
```bash
# Restore database
docker exec -i ezzday-postgres-prod psql -U ezzday < backup.sql

# Restore Redis
docker cp redis-backup.rdb ezzday-redis-master-prod:/data/dump.rdb
docker restart ezzday-redis-master-prod
```

## Troubleshooting

### Common Issues

1. **Container fails to start**
   - Check logs: `docker logs ezzday-backend-prod`
   - Verify environment variables
   - Check health endpoint: `curl http://localhost:8000/health`

2. **High memory usage**
   - Check metrics in Grafana
   - Review memory limits
   - Enable memory profiling

3. **Slow performance**
   - Check Prometheus metrics
   - Review database slow query logs
   - Check Redis memory usage

### Debug Mode

Enable debug mode for troubleshooting:

```bash
# Override entrypoint for debugging
docker run -it --rm \
  --entrypoint /bin/bash \
  -e DEBUG=true \
  ezzday/backend:latest

# Connect to running container
docker exec -it ezzday-backend-prod /bin/bash
```

### Logs

Access logs:
```bash
# Application logs
docker logs ezzday-backend-prod

# All service logs
docker-compose -f docker-compose.prod.yml logs -f

# Specific service logs
docker-compose -f docker-compose.prod.yml logs -f prometheus grafana
```

## Maintenance

### Updates

1. Update base images regularly
2. Run security scans on new builds
3. Review and update resource limits
4. Update monitoring dashboards

### Cleanup

```bash
# Remove unused images
docker image prune -a

# Remove unused volumes
docker volume prune

# Full cleanup (WARNING: removes all unused resources)
docker system prune -a --volumes
```