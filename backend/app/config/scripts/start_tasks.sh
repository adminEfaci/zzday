#!/bin/bash

# EzzDay Background Tasks Startup Script

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Docker is running
check_docker() {
    if ! docker info > /dev/null 2>&1; then
        print_error "Docker is not running. Please start Docker first."
        exit 1
    fi
    print_success "Docker is running"
}

# Check if required environment variables are set
check_environment() {
    print_status "Checking environment variables..."
    
    # Create .env file if it doesn't exist
    if [ ! -f .env ]; then
        print_warning ".env file not found. Creating default .env file..."
        cat > .env << EOF
# Database
DATABASE_URL=postgresql://ezzday:ezzday_db_pass@localhost:5432/ezzday

# RabbitMQ
RABBITMQ_USER=ezzday
RABBITMQ_PASSWORD=ezzday_rabbitmq_pass
RABBITMQ_VHOST=ezzday

# Redis
REDIS_PASSWORD=ezzday_redis_pass

# Celery
CELERY_BROKER_URL=amqp://ezzday:ezzday_rabbitmq_pass@localhost:5672/ezzday
CELERY_RESULT_BACKEND=redis://:ezzday_redis_pass@localhost:6379/0
CELERY_TASK_ALWAYS_EAGER=false

# Flower (Celery monitoring)
FLOWER_USER=admin
FLOWER_PASSWORD=flower_admin_pass

# Email (configure with your SMTP settings)
EMAIL_HOST=smtp.example.com
EMAIL_PORT=587
EMAIL_USERNAME=your-email@example.com
EMAIL_PASSWORD=your-email-password

# SMS (configure with your SMS provider)
SMS_PROVIDER_API_KEY=your-sms-api-key

# Environment
ENVIRONMENT=development
EOF
        print_success "Default .env file created. Please update it with your settings."
    fi
    
    # Source environment variables
    if [ -f .env ]; then
        export $(cat .env | grep -v '#' | xargs)
    fi
    
    print_success "Environment variables loaded"
}

# Create necessary directories
create_directories() {
    print_status "Creating necessary directories..."
    
    mkdir -p docker/rabbitmq
    mkdir -p logs
    mkdir -p celerybeat
    
    print_success "Directories created"
}

# Start infrastructure services
start_infrastructure() {
    print_status "Starting infrastructure services (RabbitMQ, Redis)..."
    
    docker-compose -f docker-compose.tasks.yml up -d rabbitmq redis
    
    # Wait for services to be healthy
    print_status "Waiting for RabbitMQ to be ready..."
    for i in {1..30}; do
        if docker-compose -f docker-compose.tasks.yml exec rabbitmq rabbitmq-diagnostics ping > /dev/null 2>&1; then
            print_success "RabbitMQ is ready"
            break
        fi
        if [ $i -eq 30 ]; then
            print_error "RabbitMQ failed to start within 30 seconds"
            exit 1
        fi
        sleep 1
    done
    
    print_status "Waiting for Redis to be ready..."
    for i in {1..30}; do
        if docker-compose -f docker-compose.tasks.yml exec redis redis-cli ping > /dev/null 2>&1; then
            print_success "Redis is ready"
            break
        fi
        if [ $i -eq 30 ]; then
            print_error "Redis failed to start within 30 seconds"
            exit 1
        fi
        sleep 1
    done
}

# Start Celery workers
start_workers() {
    print_status "Starting Celery workers..."
    
    docker-compose -f docker-compose.tasks.yml up -d \
        celery-worker-general \
        celery-worker-priority \
        celery-worker-notifications \
        celery-worker-integrations
    
    print_success "Celery workers started"
}

# Start Celery beat scheduler
start_beat() {
    print_status "Starting Celery beat scheduler..."
    
    docker-compose -f docker-compose.tasks.yml up -d celery-beat
    
    print_success "Celery beat scheduler started"
}

# Start monitoring services
start_monitoring() {
    print_status "Starting monitoring services..."
    
    docker-compose -f docker-compose.tasks.yml up -d celery-flower task-monitor
    
    print_success "Monitoring services started"
    print_status "Flower monitoring available at: http://localhost:5555"
    print_status "RabbitMQ management available at: http://localhost:15672"
}

# Show status
show_status() {
    print_status "Checking service status..."
    
    docker-compose -f docker-compose.tasks.yml ps
    
    print_status "\nService URLs:"
    echo "  - Flower (Celery monitoring): http://localhost:5555"
    echo "  - RabbitMQ Management: http://localhost:15672"
    echo "  - Default credentials in .env file"
}

# Health check
health_check() {
    print_status "Performing health check..."
    
    # Check if containers are running
    if ! docker-compose -f docker-compose.tasks.yml ps | grep -q "Up"; then
        print_warning "Some services may not be running properly"
        return 1
    fi
    
    # Ping workers
    print_status "Pinging Celery workers..."
    if docker-compose -f docker-compose.tasks.yml exec celery-worker-general celery -A app.tasks inspect ping > /dev/null 2>&1; then
        print_success "Workers are responsive"
    else
        print_warning "Workers may not be fully ready yet"
    fi
    
    print_success "Health check completed"
}

# Main execution
main() {
    print_status "Starting EzzDay Background Task System..."
    
    # Parse command line arguments
    case ${1:-start} in
        "start")
            check_docker
            check_environment
            create_directories
            start_infrastructure
            start_workers
            start_beat
            start_monitoring
            sleep 5  # Wait for services to initialize
            show_status
            health_check
            print_success "EzzDay Background Task System started successfully!"
            ;;
        "stop")
            print_status "Stopping EzzDay Background Task System..."
            docker-compose -f docker-compose.tasks.yml down
            print_success "Services stopped"
            ;;
        "restart")
            print_status "Restarting EzzDay Background Task System..."
            $0 stop
            sleep 2
            $0 start
            ;;
        "status")
            show_status
            health_check
            ;;
        "logs")
            docker-compose -f docker-compose.tasks.yml logs -f ${2:-}
            ;;
        "health")
            health_check
            ;;
        *)
            echo "Usage: $0 {start|stop|restart|status|logs [service]|health}"
            echo ""
            echo "Commands:"
            echo "  start   - Start all background task services"
            echo "  stop    - Stop all services"
            echo "  restart - Restart all services"
            echo "  status  - Show service status"
            echo "  logs    - Show logs (optionally for specific service)"
            echo "  health  - Perform health check"
            exit 1
            ;;
    esac
}

# Run main function
main "$@"