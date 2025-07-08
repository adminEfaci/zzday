# EzzDay Backend

Production-grade waste management platform backend built with FastAPI, GraphQL, and PostgreSQL.

## Architecture

- **Hexagonal Architecture** with clear separation of concerns
- **CQRS** for optimized read/write operations
- **Event-Driven** communication between bounded contexts
- **Domain-Driven Design** with aggregates, entities, and value objects
- **GraphQL API** with field-level permissions

## Tech Stack

- **Framework**: FastAPI 0.111.0
- **GraphQL**: Strawberry 0.231.2
- **Database**: PostgreSQL 15 + PostGIS
- **ORM**: SQLAlchemy 2.0 (async)
- **Cache**: Redis 7
- **Task Queue**: Celery 5.3
- **Authentication**: JWT with refresh tokens
- **Testing**: Pytest with 90%+ coverage

## Quick Start

### Prerequisites

- Python 3.11+
- Docker & Docker Compose
- Make (optional but recommended)

### Development Setup

1. Clone the repository:
```bash
git clone https://github.com/ezzday/backend.git
cd backend