# Ezzday

A modern backend application built with FastAPI and Domain-Driven Design principles.

## Project Structure

```
ezzday/
├── backend/
│   ├── app/
│   │   ├── modules/
│   │   │   ├── identity/
│   │   │   ├── audit/
│   │   │   ├── integration/
│   │   │   └── notification/
│   │   ├── core/
│   │   ├── infrastructure/
│   │   └── shared/
│   ├── tests/
│   └── docs/
└── README.md
```

## Getting Started

### Prerequisites

- Python 3.11+
- PostgreSQL
- UV package manager

### Installation

1. Clone the repository
```bash
git clone https://github.com/adminEfaci/zzday.git
cd zzday
```

2. Set up the backend
```bash
cd backend
cp .env.example .env
# Edit .env with your configuration
uv sync
```

3. Run migrations
```bash
uv run alembic upgrade head
```

4. Start the development server
```bash
uv run uvicorn app.main:app --reload
```

## Development

### Running Tests
```bash
cd backend
./run_tests.sh
```

### Type Checking
```bash
cd backend
uv run python check_types.py
```

## License

This project is proprietary and confidential.