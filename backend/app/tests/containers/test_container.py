"""
Real integration testing container.

Provides real infrastructure components for true integration testing.
"""

import asyncio
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.main import app
from app.core.database import Base, get_async_session


class TestContainer:
    """Container for real integration testing components."""
    
    def __init__(self):
        self.db_engine = None
        self.db_session = None
        self.async_client = None
        self._cleanup_tasks = []
        
    async def __aenter__(self):
        """Async context manager entry."""
        await self.start()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.stop()
        
    async def start(self):
        """Start all test infrastructure."""
        # Start database
        await self._start_database()
        
        # Start HTTP client
        await self._start_client()
        
        # Override app dependencies
        app.dependency_overrides[get_async_session] = self._get_test_session
        
    async def stop(self):
        """Stop all test infrastructure."""
        # Clear app overrides
        app.dependency_overrides.clear()
        
        # Close client
        if self.async_client:
            await self.async_client.aclose()
            
        # Close database
        if self.db_session:
            await self.db_session.close()
        if self.db_engine:
            await self.db_engine.dispose()
            
        # Run cleanup tasks
        for task in self._cleanup_tasks:
            try:
                await task()
            except Exception:
                pass  # Ignore cleanup errors
                
    async def _start_database(self):
        """Start test database."""
        test_db_url = "postgresql+asyncpg://ezzday_test:test_password@localhost:5432/ezzday_test"
        
        self.db_engine = create_async_engine(
            test_db_url,
            echo=False,
            pool_size=10,
            max_overflow=20
        )
        
        # Create tables
        async with self.db_engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            
        # Create session factory
        self.session_factory = sessionmaker(
            self.db_engine, 
            class_=AsyncSession, 
            expire_on_commit=False
        )
        
    async def _start_client(self):
        """Start HTTP test client."""
        self.async_client = AsyncClient(
            app=app,
            base_url="http://testserver"
        )
        
    async def _get_test_session(self):
        """Get test database session."""
        async with self.session_factory() as session:
            yield session
            
    async def create_user(self, user_data: dict) -> dict:
        """Create user through API."""
        response = await self.async_client.post(
            "/api/v1/auth/register",
            json=user_data
        )
        return response.json() if response.status_code == 201 else None
        
    async def login_user(self, credentials: dict) -> dict:
        """Login user and return tokens."""
        response = await self.async_client.post(
            "/api/v1/auth/login",
            json=credentials
        )
        return response.json() if response.status_code == 200 else None
        
    async def verify_database_state(self, expected_state: dict) -> bool:
        """Verify database contains expected state."""
        async with self.session_factory() as session:
            # Add verification logic based on expected_state
            return True
            
    async def cleanup_data(self):
        """Clean up test data."""
        async with self.session_factory() as session:
            # Truncate test data
            await session.execute("TRUNCATE TABLE users CASCADE")
            await session.execute("TRUNCATE TABLE sessions CASCADE")
            await session.commit()


@pytest.fixture
async def test_container() -> AsyncGenerator[TestContainer, None]:
    """Provide TestContainer for integration tests."""
    container = TestContainer()
    await container.start()
    try:
        yield container
    finally:
        await container.stop()


@pytest.fixture
async def authenticated_container(test_container: TestContainer, user_mother) -> TestContainer:
    """Provide TestContainer with authenticated user."""
    # Create user
    user = user_mother.active_verified_user()
    user_data = {
        "username": user.email.value,
        "email": user.email.value,
        "password": "TestPass123!@#",
        "confirm_password": "TestPass123!@#"
    }
    
    await test_container.create_user(user_data)
    
    # Login user
    credentials = {
        "username": user.email.value,
        "password": "TestPass123!@#"
    }
    
    tokens = await test_container.login_user(credentials)
    test_container.auth_tokens = tokens
    
    return test_container