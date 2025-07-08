"""Testing utilities following DDD principles and hexagonal architecture.

This module provides framework-agnostic testing utilities that follow Domain-Driven Design
principles. All testing classes are pure Python that can be used across different layers
of the application without tight coupling to any specific framework.

Design Principles:
- Framework-agnostic (no FastAPI/Pydantic dependencies)
- Pure Python classes with clean __init__ validation
- Rich functionality with utility methods and properties
- Comprehensive error handling with clear ValidationError messages
- Static utility methods for convenience
- Proper class behavior (__eq__, __hash__, __repr__, __str__)
"""

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock, Mock
from uuid import UUID, uuid4

from faker import Faker

from app.core.errors import ValidationError

# Handle optional dependencies
try:
    from pydantic import BaseModel
except ImportError:
    class BaseModel:
        """Fallback BaseModel."""
        def model_dump(self, exclude=None):
            return {}

try:
    from app.core.database import get_session
except ImportError:
    async def get_session():
        """Fallback session."""
        yield None

try:
    from app.core.security import hash_password
except ImportError:
    def hash_password(password: str) -> str:
        """Fallback password hasher."""
        return f"hashed_{password}"

fake = Faker()


# =====================================================================================
# TEST DATA GENERATION CLASSES
# =====================================================================================


class TestDataFactory:
    """Factory for generating test data with rich functionality."""

    def __init__(self, seed: int | None = None, locale: str | None = None):
        """
        Initialize test data factory.

        Args:
            seed: Random seed for reproducible data
            locale: Locale for data generation
        """
        self.seed = seed
        self.locale = locale or "en_US"
        self.faker = Faker(self.locale)

        if seed is not None:
            self.faker.seed_instance(seed)
            Faker.seed(seed)

    def create_user_data(
        self, email: str | None = None, password: str | None = None, **kwargs
    ) -> dict[str, Any]:
        """
        Create user test data.

        Args:
            email: Custom email (generates if None)
            password: Custom password (generates if None)
            **kwargs: Additional user attributes

        Returns:
            Dict: User data dictionary
        """
        return {
            "id": kwargs.get("id", uuid4()),
            "email": email or self.faker.email(),
            "hashed_password": hash_password(password or "Test123!"),
            "name": kwargs.get("name", self.faker.name()),
            "role": kwargs.get("role", "driver"),
            "status": kwargs.get("status", "active"),
            "created_at": kwargs.get("created_at", datetime.now(UTC)),
            "updated_at": kwargs.get("updated_at", datetime.now(UTC)),
        }

    def create_session_data(
        self, user_id: UUID | None = None, **kwargs
    ) -> dict[str, Any]:
        """
        Create session test data.

        Args:
            user_id: User ID for session (generates if None)
            **kwargs: Additional session attributes

        Returns:
            Dict: Session data dictionary
        """
        return {
            "id": kwargs.get("id", uuid4()),
            "user_id": user_id or uuid4(),
            "token_hash": kwargs.get("token_hash", self.faker.sha256()),
            "ip_address": kwargs.get("ip_address", self.faker.ipv4()),
            "user_agent": kwargs.get("user_agent", self.faker.user_agent()),
            "expires_at": kwargs.get(
                "expires_at",
                datetime.now(UTC) + timedelta(hours=24),
            ),
            "created_at": kwargs.get("created_at", datetime.now(UTC)),
        }

    def create_address_data(self, **kwargs) -> dict[str, Any]:
        """
        Create address test data.

        Args:
            **kwargs: Custom address attributes

        Returns:
            Dict: Address data dictionary
        """
        return {
            "street": kwargs.get("street", self.faker.street_address()),
            "city": kwargs.get("city", self.faker.city()),
            "state_province": kwargs.get("state_province", self.faker.state()),
            "postal_code": kwargs.get("postal_code", "A1A 1A1"),
            "country": kwargs.get("country", "Canada"),
        }

    def create_company_data(self, **kwargs) -> dict[str, Any]:
        """
        Create company test data.

        Args:
            **kwargs: Custom company attributes

        Returns:
            Dict: Company data dictionary
        """
        return {
            "id": kwargs.get("id", uuid4()),
            "name": kwargs.get("name", self.faker.company()),
            "email": kwargs.get("email", self.faker.company_email()),
            "phone": kwargs.get("phone", self.faker.phone_number()),
            "website": kwargs.get("website", self.faker.url()),
            "industry": kwargs.get(
                "industry",
                self.faker.random_element(
                    ["Technology", "Healthcare", "Finance", "Education", "Retail"]
                ),
            ),
            "size": kwargs.get(
                "size",
                self.faker.random_element(
                    ["1-10", "11-50", "51-200", "201-1000", "1000+"]
                ),
            ),
            "created_at": kwargs.get("created_at", datetime.now(UTC)),
        }

    def create_batch_data(
        self, factory_method: str, count: int, **base_kwargs
    ) -> list[dict[str, Any]]:
        """
        Create batch of test data.

        Args:
            factory_method: Name of factory method to call
            count: Number of items to create
            **base_kwargs: Base attributes for all items

        Returns:
            list[Dict]: List of generated data

        Raises:
            ValidationError: If factory method doesn't exist
        """
        if not hasattr(self, factory_method):
            raise ValidationError(f"Factory method '{factory_method}' does not exist")

        method = getattr(self, factory_method)
        return [method(**base_kwargs) for _ in range(count)]

    @staticmethod
    def create_user_data_static(
        email: str | None = None, password: str | None = None, **kwargs
    ) -> dict[str, Any]:
        """
        Static method to create user test data.

        Args:
            email: Custom email
            password: Custom password
            **kwargs: Additional attributes

        Returns:
            Dict: User data dictionary
        """
        return {
            "id": kwargs.get("id", uuid4()),
            "email": email or fake.email(),
            "hashed_password": hash_password(password or "Test123!"),
            "name": kwargs.get("name", fake.name()),
            "role": kwargs.get("role", "driver"),
            "status": kwargs.get("status", "active"),
            "created_at": kwargs.get("created_at", datetime.now(UTC)),
            "updated_at": kwargs.get("updated_at", datetime.now(UTC)),
        }

    @staticmethod
    def create_session_data_static(
        user_id: UUID | None = None, **kwargs
    ) -> dict[str, Any]:
        """
        Static method to create session test data.

        Args:
            user_id: User ID for session
            **kwargs: Additional attributes

        Returns:
            Dict: Session data dictionary
        """
        return {
            "id": kwargs.get("id", uuid4()),
            "user_id": user_id or uuid4(),
            "token_hash": kwargs.get("token_hash", fake.sha256()),
            "ip_address": kwargs.get("ip_address", fake.ipv4()),
            "user_agent": kwargs.get("user_agent", fake.user_agent()),
            "expires_at": kwargs.get(
                "expires_at",
                datetime.now(UTC) + timedelta(hours=24),
            ),
            "created_at": kwargs.get("created_at", datetime.now(UTC)),
        }

    @staticmethod
    def create_address_data_static(**kwargs) -> dict[str, Any]:
        """
        Static method to create address test data.

        Args:
            **kwargs: Custom attributes

        Returns:
            Dict: Address data dictionary
        """
        return {
            "street": kwargs.get("street", fake.street_address()),
            "city": kwargs.get("city", fake.city()),
            "state_province": kwargs.get("state_province", fake.state()),
            "postal_code": kwargs.get("postal_code", "A1A 1A1"),
            "country": kwargs.get("country", "Canada"),
        }

    def __repr__(self) -> str:
        """Detailed string representation for debugging."""
        return f"TestDataFactory(seed={self.seed}, locale='{self.locale}')"


class AsyncTestCase:
    """Base class for async test cases with rich functionality."""

    def __init__(self, debug: bool = False):
        """
        Initialize async test case.

        Args:
            debug: Enable debug mode
        """
        self.debug = debug
        self.setup_complete = False
        self.teardown_complete = False
        self._test_data = {}

    @classmethod
    def setup_class(cls):
        """Set up test class."""
        cls.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(cls.loop)

    @classmethod
    def teardown_class(cls):
        """Tear down test class."""
        if hasattr(cls, "loop"):
            cls.loop.close()

    async def async_setup(self):
        """Async setup method - override in subclasses."""
        if self.debug:
            print(f"Setting up {self.__class__.__name__}")
        self.setup_complete = True

    async def async_teardown(self):
        """Async teardown method - override in subclasses."""
        if self.debug:
            print(f"Tearing down {self.__class__.__name__}")
        self._test_data.clear()
        self.teardown_complete = True

    def setup_method(self):
        """Set up test method."""
        if hasattr(self, "loop"):
            self.loop.run_until_complete(self.async_setup())

    def teardown_method(self):
        """Tear down test method."""
        if hasattr(self, "loop"):
            self.loop.run_until_complete(self.async_teardown())

    def store_test_data(self, key: str, value: Any) -> None:
        """
        Store test data for later use.

        Args:
            key: Data key
            value: Data value
        """
        self._test_data[key] = value

    def get_test_data(self, key: str, default: Any = None) -> Any:
        """
        Get stored test data.

        Args:
            key: Data key
            default: Default value if key not found

        Returns:
            Stored value or default
        """
        return self._test_data.get(key, default)

    def clear_test_data(self) -> None:
        """Clear all stored test data."""
        self._test_data.clear()

    @property
    def test_data_keys(self) -> list[str]:
        """Get list of stored test data keys."""
        return list(self._test_data.keys())

    def __repr__(self) -> str:
        """Detailed string representation for debugging."""
        return f"AsyncTestCase(debug={self.debug}, setup={self.setup_complete})"


class MockRepository:
    """Mock repository for testing with rich functionality."""

    def __init__(self, initial_data: dict[UUID, Any] | None = None):
        """
        Initialize mock repository.

        Args:
            initial_data: Initial data to populate repository
        """
        self._data: dict[UUID, Any] = initial_data or {}
        self._access_log: list[dict[str, Any]] = []
        self._call_counts: dict[str, int] = {}

    async def get_by_id(self, id: UUID) -> Any | None:
        """
        Get entity by ID.

        Args:
            id: Entity ID

        Returns:
            Entity or None if not found
        """
        self._log_access("get_by_id", {"id": id})
        return self._data.get(id)

    async def save(self, entity: Any) -> None:
        """
        Save entity.

        Args:
            entity: Entity to save
        """
        entity_id = getattr(entity, "id", uuid4())
        self._log_access("save", {"entity_id": entity_id})
        self._data[entity_id] = entity

    async def delete(self, id: UUID) -> None:
        """
        Delete entity.

        Args:
            id: Entity ID to delete
        """
        self._log_access("delete", {"id": id})
        self._data.pop(id, None)

    async def find_by_criteria(self, criteria: dict[str, Any]) -> list[Any]:
        """
        Find entities by criteria.

        Args:
            criteria: Search criteria

        Returns:
            List of matching entities
        """
        self._log_access("find_by_criteria", {"criteria": criteria})

        results = []
        for entity in self._data.values():
            match = True
            for key, value in criteria.items():
                if not hasattr(entity, key) or getattr(entity, key) != value:
                    match = False
                    break
            if match:
                results.append(entity)

        return results

    async def count(self) -> int:
        """
        Get count of entities.

        Returns:
            Number of entities
        """
        self._log_access("count", {})
        return len(self._data)

    async def exists(self, id: UUID) -> bool:
        """
        Check if entity exists.

        Args:
            id: Entity ID

        Returns:
            True if entity exists
        """
        self._log_access("exists", {"id": id})
        return id in self._data

    def _log_access(self, method: str, params: dict[str, Any]) -> None:
        """Log repository access for testing verification."""
        self._access_log.append(
            {
                "method": method,
                "params": params,
                "timestamp": datetime.now(UTC),
            }
        )
        self._call_counts[method] = self._call_counts.get(method, 0) + 1

    def get_access_log(self) -> list[dict[str, Any]]:
        """Get repository access log."""
        return self._access_log.copy()

    def get_call_count(self, method: str) -> int:
        """
        Get call count for method.

        Args:
            method: Method name

        Returns:
            Number of calls
        """
        return self._call_counts.get(method, 0)

    def clear(self) -> None:
        """Clear all data and logs."""
        self._data.clear()
        self._access_log.clear()
        self._call_counts.clear()

    def load_test_data(self, data: dict[UUID, Any]) -> None:
        """
        Load test data into repository.

        Args:
            data: Test data to load
        """
        self._data.update(data)
        self._log_access("load_test_data", {"count": len(data)})

    @property
    def entity_count(self) -> int:
        """Get current entity count."""
        return len(self._data)

    @property
    def all_entities(self) -> list[Any]:
        """Get all entities."""
        return list(self._data.values())

    def __repr__(self) -> str:
        """Detailed string representation for debugging."""
        return f"MockRepository(entities={len(self._data)}, calls={sum(self._call_counts.values())})"


class ModelAssertion:
    """Model assertion utilities with rich functionality."""

    def __init__(self, strict: bool = True):
        """
        Initialize model assertion helper.

        Args:
            strict: Whether to use strict comparison
        """
        self.strict = strict
        self.comparison_log: list[dict[str, Any]] = []

    def assert_model_equals(
        self, model1: BaseModel, model2: BaseModel, exclude: set[str] | None = None
    ) -> None:
        """
        Assert two Pydantic models are equal.

        Args:
            model1: First model
            model2: Second model
            exclude: Fields to exclude from comparison

        Raises:
            AssertionError: If models are not equal
            ValidationError: If inputs are invalid
        """
        if not isinstance(model1, BaseModel) or not isinstance(model2, BaseModel):
            raise ValidationError("Both inputs must be Pydantic models")

        exclude = exclude or set()

        dict1 = model1.model_dump(exclude=exclude)
        dict2 = model2.model_dump(exclude=exclude)

        comparison = {
            "model1_type": type(model1).__name__,
            "model2_type": type(model2).__name__,
            "excluded_fields": list(exclude),
            "equal": dict1 == dict2,
            "timestamp": datetime.now(UTC),
        }

        self.comparison_log.append(comparison)

        if self.strict:
            assert (
                dict1 == dict2
            ), f"Models not equal:\nModel 1: {dict1}\nModel 2: {dict2}"
        # Soft comparison - log differences but don't fail
        elif dict1 != dict2:
            differences = self._find_differences(dict1, dict2)
            comparison["differences"] = differences

    def _find_differences(self, dict1: dict, dict2: dict) -> dict[str, Any]:
        """Find differences between two dictionaries."""
        differences = {
            "only_in_first": {},
            "only_in_second": {},
            "value_differences": {},
        }

        all_keys = set(dict1.keys()) | set(dict2.keys())

        for key in all_keys:
            if key in dict1 and key not in dict2:
                differences["only_in_first"][key] = dict1[key]
            elif key in dict2 and key not in dict1:
                differences["only_in_second"][key] = dict2[key]
            elif dict1[key] != dict2[key]:
                differences["value_differences"][key] = {
                    "first": dict1[key],
                    "second": dict2[key],
                }

        return differences

    def get_comparison_history(self) -> list[dict[str, Any]]:
        """Get history of model comparisons."""
        return self.comparison_log.copy()

    def clear_comparison_log(self) -> None:
        """Clear comparison log."""
        self.comparison_log.clear()

    @staticmethod
    def assert_model_equals_static(
        model1: BaseModel, model2: BaseModel, exclude: set[str] | None = None
    ) -> None:
        """
        Static method to assert model equality.

        Args:
            model1: First model
            model2: Second model
            exclude: Fields to exclude
        """
        asserter = ModelAssertion()
        asserter.assert_model_equals(model1, model2, exclude)

    def __repr__(self) -> str:
        """Detailed string representation for debugging."""
        return f"ModelAssertion(strict={self.strict}, comparisons={len(self.comparison_log)})"


# =====================================================================================
# UTILITY FUNCTIONS
# =====================================================================================


async def create_test_db_session():
    """Create test database session."""
    async with get_session() as session:
        yield session
        # Rollback any changes
        await session.rollback()


def mock_datetime(target_datetime: datetime):
    """Context manager to mock datetime.now()."""

    class MockDatetime:
        @classmethod
        def now(cls, tz=None):
            return target_datetime

        @classmethod
        def utcnow(cls):
            return target_datetime

    import datetime as dt_module

    original_datetime = dt_module.datetime

    try:
        dt_module.datetime = MockDatetime
        yield
    finally:
        dt_module.datetime = original_datetime


def create_mock_service(
    service_methods: list[str], return_values: dict[str, Any] | None = None
) -> Mock:
    """
    Create a mock service with specified methods.

    Args:
        service_methods: List of method names to mock
        return_values: Default return values for methods

    Returns:
        Mock: Configured mock service
    """
    mock_service = MagicMock()
    return_values = return_values or {}

    for method in service_methods:
        mock_method = MagicMock()
        if method in return_values:
            mock_method.return_value = return_values[method]
        setattr(mock_service, method, mock_method)

    return mock_service


def assert_called_with_subset(mock_obj: Mock, **expected_kwargs) -> None:
    """
    Assert mock was called with a subset of expected kwargs.

    Args:
        mock_obj: Mock object to check
        **expected_kwargs: Expected keyword arguments

    Raises:
        AssertionError: If mock wasn't called with expected subset
    """
    if not mock_obj.called:
        raise AssertionError("Mock was not called")

    last_call_kwargs = mock_obj.call_args.kwargs if mock_obj.call_args else {}

    for key, expected_value in expected_kwargs.items():
        assert key in last_call_kwargs, f"Expected kwarg '{key}' not found in call"
        actual_value = last_call_kwargs[key]
        assert (
            actual_value == expected_value
        ), f"Kwarg '{key}' mismatch: expected {expected_value}, got {actual_value}"


# =====================================================================================
# BACKWARD COMPATIBILITY FUNCTIONS (Legacy API)
# =====================================================================================


def assert_model_equals(
    model1: BaseModel, model2: BaseModel, exclude: set | None = None
) -> None:
    """Assert two Pydantic models are equal."""
    exclude = exclude or set()

    dict1 = model1.model_dump(exclude=exclude)
    dict2 = model2.model_dump(exclude=exclude)

    assert dict1 == dict2, f"Models not equal:\n{dict1}\n!=\n{dict2}"
