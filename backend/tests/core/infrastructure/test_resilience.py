"""
Tests for resilience patterns implementation.
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock

from app.core.infrastructure.resilience import (
    RetryHandler, TimeoutHandler, Bulkhead, ResilienceOrchestrator,
    RetryConfig, TimeoutConfig, BulkheadConfig, RetryStrategy,
    RetryExhaustedError, TimeoutError, BulkheadFullError, resilient
)
from app.core.infrastructure.circuit_breaker import CircuitBreakerConfig


class TestRetryHandler:
    """Test retry handler functionality."""
    
    def test_exponential_backoff(self):
        """Test exponential backoff calculation."""
        config = RetryConfig(
            base_delay_ms=100,
            backoff_multiplier=2.0,
            strategy=RetryStrategy.EXPONENTIAL
        )
        handler = RetryHandler(config)
        
        assert handler.calculate_delay(0) == 0.1  # 100ms
        assert handler.calculate_delay(1) == 0.2  # 200ms
        assert handler.calculate_delay(2) == 0.4  # 400ms
    
    def test_linear_backoff(self):
        """Test linear backoff calculation."""
        config = RetryConfig(
            base_delay_ms=100,
            strategy=RetryStrategy.LINEAR
        )
        handler = RetryHandler(config)
        
        assert handler.calculate_delay(0) == 0.1  # 100ms
        assert handler.calculate_delay(1) == 0.2  # 200ms
        assert handler.calculate_delay(2) == 0.3  # 300ms
    
    def test_fixed_delay(self):
        """Test fixed delay calculation."""
        config = RetryConfig(
            base_delay_ms=100,
            strategy=RetryStrategy.FIXED
        )
        handler = RetryHandler(config)
        
        assert handler.calculate_delay(0) == 0.1  # 100ms
        assert handler.calculate_delay(1) == 0.1  # 100ms
        assert handler.calculate_delay(2) == 0.1  # 100ms
    
    def test_max_delay_limit(self):
        """Test max delay limit."""
        config = RetryConfig(
            base_delay_ms=100,
            max_delay_ms=500,
            backoff_multiplier=10.0,
            strategy=RetryStrategy.EXPONENTIAL
        )
        handler = RetryHandler(config)
        
        assert handler.calculate_delay(10) == 0.5  # Capped at 500ms
    
    @pytest.mark.asyncio
    async def test_successful_execution(self):
        """Test successful execution without retries."""
        config = RetryConfig(max_attempts=3)
        handler = RetryHandler(config)
        
        async def success_func():
            return "success"
        
        result = await handler.execute(success_func)
        assert result == "success"
    
    @pytest.mark.asyncio
    async def test_retry_until_success(self):
        """Test retry until success."""
        config = RetryConfig(max_attempts=3, base_delay_ms=1)
        handler = RetryHandler(config)
        
        call_count = 0
        
        async def flaky_func():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ValueError("Temporary failure")
            return "success"
        
        result = await handler.execute(flaky_func)
        assert result == "success"
        assert call_count == 3
    
    @pytest.mark.asyncio
    async def test_retry_exhausted(self):
        """Test retry exhaustion."""
        config = RetryConfig(max_attempts=3, base_delay_ms=1)
        handler = RetryHandler(config)
        
        async def always_fail():
            raise ValueError("Always fails")
        
        with pytest.raises(ValueError):
            await handler.execute(always_fail)
    
    @pytest.mark.asyncio
    async def test_non_retryable_exception(self):
        """Test non-retryable exception handling."""
        config = RetryConfig(
            max_attempts=3,
            retryable_exceptions=(ConnectionError,)
        )
        handler = RetryHandler(config)
        
        call_count = 0
        
        async def non_retryable_func():
            nonlocal call_count
            call_count += 1
            raise ValueError("Non-retryable")
        
        with pytest.raises(ValueError):
            await handler.execute(non_retryable_func)
        
        assert call_count == 1  # Should not retry


class TestTimeoutHandler:
    """Test timeout handler functionality."""
    
    @pytest.mark.asyncio
    async def test_successful_within_timeout(self):
        """Test successful execution within timeout."""
        config = TimeoutConfig(total_timeout_ms=1000)
        handler = TimeoutHandler(config)
        
        async def quick_func():
            await asyncio.sleep(0.1)
            return "success"
        
        async with handler.timeout_context():
            result = await quick_func()
        
        assert result == "success"
    
    @pytest.mark.asyncio
    async def test_timeout_exceeded(self):
        """Test timeout exceeded."""
        config = TimeoutConfig(total_timeout_ms=100)
        handler = TimeoutHandler(config)
        
        async def slow_func():
            await asyncio.sleep(1)
            return "success"
        
        with pytest.raises(TimeoutError):
            async with handler.timeout_context():
                await slow_func()
    
    @pytest.mark.asyncio
    async def test_custom_timeout(self):
        """Test custom timeout override."""
        config = TimeoutConfig(total_timeout_ms=1000)
        handler = TimeoutHandler(config)
        
        async def slow_func():
            await asyncio.sleep(0.2)
            return "success"
        
        with pytest.raises(TimeoutError):
            async with handler.timeout_context(timeout_ms=100):
                await slow_func()


class TestBulkhead:
    """Test bulkhead isolation functionality."""
    
    @pytest.mark.asyncio
    async def test_concurrent_execution(self):
        """Test concurrent execution within limits."""
        config = BulkheadConfig(max_concurrent_calls=2, timeout_ms=1000)
        bulkhead = Bulkhead("test", config)
        
        results = []
        
        async def concurrent_func(value):
            async with bulkhead.acquire():
                await asyncio.sleep(0.1)
                results.append(value)
        
        # Should all succeed
        await asyncio.gather(
            concurrent_func(1),
            concurrent_func(2)
        )
        
        assert len(results) == 2
        assert bulkhead.get_stats()["active_calls"] == 0
    
    @pytest.mark.asyncio
    async def test_bulkhead_full(self):
        """Test bulkhead full rejection."""
        config = BulkheadConfig(max_concurrent_calls=1, timeout_ms=100)
        bulkhead = Bulkhead("test", config)
        
        async def blocking_func():
            async with bulkhead.acquire():
                await asyncio.sleep(1)
        
        # Start first call
        task1 = asyncio.create_task(blocking_func())
        await asyncio.sleep(0.05)  # Let it acquire
        
        # Second call should be rejected
        with pytest.raises(BulkheadFullError):
            await blocking_func()
        
        task1.cancel()
        try:
            await task1
        except asyncio.CancelledError:
            pass
    
    @pytest.mark.asyncio
    async def test_bulkhead_stats(self):
        """Test bulkhead statistics."""
        config = BulkheadConfig(max_concurrent_calls=2, timeout_ms=100)
        bulkhead = Bulkhead("test", config)
        
        async def test_func():
            async with bulkhead.acquire():
                await asyncio.sleep(0.1)
        
        await test_func()
        
        # Try to trigger rejection
        async def blocking_func():
            async with bulkhead.acquire():
                await asyncio.sleep(1)
        
        task1 = asyncio.create_task(blocking_func())
        task2 = asyncio.create_task(blocking_func())
        await asyncio.sleep(0.05)
        
        try:
            await bulkhead.acquire().__aenter__()
        except BulkheadFullError:
            pass
        
        stats = bulkhead.get_stats()
        assert stats["total_calls"] > 0
        assert stats["rejected_calls"] > 0
        
        task1.cancel()
        task2.cancel()
        try:
            await asyncio.gather(task1, task2, return_exceptions=True)
        except:
            pass


class TestResilienceOrchestrator:
    """Test resilience orchestrator functionality."""
    
    @pytest.mark.asyncio
    async def test_successful_execution(self):
        """Test successful execution through orchestrator."""
        orchestrator = ResilienceOrchestrator(
            name="test",
            retry_config=RetryConfig(max_attempts=3),
            timeout_config=TimeoutConfig(total_timeout_ms=1000)
        )
        
        async def success_func():
            return "success"
        
        result = await orchestrator.execute(success_func)
        assert result == "success"
    
    @pytest.mark.asyncio
    async def test_retry_with_timeout(self):
        """Test retry with timeout handling."""
        orchestrator = ResilienceOrchestrator(
            name="test",
            retry_config=RetryConfig(max_attempts=3, base_delay_ms=1),
            timeout_config=TimeoutConfig(total_timeout_ms=1000)
        )
        
        call_count = 0
        
        async def flaky_func():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ValueError("Temporary failure")
            return "success"
        
        result = await orchestrator.execute(flaky_func)
        assert result == "success"
        assert call_count == 3
    
    @pytest.mark.asyncio
    async def test_with_bulkhead(self):
        """Test orchestrator with bulkhead."""
        orchestrator = ResilienceOrchestrator(
            name="test",
            bulkhead_config=BulkheadConfig(max_concurrent_calls=1, timeout_ms=100)
        )
        
        async def blocking_func():
            await asyncio.sleep(0.5)
            return "success"
        
        # First call should succeed
        task1 = asyncio.create_task(orchestrator.execute(blocking_func))
        await asyncio.sleep(0.05)
        
        # Second call should be rejected
        with pytest.raises(BulkheadFullError):
            await orchestrator.execute(blocking_func)
        
        result = await task1
        assert result == "success"
    
    @pytest.mark.asyncio
    async def test_circuit_breaker_integration(self):
        """Test circuit breaker integration."""
        # Use low thresholds for testing
        cb_config = CircuitBreakerConfig(
            failure_threshold=2,
            recovery_timeout=0.1
        )
        
        orchestrator = ResilienceOrchestrator(
            name="test_cb",
            circuit_breaker_config=cb_config,
            retry_config=RetryConfig(max_attempts=1)  # No retries for this test
        )
        
        async def failing_func():
            raise ValueError("Always fails")
        
        # First two calls should fail and open circuit
        with pytest.raises(ValueError):
            await orchestrator.execute(failing_func)
        
        with pytest.raises(ValueError):
            await orchestrator.execute(failing_func)
        
        # Third call should be blocked by circuit breaker
        with pytest.raises(Exception):  # CircuitBreakerOpenError
            await orchestrator.execute(failing_func)
    
    @pytest.mark.asyncio
    async def test_stats_collection(self):
        """Test comprehensive stats collection."""
        orchestrator = ResilienceOrchestrator(
            name="test_stats",
            retry_config=RetryConfig(max_attempts=2),
            timeout_config=TimeoutConfig(total_timeout_ms=1000),
            bulkhead_config=BulkheadConfig(max_concurrent_calls=5)
        )
        
        async def test_func():
            return "success"
        
        await orchestrator.execute(test_func)
        
        stats = orchestrator.get_stats()
        assert stats["name"] == "test_stats"
        assert "circuit_breaker" in stats
        assert "retry_config" in stats
        assert "timeout_config" in stats
        assert "bulkhead" in stats


class TestResilientDecorator:
    """Test resilient decorator functionality."""
    
    @pytest.mark.asyncio
    async def test_decorator_basic(self):
        """Test basic decorator functionality."""
        
        @resilient(
            name="test_decorator",
            retry_config=RetryConfig(max_attempts=3, base_delay_ms=1)
        )
        async def decorated_func():
            return "success"
        
        result = await decorated_func()
        assert result == "success"
    
    @pytest.mark.asyncio
    async def test_decorator_with_retries(self):
        """Test decorator with retry functionality."""
        call_count = 0
        
        @resilient(
            name="test_decorator_retry",
            retry_config=RetryConfig(max_attempts=3, base_delay_ms=1)
        )
        async def flaky_decorated_func():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ValueError("Temporary failure")
            return "success"
        
        result = await flaky_decorated_func()
        assert result == "success"
        assert call_count == 3
    
    @pytest.mark.asyncio
    async def test_decorator_with_timeout(self):
        """Test decorator with timeout."""
        
        @resilient(
            name="test_decorator_timeout",
            timeout_config=TimeoutConfig(total_timeout_ms=100)
        )
        async def slow_decorated_func():
            await asyncio.sleep(1)
            return "success"
        
        with pytest.raises(TimeoutError):
            await slow_decorated_func()