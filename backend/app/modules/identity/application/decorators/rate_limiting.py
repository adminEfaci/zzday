"""
Rate limiting decorators for command and query handlers.

Provides rate limiting and throttling capabilities.
"""

from collections import defaultdict
from collections.abc import Callable
from datetime import UTC, date, datetime, timedelta
from functools import wraps

from app.core.cqrs import Command, Query
from app.modules.identity.domain.errors import RateLimitExceededError

# In-memory storage for rate limiting (should be Redis in production)
_rate_limit_storage = defaultdict(lambda: defaultdict(list))
_throttle_storage = defaultdict(lambda: defaultdict(date))


class RateLimitStrategy:
    """Base rate limiting strategy."""
    
    def get_key(self, request: Command | Query) -> str:
        """Get rate limit key from request."""
        raise NotImplementedError


class IPBasedStrategy(RateLimitStrategy):
    """Rate limit based on IP address."""
    
    def get_key(self, request: Command | Query) -> str:
        if hasattr(request, 'ip_address'):
            return f"ip:{request.ip_address}"
        return "ip:unknown"


class UserBasedStrategy(RateLimitStrategy):
    """Rate limit based on user ID."""
    
    def get_key(self, request: Command | Query) -> str:
        for attr in ['user_id', 'current_user_id', 'actor_id']:
            if hasattr(request, attr):
                user_id = getattr(request, attr)
                if user_id:
                    return f"user:{user_id}"
        return "user:anonymous"


class EmailBasedStrategy(RateLimitStrategy):
    """Rate limit based on email address."""
    
    def get_key(self, request: Command | Query) -> str:
        if hasattr(request, 'email'):
            return f"email:{request.email}"
        return "email:unknown"


class TokenBasedStrategy(RateLimitStrategy):
    """Rate limit based on token."""
    
    def get_key(self, request: Command | Query) -> str:
        for attr in ['token', 'refresh_token', 'access_token']:
            if hasattr(request, attr):
                token = getattr(request, attr)
                if token:
                    # Use first 8 chars of token for key
                    return f"token:{token[:8]}"
        return "token:unknown"


def rate_limit(
    max_requests: int,
    window_seconds: int,
    strategy: str | RateLimitStrategy = 'user',
    burst_allowed: bool = False
) -> Callable:
    """
    Rate limiting decorator.
    
    Args:
        max_requests: Maximum number of requests allowed
        window_seconds: Time window in seconds
        strategy: Rate limiting strategy ('ip', 'user', 'email', 'token' or custom)
        burst_allowed: Whether to allow burst requests
    """
    # Get strategy instance
    if isinstance(strategy, str):
        strategy_map = {
            'ip': IPBasedStrategy(),
            'user': UserBasedStrategy(),
            'email': EmailBasedStrategy(),
            'token': TokenBasedStrategy()
        }
        strategy_instance = strategy_map.get(strategy, UserBasedStrategy())
    else:
        strategy_instance = strategy
    
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(self, request: Command | Query, *args, **kwargs):
            # Get rate limit key
            key = strategy_instance.get_key(request)
            operation = f"{request.__class__.__module__}.{request.__class__.__name__}"
            
            # Get current timestamp
            now = datetime.now(UTC)
            window_start = now - timedelta(seconds=window_seconds)
            
            # Clean old entries
            _rate_limit_storage[operation][key] = [
                timestamp for timestamp in _rate_limit_storage[operation][key]
                if timestamp > window_start
            ]
            
            # Check rate limit
            request_count = len(_rate_limit_storage[operation][key])
            
            if request_count >= max_requests:
                # Calculate retry after
                oldest_request = min(_rate_limit_storage[operation][key])
                retry_after = (
                    oldest_request + timedelta(seconds=window_seconds) - now
                ).total_seconds()
                
                raise RateLimitExceededError(
                    f"Rate limit exceeded: {max_requests} requests per "
                    f"{window_seconds} seconds",
                    retry_after=int(retry_after),
                    limit=max_requests,
                    window=window_seconds
                )
            
            # Add current request
            _rate_limit_storage[operation][key].append(now)
            
            # Execute function
            try:
                return await func(self, request, *args, **kwargs)
            except Exception:
                # On error, remove the request from count if burst not allowed
                if not burst_allowed:
                    _rate_limit_storage[operation][key].pop()
                raise
        
        return wrapper
    return decorator


def throttle(
    min_interval_seconds: float,
    strategy: str | RateLimitStrategy = 'user'
) -> Callable:
    """
    Throttling decorator to enforce minimum time between requests.
    
    Args:
        min_interval_seconds: Minimum seconds between requests
        strategy: Throttling strategy
    """
    # Get strategy instance
    if isinstance(strategy, str):
        strategy_map = {
            'ip': IPBasedStrategy(),
            'user': UserBasedStrategy(),
            'email': EmailBasedStrategy(),
            'token': TokenBasedStrategy()
        }
        strategy_instance = strategy_map.get(strategy, UserBasedStrategy())
    else:
        strategy_instance = strategy
    
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(self, request: Command | Query, *args, **kwargs):
            # Get throttle key
            key = strategy_instance.get_key(request)
            operation = f"{request.__class__.__module__}.{request.__class__.__name__}"
            
            # Check last request time
            last_request = _throttle_storage[operation].get(key)
            now = datetime.now(UTC)
            
            if last_request:
                time_since_last = (now - last_request).total_seconds()
                if time_since_last < min_interval_seconds:
                    wait_time = min_interval_seconds - time_since_last
                    raise RateLimitExceededError(
                        f"Please wait {wait_time:.1f} seconds before next request",
                        retry_after=int(wait_time),
                        limit=1,
                        window=min_interval_seconds
                    )
            
            # Update last request time
            _throttle_storage[operation][key] = now
            
            # Execute function
            return await func(self, request, *args, **kwargs)
        
        return wrapper
    return decorator


def adaptive_rate_limit(
    base_limit: int,
    window_seconds: int,
    strategy: str | RateLimitStrategy = 'user',
    trust_score_multiplier: float = 2.0
) -> Callable:
    """
    Adaptive rate limiting based on user trust score.
    
    Args:
        base_limit: Base request limit
        window_seconds: Time window
        strategy: Rate limiting strategy
        trust_score_multiplier: Multiplier for trusted users
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(self, request: Command | Query, *args, **kwargs):
            # Get user trust score if available
            trust_score = 1.0
            if hasattr(request, 'user_id'):
                # TODO: Fetch trust score from risk assessment service
                pass
            
            # Calculate adjusted limit
            adjusted_limit = int(
                base_limit * (1 + (trust_score - 0.5) * trust_score_multiplier)
            )
            adjusted_limit = max(1, adjusted_limit)  # Ensure at least 1 request
            
            # Apply rate limiting with adjusted limit
            rate_limiter = rate_limit(
                max_requests=adjusted_limit,
                window_seconds=window_seconds,
                strategy=strategy
            )
            
            # Execute with rate limiting
            limited_func = rate_limiter(func)
            return await limited_func(self, request, *args, **kwargs)
        
        return wrapper
    return decorator


def circuit_breaker(
    failure_threshold: int = 5,
    timeout_seconds: int = 60,
    half_open_requests: int = 3
) -> Callable:
    """
    Circuit breaker pattern for handling failures.
    
    Args:
        failure_threshold: Number of failures before opening circuit
        timeout_seconds: Time before attempting to close circuit
        half_open_requests: Number of test requests in half-open state
    """
    class CircuitState:
        CLOSED = "closed"
        OPEN = "open"
        HALF_OPEN = "half_open"
    
    circuit_states = {}
    
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(self, request: Command | Query, *args, **kwargs):
            operation = f"{request.__class__.__module__}.{request.__class__.__name__}"
            
            # Initialize circuit state if needed
            if operation not in circuit_states:
                circuit_states[operation] = {
                    'state': CircuitState.CLOSED,
                    'failures': 0,
                    'last_failure': None,
                    'half_open_requests': 0
                }
            
            circuit = circuit_states[operation]
            now = datetime.now(UTC)
            
            # Check circuit state
            if circuit['state'] == CircuitState.OPEN:
                # Check if timeout has passed
                if circuit['last_failure'] and \
                   (now - circuit['last_failure']).total_seconds() > timeout_seconds:
                    circuit['state'] = CircuitState.HALF_OPEN
                    circuit['half_open_requests'] = 0
                else:
                    raise RateLimitExceededError(
                        "Service temporarily unavailable (circuit open)",
                        retry_after=timeout_seconds
                    )
            
            # Execute request
            try:
                result = await func(self, request, *args, **kwargs)
                
                # Success - update circuit state
                if circuit['state'] == CircuitState.HALF_OPEN:
                    circuit['half_open_requests'] += 1
                    if circuit['half_open_requests'] >= half_open_requests:
                        circuit['state'] = CircuitState.CLOSED
                        circuit['failures'] = 0
                elif circuit['state'] == CircuitState.CLOSED:
                    circuit['failures'] = 0
                
                return result
                
            except Exception:
                # Failure - update circuit state
                circuit['failures'] += 1
                circuit['last_failure'] = now
                
                if circuit['failures'] >= failure_threshold:
                    circuit['state'] = CircuitState.OPEN
                
                raise
        
        return wrapper
    return decorator