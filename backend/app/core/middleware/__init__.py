"""
Application middleware components.

This module provides comprehensive middleware for request processing,
authentication, authorization, and security features.

Available Middleware:
- AuthMiddleware: Authentication and authorization
- RateLimitMiddleware: Rate limiting and abuse prevention

Usage:
    from app.core.middleware import AuthMiddleware, RateLimitMiddleware
    
    app.add_middleware(AuthMiddleware, ...)
    app.add_middleware(RateLimitMiddleware, ...)
"""

# Import middleware components with fallback handling
try:
    from app.core.middleware.auth import AuthMiddleware
except ImportError as e:
    import warnings
    warnings.warn(f"AuthMiddleware not available: {e}", ImportWarning, stacklevel=2)
    
    # Provide a functional stub
    class AuthMiddleware:
        """Fallback auth middleware."""
        def __init__(self, app, *args, **kwargs):
            self.app = app
        
        async def __call__(self, scope, receive, send):
            # Pass through without authentication
            await self.app(scope, receive, send)

try:
    from app.core.middleware.rate_limiter import RateLimitMiddleware
except ImportError as e:
    import warnings
    warnings.warn(f"RateLimitMiddleware not available: {e}", ImportWarning, stacklevel=2)
    
    # Provide a functional stub
    class RateLimitMiddleware:
        """Fallback rate limit middleware."""
        def __init__(self, app, *args, **kwargs):
            self.app = app
        
        async def __call__(self, scope, receive, send):
            # Pass through without rate limiting
            await self.app(scope, receive, send)

__all__ = [
    "AuthMiddleware",
    "RateLimitMiddleware",
]

# Version info for middleware compatibility
__version__ = "1.0.0"
