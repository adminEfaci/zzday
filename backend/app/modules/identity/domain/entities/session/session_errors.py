"""
Session Entity Errors

Domain-specific exceptions for session and token management.
"""


from ...errors import AuthenticationError, IdentityDomainError


class SessionError(IdentityDomainError):
    """Base session error."""
    default_code = "SESSION_ERROR"


class SessionExpiredError(SessionError):
    """Session has expired."""

    def __init__(self):
        super().__init__("Session has expired", code="SESSION_EXPIRED")


class SessionNotFoundError(SessionError):
    """Session does not exist."""
    
    def __init__(self, session_id: str):
        super().__init__(
            f"Session not found: {session_id}",
            code="SESSION_NOT_FOUND",
            user_message="Your session is invalid. Please log in again."
        )


class ConcurrentSessionLimitError(SessionError):
    """Maximum concurrent sessions exceeded."""
    
    def __init__(self, limit: int):
        super().__init__(
            f"Maximum concurrent sessions exceeded: {limit}",
            code="CONCURRENT_SESSION_LIMIT",
            user_message=f"You have too many active sessions. Maximum allowed: {limit}"
        )
        self.details["limit"] = limit


class SessionAlreadyTerminatedError(SessionError):
    """Session has already been terminated."""
    
    def __init__(self):
        super().__init__(
            "Session already terminated",
            code="SESSION_TERMINATED",
            user_message="This session has been terminated."
        )


# Token Errors
class TokenExpiredError(AuthenticationError):
    """Token has expired."""
    
    def __init__(self, token_type: str = "access"):
        super().__init__(
            f"{token_type.capitalize()} token has expired",
            code="TOKEN_EXPIRED",
            user_message="Your session has expired. Please log in again."
        )
        self.details["token_type"] = token_type


class InvalidTokenError(AuthenticationError):
    """Invalid or malformed token."""
    
    def __init__(self, reason: str = "Invalid token"):
        super().__init__(
            reason,
            code="INVALID_TOKEN",
            user_message="Invalid authentication token. Please log in again."
        )


class RefreshTokenExpiredError(AuthenticationError):
    """Refresh token has expired."""
    
    def __init__(self):
        super().__init__(
            "Refresh token has expired",
            code="REFRESH_TOKEN_EXPIRED",
            user_message="Your session has expired. Please log in again."
        )


# Export all errors
__all__ = [
    'ConcurrentSessionLimitError',
    'InvalidTokenError',
    'RefreshTokenExpiredError',
    'SessionAlreadyTerminatedError',
    'SessionError',
    'SessionExpiredError',
    'SessionNotFoundError',
    'TokenExpiredError'
]