"""
Authentication commands.

Provides commands for user authentication operations.
"""

from .confirm_email_change_command import (
    ConfirmEmailChangeCommand,
    ConfirmEmailChangeCommandHandler,
)
from .invalidate_all_tokens_command import (
    InvalidateAllTokensCommand,
    InvalidateAllTokensCommandHandler,
)
from .login_command import LoginCommand, LoginCommandHandler
from .logout_command import LogoutCommand, LogoutCommandHandler
from .refresh_token_command import RefreshTokenCommand, RefreshTokenCommandHandler
from .register_user_command import RegisterUserCommand, RegisterUserCommandHandler
from .resend_verification_command import (
    ResendVerificationCommand,
    ResendVerificationCommandHandler,
)
from .social_login_command import SocialLoginCommand, SocialLoginCommandHandler
from .verify_email_command import VerifyEmailCommand, VerifyEmailCommandHandler

__all__ = [
    "ConfirmEmailChangeCommand",
    "ConfirmEmailChangeCommandHandler",
    "InvalidateAllTokensCommand",
    "InvalidateAllTokensCommandHandler",
    # Commands
    "LoginCommand",
    # Handlers
    "LoginCommandHandler",
    "LogoutCommand",
    "LogoutCommandHandler",
    "RefreshTokenCommand",
    "RefreshTokenCommandHandler",
    "RegisterUserCommand",
    "RegisterUserCommandHandler",
    "ResendVerificationCommand",
    "ResendVerificationCommandHandler",
    "SocialLoginCommand",
    "SocialLoginCommandHandler",
    "VerifyEmailCommand",
    "VerifyEmailCommandHandler",
]