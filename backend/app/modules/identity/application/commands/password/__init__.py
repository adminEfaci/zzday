"""
Password management commands.

Provides commands for password operations.
"""

from .change_password_command import ChangePasswordCommand, ChangePasswordCommandHandler
from .check_password_breach_command import (
    CheckPasswordBreachCommand,
    CheckPasswordBreachCommandHandler,
)
from .force_password_reset_command import (
    ForcePasswordResetCommand,
    ForcePasswordResetCommandHandler,
)
from .forgot_password_command import ForgotPasswordCommand, ForgotPasswordCommandHandler
from .reset_password_command import ResetPasswordCommand, ResetPasswordCommandHandler
from .update_password_policy_command import (
    UpdatePasswordPolicyCommand,
    UpdatePasswordPolicyCommandHandler,
)
from .validate_password_command import (
    ValidatePasswordCommand,
    ValidatePasswordCommandHandler,
)

__all__ = [
    # Commands
    "ChangePasswordCommand",
    # Handlers
    "ChangePasswordCommandHandler",
    "CheckPasswordBreachCommand",
    "CheckPasswordBreachCommandHandler",
    "ForcePasswordResetCommand",
    "ForcePasswordResetCommandHandler",
    "ForgotPasswordCommand",
    "ForgotPasswordCommandHandler",
    "ResetPasswordCommand",
    "ResetPasswordCommandHandler",
    "UpdatePasswordPolicyCommand",
    "UpdatePasswordPolicyCommandHandler",
    "ValidatePasswordCommand",
    "ValidatePasswordCommandHandler",
]