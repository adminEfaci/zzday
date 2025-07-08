"""
User management commands.

Provides commands for user CRUD operations and profile management.
"""

from .create_user_command import CreateUserCommand, CreateUserCommandHandler
from .deactivate_user_command import DeactivateUserCommand, DeactivateUserCommandHandler
from .delete_avatar_command import DeleteAvatarCommand, DeleteAvatarCommandHandler
from .delete_user_command import DeleteUserCommand, DeleteUserCommandHandler
from .generate_avatar_command import GenerateAvatarCommand, GenerateAvatarCommandHandler
from .merge_users_command import MergeUsersCommand, MergeUsersCommandHandler
from .reactivate_user_command import ReactivateUserCommand, ReactivateUserCommandHandler
from .transfer_user_data_command import (
    TransferUserDataCommand,
    TransferUserDataCommandHandler,
)
from .update_contact_info_command import (
    UpdateContactInfoCommand,
    UpdateContactInfoCommandHandler,
)
from .update_preferences_command import (
    UpdatePreferencesCommand,
    UpdatePreferencesCommandHandler,
)
from .update_profile_command import UpdateProfileCommand, UpdateProfileCommandHandler
from .upload_avatar_command import UploadAvatarCommand, UploadAvatarCommandHandler

__all__ = [
    # Commands
    "CreateUserCommand",
    # Handlers
    "CreateUserCommandHandler",
    "DeactivateUserCommand",
    "DeactivateUserCommandHandler",
    "DeleteAvatarCommand",
    "DeleteAvatarCommandHandler",
    "DeleteUserCommand",
    "DeleteUserCommandHandler",
    "GenerateAvatarCommand",
    "GenerateAvatarCommandHandler",
    "MergeUsersCommand",
    "MergeUsersCommandHandler",
    "ReactivateUserCommand",
    "ReactivateUserCommandHandler",
    "TransferUserDataCommand",
    "TransferUserDataCommandHandler",
    "UpdateContactInfoCommand",
    "UpdateContactInfoCommandHandler",
    "UpdatePreferencesCommand",
    "UpdatePreferencesCommandHandler",
    "UpdateProfileCommand",
    "UpdateProfileCommandHandler",
    "UploadAvatarCommand",
    "UploadAvatarCommandHandler",
]