# domains/identity/domain/contracts/mfa_status_contract.py

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any
from uuid import UUID


class MFAStatusContract(ABC):
    """
    Contract interface for MFA status operations.

    Lets security or notification domains check if user has MFA enabled,
    etc. without coupling to internal MFA models.
    """

    @abstractmethod
    def has_mfa(self, user_id: UUID) -> bool:
        """
        Return True if the user has multi-factor authentication enabled.

        Args:
            user_id: The unique identifier of the user

        Returns:
            bool: True if user has MFA enabled, False otherwise
        """

    @abstractmethod
    def get_mfa_method(self, user_id: UUID) -> str:
        """
        Return the user's primary MFA method.

        Args:
            user_id: The unique identifier of the user

        Returns:
            str: MFA method ('totp', 'sms', 'email', 'biometric', 'hardware', 'none')
        """

    @abstractmethod
    def get_mfa_methods(self, user_id: UUID) -> list[str]:
        """
        Return all MFA methods configured for the user.

        Args:
            user_id: The unique identifier of the user

        Returns:
            List[str]: List of configured MFA methods
        """

    @abstractmethod
    def is_mfa_required(self, user_id: UUID) -> bool:
        """
        Check if MFA is required for this user based on policies.

        Args:
            user_id: The unique identifier of the user

        Returns:
            bool: True if MFA is required by policy, False otherwise
        """

    @abstractmethod
    def get_mfa_devices(self, user_id: UUID) -> list[dict[str, Any]]:
        """
        Get list of MFA devices registered for the user.

        Args:
            user_id: The unique identifier of the user

        Returns:
            List[Dict[str, Any]]: List of MFA device info:
                [
                    {
                        "device_id": str,
                        "device_name": str,
                        "device_type": str,
                        "is_primary": bool,
                        "created_at": str,
                        "last_used_at": str,
                        "status": str
                    }
                ]
        """

    @abstractmethod
    def has_backup_codes(self, user_id: UUID) -> bool:
        """
        Check if user has backup codes available.

        Args:
            user_id: The unique identifier of the user

        Returns:
            bool: True if user has unused backup codes, False otherwise
        """

    @abstractmethod
    def get_backup_codes_count(self, user_id: UUID) -> int:
        """
        Get the number of unused backup codes for the user.

        Args:
            user_id: The unique identifier of the user

        Returns:
            int: Number of unused backup codes
        """

    @abstractmethod
    def is_mfa_setup_complete(self, user_id: UUID) -> bool:
        """
        Check if MFA setup is complete for the user.

        Args:
            user_id: The unique identifier of the user

        Returns:
            bool: True if MFA setup is complete, False if pending
        """

    @abstractmethod
    def get_mfa_enforcement_level(self, user_id: UUID) -> str:
        """
        Get the MFA enforcement level for the user.

        Args:
            user_id: The unique identifier of the user

        Returns:
            str: Enforcement level ('none', 'optional', 'required', 'strict')
        """

    @abstractmethod
    def get_last_mfa_verification(self, user_id: UUID) -> datetime | None:
        """
        Get the timestamp of the last successful MFA verification.

        Args:
            user_id: The unique identifier of the user

        Returns:
            Optional[datetime]: Last MFA verification time or None if never verified
        """

    @abstractmethod
    def is_mfa_grace_period_active(self, user_id: UUID) -> bool:
        """
        Check if user is in MFA grace period (newly required but not enforced yet).

        Args:
            user_id: The unique identifier of the user

        Returns:
            bool: True if in grace period, False otherwise
        """

    @abstractmethod
    def get_mfa_compliance_status(self, user_id: UUID) -> dict[str, Any]:
        """
        Get comprehensive MFA compliance status for the user.

        Args:
            user_id: The unique identifier of the user

        Returns:
            Dict[str, Any]: MFA compliance information:
                {
                    "is_compliant": bool,
                    "required": bool,
                    "enabled": bool,
                    "setup_complete": bool,
                    "grace_period_active": bool,
                    "grace_period_expires": str,
                    "enforcement_level": str,
                    "device_count": int,
                    "backup_codes_available": bool,
                    "last_verification": str,
                    "compliance_score": float
                }
        """
