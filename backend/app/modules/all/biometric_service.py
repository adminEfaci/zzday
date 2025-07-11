"""
Biometric Authentication Service Interface

Protocol for biometric authentication operations.
"""

from typing import Protocol
from uuid import UUID


class IBiometricService(Protocol):
    """Protocol for biometric authentication."""
    
    async def register_biometric(
        self,
        user_id: UUID,
        biometric_type: str,
        biometric_data: bytes
    ) -> str:
        """
        Register biometric data.
        
        Args:
            user_id: User identifier
            biometric_type: Type of biometric (fingerprint/face/voice)
            biometric_data: Encrypted biometric template
            
        Returns:
            Registration identifier
            
        Raises:
            BiometricRegistrationError: If registration fails
        """
    
    async def verify_biometric(
        self,
        user_id: UUID,
        biometric_type: str,
        biometric_data: bytes
    ) -> bool:
        """
        Verify biometric data.
        
        Args:
            user_id: User identifier
            biometric_type: Type of biometric
            biometric_data: Biometric data to verify
            
        Returns:
            True if biometric matches
        """
    
    async def delete_biometric(
        self,
        user_id: UUID,
        biometric_type: str
    ) -> bool:
        """
        Delete biometric registration.
        
        Args:
            user_id: User identifier
            biometric_type: Type to delete
            
        Returns:
            True if deleted successfully
        """
    
    async def get_registered_biometrics(self, user_id: UUID) -> list[str]:
        """
        Get list of registered biometric types.
        
        Args:
            user_id: User identifier
            
        Returns:
            List of biometric types registered
        """
        ...
