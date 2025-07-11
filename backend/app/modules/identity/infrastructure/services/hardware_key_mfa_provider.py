"""
Hardware Key MFA Provider Implementation

FIDO2/WebAuthn hardware security key provider.
"""

import base64
import json
import logging
from datetime import UTC, datetime
from typing import Any

from app.modules.identity.domain.entities.admin.mfa_device import MFADevice, MFAMethod
from app.modules.identity.infrastructure.services.mfa_provider_factory import (
    IMFAProvider,
)

logger = logging.getLogger(__name__)


class HardwareKeyMFAProvider(IMFAProvider):
    """Hardware security key MFA provider implementation."""
    
    def __init__(
        self,
        timeout_seconds: int = 30,
        supported_protocols: list[str] | None = None,
        require_pin: bool = False,
        rp_id: str | None = None,
        rp_name: str = "EzzDay"
    ):
        """Initialize hardware key MFA provider.
        
        Args:
            timeout_seconds: Timeout for key interaction
            supported_protocols: Supported protocols (FIDO2, U2F)
            require_pin: Whether to require PIN
            rp_id: Relying party ID (domain)
            rp_name: Relying party name
        """
        self.timeout_seconds = timeout_seconds
        self.supported_protocols = supported_protocols or ['FIDO2', 'U2F']
        self.require_pin = require_pin
        self.rp_id = rp_id
        self.rp_name = rp_name
        
        # In-memory challenge storage (should use cache in production)
        self._active_challenges: dict[str, dict[str, Any]] = {}
    
    @property
    def method(self) -> MFAMethod:
        """Get MFA method type."""
        return MFAMethod.HARDWARE_KEY
    
    @property
    def name(self) -> str:
        """Get provider name."""
        return "Hardware Security Key"
    
    async def send_code(
        self,
        device: MFADevice,
        user_identifier: str | None = None
    ) -> dict[str, Any]:
        """Hardware keys don't send codes - they use challenges.
        
        Args:
            device: MFA device
            user_identifier: Optional user identifier
            
        Returns:
            Challenge information for client
        """
        if device.method != MFAMethod.HARDWARE_KEY:
            raise ValueError("Device must be HARDWARE_KEY method")
        
        # Generate challenge
        import secrets
        challenge = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('=')
        
        # Store challenge
        challenge_key = f"hw:{device.id}"
        self._active_challenges[challenge_key] = {
            'challenge': challenge,
            'device_id': str(device.id),
            'user_id': str(device.user_id),
            'created_at': datetime.now(UTC),
            'timeout': self.timeout_seconds
        }
        
        # Return WebAuthn challenge data
        return {
            'sent': False,
            'challenge': challenge,
            'timeout': self.timeout_seconds * 1000,  # Convert to milliseconds
            'rpId': self.rp_id,
            'userVerification': 'preferred' if self.require_pin else 'discouraged',
            'allowCredentials': [{
                'type': 'public-key',
                'id': device.credential_id if hasattr(device, 'credential_id') else device.secret.value
            }] if device.secret and device.secret.value else [],
            'instructions': 'Insert your security key and follow the prompts'
        }
    
    async def verify_code(
        self,
        device: MFADevice,
        code: str
    ) -> tuple[bool, dict[str, Any]]:
        """Verify hardware key response.
        
        Args:
            device: MFA device
            code: WebAuthn assertion response (JSON)
            
        Returns:
            Tuple of (is_valid, metadata)
        """
        if device.method != MFAMethod.HARDWARE_KEY:
            return False, {'error': 'Device must be HARDWARE_KEY method'}
        
        challenge_key = f"hw:{device.id}"
        
        # Check if challenge exists
        if challenge_key not in self._active_challenges:
            return False, {'error': 'No active challenge found'}
        
        challenge_data = self._active_challenges[challenge_key]
        
        # Check timeout
        elapsed = (datetime.now(UTC) - challenge_data['created_at']).total_seconds()
        if elapsed > self.timeout_seconds:
            del self._active_challenges[challenge_key]
            return False, {'error': 'Challenge has expired'}
        
        try:
            # Parse WebAuthn response
            response = json.loads(code)
            
            # In production, would verify with python-fido2 library
            # This is a simplified validation
            is_valid = self._verify_webauthn_response(
                device,
                challenge_data['challenge'],
                response
            )
            
            if is_valid:
                del self._active_challenges[challenge_key]
                return True, {
                    'verified_at': datetime.now(UTC).isoformat(),
                    'method': 'hardware_key',
                    'device_id': str(device.id),
                    'authenticator_data': response.get('authenticatorData')
                }
            return False, {'error': 'Invalid signature'}
                
        except json.JSONDecodeError:
            return False, {'error': 'Invalid response format'}
        except Exception as e:
            logger.error(f"Hardware key verification error: {e}")
            return False, {'error': 'Verification failed'}
    
    async def setup_device(
        self,
        device: MFADevice,
        user_name: str | None = None,
        user_display_name: str | None = None
    ) -> dict[str, Any]:
        """Setup hardware key MFA device.
        
        Args:
            device: MFA device
            user_name: Username for registration
            user_display_name: Display name for registration
            
        Returns:
            Registration challenge information
        """
        if device.method != MFAMethod.HARDWARE_KEY:
            raise ValueError("Device must be HARDWARE_KEY method")
        
        # Generate registration challenge
        import secrets
        challenge = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('=')
        user_id = base64.urlsafe_b64encode(str(device.user_id).encode()).decode().rstrip('=')
        
        # Store registration data
        reg_key = f"reg:{device.id}"
        self._active_challenges[reg_key] = {
            'challenge': challenge,
            'device_id': str(device.id),
            'user_id': str(device.user_id),
            'created_at': datetime.now(UTC),
            'timeout': self.timeout_seconds * 2  # Longer timeout for registration
        }
        
        # Return WebAuthn creation options
        return {
            'device_id': str(device.id),
            'publicKey': {
                'challenge': challenge,
                'rp': {
                    'id': self.rp_id,
                    'name': self.rp_name
                },
                'user': {
                    'id': user_id,
                    'name': user_name or str(device.user_id),
                    'displayName': user_display_name or user_name or 'User'
                },
                'pubKeyCredParams': [
                    {'type': 'public-key', 'alg': -7},   # ES256
                    {'type': 'public-key', 'alg': -257}  # RS256
                ],
                'authenticatorSelection': {
                    'authenticatorAttachment': 'cross-platform',
                    'userVerification': 'preferred' if self.require_pin else 'discouraged',
                    'requireResidentKey': False
                },
                'timeout': self.timeout_seconds * 2000,
                'attestation': 'none'
            }
        }
    
    async def is_available(self) -> bool:
        """Check if provider is available."""
        # Check if WebAuthn is supported (would check actual support in production)
        try:
            # In production, would check for python-fido2 library
            return True
        except (ImportError, AttributeError, Exception):
            return False
    
    def _verify_webauthn_response(
        self,
        device: MFADevice,
        challenge: str,
        response: dict[str, Any]
    ) -> bool:
        """Verify WebAuthn assertion response.
        
        Args:
            device: MFA device
            challenge: Original challenge
            response: WebAuthn response
            
        Returns:
            True if valid
        """
        # In production, this would use python-fido2 to verify
        # the cryptographic signature against the stored public key
        
        # Simplified validation for stub
        required_fields = ['clientDataJSON', 'authenticatorData', 'signature']
        
        if not all(field in response for field in required_fields):
            return False
        
        try:
            # Decode client data
            client_data = json.loads(
                base64.urlsafe_b64decode(response['clientDataJSON'] + '==').decode()
            )
            
            # Verify challenge matches
            response_challenge = client_data.get('challenge', '').rstrip('=')
            if response_challenge != challenge:
                return False
            
            # Verify type
            if client_data.get('type') != 'webauthn.get':
                return False
            
            # In production, would verify signature here
            return True
            
        except Exception as e:
            logger.error(f"WebAuthn response validation error: {e}")
            return False
    
    async def complete_registration(
        self,
        device_id: str,
        credential_response: dict[str, Any]
    ) -> dict[str, Any]:
        """Complete hardware key registration.
        
        Args:
            device_id: Device ID
            credential_response: WebAuthn credential response
            
        Returns:
            Registration result
        """
        reg_key = f"reg:{device_id}"
        
        if reg_key not in self._active_challenges:
            raise ValueError("No active registration found")
        
        reg_data = self._active_challenges[reg_key]
        
        # In production, would verify attestation and store public key
        # This is simplified for the stub
        
        credential_id = credential_response.get('id')
        public_key = credential_response.get('publicKey')
        
        del self._active_challenges[reg_key]
        
        return {
            'success': True,
            'credential_id': credential_id,
            'public_key': public_key,
            'registered_at': datetime.now(UTC).isoformat()
        }
    
    def get_supported_protocols(self) -> list[str]:
        """Get supported protocols.
        
        Returns:
            List of supported protocol names
        """
        return self.supported_protocols