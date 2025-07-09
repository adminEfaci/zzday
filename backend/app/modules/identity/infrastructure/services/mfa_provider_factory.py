"""
MFA Provider Factory

Factory for instantiating MFA providers based on method type.
"""

import logging
from typing import Any, Protocol

from app.modules.identity.domain.entities.admin.mfa_device import MFADevice
from app.modules.identity.domain.enums import MFAMethod
from app.modules.identity.domain.interfaces.services.communication.notification_service import (
    IEmailService,
    ISMSService,
)
from app.modules.identity.infrastructure.services.backup_code_mfa_provider import (
    BackupCodeMFAProvider,
)
from app.modules.identity.infrastructure.services.email_mfa_provider import (
    EmailMFAProvider,
)
from app.modules.identity.infrastructure.services.hardware_key_mfa_provider import (
    HardwareKeyMFAProvider,
)
from app.modules.identity.infrastructure.services.sms_mfa_provider import SMSMFAProvider
from app.modules.identity.infrastructure.services.totp_mfa_provider import (
    TOTPMFAProvider,
)

logger = logging.getLogger(__name__)


class IMFAProvider(Protocol):
    """MFA Provider protocol interface."""
    
    @property
    def method(self) -> MFAMethod:
        """Get MFA method type."""
        ...
    
    @property
    def name(self) -> str:
        """Get provider name."""
        ...
    
    async def send_code(
        self,
        device: MFADevice,
        user_identifier: str | None = None
    ) -> dict[str, Any]:
        """Send verification code."""
        ...
    
    async def verify_code(
        self,
        device: MFADevice,
        code: str
    ) -> tuple[bool, dict[str, Any]]:
        """Verify code."""
        ...
    
    async def setup_device(
        self,
        device: MFADevice,
        **kwargs: Any
    ) -> dict[str, Any]:
        """Setup MFA device."""
        ...
    
    async def is_available(self) -> bool:
        """Check if provider is available."""
        ...


class MFAProviderFactory:
    """Factory for creating MFA providers."""
    
    def __init__(
        self,
        sms_service: ISMSService | None = None,
        email_service: IEmailService | None = None,
        config: dict[str, Any] | None = None
    ):
        """Initialize MFA provider factory.
        
        Args:
            sms_service: SMS sending service
            email_service: Email sending service
            config: Provider configuration
        """
        self.sms_service = sms_service
        self.email_service = email_service
        self.config = config or {}
        
        # Provider instances cache
        self._providers: dict[MFAMethod, IMFAProvider] = {}
        
        # Provider availability cache
        self._availability_cache: dict[MFAMethod, bool] = {}
    
    def create_provider(self, method: MFAMethod) -> IMFAProvider:
        """Create MFA provider for given method.
        
        Args:
            method: MFA method type
            
        Returns:
            MFA provider instance
            
        Raises:
            ValueError: If provider not available or unsupported
        """
        # Check cache first
        if method in self._providers:
            return self._providers[method]
        
        # Create provider based on method
        provider = self._create_provider_instance(method)
        
        if provider is None:
            raise ValueError(f"Unsupported MFA method: {method.value}")
        
        # Cache provider
        self._providers[method] = provider
        
        return provider
    
    def _create_provider_instance(self, method: MFAMethod) -> IMFAProvider | None:
        """Create provider instance based on method.
        
        Args:
            method: MFA method type
            
        Returns:
            Provider instance or None if unsupported
        """
        if method == MFAMethod.SMS:
            if not self.sms_service:
                logger.warning("SMS service not configured")
                return None
            
            return SMSMFAProvider(
                sms_service=self.sms_service,
                **self._get_sms_config()
            )
        
        if method == MFAMethod.EMAIL:
            if not self.email_service:
                logger.warning("Email service not configured")
                return None
            
            return EmailMFAProvider(
                email_service=self.email_service,
                **self._get_email_config()
            )
        
        if method == MFAMethod.TOTP:
            return TOTPMFAProvider(**self._get_totp_config())
        
        if method == MFAMethod.BACKUP_CODE:
            return BackupCodeMFAProvider(**self._get_backup_code_config())
        
        if method == MFAMethod.HARDWARE_KEY:
            return HardwareKeyMFAProvider(**self._get_hardware_key_config())
        
        logger.warning(f"Unsupported MFA method: {method.value}")
        return None
    
    async def get_available_providers(self) -> list[IMFAProvider]:
        """Get all available MFA providers.
        
        Returns:
            List of available providers
        """
        available = []
        
        for method in MFAMethod:
            if await self.is_method_available(method):
                try:
                    provider = self.create_provider(method)
                    available.append(provider)
                except ValueError:
                    continue
        
        return available
    
    async def is_method_available(self, method: MFAMethod) -> bool:
        """Check if MFA method is available.
        
        Args:
            method: MFA method to check
            
        Returns:
            True if method is available
        """
        # Check cache
        if method in self._availability_cache:
            return self._availability_cache[method]
        
        # Check provider availability
        available = await self._check_method_availability(method)
        
        # Cache result for 5 minutes
        self._availability_cache[method] = available
        
        return available
    
    async def _check_method_availability(self, method: MFAMethod) -> bool:
        """Check actual method availability.
        
        Args:
            method: MFA method to check
            
        Returns:
            True if available
        """
        # Check configuration
        if not self._is_method_enabled(method):
            return False
        
        # Check service dependencies
        if method == MFAMethod.SMS:
            return self.sms_service is not None and await self._check_sms_availability()
        
        if method == MFAMethod.EMAIL:
            return self.email_service is not None and await self._check_email_availability()
        
        if method == MFAMethod.TOTP or method == MFAMethod.BACKUP_CODE:
            return True  # Always available
        
        if method == MFAMethod.HARDWARE_KEY:
            return self._is_hardware_key_supported()
        
        return False
    
    def _is_method_enabled(self, method: MFAMethod) -> bool:
        """Check if method is enabled in configuration.
        
        Args:
            method: MFA method
            
        Returns:
            True if enabled
        """
        enabled_methods = self.config.get('enabled_methods', [])
        
        # If no configuration, enable common methods
        if not enabled_methods:
            return method in {
                MFAMethod.TOTP,
                MFAMethod.SMS,
                MFAMethod.EMAIL,
                MFAMethod.BACKUP_CODE
            }
        
        return method.value in enabled_methods
    
    async def _check_sms_availability(self) -> bool:
        """Check SMS service availability."""
        try:
            return await self.sms_service.is_available()
        except Exception as e:
            logger.error(f"SMS service check failed: {e}")
            return False
    
    async def _check_email_availability(self) -> bool:
        """Check email service availability."""
        try:
            return await self.email_service.is_available()
        except Exception as e:
            logger.error(f"Email service check failed: {e}")
            return False
    
    def _is_hardware_key_supported(self) -> bool:
        """Check if hardware keys are supported."""
        return self.config.get('hardware_key', {}).get('enabled', False)
    
    def _get_sms_config(self) -> dict[str, Any]:
        """Get SMS provider configuration."""
        return self.config.get('sms', {
            'code_length': 6,
            'code_expiry_minutes': 5,
            'max_attempts': 3,
            'rate_limit_minutes': 1
        })
    
    def _get_email_config(self) -> dict[str, Any]:
        """Get email provider configuration."""
        return self.config.get('email', {
            'code_length': 6,
            'code_expiry_minutes': 10,
            'max_attempts': 3,
            'rate_limit_minutes': 1
        })
    
    def _get_totp_config(self) -> dict[str, Any]:
        """Get TOTP provider configuration."""
        return self.config.get('totp', {
            'issuer': 'EzzDay',
            'algorithm': 'SHA1',
            'digits': 6,
            'period': 30,
            'window': 1
        })
    
    def _get_backup_code_config(self) -> dict[str, Any]:
        """Get backup code provider configuration."""
        return self.config.get('backup_code', {
            'code_length': 8,
            'code_count': 10,
            'alphanumeric': True
        })
    
    def _get_hardware_key_config(self) -> dict[str, Any]:
        """Get hardware key provider configuration."""
        return self.config.get('hardware_key', {
            'timeout_seconds': 30,
            'supported_protocols': ['FIDO2', 'U2F'],
            'require_pin': False
        })
    
    def get_provider_info(self, method: MFAMethod) -> dict[str, Any]:
        """Get provider information.
        
        Args:
            method: MFA method
            
        Returns:
            Provider information
        """
        try:
            provider = self.create_provider(method)
            return {
                'method': method.value,
                'name': provider.name,
                'display_name': method.get_display_name(),
                'requires_device': method.requires_device,
                'is_secure': method.is_secure,
                'is_phishing_resistant': method.is_phishing_resistant,
                'security_level': method.security_level
            }
        except ValueError:
            return {
                'method': method.value,
                'name': method.get_display_name(),
                'available': False
            }
    
    def clear_cache(self) -> None:
        """Clear provider and availability caches."""
        self._providers.clear()
        self._availability_cache.clear()
        logger.info("MFA provider factory cache cleared")