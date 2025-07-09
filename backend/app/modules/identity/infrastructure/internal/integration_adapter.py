"""
Integration Adapter for Identity Module

Internal adapter that allows the Identity module to use external services
through the Integration module. This ensures all external API calls go
through the Integration module.
"""

from typing import Optional, Dict, Any, List
from uuid import UUID

from app.core.infrastructure.internal_adapter_base import BaseInternalAdapter
from app.core.logging import get_logger
from app.modules.integration.application.contracts.integration_contract import (
    IIntegrationContract,
    EmailMessageDTO,
    SMSMessageDTO,
    DeliveryResultDTO,
    GeocodeRequestDTO,
    GeocodeResultDTO
)

logger = get_logger(__name__)


class IntegrationAdapter(BaseInternalAdapter):
    """
    Adapter for accessing external services from Identity module.
    
    This adapter provides methods for the Identity module to interact
    with external services through the Integration module.
    """
    
    def __init__(self, integration_service: IIntegrationContract):
        """
        Initialize Integration adapter.
        
        Args:
            integration_service: Integration service implementation
        """
        super().__init__(module_name="identity", target_module="integration")
        self._integration_service = integration_service
    
    async def health_check(self) -> bool:
        """Check if Integration module is healthy."""
        try:
            services = await self._integration_service.get_available_services()
            return len(services) > 0
        except Exception as e:
            logger.warning(
                "Integration module health check failed",
                error=str(e)
            )
            return False
    
    async def send_direct_email(
        self,
        to_email: str,
        subject: str,
        body: str,
        is_html: bool = False
    ) -> Optional[DeliveryResultDTO]:
        """
        Send email directly without going through notification module.
        
        Used for critical system emails that bypass user preferences.
        
        Args:
            to_email: Recipient email
            subject: Email subject
            body: Email body
            is_html: Whether body is HTML
            
        Returns:
            DeliveryResultDTO if sent successfully
        """
        try:
            message = EmailMessageDTO(
                to=[to_email],
                subject=subject,
                body_text=body if not is_html else "Please view HTML version",
                body_html=body if is_html else None,
                tags=["identity", "system"],
                metadata={
                    "source": "identity.direct",
                    "bypass_preferences": True
                }
            )
            
            return await self._execute_with_resilience(
                "send_direct_email",
                self._integration_service.send_email,
                message
            )
        except Exception as e:
            logger.error(
                "Failed to send direct email",
                to_email=to_email,
                subject=subject,
                error=str(e)
            )
            return None
    
    async def send_direct_sms(
        self,
        phone_number: str,
        message: str
    ) -> Optional[DeliveryResultDTO]:
        """
        Send SMS directly for critical alerts.
        
        Args:
            phone_number: Recipient phone number
            message: SMS message
            
        Returns:
            DeliveryResultDTO if sent successfully
        """
        try:
            sms = SMSMessageDTO(
                to=phone_number,
                body=message,
                metadata={
                    "source": "identity.direct",
                    "bypass_preferences": True
                }
            )
            
            return await self._execute_with_resilience(
                "send_direct_sms",
                self._integration_service.send_sms,
                sms
            )
        except Exception as e:
            logger.error(
                "Failed to send direct SMS",
                phone_number=phone_number,
                error=str(e)
            )
            return None
    
    async def verify_address(
        self,
        address: str,
        country: Optional[str] = None
    ) -> Optional[GeocodeResultDTO]:
        """
        Verify and geocode user address.
        
        Args:
            address: Address to verify
            country: Optional country code
            
        Returns:
            GeocodeResultDTO if successful
        """
        try:
            request = GeocodeRequestDTO(
                address=address,
                country=country
            )
            
            return await self._execute_with_resilience(
                "verify_address",
                self._integration_service.geocode_address,
                request
            )
        except Exception as e:
            logger.error(
                "Failed to verify address",
                address=address,
                error=str(e)
            )
            return None
    
    async def get_location_from_ip(
        self,
        ip_address: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get location information from IP address.
        
        This would typically use a geolocation service through Integration.
        
        Args:
            ip_address: IP address to lookup
            
        Returns:
            Location data if successful
        """
        try:
            # This is a placeholder - actual implementation would use
            # a specific geolocation service through Integration
            logger.info(
                "IP geolocation requested",
                ip_address=ip_address
            )
            
            # For now, return mock data
            # In production, this would call an actual service
            return {
                "ip": ip_address,
                "country": "US",
                "region": "California",
                "city": "San Francisco",
                "timezone": "America/Los_Angeles"
            }
        except Exception as e:
            logger.error(
                "Failed to get location from IP",
                ip_address=ip_address,
                error=str(e)
            )
            return None
    
    async def check_email_deliverability(
        self,
        email: str
    ) -> bool:
        """
        Check if email address is deliverable.
        
        Uses email validation service through Integration.
        
        Args:
            email: Email to check
            
        Returns:
            True if deliverable
        """
        try:
            # This would typically use an email validation service
            # For now, just check if we can send to it
            logger.info(
                "Email deliverability check requested",
                email=email
            )
            
            # Basic validation for now
            return "@" in email and "." in email.split("@")[1]
        except Exception as e:
            logger.error(
                "Failed to check email deliverability",
                email=email,
                error=str(e)
            )
            return False
    
    async def verify_phone_number(
        self,
        phone_number: str,
        country_code: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Verify and format phone number.
        
        Uses phone validation service through Integration.
        
        Args:
            phone_number: Phone number to verify
            country_code: Optional country code
            
        Returns:
            Formatted phone data if valid
        """
        try:
            # This would typically use a phone validation service
            logger.info(
                "Phone verification requested",
                phone_number=phone_number,
                country_code=country_code
            )
            
            # Basic validation for now
            cleaned = "".join(filter(str.isdigit, phone_number))
            if len(cleaned) >= 10:
                return {
                    "valid": True,
                    "formatted": phone_number,
                    "country_code": country_code or "US",
                    "type": "mobile"
                }
            
            return None
        except Exception as e:
            logger.error(
                "Failed to verify phone number",
                phone_number=phone_number,
                error=str(e)
            )
            return None
    
    async def check_compromised_password(
        self,
        password_hash: str
    ) -> bool:
        """
        Check if password appears in breach databases.
        
        Uses password breach checking service through Integration.
        
        Args:
            password_hash: SHA-1 hash prefix of password
            
        Returns:
            True if password is compromised
        """
        try:
            # This would typically use HaveIBeenPwned or similar service
            logger.info(
                "Password breach check requested",
                hash_prefix=password_hash[:5]  # Log only prefix
            )
            
            # For now, return false (not compromised)
            # In production, this would check against breach databases
            return False
        except Exception as e:
            logger.error(
                "Failed to check compromised password",
                error=str(e)
            )
            # Fail open - don't block if service is down
            return False