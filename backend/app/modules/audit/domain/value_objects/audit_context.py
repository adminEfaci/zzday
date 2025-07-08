"""Audit context value object.

This module defines the AuditContext value object that captures
contextual information about when and how an audit event occurred.
"""

from typing import Any

from app.core.domain.base import ValueObject
from app.core.errors import ValidationError
from app.utils.validation import validate_string


class AuditContext(ValueObject):
    """
    Represents the context in which an audit event occurred.

    This value object captures environmental and contextual information
    that provides additional details about the circumstances of an audit event.

    Attributes:
        ip_address: IP address from which the action originated
        user_agent: User agent string of the client
        request_id: Unique identifier for the request
        session_id: Session identifier
        environment: Environment where the action occurred (e.g., 'production', 'staging')
        additional_data: Additional context-specific data

    Usage:
        context = AuditContext(
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0...",
            request_id="req-123",
            session_id="sess-456",
            environment="production"
        )
    """

    def __init__(
        self,
        ip_address: str | None = None,
        user_agent: str | None = None,
        request_id: str | None = None,
        session_id: str | None = None,
        environment: str = "production",
        additional_data: dict[str, Any] | None = None,
    ):
        """
        Initialize audit context.

        Args:
            ip_address: Client IP address
            user_agent: Client user agent string
            request_id: Request identifier
            session_id: Session identifier
            environment: Environment name
            additional_data: Additional context data

        Raises:
            ValidationError: If environment is invalid
        """
        super().__init__()

        # Set IP address with validation
        if ip_address:
            self.ip_address = self._validate_ip_address(ip_address)
        else:
            self.ip_address = None

        # Set user agent with truncation if needed
        if user_agent:
            self.user_agent = user_agent[:500]  # Limit length
        else:
            self.user_agent = None

        # Set identifiers
        self.request_id = request_id
        self.session_id = session_id

        # Validate and set environment
        self.validate_not_empty(environment, "environment")
        self.environment = self._validate_environment(environment.lower().strip())

        # Set additional data (immutable)
        if additional_data:
            self.additional_data = frozenset(additional_data.items())
        else:
            self.additional_data = frozenset()

        # Freeze the value object
        self._freeze()

    def _validate_ip_address(self, ip_address: str) -> str:
        """
        Validate IP address format.

        Args:
            ip_address: IP address to validate

        Returns:
            Validated IP address

        Raises:
            ValidationError: If IP address format is invalid
        """
        if not ip_address:
            raise ValidationError("IP address cannot be empty")
            
        ip_stripped = ip_address.strip()
        
        # Basic length validation
        if len(ip_stripped) > 45:  # Max length for IPv6
            raise ValidationError("IP address too long")
        
        if len(ip_stripped) < 7:  # Min length for IPv4 (x.x.x.x)
            raise ValidationError("IP address too short")
        
        # Basic format validation
        if not any(char.isdigit() for char in ip_stripped):
            raise ValidationError("IP address must contain digits")

        return ip_stripped

    def _validate_environment(self, environment: str) -> str:
        """
        Validate environment name.

        Args:
            environment: Environment name to validate

        Returns:
            Validated environment name

        Raises:
            ValidationError: If environment is invalid
        """
        valid_environments = [
            "production", "prod", "staging", "stage", "development", 
            "dev", "test", "testing", "local", "demo"
        ]
        
        return validate_string(
            environment,
            "environment",
            required=True,
            max_length=20,
            allowed_values=valid_environments
        )

    def is_production(self) -> bool:
        """Check if this context is from production environment."""
        return self.environment in ("production", "prod")

    def is_development(self) -> bool:
        """Check if this context is from development environment."""
        return self.environment in ("development", "dev", "local")

    def is_authenticated_context(self) -> bool:
        """Check if this context has authentication information."""
        return bool(self.session_id)

    def get_location_hint(self) -> str | None:
        """
        Get a location hint from IP address.

        Returns:
            Location hint if IP is recognizable, None otherwise
        """
        if not self.ip_address:
            return None

        # Check for local/private IPs
        if self.ip_address.startswith(("127.", "10.", "172.", "192.168.")):
            return "internal"

        # Could be extended with GeoIP lookup
        return "external"

    def with_additional_data(self, **kwargs) -> "AuditContext":
        """
        Create a new context with additional data.

        Args:
            **kwargs: Additional data to include

        Returns:
            New AuditContext instance with merged data
        """
        new_data = dict(self.additional_data)
        new_data.update(kwargs)

        return AuditContext(
            ip_address=self.ip_address,
            user_agent=self.user_agent,
            request_id=self.request_id,
            session_id=self.session_id,
            environment=self.environment,
            additional_data=new_data,
        )

    def mask_sensitive_data(self) -> "AuditContext":
        """
        Create a new context with sensitive data masked.

        Returns:
            New AuditContext instance with masked data
        """
        # Mask IP address (keep first two octets)
        masked_ip = None
        if self.ip_address:
            parts = self.ip_address.split(".")
            masked_ip = f"{parts[0]}.{parts[1]}.*.*" if len(parts) == 4 else "***"

        # Filter sensitive keys from additional data
        sensitive_keys = {"password", "token", "secret", "key", "credential"}
        additional_dict = dict(self.additional_data)
        filtered_data = {
            k: "***" if any(s in k.lower() for s in sensitive_keys) else v
            for k, v in additional_dict.items()
        }

        return AuditContext(
            ip_address=masked_ip,
            user_agent=self.user_agent,
            request_id=self.request_id,
            session_id=self.session_id,
            environment=self.environment,
            additional_data=filtered_data,
        )

    def _get_atomic_values(self) -> tuple[Any, ...]:
        """Get atomic values for equality comparison."""
        return (
            self.ip_address,
            self.user_agent,
            self.request_id,
            self.session_id,
            self.environment,
            self.additional_data,
        )

    def __str__(self) -> str:
        """String representation of the audit context."""
        parts = [f"env={self.environment}"]

        if self.ip_address:
            parts.append(f"ip={self.ip_address}")

        if self.session_id:
            parts.append(f"session={self.session_id}")

        if self.request_id:
            parts.append(f"request={self.request_id}")

        return f"AuditContext({', '.join(parts)})"

    @classmethod
    def create_system_context(cls, environment: str = "production") -> "AuditContext":
        """Factory method for system-generated audit events."""
        return cls(
            ip_address="127.0.0.1",
            user_agent="system",
            environment=environment,
            additional_data={"source": "system"},
        )

    @classmethod
    def create_api_context(
        cls,
        ip_address: str,
        user_agent: str,
        request_id: str,
        environment: str = "production",
    ) -> "AuditContext":
        """Factory method for API request audit events."""
        return cls(
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
            environment=environment,
            additional_data={"source": "api"},
        )

    @classmethod
    def create_web_context(
        cls,
        ip_address: str,
        user_agent: str,
        session_id: str,
        request_id: str | None = None,
        environment: str = "production",
        referrer: str | None = None,
    ) -> "AuditContext":
        """Factory method for web application audit events."""
        additional_data = {"source": "web"}
        if referrer:
            additional_data["referrer"] = referrer
            
        return cls(
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id,
            session_id=session_id,
            environment=environment,
            additional_data=additional_data,
        )

    @classmethod
    def create_mobile_context(
        cls,
        device_id: str,
        app_version: str,
        platform: str,
        environment: str = "production",
        location: dict[str, Any] | None = None,
    ) -> "AuditContext":
        """Factory method for mobile application audit events."""
        additional_data = {
            "source": "mobile",
            "device_id": device_id,
            "app_version": app_version,
            "platform": platform,
        }
        if location:
            additional_data["location"] = location
            
        return cls(
            ip_address=None,  # May not be available for mobile
            user_agent=f"{platform}/{app_version}",
            environment=environment,
            additional_data=additional_data,
        )

    @classmethod
    def create_batch_context(
        cls,
        job_id: str,
        job_type: str,
        environment: str = "production",
        triggered_by: str | None = None,
    ) -> "AuditContext":
        """Factory method for batch job audit events."""
        additional_data = {
            "source": "batch",
            "job_id": job_id,
            "job_type": job_type,
        }
        if triggered_by:
            additional_data["triggered_by"] = triggered_by
            
        return cls(
            ip_address="127.0.0.1",
            user_agent="batch-processor",
            environment=environment,
            additional_data=additional_data,
        )

    @classmethod
    def create_integration_context(
        cls,
        integration_name: str,
        integration_version: str | None = None,
        environment: str = "production",
        external_id: str | None = None,
    ) -> "AuditContext":
        """Factory method for external integration audit events."""
        additional_data = {
            "source": "integration",
            "integration_name": integration_name,
        }
        if integration_version:
            additional_data["integration_version"] = integration_version
        if external_id:
            additional_data["external_id"] = external_id
            
        return cls(
            ip_address=None,  # External integrations may not have IP
            user_agent=f"integration/{integration_name}",
            environment=environment,
            additional_data=additional_data,
        )


__all__ = ["AuditContext"]
