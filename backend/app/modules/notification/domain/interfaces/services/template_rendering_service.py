"""
Template Rendering Service Interface

Port for notification template operations including rendering,
validation, and personalization.
"""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any
from uuid import UUID

if TYPE_CHECKING:
    from app.modules.notification.domain.aggregates.notification_template import NotificationTemplate
    from app.modules.notification.domain.enums import NotificationChannel


class ITemplateRenderingService(ABC):
    """Port for template rendering operations."""
    
    @abstractmethod
    async def render_template(
        self,
        template: "NotificationTemplate",
        data: dict[str, Any],
        channel: "NotificationChannel",
        locale: str = "en"
    ) -> dict[str, str]:
        """
        Render a notification template with data.
        
        Args:
            template: NotificationTemplate aggregate
            data: Template variables
            channel: Target channel for rendering
            locale: Locale for internationalization
            
        Returns:
            Dictionary with rendered content (subject, body, etc.)
            
        Raises:
            TemplateRenderingError: If rendering fails
            MissingVariableError: If required variable is missing
            InvalidTemplateError: If template syntax is invalid
        """
        ...
    
    @abstractmethod
    async def validate_template_syntax(
        self,
        template_content: str,
        template_engine: str = "jinja2"
    ) -> tuple[bool, list[str]]:
        """
        Validate template syntax before saving.
        
        Args:
            template_content: Template content to validate
            template_engine: Template engine to use
            
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        ...
    
    @abstractmethod
    async def extract_template_variables(
        self,
        template_content: str
    ) -> list[str]:
        """
        Extract all variables used in template.
        
        Args:
            template_content: Template content
            
        Returns:
            List of variable names used in template
        """
        ...
    
    @abstractmethod
    async def preview_template(
        self,
        template_id: UUID,
        sample_data: dict[str, Any],
        channel: "NotificationChannel"
    ) -> dict[str, str]:
        """
        Preview template with sample data.
        
        Args:
            template_id: ID of template to preview
            sample_data: Sample data for preview
            channel: Channel to preview for
            
        Returns:
            Dictionary with preview content
        """
        ...
    
    @abstractmethod
    async def personalize_content(
        self,
        content: str,
        recipient_id: UUID,
        personalization_rules: dict[str, Any] | None = None
    ) -> str:
        """
        Apply personalization rules to content.
        
        Args:
            content: Base content to personalize
            recipient_id: ID of recipient
            personalization_rules: Optional custom rules
            
        Returns:
            Personalized content
        """
        ...
    
    @abstractmethod
    async def sanitize_content(
        self,
        content: str,
        channel: "NotificationChannel"
    ) -> str:
        """
        Sanitize content for specific channel.
        
        Args:
            content: Content to sanitize
            channel: Target channel
            
        Returns:
            Sanitized content safe for channel
        """
        ...
    
    @abstractmethod
    async def apply_content_policies(
        self,
        content: dict[str, str],
        policies: list[str]
    ) -> dict[str, str]:
        """
        Apply content policies (length limits, forbidden words, etc).
        
        Args:
            content: Rendered content
            policies: List of policy names to apply
            
        Returns:
            Content after applying policies
        """
        ...
    
    @abstractmethod
    async def generate_fallback_content(
        self,
        template_id: UUID,
        channel: "NotificationChannel",
        error_context: dict[str, Any]
    ) -> dict[str, str]:
        """
        Generate fallback content when rendering fails.
        
        Args:
            template_id: ID of failed template
            channel: Target channel
            error_context: Context about the failure
            
        Returns:
            Fallback content
        """
        ...