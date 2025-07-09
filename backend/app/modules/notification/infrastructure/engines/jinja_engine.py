"""Jinja2-based template engine for notification rendering."""

import re
from datetime import date, datetime
from typing import Any

import jinja2
from jinja2 import BaseLoader, Environment, Template
from jinja2.sandbox import SandboxedEnvironment
from markupsafe import Markup

from app.modules.notification.domain.enums import VariableType
from app.modules.notification.domain.value_objects import (
    NotificationContent,
    TemplateVariable,
)

# Constants
BOOLEAN_FORMAT_PARTS = 2


class TemplateCache:
    """In-memory cache for compiled templates."""

    def __init__(self, max_size: int = 1000):
        """Initialize template cache.

        Args:
            max_size: Maximum number of templates to cache
        """
        self.max_size = max_size
        self._cache: dict[str, Template] = {}
        self._access_times: dict[str, datetime] = {}

    def get(self, key: str) -> Template | None:
        """Get template from cache.

        Args:
            key: Cache key

        Returns:
            Cached template if found
        """
        if key in self._cache:
            self._access_times[key] = datetime.utcnow()
            return self._cache[key]
        return None

    def set(self, key: str, template: Template) -> None:
        """Store template in cache.

        Args:
            key: Cache key
            template: Compiled template
        """
        # Evict least recently used if at capacity
        if len(self._cache) >= self.max_size:
            lru_key = min(self._access_times.keys(), key=self._access_times.get)
            del self._cache[lru_key]
            del self._access_times[lru_key]

        self._cache[key] = template
        self._access_times[key] = datetime.utcnow()

    def clear(self) -> None:
        """Clear all cached templates."""
        self._cache.clear()
        self._access_times.clear()

    def remove(self, key: str) -> None:
        """Remove specific template from cache.

        Args:
            key: Cache key to remove
        """
        if key in self._cache:
            del self._cache[key]
            del self._access_times[key]


class VariableResolver:
    """Resolves and validates template variables."""

    def __init__(self):
        """Initialize variable resolver."""
        self._formatters = {
            VariableType.STRING: self._format_string,
            VariableType.NUMBER: self._format_number,
            VariableType.DATE: self._format_date,
            VariableType.DATETIME: self._format_datetime,
            VariableType.BOOLEAN: self._format_boolean,
            VariableType.URL: self._format_url,
            VariableType.EMAIL: self._format_email,
            VariableType.CURRENCY: self._format_currency,
        }

    def resolve(
        self, variables: dict[str, Any], definitions: dict[str, TemplateVariable]
    ) -> dict[str, Any]:
        """Resolve and format variables according to their definitions.

        Args:
            variables: Raw variable values
            definitions: Variable definitions

        Returns:
            Resolved and formatted variables
        """
        resolved = {}

        for name, definition in definitions.items():
            if name in variables:
                value = variables[name]
            elif definition.default_value is not None:
                value = definition.default_value
            elif definition.required:
                raise ValueError(f"Required variable '{name}' not provided")
            else:
                continue

            # Validate and format value
            if definition.var_type in self._formatters:
                resolved[name] = self._formatters[definition.var_type](
                    value, definition
                )
            else:
                resolved[name] = str(value)

        # Include any extra variables not in definitions
        for name, value in variables.items():
            if name not in resolved:
                resolved[name] = value

        return resolved

    def _format_string(self, value: Any, definition: TemplateVariable) -> str:
        """Format string value."""
        str_value = str(value)

        # Apply validation rules
        if definition.validation_rules:
            if "max_length" in definition.validation_rules:
                max_len = definition.validation_rules["max_length"]
                if len(str_value) > max_len:
                    str_value = str_value[:max_len] + "..."

        return str_value

    def _format_number(self, value: Any, definition: TemplateVariable) -> str:
        """Format number value."""
        try:
            num = float(value)

            # Apply format pattern if provided
            if definition.format_pattern:
                return definition.format_pattern.format(num)

            # Default formatting
            if num.is_integer():
                return str(int(num))
            return f"{num:.2f}"
        except (ValueError, TypeError):
            return str(value)

    def _format_date(self, value: Any, definition: TemplateVariable) -> str:
        """Format date value."""
        if isinstance(value, date):
            date_obj = value
        elif isinstance(value, datetime):
            date_obj = value.date()
        elif isinstance(value, str):
            try:
                # Parse ISO format
                date_obj = datetime.fromisoformat(value.replace("Z", "+00:00")).date()
            except (ValueError, TypeError) as e:
                return str(value)
        else:
            return str(value)

        # Apply format pattern if provided
        if definition.format_pattern:
            return date_obj.strftime(definition.format_pattern)

        # Default format
        return date_obj.strftime("%Y-%m-%d")

    def _format_datetime(self, value: Any, definition: TemplateVariable) -> str:
        """Format datetime value."""
        if isinstance(value, datetime):
            dt_obj = value
        elif isinstance(value, str):
            try:
                # Parse ISO format
                dt_obj = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except (ValueError, TypeError) as e:
                return str(value)
        else:
            return str(value)

        # Apply format pattern if provided
        if definition.format_pattern:
            return dt_obj.strftime(definition.format_pattern)

        # Default format
        return dt_obj.strftime("%Y-%m-%d %H:%M:%S")

    def _format_boolean(self, value: Any, definition: TemplateVariable) -> str:
        """Format boolean value."""
        bool_value = bool(value)

        # Apply format pattern if provided
        if definition.format_pattern:
            # Expect pattern like "Yes|No"
            parts = definition.format_pattern.split("|")
            if len(parts) == BOOLEAN_FORMAT_PARTS:
                return parts[0] if bool_value else parts[1]

        return "true" if bool_value else "false"

    def _format_url(self, value: Any, definition: TemplateVariable) -> str:
        """Format URL value."""
        url = str(value)

        # Ensure URL has protocol
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        return url

    def _format_email(self, value: Any, definition: TemplateVariable) -> str:
        """Format email value."""
        return str(value).lower()

    def _format_currency(self, value: Any, definition: TemplateVariable) -> str:
        """Format currency value."""
        try:
            amount = float(value)

            # Apply format pattern if provided
            if definition.format_pattern:
                return definition.format_pattern.format(amount)

            # Default format (USD)
            return f"${amount:,.2f}"
        except (ValueError, TypeError):
            return str(value)


class ContentFormatter:
    """Formats notification content for different channels."""

    @staticmethod
    def strip_html(html_content: str) -> str:
        """Strip HTML tags from content.

        Args:
            html_content: HTML content

        Returns:
            Plain text content
        """
        # Remove script and style elements
        html_content = re.sub(
            r"<script[^>]*>.*?</script>",
            "",
            html_content,
            flags=re.DOTALL | re.IGNORECASE,
        )
        html_content = re.sub(
            r"<style[^>]*>.*?</style>",
            "",
            html_content,
            flags=re.DOTALL | re.IGNORECASE,
        )

        # Replace br tags with newlines
        html_content = re.sub(r"<br\s*/?>", "\n", html_content, flags=re.IGNORECASE)

        # Replace p tags with double newlines
        html_content = re.sub(r"</p>", "\n\n", html_content, flags=re.IGNORECASE)

        # Remove all other tags
        html_content = re.sub(r"<[^>]+>", "", html_content)

        # Decode HTML entities
        html_content = html_content.replace("&amp;", "&")
        html_content = html_content.replace("&lt;", "<")
        html_content = html_content.replace("&gt;", ">")
        html_content = html_content.replace("&quot;", '"')
        html_content = html_content.replace("&#39;", "'")
        html_content = html_content.replace("&nbsp;", " ")

        # Clean up whitespace
        lines = [line.strip() for line in html_content.splitlines()]
        html_content = "\n".join(line for line in lines if line)

        return html_content.strip()

    @staticmethod
    def truncate_for_sms(content: str, max_length: int = 160) -> str:
        """Truncate content for SMS.

        Args:
            content: Content to truncate
            max_length: Maximum length

        Returns:
            Truncated content
        """
        if len(content) <= max_length:
            return content

        # Truncate and add ellipsis
        return content[: max_length - 3] + "..."

    @staticmethod
    def format_for_push(
        title: str, body: str, max_title: int = 65, max_body: int = 240
    ) -> tuple:
        """Format content for push notification.

        Args:
            title: Notification title
            body: Notification body
            max_title: Maximum title length
            max_body: Maximum body length

        Returns:
            Tuple of (formatted_title, formatted_body)
        """
        # Truncate title if needed
        if len(title) > max_title:
            title = title[: max_title - 3] + "..."

        # Truncate body if needed
        if len(body) > max_body:
            body = body[: max_body - 3] + "..."

        return title, body


class JinjaTemplateEngine:
    """Jinja2-based template engine for rendering notifications."""

    def __init__(
        self,
        cache: TemplateCache | None = None,
        variable_resolver: VariableResolver | None = None,
        content_formatter: ContentFormatter | None = None,
        enable_autoescape: bool = True,
        enable_sandbox: bool = True,
    ):
        """Initialize template engine.

        Args:
            cache: Template cache instance
            variable_resolver: Variable resolver instance
            content_formatter: Content formatter instance
            enable_autoescape: Whether to enable HTML autoescape
            enable_sandbox: Whether to use sandboxed environment
        """
        self.cache = cache or TemplateCache()
        self.variable_resolver = variable_resolver or VariableResolver()
        self.content_formatter = content_formatter or ContentFormatter()

        # Create Jinja environment
        if enable_sandbox:
            self.env = SandboxedEnvironment(
                autoescape=enable_autoescape,
                loader=BaseLoader(),
                trim_blocks=True,
                lstrip_blocks=True,
            )
        else:
            self.env = Environment(
                autoescape=enable_autoescape,
                loader=BaseLoader(),
                trim_blocks=True,
                lstrip_blocks=True,
            )

        # Add custom filters
        self._register_filters()

        # Add custom functions
        self._register_functions()

    def _register_filters(self) -> None:
        """Register custom Jinja filters."""
        self.env.filters["currency"] = self._filter_currency
        self.env.filters["date"] = self._filter_date
        self.env.filters["datetime"] = self._filter_datetime
        self.env.filters["truncate_words"] = self._filter_truncate_words
        self.env.filters["nl2br"] = self._filter_nl2br
        self.env.filters["strip_html"] = ContentFormatter.strip_html

    def _register_functions(self) -> None:
        """Register custom Jinja functions."""
        self.env.globals["now"] = datetime.utcnow
        self.env.globals["today"] = date.today

    def _filter_currency(
        self, value: float, currency: str = "USD", locale: str = "en_US"
    ) -> str:
        """Format currency value."""
        symbols = {"USD": "$", "EUR": "€", "GBP": "£", "JPY": "¥"}
        symbol = symbols.get(currency, currency)
        return f"{symbol}{value:,.2f}"

    def _filter_date(self, value: Any, format: str = "%Y-%m-%d") -> str:
        """Format date value."""
        if isinstance(value, str):
            try:
                value = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except (ValueError, TypeError):
                return str(value)

        if isinstance(value, date | datetime):
            return value.strftime(format)

        return str(value)

    def _filter_datetime(self, value: Any, format: str = "%Y-%m-%d %H:%M:%S") -> str:
        """Format datetime value."""
        if isinstance(value, str):
            try:
                value = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except (ValueError, TypeError):
                return str(value)

        if isinstance(value, datetime):
            return value.strftime(format)

        return str(value)

    def _filter_truncate_words(
        self, value: str, count: int = 10, suffix: str = "..."
    ) -> str:
        """Truncate text to specified number of words."""
        words = value.split()
        if len(words) <= count:
            return value
        return " ".join(words[:count]) + suffix

    def _filter_nl2br(self, value: str) -> Markup:
        """Convert newlines to <br> tags."""
        result = value.replace("\n", "<br>\n")
        return Markup(result)

    def render_template(
        self,
        template_string: str,
        variables: dict[str, Any],
        variable_definitions: dict[str, TemplateVariable] | None = None,
        cache_key: str | None = None,
    ) -> str:
        """Render a template with variables.

        Args:
            template_string: Template string
            variables: Template variables
            variable_definitions: Variable definitions for validation
            cache_key: Optional cache key

        Returns:
            Rendered template
        """
        # Resolve variables if definitions provided
        if variable_definitions:
            variables = self.variable_resolver.resolve(variables, variable_definitions)

        # Get or compile template
        template = None
        if cache_key:
            template = self.cache.get(cache_key)

        if not template:
            template = self.env.from_string(template_string)
            if cache_key:
                self.cache.set(cache_key, template)

        # Render template
        return template.render(**variables)

    def render_content(
        self,
        content: NotificationContent,
        variables: dict[str, Any],
        variable_definitions: dict[str, TemplateVariable] | None = None,
    ) -> NotificationContent:
        """Render notification content with variables.

        Args:
            content: Notification content
            variables: Template variables
            variable_definitions: Variable definitions

        Returns:
            Rendered notification content
        """
        # Merge content variables with provided variables
        all_variables = {**content.variables, **variables}

        # Resolve variables
        if variable_definitions:
            all_variables = self.variable_resolver.resolve(
                all_variables, variable_definitions
            )

        # Render each part
        rendered_subject = None
        if content.subject:
            rendered_subject = self.render_template(
                content.subject,
                all_variables,
                cache_key=f"subject_{hash(content.subject)}",
            )

        rendered_body = self.render_template(
            content.body, all_variables, cache_key=f"body_{hash(content.body)}"
        )

        rendered_html_body = None
        if content.html_body:
            rendered_html_body = self.render_template(
                content.html_body,
                all_variables,
                cache_key=f"html_{hash(content.html_body)}",
            )

        return NotificationContent(
            subject=rendered_subject,
            body=rendered_body,
            html_body=rendered_html_body,
            attachments=content.attachments,
            metadata=content.metadata,
        )

    def extract_variables(self, template_string: str) -> set[str]:
        """Extract variable names from a template.

        Args:
            template_string: Template string

        Returns:
            Set of variable names
        """
        try:
            ast = self.env.parse(template_string)
            return ast.find_all(jinja2.nodes.Name)
        except (jinja2.TemplateSyntaxError, jinja2.TemplateError):
            # Fallback to regex if parsing fails
            pattern = r"\{\{\s*(\w+)(?:\.\w+)*\s*(?:\|[^}]+)?\}\}"
            matches = re.findall(pattern, template_string)
            return set(matches)

    def validate_template(self, template_string: str) -> tuple[bool, str | None]:
        """Validate a template string.

        Args:
            template_string: Template to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            self.env.from_string(template_string)
            return True, None
        except Exception as e:
            return False, str(e)
