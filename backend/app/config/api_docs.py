"""Hybrid API documentation configuration.

This provides a simple interface (like your current version) while internally
using the comprehensive structure for better maintainability and scalability.

Design: Simple API, Rich Implementation
"""

from dataclasses import dataclass, field
from typing import Any

from app.core.enums import Environment
from app.core.errors import ConfigurationError
from app.utils.validation import validate_integer, validate_string


@dataclass
class APIDocumentationConfig:
    """
    Simple API documentation configuration with rich internal structure.

    This provides a simple interface while internally organizing settings
    into logical groups for better maintainability.
    """

    # Simple flat interface (your preferred style)
    required_fields: list[str] = field(
        default_factory=lambda: ["summary", "description"]
    )
    max_path_length: int = 100
    max_description_length: int = 500
    required_response_codes: list[str] = field(
        default_factory=lambda: ["200", "400", "500"]
    )

    cache_enabled: bool = True
    include_examples: bool = True
    include_security_analysis: bool = True
    generator_version: str = "2.0.0"

    default_output_formats: list[str] = field(
        default_factory=lambda: ["json", "yaml", "markdown"]
    )
    output_directory: str = "docs/api"

    mask_sensitive_examples: bool = True
    security_schemes_required: bool = True

    cache_max_size: int = 1000
    generation_timeout: int = 300

    validate_examples: bool = True
    validate_security_schemes: bool = True
    validate_response_schemas: bool = True
    strict_validation: bool = False

    require_operation_descriptions: bool = True
    require_parameter_descriptions: bool = True
    require_response_descriptions: bool = True
    minimum_description_length: int = 10

    enable_swagger_ui: bool = True
    enable_redoc: bool = True
    enable_openapi_explorer: bool = False

    def __post_init__(self):
        """Validate and organize configuration."""
        self._validate_configuration()
        self._organize_settings()

    def _validate_configuration(self) -> None:
        """Validate configuration parameters."""
        if self.max_path_length < 10:
            raise ConfigurationError("Max path length must be at least 10")

        if self.max_path_length > 1000:
            raise ConfigurationError("Max path length must be at most 1000")

        if self.max_description_length < 50:
            raise ConfigurationError("Max description length must be at least 50")

        if self.minimum_description_length < 5:
            raise ConfigurationError("Minimum description length must be at least 5")

        if self.minimum_description_length >= self.max_description_length:
            raise ConfigurationError(
                "Minimum description length must be less than maximum"
            )

        if self.generation_timeout < 30:
            raise ConfigurationError("Generation timeout must be at least 30 seconds")

        if self.generation_timeout > 3600:
            raise ConfigurationError("Generation timeout must be at most 3600 seconds")

        if self.cache_max_size < 100:
            raise ConfigurationError("Cache max size must be at least 100")

        if not self.required_fields:
            raise ConfigurationError("Required fields list cannot be empty")

        if not self.required_response_codes:
            raise ConfigurationError("Required response codes list cannot be empty")

        self.output_directory = validate_string(
            self.output_directory, "output_directory", required=True, min_length=1
        )

    def _organize_settings(self) -> None:
        """Organize settings into logical groups (internal rich structure)."""
        # Create internal organized structure for better maintainability
        self._validation_settings = {
            "required_fields": self.required_fields,
            "max_path_length": self.max_path_length,
            "max_description_length": self.max_description_length,
            "minimum_description_length": self.minimum_description_length,
            "required_response_codes": self.required_response_codes,
            "validate_examples": self.validate_examples,
            "validate_security_schemes": self.validate_security_schemes,
            "validate_response_schemas": self.validate_response_schemas,
            "strict_validation": self.strict_validation,
            "require_operation_descriptions": self.require_operation_descriptions,
            "require_parameter_descriptions": self.require_parameter_descriptions,
            "require_response_descriptions": self.require_response_descriptions,
        }

        self._generation_settings = {
            "include_examples": self.include_examples,
            "include_security_analysis": self.include_security_analysis,
            "generator_version": self.generator_version,
        }

        self._output_settings = {
            "default_output_formats": self.default_output_formats,
            "output_directory": self.output_directory,
            "enable_swagger_ui": self.enable_swagger_ui,
            "enable_redoc": self.enable_redoc,
            "enable_openapi_explorer": self.enable_openapi_explorer,
        }

        self._security_settings = {
            "mask_sensitive_examples": self.mask_sensitive_examples,
            "security_schemes_required": self.security_schemes_required,
        }

        self._performance_settings = {
            "cache_enabled": self.cache_enabled,
            "cache_max_size": self.cache_max_size,
            "generation_timeout": self.generation_timeout,
        }

    @classmethod
    def from_environment(cls, environment: Environment) -> "APIDocumentationConfig":
        """
        Create configuration with environment-specific defaults.

        Args:
            environment: Target environment

        Returns:
            APIDocumentationConfig: Environment-optimized configuration
        """
        config = cls()

        if environment == Environment.DEVELOPMENT:
            config.include_examples = True
            config.include_security_analysis = False
            config.validate_examples = True
            config.strict_validation = False
            config.enable_swagger_ui = True
            config.enable_redoc = True
            config.enable_openapi_explorer = True
            config.cache_enabled = False

        elif environment == Environment.TESTING:
            config.include_examples = False
            config.include_security_analysis = False
            config.validate_examples = False
            config.strict_validation = False
            config.enable_swagger_ui = False
            config.enable_redoc = False
            config.enable_openapi_explorer = False
            config.cache_enabled = False
            config.generation_timeout = 60

        elif environment == Environment.STAGING:
            config.include_examples = True
            config.include_security_analysis = True
            config.validate_examples = True
            config.strict_validation = True
            config.enable_swagger_ui = True
            config.enable_redoc = True
            config.cache_enabled = True

        elif environment == Environment.PRODUCTION:
            config.include_examples = True
            config.include_security_analysis = True
            config.validate_examples = True
            config.strict_validation = True
            config.mask_sensitive_examples = True
            config.security_schemes_required = True
            config.enable_swagger_ui = True
            config.enable_redoc = True
            config.cache_enabled = True
            config.cache_max_size = 2000

        return config

    @classmethod
    def from_environment_variables(
        cls, env_prefix: str = "API_DOCS_"
    ) -> "APIDocumentationConfig":
        """Create configuration from environment variables."""
        import os

        from app.utils.validation import validate_boolean, validate_string

        config = cls()

        # Override from environment variables
        if cache_enabled := os.getenv(f"{env_prefix}CACHE_ENABLED"):
            config.cache_enabled = validate_boolean(
                cache_enabled, f"{env_prefix}CACHE_ENABLED", required=False
            )

        if include_examples := os.getenv(f"{env_prefix}INCLUDE_EXAMPLES"):
            config.include_examples = validate_boolean(
                include_examples, f"{env_prefix}INCLUDE_EXAMPLES", required=False
            )

        if output_dir := os.getenv(f"{env_prefix}OUTPUT_DIR"):
            config.output_directory = validate_string(
                output_dir, f"{env_prefix}OUTPUT_DIR", min_length=1
            )

        if timeout := os.getenv(f"{env_prefix}TIMEOUT"):
            config.generation_timeout = validate_integer(
                timeout, f"{env_prefix}TIMEOUT", min_value=30
            )

        if max_path := os.getenv(f"{env_prefix}MAX_PATH_LENGTH"):
            config.max_path_length = validate_integer(
                max_path, f"{env_prefix}MAX_PATH_LENGTH", min_value=10, max_value=1000
            )

        return config

    # Getter methods for organized access (rich internal structure)
    def get_validation_settings(self) -> dict[str, Any]:
        """Get validation-related settings."""
        return self._validation_settings.copy()

    def get_generation_settings(self) -> dict[str, Any]:
        """Get generation-related settings."""
        return self._generation_settings.copy()

    def get_output_settings(self) -> dict[str, Any]:
        """Get output-related settings."""
        return self._output_settings.copy()

    def get_security_settings(self) -> dict[str, Any]:
        """Get security-related settings."""
        return self._security_settings.copy()

    def get_performance_settings(self) -> dict[str, Any]:
        """Get performance-related settings."""
        return self._performance_settings.copy()

    def to_dict(self) -> dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            "required_fields": self.required_fields,
            "max_path_length": self.max_path_length,
            "max_description_length": self.max_description_length,
            "required_response_codes": self.required_response_codes,
            "cache_enabled": self.cache_enabled,
            "include_examples": self.include_examples,
            "include_security_analysis": self.include_security_analysis,
            "generator_version": self.generator_version,
            "default_output_formats": self.default_output_formats,
            "output_directory": self.output_directory,
            "mask_sensitive_examples": self.mask_sensitive_examples,
            "security_schemes_required": self.security_schemes_required,
            "cache_max_size": self.cache_max_size,
            "generation_timeout": self.generation_timeout,
            "validate_examples": self.validate_examples,
            "validate_security_schemes": self.validate_security_schemes,
            "validate_response_schemas": self.validate_response_schemas,
            "strict_validation": self.strict_validation,
            "require_operation_descriptions": self.require_operation_descriptions,
            "require_parameter_descriptions": self.require_parameter_descriptions,
            "require_response_descriptions": self.require_response_descriptions,
            "minimum_description_length": self.minimum_description_length,
            "enable_swagger_ui": self.enable_swagger_ui,
            "enable_redoc": self.enable_redoc,
            "enable_openapi_explorer": self.enable_openapi_explorer,
        }


def create_api_docs_config_from_settings(settings) -> APIDocumentationConfig:
    """
    Create API docs configuration from application settings.

    Args:
        settings: Main application settings

    Returns:
        APIDocumentationConfig: Configured instance
    """
    return APIDocumentationConfig.from_environment(settings.environment)


__all__ = [
    "APIDocumentationConfig",
    "create_api_docs_config_from_settings",
]
