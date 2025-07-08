"""Complete API documentation service following DDD and clean architecture principles.

This module provides comprehensive API documentation generation with validation,
security analysis, metrics calculation, and multi-format output support.

Design Principles:
- Clean architecture with dependency injection
- Framework-agnostic design (ready for any DI container)
- Comprehensive validation and security analysis
- Rich metrics and monitoring capabilities
- Multiple output format support
- Performance optimization with caching
- Proper error handling and logging
"""

import json
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

import yaml

# Framework imports (these would be injected in real usage)
from fastapi import FastAPI
from strawberry import Schema as StrawberrySchema

# Internal imports
try:
    from app.config.api_docs import APIDocumentationConfig
except ImportError:
    # Fallback implementation
    from dataclasses import dataclass
    
    @dataclass
    class APIDocumentationConfig:
        cache_enabled: bool = True
        include_examples: bool = True
        include_security_analysis: bool = False
        max_path_length: int = 100
        output_directory: str = "docs/api"
        generation_timeout: int = 300

try:
    from app.core.enums import APIDocumentationFormat, ValidationSeverity
except ImportError:
    from enum import Enum
    
    class APIDocumentationFormat(Enum):
        JSON = "json"
        YAML = "yaml"
        MARKDOWN = "markdown"
        HTML = "html"
    
    class ValidationSeverity(Enum):
        INFO = "info"
        WARNING = "warning"
        ERROR = "error"
        CRITICAL = "critical"

from app.core.errors import ValidationError

try:
    from app.utils.validation import EmailValidator, URLValidator, UUIDValidator
except ImportError:
    # Fallback validation classes
    class EmailValidator:
        @staticmethod
        def validate_format(email: str) -> bool:
            return "@" in email and "." in email.split("@")[1]
    
    class URLValidator:
        def __init__(self, url: str):
            if not url.startswith(('http://', 'https://', 'redis://', 'postgresql://')):
                raise ValueError("Invalid URL format")
    
    class UUIDValidator:
        @staticmethod
        def validate_format(uuid_str: str) -> bool:
            try:
                from uuid import UUID
                UUID(uuid_str)
                return True
            except ValueError:
                return False

# =====================================================================================
# PROTOCOLS AND INTERFACES
# =====================================================================================


class CacheServiceProtocol(Protocol):
    """Protocol for cache service dependency."""

    async def get(self, key: str) -> Any | None:
        """Get value from cache."""
        ...

    async def set(self, key: str, value: Any, ttl: int | None = None) -> None:
        """Set value in cache."""
        ...

    async def delete(self, key: str) -> None:
        """Delete value from cache."""
        ...


class LoggerProtocol(Protocol):
    """Protocol for logger dependency."""

    def info(self, message: str, **kwargs: Any) -> None:
        """Log info message."""
        ...

    def warning(self, message: str, **kwargs: Any) -> None:
        """Log warning message."""
        ...

    def error(self, message: str, **kwargs: Any) -> None:
        """Log error message."""
        ...

    def debug(self, message: str, **kwargs: Any) -> None:
        """Log debug message."""
        ...


class MetricsServiceProtocol(Protocol):
    """Protocol for metrics service dependency."""

    def increment_counter(self, name: str, tags: dict[str, str] | None = None) -> None:
        """Increment counter metric."""
        ...

    def record_histogram(
        self, name: str, value: float, tags: dict[str, str] | None = None
    ) -> None:
        """Record histogram metric."""
        ...

    def set_gauge(
        self, name: str, value: float, tags: dict[str, str] | None = None
    ) -> None:
        """Set gauge metric."""
        ...


# =====================================================================================
# DATA MODELS
# =====================================================================================


@dataclass
class ValidationIssue:
    """Represents a validation issue found in API documentation."""

    type: str
    severity: ValidationSeverity
    message: str
    location: str
    suggestion: str | None = None
    rule_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "type": self.type,
            "severity": self.severity.value,
            "message": self.message,
            "location": self.location,
            "suggestion": self.suggestion,
            "rule_id": self.rule_id,
        }


@dataclass
class APIMetrics:
    """API documentation metrics and statistics."""

    # Endpoint metrics
    total_endpoints: int
    rest_endpoints: int
    graphql_endpoints: int
    deprecated_endpoints: int

    # Documentation quality metrics
    documented_endpoints: int
    endpoints_with_examples: int
    endpoints_with_security: int
    average_description_length: float

    # Schema metrics
    total_schemas: int
    reused_schemas: int
    complex_schemas: int
    schema_depth_average: float

    # Security metrics
    endpoints_with_auth: int
    security_schemes_count: int
    public_endpoints: int

    # Performance indicators
    generation_time_seconds: float
    cache_hit_ratio: float | None = None
    output_size_bytes: int | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "endpoints": {
                "total": self.total_endpoints,
                "rest": self.rest_endpoints,
                "graphql": self.graphql_endpoints,
                "deprecated": self.deprecated_endpoints,
                "deprecation_ratio": self.deprecated_endpoints
                / max(self.total_endpoints, 1),
            },
            "documentation_quality": {
                "documented": self.documented_endpoints,
                "with_examples": self.endpoints_with_examples,
                "with_security": self.endpoints_with_security,
                "documentation_ratio": self.documented_endpoints
                / max(self.total_endpoints, 1),
                "example_ratio": self.endpoints_with_examples
                / max(self.total_endpoints, 1),
                "average_description_length": self.average_description_length,
            },
            "schemas": {
                "total": self.total_schemas,
                "reused": self.reused_schemas,
                "complex": self.complex_schemas,
                "reuse_ratio": self.reused_schemas / max(self.total_schemas, 1),
                "average_depth": self.schema_depth_average,
            },
            "security": {
                "endpoints_with_auth": self.endpoints_with_auth,
                "security_schemes": self.security_schemes_count,
                "public_endpoints": self.public_endpoints,
                "auth_ratio": self.endpoints_with_auth / max(self.total_endpoints, 1),
            },
            "performance": {
                "generation_time_seconds": self.generation_time_seconds,
                "cache_hit_ratio": self.cache_hit_ratio,
                "output_size_bytes": self.output_size_bytes,
            },
        }


@dataclass
class SecurityFinding:
    """Security analysis finding."""

    finding_type: str
    severity: ValidationSeverity
    endpoint: str
    description: str
    recommendation: str
    cwe_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "type": self.finding_type,
            "severity": self.severity.value,
            "endpoint": self.endpoint,
            "description": self.description,
            "recommendation": self.recommendation,
            "cwe_id": self.cwe_id,
        }


@dataclass
class ServiceDependencies:
    """Optional service dependencies for API documentation service."""

    cache_service: CacheServiceProtocol | None = None
    metrics_service: MetricsServiceProtocol | None = None
    logger: LoggerProtocol | None = None


@dataclass
class CoreServices:
    """Core services for API documentation generation."""

    validation_service: "ValidationService"
    metrics_calculator: "MetricsCalculatorService"
    security_analyzer: "SecurityAnalyzerService"
    output_formatter: "OutputFormatterService"


# =====================================================================================
# SERVICE IMPLEMENTATIONS
# =====================================================================================


class ValidationService:
    """Service for API documentation validation."""

    def __init__(self, config: APIDocumentationConfig, logger: LoggerProtocol):
        """
        Initialize validation service.

        Args:
            config: API documentation configuration
            logger: Logger instance
        """
        self.config = config
        self.logger = logger
        self._validation_rules = self._build_validation_rules()
        
        # Add fallback config properties if missing
        if not hasattr(self.config, 'validation'):
            from types import SimpleNamespace
            self.config.validation = SimpleNamespace(
                required_fields=['summary', 'description'],
                max_path_length=100,
                min_path_length=1,
                max_description_length=1000,
                min_description_length=10,
                required_response_codes=['200', '400', '500'],
                max_parameters_per_endpoint=20,
                examples_required=True,
                require_parameter_descriptions=True,
                security_schemes_required=True
            )

    def _build_validation_rules(self) -> dict[str, Any]:
        """Build validation rules from configuration."""
        return {
            "required_fields": set(self.config.validation.required_fields),
            "max_path_length": self.config.validation.max_path_length,
            "min_path_length": self.config.validation.min_path_length,
            "max_description_length": self.config.validation.max_description_length,
            "min_description_length": self.config.validation.min_description_length,
            "required_response_codes": set(
                self.config.validation.required_response_codes
            ),
            "max_parameters": self.config.validation.max_parameters_per_endpoint,
        }

    def validate_openapi_spec(
        self, openapi_spec: dict[str, Any]
    ) -> list[ValidationIssue]:
        """
        Validate OpenAPI specification.

        Args:
            openapi_spec: OpenAPI specification dictionary

        Returns:
            list[ValidationIssue]: List of validation issues
        """
        issues = []

        # Validate basic structure
        issues.extend(self._validate_basic_structure(openapi_spec))

        # Validate paths and operations
        issues.extend(self._validate_paths(openapi_spec.get("paths", {})))

        # Validate schemas
        issues.extend(
            self._validate_schemas(
                openapi_spec.get("components", {}).get("schemas", {})
            )
        )

        # Validate security schemes
        issues.extend(self._validate_security_schemes(openapi_spec))

        # Validate examples
        if self.config.validation.examples_required:
            issues.extend(self._validate_examples(openapi_spec))

        self.logger.info(f"Validation completed with {len(issues)} issues found")
        return issues

    def _validate_basic_structure(self, spec: dict[str, Any]) -> list[ValidationIssue]:
        """Validate basic OpenAPI structure."""
        issues = []

        # Check required top-level fields
        required_fields = ["openapi", "info", "paths"]
        for field in required_fields:
            if field not in spec:
                issues.append(
                    ValidationIssue(
                        type="structure",
                        severity=ValidationSeverity.ERROR,
                        message=f"Missing required field: {field}",
                        location="root",
                        rule_id="STRUCT_001",
                    )
                )

        # Validate info object
        info = spec.get("info", {})
        if "title" not in info:
            issues.append(
                ValidationIssue(
                    type="structure",
                    severity=ValidationSeverity.ERROR,
                    message="Missing title in info object",
                    location="info",
                    rule_id="STRUCT_002",
                )
            )

        if "version" not in info:
            issues.append(
                ValidationIssue(
                    type="structure",
                    severity=ValidationSeverity.ERROR,
                    message="Missing version in info object",
                    location="info",
                    rule_id="STRUCT_003",
                )
            )

        return issues

    def _validate_paths(self, paths: dict[str, Any]) -> list[ValidationIssue]:
        """Validate API paths and operations."""
        issues = []

        for path, path_item in paths.items():
            # Validate path format
            if len(path) > self._validation_rules["max_path_length"]:
                issues.append(
                    ValidationIssue(
                        type="path_format",
                        severity=ValidationSeverity.WARNING,
                        message=f"Path length ({len(path)}) exceeds maximum ({self._validation_rules['max_path_length']})",
                        location=path,
                        rule_id="PATH_001",
                    )
                )

            # Validate path structure
            try:
                URLValidator(f"https://example.com{path}")
            except ValidationError:
                issues.append(
                    ValidationIssue(
                        type="path_format",
                        severity=ValidationSeverity.ERROR,
                        message="Invalid path format",
                        location=path,
                        suggestion="Ensure path follows URL path conventions",
                        rule_id="PATH_002",
                    )
                )

            # Validate operations
            for method, operation in path_item.items():
                if method.lower() in [
                    "get",
                    "post",
                    "put",
                    "delete",
                    "patch",
                    "options",
                    "head",
                ]:
                    issues.extend(
                        self._validate_operation(f"{method.upper()} {path}", operation)
                    )

        return issues

    def _validate_operation(
        self, endpoint: str, operation: dict[str, Any]
    ) -> list[ValidationIssue]:
        """Validate individual operation."""
        issues = []

        # Check required fields
        for field in self._validation_rules["required_fields"]:
            if field not in operation:
                issues.append(
                    ValidationIssue(
                        type="documentation_quality",
                        severity=ValidationSeverity.WARNING,
                        message=f"Missing {field} for {endpoint}",
                        location=endpoint,
                        suggestion=f"Add a clear {field} to improve documentation quality",
                        rule_id="DOC_001",
                    )
                )

        # Validate description length
        description = operation.get("description", "")
        if description:
            if len(description) > self._validation_rules["max_description_length"]:
                issues.append(
                    ValidationIssue(
                        type="documentation_quality",
                        severity=ValidationSeverity.WARNING,
                        message=f"Description too long ({len(description)} characters)",
                        location=endpoint,
                        suggestion="Consider shortening the description or moving details to external docs",
                        rule_id="DOC_002",
                    )
                )
            elif len(description) < self._validation_rules["min_description_length"]:
                issues.append(
                    ValidationIssue(
                        type="documentation_quality",
                        severity=ValidationSeverity.INFO,
                        message="Description is very short",
                        location=endpoint,
                        suggestion="Consider adding more details to help users understand the endpoint",
                        rule_id="DOC_003",
                    )
                )

        # Validate responses
        responses = operation.get("responses", {})
        for required_code in self._validation_rules["required_response_codes"]:
            if required_code not in responses:
                issues.append(
                    ValidationIssue(
                        type="api_design",
                        severity=ValidationSeverity.WARNING,
                        message=f"Missing response for status code {required_code}",
                        location=endpoint,
                        suggestion=f"Add response definition for {required_code} status code",
                        rule_id="RESP_001",
                    )
                )

        # Validate parameters
        parameters = operation.get("parameters", [])
        if len(parameters) > self._validation_rules["max_parameters"]:
            issues.append(
                ValidationIssue(
                    type="api_design",
                    severity=ValidationSeverity.WARNING,
                    message=f"Too many parameters ({len(parameters)})",
                    location=endpoint,
                    suggestion="Consider grouping parameters into request body or reducing complexity",
                    rule_id="PARAM_001",
                )
            )

        # Check parameter descriptions
        if self.config.validation.require_parameter_descriptions:
            for i, param in enumerate(parameters):
                if "description" not in param or not param["description"].strip():
                    issues.append(
                        ValidationIssue(
                            type="documentation_quality",
                            severity=ValidationSeverity.INFO,
                            message=f"Parameter '{param.get('name', f'parameter_{i}')}' missing description",
                            location=endpoint,
                            suggestion="Add descriptions to all parameters",
                            rule_id="PARAM_002",
                        )
                    )

        return issues

    def _validate_schemas(self, schemas: dict[str, Any]) -> list[ValidationIssue]:
        """Validate schema definitions."""
        issues = []

        for schema_name, schema in schemas.items():
            # Check for recursive schemas (basic check)
            max_depth = getattr(self.config, 'performance', None)
            max_depth = getattr(max_depth, 'max_schema_depth', 10) if max_depth else 10
            
            if self._has_deep_recursion(schema, max_depth=max_depth):
                issues.append(
                    ValidationIssue(
                        type="schema_design",
                        severity=ValidationSeverity.WARNING,
                        message=f"Schema '{schema_name}' may have excessive nesting",
                        location=f"schemas.{schema_name}",
                        suggestion="Consider flattening the schema or using references",
                        rule_id="SCHEMA_001",
                    )
                )

            # Check for missing descriptions
            if "description" not in schema and schema.get("type") == "object":
                issues.append(
                    ValidationIssue(
                        type="documentation_quality",
                        severity=ValidationSeverity.INFO,
                        message=f"Schema '{schema_name}' missing description",
                        location=f"schemas.{schema_name}",
                        suggestion="Add description to explain the schema purpose",
                        rule_id="SCHEMA_002",
                    )
                )

        return issues

    def _validate_security_schemes(self, spec: dict[str, Any]) -> list[ValidationIssue]:
        """Validate security schemes."""
        issues = []

        if self.config.validation.security_schemes_required:
            components = spec.get("components", {})
            security_schemes = components.get("securitySchemes", {})

            if not security_schemes:
                issues.append(
                    ValidationIssue(
                        type="security",
                        severity=ValidationSeverity.WARNING,
                        message="No security schemes defined",
                        location="components.securitySchemes",
                        suggestion="Define appropriate security schemes for your API",
                        rule_id="SEC_001",
                    )
                )

            # Check if paths use security
            paths = spec.get("paths", {})
            unprotected_endpoints = []

            for path, path_item in paths.items():
                for method, operation in path_item.items():
                    if (method.lower() in ["get", "post", "put", "delete", "patch"] and
                            "security" not in operation and "security" not in spec):
                        unprotected_endpoints.append(f"{method.upper()} {path}")

            if unprotected_endpoints and len(unprotected_endpoints) > len(paths) * 0.5:
                issues.append(
                    ValidationIssue(
                        type="security",
                        severity=ValidationSeverity.INFO,
                        message=f"Many endpoints ({len(unprotected_endpoints)}) appear unprotected",
                        location="security",
                        suggestion="Consider if all endpoints should require authentication",
                        rule_id="SEC_002",
                    )
                )

        return issues

    def _validate_examples(self, spec: dict[str, Any]) -> list[ValidationIssue]:
        """Validate examples in the specification."""
        issues = []

        def check_examples_in_object(obj: Any, path: str = "") -> None:
            if isinstance(obj, dict):
                for key, value in obj.items():
                    current_path = f"{path}.{key}" if path else key

                    # Check email examples
                    if "email" in key.lower() and isinstance(value, str):
                        if not EmailValidator.validate_format(value):
                            issues.append(
                                ValidationIssue(
                                    type="example_validation",
                                    severity=ValidationSeverity.WARNING,
                                    message=f"Invalid email example at {current_path}: {value}",
                                    location=current_path,
                                    suggestion="Use valid email format in examples",
                                    rule_id="EX_001",
                                )
                            )

                    # Check UUID examples
                    elif "id" in key.lower() and isinstance(value, str):
                        if len(value) == 36 and not UUIDValidator.validate_format(
                            value
                        ):
                            issues.append(
                                ValidationIssue(
                                    type="example_validation",
                                    severity=ValidationSeverity.WARNING,
                                    message=f"Invalid UUID example at {current_path}: {value}",
                                    location=current_path,
                                    suggestion="Use valid UUID format in examples",
                                    rule_id="EX_002",
                                )
                            )

                    # Recurse into nested objects
                    elif isinstance(value, dict | list):
                        check_examples_in_object(value, current_path)

            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    check_examples_in_object(item, f"{path}[{i}]")

        check_examples_in_object(spec)
        return issues

    def _has_deep_recursion(
        self, schema: dict[str, Any], max_depth: int, current_depth: int = 0
    ) -> bool:
        """Check if schema has excessive nesting depth."""
        if current_depth > max_depth:
            return True

        if isinstance(schema, dict):
            if "properties" in schema:
                for prop_schema in schema["properties"].values():
                    if self._has_deep_recursion(
                        prop_schema, max_depth, current_depth + 1
                    ):
                        return True

            if "items" in schema and self._has_deep_recursion(
                schema["items"], max_depth, current_depth + 1
            ):
                return True

        return False


class MetricsCalculatorService:
    """Service for calculating API documentation metrics."""

    def __init__(self, config: APIDocumentationConfig, logger: LoggerProtocol):
        """
        Initialize metrics calculator service.

        Args:
            config: API documentation configuration
            logger: Logger instance
        """
        self.config = config
        self.logger = logger

    def calculate_api_metrics(
        self,
        openapi_spec: dict[str, Any],
        graphql_schema: dict[str, Any] | None = None,
        generation_time: float = 0.0,
    ) -> APIMetrics:
        """
        Calculate comprehensive API metrics.

        Args:
            openapi_spec: OpenAPI specification
            graphql_schema: GraphQL schema information
            generation_time: Time taken to generate documentation

        Returns:
            APIMetrics: Calculated metrics
        """
        start_time = time.time()

        # REST API metrics
        rest_metrics = self._calculate_rest_metrics(openapi_spec)

        # GraphQL metrics
        graphql_metrics = (
            self._calculate_graphql_metrics(graphql_schema) if graphql_schema else {}
        )

        # Schema metrics
        schema_metrics = self._calculate_schema_metrics(
            openapi_spec.get("components", {}).get("schemas", {})
        )

        # Security metrics
        security_metrics = self._calculate_security_metrics(openapi_spec)

        # Combine all metrics
        metrics = APIMetrics(
            # Endpoint metrics
            total_endpoints=rest_metrics["total_endpoints"]
            + graphql_metrics.get("total_endpoints", 0),
            rest_endpoints=rest_metrics["total_endpoints"],
            graphql_endpoints=graphql_metrics.get("total_endpoints", 0),
            deprecated_endpoints=rest_metrics["deprecated_endpoints"],
            # Documentation quality
            documented_endpoints=rest_metrics["documented_endpoints"],
            endpoints_with_examples=rest_metrics["endpoints_with_examples"],
            endpoints_with_security=security_metrics["endpoints_with_auth"],
            average_description_length=rest_metrics["average_description_length"],
            # Schema metrics
            total_schemas=schema_metrics["total_schemas"],
            reused_schemas=schema_metrics["reused_schemas"],
            complex_schemas=schema_metrics["complex_schemas"],
            schema_depth_average=schema_metrics["average_depth"],
            # Security metrics
            endpoints_with_auth=security_metrics["endpoints_with_auth"],
            security_schemes_count=security_metrics["security_schemes_count"],
            public_endpoints=security_metrics["public_endpoints"],
            # Performance
            generation_time_seconds=generation_time,
        )

        calculation_time = time.time() - start_time
        self.logger.debug(f"Metrics calculation completed in {calculation_time:.2f}s")

        return metrics

    def _calculate_rest_metrics(self, openapi_spec: dict[str, Any]) -> dict[str, Any]:
        """Calculate REST API specific metrics."""
        paths = openapi_spec.get("paths", {})

        total_endpoints = 0
        deprecated_endpoints = 0
        documented_endpoints = 0
        endpoints_with_examples = 0
        description_lengths = []

        for _path, path_item in paths.items():
            for method, operation in path_item.items():
                if method.lower() in [
                    "get",
                    "post",
                    "put",
                    "delete",
                    "patch",
                    "options",
                    "head",
                ]:
                    total_endpoints += 1

                    # Check if deprecated
                    if operation.get("deprecated", False):
                        deprecated_endpoints += 1

                    # Check documentation quality
                    if operation.get("summary") or operation.get("description"):
                        documented_endpoints += 1

                    # Check for examples
                    if self._has_examples(operation):
                        endpoints_with_examples += 1

                    # Track description lengths
                    description = operation.get("description", "")
                    if description:
                        description_lengths.append(len(description))

        average_description_length = (
            sum(description_lengths) / len(description_lengths)
            if description_lengths
            else 0
        )

        return {
            "total_endpoints": total_endpoints,
            "deprecated_endpoints": deprecated_endpoints,
            "documented_endpoints": documented_endpoints,
            "endpoints_with_examples": endpoints_with_examples,
            "average_description_length": average_description_length,
        }

    def _calculate_graphql_metrics(
        self, graphql_schema: dict[str, Any]
    ) -> dict[str, Any]:
        """Calculate GraphQL specific metrics."""
        # This would analyze GraphQL schema structure
        # For now, return basic metrics
        types = graphql_schema.get("types", [])
        queries = graphql_schema.get("queries", [])
        mutations = graphql_schema.get("mutations", [])

        return {
            "total_endpoints": len(queries) + len(mutations),
            "types_count": len(types),
            "queries_count": len(queries),
            "mutations_count": len(mutations),
        }

    def _calculate_schema_metrics(self, schemas: dict[str, Any]) -> dict[str, Any]:
        """Calculate schema-related metrics."""
        total_schemas = len(schemas)
        complex_schemas = 0
        depth_values = []
        reference_counts = {}

        for _schema_name, schema in schemas.items():
            # Calculate complexity
            if self._is_complex_schema(schema):
                complex_schemas += 1

            # Calculate depth
            depth = self._calculate_schema_depth(schema)
            depth_values.append(depth)

            # Track references
            refs = self._extract_references(schema)
            for ref in refs:
                reference_counts[ref] = reference_counts.get(ref, 0) + 1

        reused_schemas = sum(1 for count in reference_counts.values() if count > 1)
        average_depth = sum(depth_values) / len(depth_values) if depth_values else 0

        return {
            "total_schemas": total_schemas,
            "complex_schemas": complex_schemas,
            "reused_schemas": reused_schemas,
            "average_depth": average_depth,
        }

    def _calculate_security_metrics(
        self, openapi_spec: dict[str, Any]
    ) -> dict[str, Any]:
        """Calculate security-related metrics."""
        security_schemes = openapi_spec.get("components", {}).get("securitySchemes", {})
        global_security = openapi_spec.get("security", [])

        endpoints_with_auth = 0
        public_endpoints = 0
        total_endpoints = 0

        paths = openapi_spec.get("paths", {})
        for _path, path_item in paths.items():
            for method, operation in path_item.items():
                if method.lower() in ["get", "post", "put", "delete", "patch"]:
                    total_endpoints += 1

                    # Check if endpoint has security
                    operation_security = operation.get("security")
                    if operation_security or global_security:
                        endpoints_with_auth += 1
                    else:
                        public_endpoints += 1

        return {
            "security_schemes_count": len(security_schemes),
            "endpoints_with_auth": endpoints_with_auth,
            "public_endpoints": public_endpoints,
        }

    def _has_examples(self, operation: dict[str, Any]) -> bool:
        """Check if operation has examples."""
        # Check in request body
        request_body = operation.get("requestBody", {})
        if self._has_examples_in_content(request_body.get("content", {})):
            return True

        # Check in responses
        responses = operation.get("responses", {})
        for response in responses.values():
            if self._has_examples_in_content(response.get("content", {})):
                return True

        # Check in parameters
        parameters = operation.get("parameters", [])
        return any("example" in param or "examples" in param for param in parameters)

    def _has_examples_in_content(self, content: dict[str, Any]) -> bool:
        """Check if content has examples."""
        for media_type in content.values():
            if "example" in media_type or "examples" in media_type:
                return True
        return False

    def _is_complex_schema(self, schema: dict[str, Any]) -> bool:
        """Determine if schema is complex."""
        # Consider schema complex if it has many properties or deep nesting
        properties = schema.get("properties", {})
        return len(properties) > 10 or self._calculate_schema_depth(schema) > 3

    def _calculate_schema_depth(
        self, schema: dict[str, Any], current_depth: int = 0
    ) -> int:
        """Calculate maximum depth of schema."""
        if current_depth > 10:  # Prevent infinite recursion
            return current_depth

        max_depth = current_depth

        if isinstance(schema, dict):
            if "properties" in schema:
                for prop_schema in schema["properties"].values():
                    depth = self._calculate_schema_depth(prop_schema, current_depth + 1)
                    max_depth = max(max_depth, depth)

            if "items" in schema:
                depth = self._calculate_schema_depth(schema["items"], current_depth + 1)
                max_depth = max(max_depth, depth)

        return max_depth

    def _extract_references(self, schema: dict[str, Any]) -> list[str]:
        """Extract schema references."""
        refs = []

        def extract_refs(obj: Any) -> None:
            if isinstance(obj, dict):
                if "$ref" in obj:
                    refs.append(obj["$ref"])
                for value in obj.values():
                    extract_refs(value)
            elif isinstance(obj, list):
                for item in obj:
                    extract_refs(item)

        extract_refs(schema)
        return refs


class SecurityAnalyzerService:
    """Service for security analysis of API documentation."""

    def __init__(self, config: APIDocumentationConfig, logger: LoggerProtocol):
        """
        Initialize security analyzer service.

        Args:
            config: API documentation configuration
            logger: Logger instance
        """
        self.config = config
        self.logger = logger

    def analyze_security_vulnerabilities(
        self, openapi_spec: dict[str, Any]
    ) -> list[SecurityFinding]:
        """
        Analyze API specification for security vulnerabilities.

        Args:
            openapi_spec: OpenAPI specification

        Returns:
            list[SecurityFinding]: Security findings
        """
        findings = []

        # Analyze authentication and authorization
        findings.extend(self._analyze_authentication(openapi_spec))

        # Analyze data exposure risks
        findings.extend(self._analyze_data_exposure(openapi_spec))

        # Analyze input validation
        findings.extend(self._analyze_input_validation(openapi_spec))

        # Analyze HTTPS usage
        findings.extend(self._analyze_transport_security(openapi_spec))

        # Analyze sensitive data in examples
        findings.extend(self._analyze_sensitive_examples(openapi_spec))

        self.logger.info(f"Security analysis completed with {len(findings)} findings")
        return findings

    def _analyze_authentication(self, spec: dict[str, Any]) -> list[SecurityFinding]:
        """Analyze authentication and authorization."""
        findings = []

        security_schemes = spec.get("components", {}).get("securitySchemes", {})
        global_security = spec.get("security", [])

        # Check for missing authentication
        if not security_schemes and not global_security:
            findings.append(
                SecurityFinding(
                    finding_type="missing_authentication",
                    severity=ValidationSeverity.WARNING,
                    endpoint="global",
                    description="No authentication schemes defined",
                    recommendation="Implement appropriate authentication mechanisms",
                    cwe_id="CWE-306",
                )
            )

        # Analyze individual endpoints
        paths = spec.get("paths", {})
        for path, path_item in paths.items():
            for method, operation in path_item.items():
                if method.lower() in ["post", "put", "delete", "patch"]:
                    endpoint = f"{method.upper()} {path}"

                    # Check if write operations have security
                    operation_security = operation.get("security")
                    if not operation_security and not global_security:
                        findings.append(
                            SecurityFinding(
                                finding_type="unprotected_write_operation",
                                severity=ValidationSeverity.ERROR,
                                endpoint=endpoint,
                                description="Write operation without authentication",
                                recommendation="Require authentication for data modification operations",
                                cwe_id="CWE-306",
                            )
                        )

        # Check for weak authentication schemes
        for scheme_name, scheme in security_schemes.items():
            if scheme.get("type") == "http" and scheme.get("scheme") == "basic":
                findings.append(
                    SecurityFinding(
                        finding_type="weak_authentication",
                        severity=ValidationSeverity.WARNING,
                        endpoint=f"securitySchemes.{scheme_name}",
                        description="Basic authentication scheme detected",
                        recommendation="Consider using more secure authentication methods like OAuth 2.0 or JWT",
                        cwe_id="CWE-522",
                    )
                )

        return findings

    def _analyze_data_exposure(self, spec: dict[str, Any]) -> list[SecurityFinding]:
        """Analyze potential data exposure risks."""
        findings = []

        # Check schemas for sensitive data
        schemas = spec.get("components", {}).get("schemas", {})
        sensitive_patterns = [
            "password",
            "secret",
            "token",
            "key",
            "credential",
            "ssn",
            "social_security",
            "credit_card",
            "cvv",
            "pin",
        ]

        for schema_name, schema in schemas.items():
            properties = schema.get("properties", {})
            for prop_name, prop_schema in properties.items():
                if (any(pattern in prop_name.lower() for pattern in sensitive_patterns) and
                        not prop_schema.get("writeOnly", False)):
                    findings.append(
                        SecurityFinding(
                            finding_type="sensitive_data_exposure",
                            severity=ValidationSeverity.WARNING,
                            endpoint=f"schemas.{schema_name}.{prop_name}",
                            description=f"Potentially sensitive field '{prop_name}' may be exposed in responses",
                            recommendation="Mark sensitive fields as writeOnly or exclude from responses",
                            cwe_id="CWE-200",
                        )
                    )

        return findings

    def _analyze_input_validation(self, spec: dict[str, Any]) -> list[SecurityFinding]:
        """Analyze input validation."""
        findings = []

        paths = spec.get("paths", {})
        for path, path_item in paths.items():
            for method, operation in path_item.items():
                if method.lower() in ["post", "put", "patch"]:
                    endpoint = f"{method.upper()} {path}"

                    # Check request body validation
                    request_body = operation.get("requestBody", {})
                    if request_body:
                        content = request_body.get("content", {})
                        for _media_type, media_schema in content.items():
                            schema = media_schema.get("schema", {})
                            if not self._has_validation_constraints(schema):
                                findings.append(
                                    SecurityFinding(
                                        finding_type="insufficient_input_validation",
                                        severity=ValidationSeverity.INFO,
                                        endpoint=endpoint,
                                        description="Request body schema lacks validation constraints",
                                        recommendation="Add validation constraints (minLength, maxLength, pattern, etc.)",
                                        cwe_id="CWE-20",
                                    )
                                )

                    # Check parameters validation
                    parameters = operation.get("parameters", [])
                    for param in parameters:
                        if (param.get("in") == "query" and 
                                not self._has_validation_constraints(param.get("schema", {}))):
                            findings.append(
                                SecurityFinding(
                                    finding_type="insufficient_parameter_validation",
                                    severity=ValidationSeverity.INFO,
                                    endpoint=endpoint,
                                    description=f"Query parameter '{param.get('name')}' lacks validation",
                                    recommendation="Add validation constraints to prevent injection attacks",
                                    cwe_id="CWE-20",
                                )
                            )

        return findings

    def _analyze_transport_security(
        self, spec: dict[str, Any]
    ) -> list[SecurityFinding]:
        """Analyze transport security."""
        findings = []

        servers = spec.get("servers", [])
        for server in servers:
            url = server.get("url", "")
            if url.startswith("http://"):
                findings.append(
                    SecurityFinding(
                        finding_type="insecure_transport",
                        severity=ValidationSeverity.ERROR,
                        endpoint=f"server: {url}",
                        description="Server URL uses insecure HTTP protocol",
                        recommendation="Use HTTPS for all API communications",
                        cwe_id="CWE-319",
                    )
                )

        return findings

    def _analyze_sensitive_examples(
        self, spec: dict[str, Any]
    ) -> list[SecurityFinding]:
        """Analyze examples for sensitive data."""
        findings = []

        def check_examples(obj: Any, path: str = "") -> None:
            if isinstance(obj, dict):
                for key, value in obj.items():
                    current_path = f"{path}.{key}" if path else key

                    # Check for sensitive data in examples
                    if isinstance(value, str) and any(
                        pattern in key.lower()
                        for pattern in self.config.security.sensitive_field_patterns
                    ):
                        if not self._is_masked_value(value):
                            findings.append(
                                SecurityFinding(
                                    finding_type="sensitive_data_in_examples",
                                    severity=ValidationSeverity.WARNING,
                                    endpoint=current_path,
                                    description=f"Potentially sensitive data in example: {key}",
                                    recommendation="Use placeholder or masked values in examples",
                                    cwe_id="CWE-200",
                                )
                            )

                    elif isinstance(value, dict | list):
                        check_examples(value, current_path)

            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    check_examples(item, f"{path}[{i}]")

        check_examples(spec)
        return findings

    def _has_validation_constraints(self, schema: dict[str, Any]) -> bool:
        """Check if schema has validation constraints."""
        validation_keywords = [
            "minLength",
            "maxLength",
            "pattern",
            "minimum",
            "maximum",
            "minItems",
            "maxItems",
            "enum",
            "format",
        ]
        return any(keyword in schema for keyword in validation_keywords)

    def _is_masked_value(self, value: str) -> bool:
        """Check if value appears to be masked/placeholder."""
        masked_indicators = [
            "***",
            "...",
            "xxx",
            "[masked]",
            "[redacted]",
            "placeholder",
        ]
        return any(indicator in value.lower() for indicator in masked_indicators)


class OutputFormatterService:
    """Service for formatting and outputting API documentation."""

    def __init__(self, config: APIDocumentationConfig, logger: LoggerProtocol):
        """
        Initialize output formatter service.

        Args:
            config: API documentation configuration
            logger: Logger instance
        """
        self.config = config
        self.logger = logger

    def format_and_save(
        self,
        openapi_spec: dict[str, Any],
        formats: list[APIDocumentationFormat] | None = None,
    ) -> dict[APIDocumentationFormat, Path]:
        """
        Format and save API documentation in specified formats.

        Args:
            openapi_spec: OpenAPI specification
            formats: Output formats (uses config default if not specified)

        Returns:
            dict[APIDocumentationFormat, Path]: Mapping of format to output file path
        """
        if formats is None:
            formats = self.config.output.default_formats

        output_files = {}
        output_dir = Path(self.config.output.output_directory)

        # Create output directory
        output_dir.mkdir(parents=True, exist_ok=True)

        for format_type in formats:
            try:
                filename = self.config.output.filename_template.format(
                    format=format_type.value
                )
                output_path = output_dir / filename

                # Create backup if needed
                if (
                    output_path.exists()
                    and self.config.output.create_backup_before_overwrite
                ):
                    backup_path = output_path.with_suffix(
                        f".backup.{format_type.value}"
                    )
                    backup_path.write_bytes(output_path.read_bytes())

                # Format and write content
                formatted_content = self._format_content(openapi_spec, format_type)

                if format_type in [
                    APIDocumentationFormat.JSON,
                    APIDocumentationFormat.YAML,
                ]:
                    output_path.write_text(formatted_content, encoding="utf-8")
                else:
                    output_path.write_text(formatted_content, encoding="utf-8")

                # Set file permissions
                output_path.chmod(self.config.output.file_permissions)

                output_files[format_type] = output_path
                self.logger.info(
                    f"Generated {format_type.value} documentation: {output_path}"
                )

            except Exception:
                self.logger.exception(
                    f"Failed to generate {format_type.value} output"
                )
                raise

        # Generate index file if configured
        if self.config.output.generate_index_file:
            self._generate_index_file(output_dir, output_files)

        return output_files

    def _format_content(
        self, spec: dict[str, Any], format_type: APIDocumentationFormat
    ) -> str:
        """Format content according to specified format."""
        if format_type == APIDocumentationFormat.JSON:
            if self.config.generation.minify_output:
                return json.dumps(spec, separators=(",", ":"))
            return json.dumps(spec, indent=2, ensure_ascii=False)

        if format_type == APIDocumentationFormat.YAML:
            return yaml.dump(
                spec, default_flow_style=False, allow_unicode=True, sort_keys=False
            )

        if format_type == APIDocumentationFormat.MARKDOWN:
            return self._generate_markdown_docs(spec)

        if format_type == APIDocumentationFormat.HTML:
            return self._generate_html_docs(spec)

        raise ValueError(f"Unsupported format: {format_type}")

    def _generate_markdown_docs(self, spec: dict[str, Any]) -> str:
        """Generate Markdown documentation."""
        lines = []

        # Title and info
        info = spec.get("info", {})
        lines.append(f"# {info.get('title', 'API Documentation')}")
        lines.append("")

        if description := info.get("description"):
            lines.append(description)
            lines.append("")

        if version := info.get("version"):
            lines.append(f"**Version:** {version}")
            lines.append("")

        # Table of contents
        lines.append("## Table of Contents")
        lines.append("")

        paths = spec.get("paths", {})
        for path in sorted(paths.keys()):
            lines.append(
                f"- [{path}](#{path.replace('/', '').replace('{', '').replace('}', '')})"
            )
        lines.append("")

        # Endpoints
        lines.append("## Endpoints")
        lines.append("")

        for path, path_item in paths.items():
            lines.append(f"### {path}")
            lines.append("")

            for method, operation in path_item.items():
                if method.lower() in ["get", "post", "put", "delete", "patch"]:
                    lines.append(f"#### {method.upper()}")
                    lines.append("")

                    if summary := operation.get("summary"):
                        lines.append(f"**Summary:** {summary}")
                        lines.append("")

                    if description := operation.get("description"):
                        lines.append(description)
                        lines.append("")

                    # Parameters
                    if parameters := operation.get("parameters"):
                        lines.append("**Parameters:**")
                        lines.append("")
                        for param in parameters:
                            name = param.get("name", "")
                            param_type = param.get("schema", {}).get("type", "string")
                            required = " (required)" if param.get("required") else ""
                            param_desc = param.get("description", "")
                            lines.append(
                                f"- `{name}` ({param_type}){required}: {param_desc}"
                            )
                        lines.append("")

                    # Responses
                    if responses := operation.get("responses"):
                        lines.append("**Responses:**")
                        lines.append("")
                        for status_code, response in responses.items():
                            desc = response.get("description", "")
                            lines.append(f"- `{status_code}`: {desc}")
                        lines.append("")

            lines.append("---")
            lines.append("")

        return "\n".join(lines)

    def _generate_html_docs(self, spec: dict[str, Any]) -> str:
        """Generate HTML documentation."""
        info = spec.get("info", {})
        title = info.get("title", "API Documentation")

        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 2rem; line-height: 1.6; }}
        .endpoint {{ margin: 2rem 0; padding: 1rem; border: 1px solid #ddd; border-radius: 5px; }}
        .method {{ font-weight: bold; text-transform: uppercase; }}
        .get {{ color: #28a745; }}
        .post {{ color: #007bff; }}
        .put {{ color: #ffc107; }}
        .delete {{ color: #dc3545; }}
        .patch {{ color: #6f42c1; }}
        pre {{ background: #f8f9fa; padding: 1rem; border-radius: 3px; overflow-x: auto; }}
        .toc {{ background: #f8f9fa; padding: 1rem; border-radius: 5px; margin: 1rem 0; }}
    </style>
</head>
<body>
    <h1>{title}</h1>
"""

        if description := info.get("description"):
            html += f"<p>{description}</p>"

        if version := info.get("version"):
            html += f"<p><strong>Version:</strong> {version}</p>"

        # Table of contents
        html += '<div class="toc"><h2>Table of Contents</h2><ul>'
        paths = spec.get("paths", {})
        for path in sorted(paths.keys()):
            anchor = path.replace("/", "").replace("{", "").replace("}", "")
            html += f'<li><a href="#{anchor}">{path}</a></li>'
        html += "</ul></div>"

        # Endpoints
        html += "<h2>Endpoints</h2>"

        for path, path_item in paths.items():
            anchor = path.replace("/", "").replace("{", "").replace("}", "")
            html += f'<div class="endpoint" id="{anchor}">'
            html += f"<h3>{path}</h3>"

            for method, operation in path_item.items():
                if method.lower() in ["get", "post", "put", "delete", "patch"]:
                    html += f'<h4><span class="method {method.lower()}">{method.upper()}</span></h4>'

                    if summary := operation.get("summary"):
                        html += f"<p><strong>Summary:</strong> {summary}</p>"

                    if description := operation.get("description"):
                        html += f"<p>{description}</p>"

                    # Parameters
                    if parameters := operation.get("parameters"):
                        html += "<h5>Parameters:</h5><ul>"
                        for param in parameters:
                            name = param.get("name", "")
                            param_type = param.get("schema", {}).get("type", "string")
                            required = " (required)" if param.get("required") else ""
                            param_desc = param.get("description", "")
                            html += f"<li><code>{name}</code> ({param_type}){required}: {param_desc}</li>"
                        html += "</ul>"

                    # Responses
                    if responses := operation.get("responses"):
                        html += "<h5>Responses:</h5><ul>"
                        for status_code, response in responses.items():
                            desc = response.get("description", "")
                            html += f"<li><code>{status_code}</code>: {desc}</li>"
                        html += "</ul>"

            html += "</div>"

        html += """
</body>
</html>
"""
        return html

    def _generate_index_file(
        self, output_dir: Path, output_files: dict[APIDocumentationFormat, Path]
    ) -> None:
        """Generate index file listing all generated formats."""
        index_content = [
            "# API Documentation",
            "",
            "Generated API documentation in multiple formats:",
            "",
        ]

        for format_type, file_path in output_files.items():
            relative_path = file_path.relative_to(output_dir)
            index_content.append(f"- [{format_type.value.upper()}]({relative_path})")

        index_content.extend(
            [
                "",
                f"Generated on: {datetime.now(UTC).isoformat()}",
                f"Generator version: {self.config.generation.generator_version}",
            ]
        )

        index_path = output_dir / "README.md"
        index_path.write_text("\n".join(index_content), encoding="utf-8")


class APIDocumentationService:
    """
    Main API documentation service with comprehensive functionality.

    This service orchestrates all aspects of API documentation generation
    including validation, metrics calculation, security analysis, and output formatting.

    Design Features:
    - Dependency injection for all services
    - Comprehensive caching support
    - Rich metrics and monitoring
    - Security-focused analysis
    - Multiple output formats
    - Performance optimization
    """

    def __init__(
        self,
        fastapi_app: FastAPI,
        graphql_schema: StrawberrySchema | None,
        config: APIDocumentationConfig,
        core_services: CoreServices,
        dependencies: ServiceDependencies | None = None,
    ):
        """
        Initialize API documentation service with injected dependencies.

        Args:
            fastapi_app: FastAPI application instance
            graphql_schema: GraphQL schema (optional)
            config: API documentation configuration
            core_services: Core services (validation, metrics, security, output)
            dependencies: Optional service dependencies (cache, metrics, logger)
        """
        self.fastapi_app = fastapi_app
        self.graphql_schema = graphql_schema
        self.config = config
        
        # Extract core services
        self.validation_service = core_services.validation_service
        self.metrics_calculator = core_services.metrics_calculator
        self.security_analyzer = core_services.security_analyzer
        self.output_formatter = core_services.output_formatter
        
        # Extract dependencies
        deps = dependencies or ServiceDependencies()
        self.cache_service = deps.cache_service
        self.metrics_service = deps.metrics_service
        self.logger = deps.logger

        # Internal state
        self._generation_count = 0
        self._last_generation_time: datetime | None = None

    async def generate_complete_documentation(
        self,
        include_validation: bool = True,
        include_security_analysis: bool | None = None,
        include_metrics: bool = True,
        output_formats: list[APIDocumentationFormat] | None = None,
        use_cache: bool = True,
    ) -> dict[str, Any]:
        """
        Generate complete API documentation with all features.

        Args:
            include_validation: Whether to include validation analysis
            include_security_analysis: Whether to include security analysis
            include_metrics: Whether to include metrics calculation
            output_formats: Output formats to generate
            use_cache: Whether to use caching

        Returns:
            dict[str, Any]: Complete documentation generation result
        """
        start_time = time.time()

        if include_security_analysis is None:
            include_security_analysis = self.config.generation.include_security_analysis

        try:
            # Check cache first
            cache_key = None
            if use_cache and self.cache_service:
                cache_key = self.config.get_cache_key(
                    "complete_docs",
                    str(include_validation),
                    str(include_security_analysis),
                    str(include_metrics),
                    str(
                        sorted(
                            fmt.value
                            for fmt in (
                                output_formats or self.config.output.default_formats
                            )
                        )
                    ),
                )

                cached_result = await self.cache_service.get(cache_key)
                if cached_result:
                    self.logger and self.logger.info("Returning cached documentation")
                    self.metrics_service and self.metrics_service.increment_counter(
                        "api_docs_cache_hit", {"source": "complete_docs"}
                    )
                    return cached_result

            # Generate OpenAPI specification
            openapi_spec = await self._generate_openapi_spec()

            # Initialize result
            result = {
                "openapi_spec": openapi_spec,
                "generation_info": {
                    "generated_at": datetime.now(UTC).isoformat(),
                    "generator_version": self.config.generation.generator_version,
                    "environment": self.config.environment.value,
                    "features_enabled": {
                        "validation": include_validation,
                        "security_analysis": include_security_analysis,
                        "metrics": include_metrics,
                    },
                },
            }

            # Validation analysis
            if include_validation:
                validation_issues = self.validation_service.validate_openapi_spec(
                    openapi_spec
                )
                result["validation"] = {
                    "issues": [issue.to_dict() for issue in validation_issues],
                    "summary": self._summarize_validation_issues(validation_issues),
                }

            # Security analysis
            if include_security_analysis:
                security_findings = (
                    self.security_analyzer.analyze_security_vulnerabilities(
                        openapi_spec
                    )
                )
                result["security"] = {
                    "findings": [finding.to_dict() for finding in security_findings],
                    "summary": self._summarize_security_findings(security_findings),
                }

            # Metrics calculation
            generation_time = time.time() - start_time
            if include_metrics:
                graphql_info = (
                    await self._extract_graphql_info() if self.graphql_schema else None
                )
                metrics = self.metrics_calculator.calculate_api_metrics(
                    openapi_spec, graphql_info, generation_time
                )
                result["metrics"] = metrics.to_dict()

            # Generate output files
            if output_formats:
                output_files = self.output_formatter.format_and_save(
                    openapi_spec, output_formats
                )
                result["output_files"] = {
                    fmt.value: str(path) for fmt, path in output_files.items()
                }

            # Update metrics
            self._generation_count += 1
            self._last_generation_time = datetime.now(UTC)

            if self.metrics_service:
                self.metrics_service.increment_counter("api_docs_generated")
                self.metrics_service.record_histogram(
                    "api_docs_generation_time", generation_time
                )

            # Cache result
            if cache_key and self.cache_service:
                performance_config = getattr(self.config, 'performance', None)
                cache_ttl = getattr(performance_config, 'cache_ttl_seconds', 3600) if performance_config else 3600
                
                await self.cache_service.set(cache_key, result, ttl=cache_ttl)

            self.logger and self.logger.info(
                f"Documentation generation completed in {generation_time:.2f}s"
            )

        except Exception:
            self.logger and self.logger.exception(
                "Documentation generation failed"
            )
            if self.metrics_service:
                self.metrics_service.increment_counter("api_docs_generation_error")
            raise
        else:
            return result

    async def generate_openapi_spec(
        self, include_examples: bool | None = None
    ) -> dict[str, Any]:
        """
        Generate OpenAPI specification only.

        Args:
            include_examples: Whether to include examples

        Returns:
            dict[str, Any]: OpenAPI specification
        """
        if include_examples is None:
            include_examples = self.config.generation.include_examples

        cache_key = None
        if self.cache_service:
            cache_key = self.config.get_cache_key("openapi_spec", str(include_examples))
            cached_spec = await self.cache_service.get(cache_key)
            if cached_spec:
                return cached_spec

        spec = await self._generate_openapi_spec()

        if include_examples:
            spec = self._enhance_with_examples(spec)

        # Add generation metadata
        if self.config.generation.include_generation_timestamp:
            spec.setdefault("x-generation-info", {}).update(
                {
                    "generated_at": datetime.now(UTC).isoformat(),
                    "generator": f"EzzDay API Documentation Generator v{self.config.generation.generator_version}",
                    "environment": self.config.environment.value,
                }
            )

        # Cache the result
        if cache_key and self.cache_service:
            performance_config = getattr(self.config, 'performance', None)
            cache_ttl = getattr(performance_config, 'cache_ttl_seconds', 3600) if performance_config else 3600
            
            await self.cache_service.set(cache_key, spec, ttl=cache_ttl)

        return spec

    async def _generate_openapi_spec(self) -> dict[str, Any]:
        """Generate base OpenAPI specification."""
        # Get OpenAPI spec from FastAPI
        spec = self.fastapi_app.openapi()

        # Apply security filtering if configured
        if self.config.security.exclude_internal_endpoints:
            spec = self._filter_internal_endpoints(spec)

        if self.config.security.exclude_debug_endpoints:
            spec = self._filter_debug_endpoints(spec)

        # Remove unused schemas if configured
        if self.config.generation.remove_unused_schemas:
            spec = self._remove_unused_schemas(spec)

        return spec

    def _enhance_with_examples(self, spec: dict[str, Any]) -> dict[str, Any]:
        """Enhance specification with examples."""
        # This would add realistic examples to the specification
        # Implementation would depend on specific requirements

        if self.config.security.mask_sensitive_examples:
            spec = self._mask_sensitive_examples(spec)

        return spec

    def _filter_internal_endpoints(self, spec: dict[str, Any]) -> dict[str, Any]:
        """Filter out internal endpoints."""
        filtered_paths = {}

        for path, path_item in spec.get("paths", {}).items():
            # Skip internal paths
            if path.startswith(("/internal/", "/_")):
                continue

            filtered_operations = {}
            for method, operation in path_item.items():
                # Skip operations marked as internal
                if operation.get("tags") and "internal" in [
                    tag.lower() for tag in operation["tags"]
                ]:
                    continue

                filtered_operations[method] = operation

            if filtered_operations:
                filtered_paths[path] = filtered_operations

        spec["paths"] = filtered_paths
        return spec

    def _filter_debug_endpoints(self, spec: dict[str, Any]) -> dict[str, Any]:
        """Filter out debug endpoints."""
        filtered_paths = {}

        for path, path_item in spec.get("paths", {}).items():
            # Skip debug paths
            if "/debug" in path or "/test" in path:
                continue

            filtered_operations = {}
            for method, operation in path_item.items():
                # Skip operations marked as debug
                if operation.get("tags") and "debug" in [
                    tag.lower() for tag in operation["tags"]
                ]:
                    continue

                filtered_operations[method] = operation

            if filtered_operations:
                filtered_paths[path] = filtered_operations

        spec["paths"] = filtered_paths
        return spec

    def _remove_unused_schemas(self, spec: dict[str, Any]) -> dict[str, Any]:
        """Remove unused schema definitions."""
        # This would analyze references and remove unused schemas
        # Implementation would require comprehensive reference tracking
        return spec

    def _mask_sensitive_examples(self, spec: dict[str, Any]) -> dict[str, Any]:
        """Mask sensitive data in examples."""

        def mask_examples(obj: Any) -> Any:
            if isinstance(obj, dict):
                masked_obj = {}
                for key, value in obj.items():
                    security_config = getattr(self.config, 'security', None)
                    sensitive_patterns = getattr(security_config, 'sensitive_field_patterns', [
                        'password', 'secret', 'token', 'key', 'credential'
                    ]) if security_config else ['password', 'secret', 'token', 'key', 'credential']
                    
                    if any(pattern in key.lower() for pattern in sensitive_patterns):
                        masked_obj[key] = "***[MASKED]***" if isinstance(value, str) else value
                    else:
                        masked_obj[key] = mask_examples(value)
                return masked_obj
            if isinstance(obj, list):
                return [mask_examples(item) for item in obj]
            return obj

        return mask_examples(spec)

    async def _extract_graphql_info(self) -> dict[str, Any] | None:
        """Extract GraphQL schema information."""
        if not self.graphql_schema:
            return None

        # This would extract information from the GraphQL schema
        # Implementation would depend on the specific GraphQL library
        return {
            "types": [],
            "queries": [],
            "mutations": [],
        }

    def _summarize_validation_issues(
        self, issues: list[ValidationIssue]
    ) -> dict[str, Any]:
        """Summarize validation issues."""
        severity_counts = {}
        type_counts = {}

        for issue in issues:
            severity_counts[issue.severity.value] = (
                severity_counts.get(issue.severity.value, 0) + 1
            )
            type_counts[issue.type] = type_counts.get(issue.type, 0) + 1

        return {
            "total_issues": len(issues),
            "by_severity": severity_counts,
            "by_type": type_counts,
            "has_errors": any(
                issue.severity == ValidationSeverity.ERROR for issue in issues
            ),
            "has_warnings": any(
                issue.severity == ValidationSeverity.WARNING for issue in issues
            ),
        }

    def _summarize_security_findings(
        self, findings: list[SecurityFinding]
    ) -> dict[str, Any]:
        """Summarize security findings."""
        severity_counts = {}
        type_counts = {}

        for finding in findings:
            severity_counts[finding.severity.value] = (
                severity_counts.get(finding.severity.value, 0) + 1
            )
            type_counts[finding.finding_type] = (
                type_counts.get(finding.finding_type, 0) + 1
            )

        return {
            "total_findings": len(findings),
            "by_severity": severity_counts,
            "by_type": type_counts,
            "has_critical": any(
                finding.severity == ValidationSeverity.CRITICAL for finding in findings
            ),
            "has_high": any(
                finding.severity == ValidationSeverity.ERROR for finding in findings
            ),
        }

    def get_service_stats(self) -> dict[str, Any]:
        """Get service statistics."""
        return {
            "generation_count": self._generation_count,
            "last_generation_time": self._last_generation_time.isoformat()
            if self._last_generation_time
            else None,
            "configuration": self.config.to_dict(),
            "features": {
                "cache_enabled": self.cache_service is not None,
                "metrics_enabled": self.metrics_service is not None,
                "graphql_enabled": self.graphql_schema is not None,
            },
        }


__all__ = [
    "APIDocumentationService",
    "APIMetrics",
    # Protocols
    "CacheServiceProtocol",
    # Data models
    "CoreServices",
    "LoggerProtocol",
    "MetricsCalculatorService",
    "MetricsServiceProtocol",
    "OutputFormatterService",
    "SecurityAnalyzerService",
    "SecurityFinding",
    "ServiceDependencies",
    "ValidationIssue",
    # Services
    "ValidationService",
]
