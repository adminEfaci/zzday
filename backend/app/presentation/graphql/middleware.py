"""
GraphQL Middleware for error handling, logging, and request processing.
"""

import logging
import time
from uuid import uuid4

from strawberry import GraphQLError
from strawberry.extensions import Extension
from strawberry.types import ExecutionResult

from .common import ErrorCode
from .complexity import QueryComplexityAnalyzer, QueryDepthAnalyzer
from .rate_limiting import RateLimitExtension

logger = logging.getLogger(__name__)


class RequestLoggingExtension(Extension):
    """Extension for request logging and metrics."""
    
    def __init__(self, log_queries: bool = True, log_variables: bool = False):
        self.log_queries = log_queries
        self.log_variables = log_variables
        self.request_id = None
        self.start_time = None
    
    def on_request_start(self):
        """Called when a GraphQL request starts."""
        self.request_id = str(uuid4())
        self.start_time = time.time()
        
        if self.log_queries:
            logger.info(
                "GraphQL request started",
                extra={
                    "request_id": self.request_id,
                    "operation": self.execution_context.operation_name,
                }
            )
    
    def on_request_end(self, result: ExecutionResult):
        """Called when a GraphQL request ends."""
        duration = time.time() - self.start_time if self.start_time else 0
        
        log_data = {
            "request_id": self.request_id,
            "duration_ms": round(duration * 1000, 2),
            "operation": self.execution_context.operation_name,
            "has_errors": bool(result.errors),
            "error_count": len(result.errors) if result.errors else 0,
        }
        
        if result.errors:
            logger.warning("GraphQL request completed with errors", extra=log_data)
        else:
            logger.info("GraphQL request completed successfully", extra=log_data)
    
    def on_validation_start(self):
        """Called when query validation starts."""
        logger.debug("Query validation started", extra={"request_id": self.request_id})
    
    def on_validation_end(self, errors):
        """Called when query validation ends."""
        if errors:
            logger.warning(
                "Query validation failed",
                extra={
                    "request_id": self.request_id,
                    "validation_errors": len(errors),
                }
            )
    
    def on_execution_start(self):
        """Called when query execution starts."""
        logger.debug("Query execution started", extra={"request_id": self.request_id})
    
    def on_execution_end(self, result: ExecutionResult):
        """Called when query execution ends."""
        logger.debug(
            "Query execution completed",
            extra={
                "request_id": self.request_id,
                "has_errors": bool(result.errors),
            }
        )


class ErrorHandlingExtension(Extension):
    """Extension for standardized error handling."""
    
    def __init__(self, include_stack_trace: bool = False):
        self.include_stack_trace = include_stack_trace
    
    def on_request_end(self, result: ExecutionResult):
        """Process errors and standardize format."""
        if not result.errors:
            return
        
        processed_errors = []
        
        for error in result.errors:
            processed_error = self._process_error(error)
            processed_errors.append(processed_error)
        
        # Replace errors with processed versions
        result.errors = processed_errors
    
    def _process_error(self, error: GraphQLError) -> GraphQLError:
        """Process and standardize a single error."""
        # Extract error code from extensions
        error_code = None
        if hasattr(error, 'extensions') and error.extensions:
            error_code = error.extensions.get('code')
        
        # Categorize error if no code provided
        if not error_code:
            error_code = self._categorize_error(error)
        
        # Create standardized error message
        message = self._create_error_message(error, error_code)
        
        # Build extensions
        extensions = {
            'code': error_code,
            'timestamp': time.time(),
        }
        
        # Add existing extensions
        if hasattr(error, 'extensions') and error.extensions:
            extensions.update(error.extensions)
        
        # Add stack trace if enabled
        if self.include_stack_trace and hasattr(error, 'original_error'):
            extensions['stack_trace'] = str(error.original_error)
        
        return GraphQLError(
            message=message,
            nodes=error.nodes,
            source=error.source,
            positions=error.positions,
            path=error.path,
            original_error=error.original_error,
            extensions=extensions
        )
    
    def _categorize_error(self, error: GraphQLError) -> str:
        """Categorize error based on its type and message."""
        error_str = str(error).lower()
        
        # Authentication/Authorization errors
        if any(keyword in error_str for keyword in ['unauthorized', 'forbidden', 'permission']):
            return ErrorCode.FORBIDDEN.value
        
        if 'authentication' in error_str:
            return ErrorCode.UNAUTHENTICATED.value
        
        # Validation errors
        if any(keyword in error_str for keyword in ['validation', 'invalid', 'required']):
            return ErrorCode.VALIDATION_ERROR.value
        
        # Rate limiting
        if 'rate limit' in error_str:
            return ErrorCode.RATE_LIMITED.value
        
        # Query complexity
        if 'complexity' in error_str or 'too complex' in error_str:
            return ErrorCode.RATE_LIMITED.value
        
        # Not found
        if 'not found' in error_str:
            return ErrorCode.NOT_FOUND.value
        
        # Default to internal error
        return ErrorCode.INTERNAL_ERROR.value
    
    def _create_error_message(self, error: GraphQLError, error_code: str) -> str:
        """Create user-friendly error message."""
        original_message = str(error)
        
        # For internal errors, provide generic message
        if error_code == ErrorCode.INTERNAL_ERROR.value:
            return "An internal error occurred. Please try again later."
        
        # For other errors, use original message
        return original_message


class PerformanceExtension(Extension):
    """Extension for performance monitoring and optimization."""
    
    def __init__(self, 
                 max_complexity: int = 1000,
                 max_depth: int = 10,
                 slow_query_threshold: float = 1.0):
        self.max_complexity = max_complexity
        self.max_depth = max_depth
        self.slow_query_threshold = slow_query_threshold
        self.start_time = None
        self.complexity = None
        self.depth = None
    
    def on_validation_start(self):
        """Validate query complexity and depth."""
        if not self.execution_context.query:
            return
        
        schema = self.execution_context.schema
        document = self.execution_context.document
        variables = self.execution_context.variable_values or {}
        
        # Check complexity
        complexity_analyzer = QueryComplexityAnalyzer(
            schema=schema,
            max_complexity=self.max_complexity
        )
        
        try:
            self.complexity = complexity_analyzer.validate_query(document, variables)
        except Exception as e:
            logger.exception("Query complexity validation failed")
            raise GraphQLError(
                "Query complexity validation failed",
                extensions={"code": ErrorCode.INTERNAL_ERROR.value}
            ) from e
        
        # Check depth
        depth_analyzer = QueryDepthAnalyzer(max_depth=self.max_depth)
        
        try:
            self.depth = depth_analyzer.validate_depth(document, schema)
        except Exception as e:
            logger.exception("Query depth validation failed")
            raise GraphQLError(
                "Query depth validation failed",
                extensions={"code": ErrorCode.INTERNAL_ERROR.value}
            ) from e
    
    def on_execution_start(self):
        """Track execution start time."""
        self.start_time = time.time()
    
    def on_execution_end(self, result: ExecutionResult):
        """Track execution metrics."""
        if not self.start_time:
            return
        
        duration = time.time() - self.start_time
        
        # Log slow queries
        if duration > self.slow_query_threshold:
            logger.warning(
                "Slow GraphQL query detected",
                extra={
                    "duration_ms": round(duration * 1000, 2),
                    "complexity": self.complexity,
                    "depth": self.depth,
                    "operation": self.execution_context.operation_name,
                }
            )
        
        # Add performance metrics to response
        if not result.extensions:
            result.extensions = {}
        
        result.extensions.update({
            "performance": {
                "duration_ms": round(duration * 1000, 2),
                "complexity": self.complexity,
                "depth": self.depth,
            }
        })


class SecurityExtension(Extension):
    """Extension for security monitoring and protection."""
    
    def __init__(self, 
                 log_failed_auth: bool = True,
                 block_introspection: bool = False):
        self.log_failed_auth = log_failed_auth
        self.block_introspection = block_introspection
    
    def on_validation_start(self):
        """Security validation before query execution."""
        # Block introspection queries in production
        if self.block_introspection and self._is_introspection_query():
            raise GraphQLError(
                "Introspection queries are not allowed",
                extensions={"code": ErrorCode.FORBIDDEN.value}
            )
    
    def on_request_end(self, result: ExecutionResult):
        """Log security events."""
        if not result.errors:
            return
        
        for error in result.errors:
            if self._is_auth_error(error) and self.log_failed_auth:
                    logger.warning(
                        "Authentication/Authorization failure",
                        extra={
                            "error_code": error.extensions.get("code"),
                            "error_message": str(error),
                            "operation": self.execution_context.operation_name,
                        }
                    )
    
    def _is_introspection_query(self) -> bool:
        """Check if query is an introspection query."""
        if not self.execution_context.query:
            return False
        
        query_str = self.execution_context.query.lower()
        return '__schema' in query_str or '__type' in query_str
    
    def _is_auth_error(self, error: GraphQLError) -> bool:
        """Check if error is authentication/authorization related."""
        if not hasattr(error, 'extensions') or not error.extensions:
            return False
        
        code = error.extensions.get('code', '')
        return code in [
            ErrorCode.UNAUTHENTICATED.value,
            ErrorCode.FORBIDDEN.value,
            ErrorCode.INVALID_TOKEN.value,
            ErrorCode.TOKEN_EXPIRED.value,
        ]


def create_graphql_extensions(
    environment: str = "development",
    enable_logging: bool = True,
    enable_performance: bool = True,
    enable_security: bool = True,
    enable_rate_limiting: bool = True,
    **kwargs
) -> list[Extension]:
    """
    Create GraphQL extensions based on environment and configuration.
    
    Args:
        environment: Deployment environment (development/production)
        enable_logging: Enable request logging
        enable_performance: Enable performance monitoring
        enable_security: Enable security monitoring
        enable_rate_limiting: Enable rate limiting
        **kwargs: Additional configuration options
    
    Returns:
        List of configured extensions
    """
    extensions = []
    
    # Always include error handling
    extensions.append(ErrorHandlingExtension(
        include_stack_trace=(environment == "development")
    ))
    
    if enable_logging:
        extensions.append(RequestLoggingExtension(
            log_queries=kwargs.get("log_queries", True),
            log_variables=kwargs.get("log_variables", environment == "development")
        ))
    
    if enable_performance:
        extensions.append(PerformanceExtension(
            max_complexity=kwargs.get("max_complexity", 1000),
            max_depth=kwargs.get("max_depth", 10),
            slow_query_threshold=kwargs.get("slow_query_threshold", 1.0)
        ))
    
    if enable_security:
        extensions.append(SecurityExtension(
            log_failed_auth=kwargs.get("log_failed_auth", True),
            block_introspection=kwargs.get("block_introspection", environment == "production")
        ))
    
    if enable_rate_limiting:
        extensions.append(RateLimitExtension(
            rate_limiter=kwargs.get("rate_limiter"),
            global_limit=kwargs.get("global_limit", 1000),
            global_window=kwargs.get("global_window", 60)
        ))
    
    return extensions


__all__ = [
    "ErrorHandlingExtension",
    "PerformanceExtension",
    "RequestLoggingExtension",
    "SecurityExtension",
    "create_graphql_extensions",
]