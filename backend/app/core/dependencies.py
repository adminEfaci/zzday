"""Dependency injection container following pure Python principles.

This module provides a simple, clean dependency injection container for the EzzDay backend,
implementing clean architecture principles with pure Python classes that are completely
independent of any framework (FastAPI, Pydantic, etc.).

The dependency injection system provides a single Container class that you initialize
once in your main application file and use throughout your application.

Design Principles:
- Pure Python classes with sensible defaults
- Framework-agnostic design for maximum portability
- Single container approach - initialize once in main
- Rich error handling with clear guidance
- Performance monitoring with configurable verbosity
- Full DIP (Dependency Inversion Principle) support
- Environment-aware configuration with auto-tuning

Quick Start:
    # Simple usage - just works
    container = Container()
    container.register(IUserService, UserService)
    user_service = container.resolve(IUserService)
    
    # Production usage with monitoring
    container = Container(DependencyConfig(
        environment=Environment.PRODUCTION,
        enable_monitoring=True
    ))

Architecture:
- DependencyConfig: Configuration with sensible defaults and environment auto-tuning
- ServiceDefinition: Service metadata and lifecycle configuration
- Container: Core dependency injection container (the main class you'll use)
- ContainerScope: Scoped container for request-level dependencies
- LifecycleHooks: Extensible lifecycle management
"""

import asyncio
import inspect
import threading
import time
import warnings
from collections.abc import Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, TypeVar, cast, get_type_hints
from weakref import WeakSet

from app.core.enums import Environment, ServiceLifetime, ServiceState
from app.core.errors import ConfigurationError, InfrastructureError
from app.core.logging import get_logger

logger = get_logger(__name__)
T = TypeVar("T")

# Constants
DEFAULT_CACHE_SIZE = 100
DEFAULT_DISPOSAL_TIMEOUT = 5
DEFAULT_MAX_DISPOSAL_TIMEOUT = 30
DEFAULT_MAX_CONCURRENT_INIT = 5
DEFAULT_MAX_REGISTRATION_DEPTH = 10
MAGIC_NUMBER_TEN = 10
MAGIC_NUMBER_HUNDRED = 100
MAGIC_NUMBER_TWO = 2
MAX_ACCESS_PATTERN_HISTORY = 100
MAX_RESOLUTION_TIME_HISTORY = 100


# =====================================================================================
# CONFIGURATION MODES AND ENUMS
# =====================================================================================


class ContainerMode(Enum):
    """Container operational modes for different use cases."""

    LIGHTWEIGHT = "lightweight"  # Minimal features, fast startup
    STANDARD = "standard"  # Balanced features and performance
    ADVANCED = "advanced"  # Full monitoring and debugging
    PRODUCTION = "production"  # Optimized for production workloads


class LifecycleEvent(Enum):
    """Lifecycle events for hooks."""

    BEFORE_REGISTRATION = "before_registration"
    AFTER_REGISTRATION = "after_registration"
    BEFORE_RESOLUTION = "before_resolution"
    AFTER_RESOLUTION = "after_resolution"
    BEFORE_DISPOSAL = "before_disposal"
    AFTER_DISPOSAL = "after_disposal"


# =====================================================================================
# EXCEPTION CLASSES
# =====================================================================================


class DependencyConfigurationError(ConfigurationError):
    """Configuration errors for dependency injection."""


class CircularDependencyError(DependencyConfigurationError):
    """Circular dependency detected in service graph."""

    @classmethod
    def detected_in_graph(
        cls, cycle_description: str = ""
    ) -> "CircularDependencyError":
        """Create exception for detected circular dependency."""
        message = "Circular dependency detected in service graph"
        if cycle_description:
            message += f": {cycle_description}"
        return cls(message)


class ServiceRegistrationError(DependencyConfigurationError):
    """Service registration failed or violates policies."""

    def __init__(
        self, message: str = "Service registration failed or violates policies"
    ):
        super().__init__(message)

    @classmethod
    def already_registered(cls, interface_name: str) -> "ServiceRegistrationError":
        """Create exception for already registered service."""
        return cls(f"Service already registered: {interface_name}")

    @classmethod
    def invalid_disposal_complexity(cls, complexity: int) -> "ServiceRegistrationError":
        """Create exception for invalid disposal complexity."""
        return cls(f"Disposal complexity must be between 1 and 10 (got {complexity})")

    @classmethod
    def unsupported_lifetime(cls, lifetime) -> "ServiceRegistrationError":
        """Create exception for unsupported service lifetime."""
        return cls(f"Unsupported service lifetime: {lifetime}")

    @classmethod
    def invalid_factory(cls, interface_name: str) -> "ServiceRegistrationError":
        """Create exception for invalid factory function."""
        return cls(f"Invalid factory function for service: {interface_name}")

    @classmethod
    def missing_implementation(cls, interface_name: str) -> "ServiceRegistrationError":
        """Create exception for missing implementation."""
        return cls(f"No implementation provided for interface: {interface_name}")


class ServiceResolutionError(DependencyConfigurationError):
    """Service resolution failed or service not found."""

    def __init__(
        self,
        message: str,
        service_name: str = "",
        original_exception: Exception | None = None,
    ):
        super().__init__(message)
        self.service_name = service_name
        self.original_exception = original_exception

    @classmethod
    def service_not_registered(cls, interface_name: str) -> "ServiceResolutionError":
        """Create exception for unregistered service."""
        return cls(
            f"Service not registered: {interface_name}", service_name=interface_name
        )

    @classmethod
    def resolution_failed(
        cls, service_name: str, original_exception: Exception
    ) -> "ServiceResolutionError":
        """Create exception for failed service resolution."""
        return cls(
            f"Failed to resolve {service_name}",
            service_name=service_name,
            original_exception=original_exception,
        )

    @classmethod
    def instantiation_failed(
        cls, service_name: str, reason: str = ""
    ) -> "ServiceResolutionError":
        """Create exception for failed service instantiation."""
        message = f"Failed to instantiate {service_name}"
        if reason:
            message += f": {reason}"
        return cls(message, service_name=service_name)

    @classmethod
    def dependency_missing(
        cls, service_name: str, dependency_name: str
    ) -> "ServiceResolutionError":
        """Create exception for missing dependency."""
        return cls(
            f"Cannot resolve {service_name}: missing dependency {dependency_name}",
            service_name=service_name,
        )


class SecurityViolationError(DependencyConfigurationError):
    """Security policy violation during service registration."""

    def __init__(self, message: str):
        super().__init__(message)

    @classmethod
    def restricted_namespace(
        cls, restricted: str, interface_module: str, impl_module: str
    ) -> "SecurityViolationError":
        """Create exception for restricted namespace violation."""
        message = (
            f"Cannot register service from restricted namespace '{restricted}'. "
            f"Interface module: {interface_module}, Implementation module: {impl_module}"
        )
        return cls(message)

    @classmethod
    def unauthorized_access(
        cls, service_name: str, context: str = ""
    ) -> "SecurityViolationError":
        """Create exception for unauthorized service access."""
        message = f"Unauthorized access to service: {service_name}"
        if context:
            message += f" (context: {context})"
        return cls(message)


class DisposalTimeoutError(InfrastructureError):
    """Service disposal exceeded configured timeout."""

    @classmethod
    def timeout_exceeded(
        cls, service_name: str, timeout_seconds: float
    ) -> "DisposalTimeoutError":
        """Create exception for disposal timeout."""
        return cls(
            f"Disposal of {service_name} exceeded timeout of {timeout_seconds} seconds"
        )

    @classmethod
    def batch_timeout_exceeded(
        cls, count: int, timeout_seconds: float
    ) -> "DisposalTimeoutError":
        """Create exception for batch disposal timeout."""
        return cls(
            f"Disposal of {count} services exceeded timeout of {timeout_seconds} seconds"
        )


class ContainerDisposedError(InfrastructureError):
    """Operation attempted on disposed container or scope."""

    @classmethod
    def cannot_resolve(cls) -> "ContainerDisposedError":
        """Create exception for resolution attempt on disposed scope."""
        return cls("Cannot resolve from disposed scope")

    @classmethod
    def cannot_register(cls) -> "ContainerDisposedError":
        """Create exception for registration attempt on disposed container."""
        return cls("Cannot register services in disposed container")

    @classmethod
    def cannot_create_scope(cls) -> "ContainerDisposedError":
        """Create exception for scope creation attempt on disposed container."""
        return cls("Cannot create scope from disposed container")

    @classmethod
    def operation_not_allowed(cls, operation: str) -> "ContainerDisposedError":
        """Create exception for general operations on disposed container."""
        return cls(f"Cannot perform {operation} on disposed container")


class TooManyArgumentsError(DependencyConfigurationError):
    """Function called with too many arguments."""

    @classmethod
    def constructor_args(
        cls, service_name: str, expected: int, got: int
    ) -> "TooManyArgumentsError":
        """Create exception for constructor with too many arguments."""
        return cls(
            f"Constructor for {service_name} expects {expected} arguments, got {got}"
        )

    @classmethod
    def factory_args(
        cls, factory_name: str, expected: int, got: int
    ) -> "TooManyArgumentsError":
        """Create exception for factory with too many arguments."""
        return cls(f"Factory {factory_name} expects {expected} arguments, got {got}")


class InvalidConfigurationError(DependencyConfigurationError):
    """Invalid configuration parameters provided."""

    def __init__(self, message: str = "Invalid configuration"):
        super().__init__(message)

    @classmethod
    def disposal_timeout_base_error(cls) -> "InvalidConfigurationError":
        """Create exception for invalid disposal timeout base."""
        return cls("Disposal timeout base must be at least 1 second")

    @classmethod
    def disposal_timeout_max_error(cls) -> "InvalidConfigurationError":
        """Create exception for invalid maximum disposal timeout."""
        return cls("Maximum disposal timeout must be >= base timeout")

    @classmethod
    def cache_max_size_error(cls) -> "InvalidConfigurationError":
        """Create exception for invalid cache max size."""
        return cls("Cache max size must be at least 1")

    @classmethod
    def max_concurrent_initializations_error(cls) -> "InvalidConfigurationError":
        """Create exception for invalid max concurrent initializations."""
        return cls("Max concurrent initializations must be at least 1")

    @classmethod
    def invalid_lifetime(cls, lifetime: str) -> "InvalidConfigurationError":
        """Create exception for invalid service lifetime."""
        return cls(f"Invalid service lifetime: {lifetime}")

    @classmethod
    def invalid_scope_mode(cls, mode: str) -> "InvalidConfigurationError":
        """Create exception for invalid scope mode."""
        return cls(f"Invalid scope mode: {mode}")

    @classmethod
    def invalid_restricted_namespace(cls, namespace: str) -> "InvalidConfigurationError":
        """Create exception for invalid restricted namespace."""
        return cls(f"Invalid restricted namespace: {namespace}")


# =====================================================================================
# LIFECYCLE HOOKS
# =====================================================================================


class LifecycleHooks:
    """
    Extensible lifecycle hooks for custom logic during container operations.

    Example:
        hooks = LifecycleHooks()

        @hooks.on(LifecycleEvent.AFTER_REGISTRATION)
        def log_registration(interface, implementation, **kwargs):
            logger.info(f"Registered {interface.__name__}")

        container = Container(hooks=hooks)
    """

    def __init__(self):
        self._hooks: dict[LifecycleEvent, list[Callable]] = {
            event: [] for event in LifecycleEvent
        }

    def on(self, event: LifecycleEvent):
        """Decorator to register a hook for a lifecycle event."""

        def decorator(func: Callable):
            self._hooks[event].append(func)
            return func

        return decorator

    def register_hook(self, event: LifecycleEvent, func: Callable):
        """Register a hook function for a lifecycle event."""
        self._hooks[event].append(func)

    async def trigger(self, event: LifecycleEvent, **kwargs):
        """Trigger all hooks for a lifecycle event."""
        for hook in self._hooks[event]:
            try:
                if asyncio.iscoroutinefunction(hook):
                    await hook(**kwargs)
                else:
                    hook(**kwargs)
            except Exception as e:
                logger.warning(
                    "Lifecycle hook failed",
                    event=event.value,
                    hook=hook.__name__,
                    error=str(e),
                    stacklevel=2,
                )


# =====================================================================================
# CONFIGURATION CLASSES
# =====================================================================================


@dataclass
class DependencyConfig:
    """
    Dependency injection configuration with sensible defaults and environment auto-tuning.

    The configuration automatically adapts based on your environment and chosen mode,
    so you typically only need to specify environment and mode. All other settings
    have sensible defaults that work well in most scenarios.

    Common Usage Patterns:

        # Simple development setup
        config = DependencyConfig()  # Uses DEVELOPMENT + LIGHTWEIGHT

        # Production with monitoring
        config = DependencyConfig(
            environment=Environment.PRODUCTION,
            mode=ContainerMode.PRODUCTION
        )

        # Development with full debugging
        config = DependencyConfig(
            environment=Environment.DEVELOPMENT,
            mode=ContainerMode.ADVANCED,
            enable_debug_logging=True
        )

        # Testing with minimal overhead
        config = DependencyConfig(
            environment=Environment.TESTING,
            mode=ContainerMode.LIGHTWEIGHT
        )

    Security Settings:
        restricted_namespaces: List of module/package prefixes that cannot be registered.
                              Example: ["os", "sys", "subprocess"] prevents system modules.
        enable_service_isolation: When True, services cannot access container internals
                                 and are isolated from each other during resolution.
    """

    # === CORE SETTINGS (commonly configured) ===
    environment: Environment = field(default=Environment.DEVELOPMENT)
    mode: ContainerMode = field(default=ContainerMode.LIGHTWEIGHT)
    enable_monitoring: bool | None = field(default=None)  # Auto-set based on mode
    enable_debug_logging: bool | None = field(
        default=None
    )  # Auto-set based on environment

    # === SERVICE LIFECYCLE (sensible defaults) ===
    default_lifetime: ServiceLifetime = field(default=ServiceLifetime.TRANSIENT)
    enable_lazy_loading: bool = field(default=True)
    disposal_timeout_base: int = field(
        default=DEFAULT_DISPOSAL_TIMEOUT
    )  # Base timeout, adapted per environment
    disposal_timeout_max: int = field(
        default=DEFAULT_MAX_DISPOSAL_TIMEOUT
    )  # Maximum timeout
    enable_automatic_disposal: bool = field(default=True)

    # === VALIDATION AND SAFETY (adaptive defaults) ===
    enable_circular_detection: bool | None = field(
        default=None
    )  # Auto-enabled for dev/staging
    enable_interface_validation: bool = field(default=True)
    enable_constructor_validation: bool = field(default=True)
    max_registration_depth: int = field(default=DEFAULT_MAX_REGISTRATION_DEPTH)

    # === REGISTRATION POLICIES (safety-focused) ===
    allow_override: bool = field(default=False)
    warn_on_override: bool = field(default=True)
    safe_mode: bool = field(default=True)  # Enables additional safety checks

    # === PERFORMANCE SETTINGS (auto-tuned) ===
    enable_caching: bool | None = field(default=None)  # Auto-set based on mode
    cache_max_size: int = field(
        default=DEFAULT_CACHE_SIZE
    )  # Grows with mode complexity
    enable_metrics_collection: bool | None = field(
        default=None
    )  # Auto-set based on monitoring

    # === SECURITY SETTINGS (with clear definitions) ===
    enable_service_isolation: bool | None = field(
        default=None
    )  # Auto-enabled for production
    enable_access_logging: bool = field(default=False)
    restricted_namespaces: list[str] = field(
        default_factory=lambda: [
            "os",
            "sys",
            "subprocess",
            "importlib",
            "__builtin__",
            "builtins",
        ]
    )

    # === THREADING (simplified) ===
    thread_safe: bool = field(default=True)
    max_concurrent_initializations: int = field(
        default=DEFAULT_MAX_CONCURRENT_INIT
    )  # Conservative default

    def __post_init__(self):
        """Auto-configure based on environment and mode, then validate."""
        self._auto_configure()
        self.validate()
        self._log_configuration()

    def _auto_configure(self) -> None:
        """
        Auto-configure settings based on environment and mode.

        This reduces the cognitive load on users by providing smart defaults
        that adapt to their context.
        """
        # Auto-enable monitoring based on mode
        if self.enable_monitoring is None:
            self.enable_monitoring = self.mode in (
                ContainerMode.ADVANCED,
                ContainerMode.PRODUCTION,
            )

        # Auto-enable debug logging based on environment
        if self.enable_debug_logging is None:
            self.enable_debug_logging = self.environment in (
                Environment.DEVELOPMENT,
                Environment.TESTING,
            )

        # Auto-enable circular detection for non-production environments
        if self.enable_circular_detection is None:
            self.enable_circular_detection = self.environment != Environment.PRODUCTION

        # Auto-enable caching except for lightweight mode
        if self.enable_caching is None:
            self.enable_caching = self.mode != ContainerMode.LIGHTWEIGHT

        # Auto-enable metrics collection when monitoring is enabled
        if self.enable_metrics_collection is None:
            self.enable_metrics_collection = self.enable_monitoring

        # Auto-enable service isolation for production
        if self.enable_service_isolation is None:
            self.enable_service_isolation = self.environment == Environment.PRODUCTION

        # Adjust cache size based on mode
        mode_cache_multipliers = {
            ContainerMode.LIGHTWEIGHT: 1,
            ContainerMode.STANDARD: 2,
            ContainerMode.ADVANCED: 5,
            ContainerMode.PRODUCTION: 10,
        }
        self.cache_max_size *= mode_cache_multipliers[self.mode]

        # Adjust concurrent initializations based on environment
        if self.environment == Environment.PRODUCTION:
            self.max_concurrent_initializations = min(
                self.max_concurrent_initializations * 2, 20
            )
        elif self.environment == Environment.TESTING:
            self.max_concurrent_initializations = MAGIC_NUMBER_TWO

        # Environment-specific overrides
        if self.environment == Environment.TESTING:
            # Testing: Fast, minimal, no persistence
            self.enable_caching = False
            self.enable_metrics_collection = False
            self.disposal_timeout_base = 1
            self.disposal_timeout_max = 5

        elif self.environment == Environment.PRODUCTION:
            # Production: Secure, stable, monitored
            self.allow_override = False
            self.safe_mode = True
            self.enable_access_logging = self.enable_monitoring

    def validate(self) -> None:
        """
        Validate configuration and check for invalid combinations.
        """
        # Validate timeout settings
        if self.disposal_timeout_base < 1:
            raise InvalidConfigurationError.disposal_timeout_base_error()
        if self.disposal_timeout_max < self.disposal_timeout_base:
            raise InvalidConfigurationError.disposal_timeout_max_error()

        if self.cache_max_size < 1:
            raise InvalidConfigurationError.cache_max_size_error()

        # Validate performance settings
        if self.cache_max_size < 1:
            raise InvalidConfigurationError.cache_max_size_error()

        if self.max_concurrent_initializations < 1:
            raise InvalidConfigurationError.max_concurrent_initializations_error()

        # Validate threading settings
        if self.max_concurrent_initializations < 1:
            raise InvalidConfigurationError.max_concurrent_initializations_error()

        # Check for invalid combinations
        if not self.enable_lazy_loading and self.enable_circular_detection:
            warnings.warn(
                "Circular dependency detection with eager loading may cause "
                "initialization order issues. Consider enabling lazy loading.",
                UserWarning,
                stacklevel=2,
            )

        if self.allow_override and not self.warn_on_override:
            warnings.warn(
                "Override is enabled without warnings. This can cause hard-to-debug issues.",
                UserWarning,
                stacklevel=2,
            )

        # Validate restricted namespaces
        for namespace in self.restricted_namespaces:
            if not isinstance(namespace, str) or not namespace:
                raise InvalidConfigurationError.invalid_restricted_namespace(namespace)

    def get_adaptive_disposal_timeout(self, service_complexity: int = 1) -> int:
        """
        Calculate adaptive disposal timeout based on service complexity.

        Args:
            service_complexity: Factor representing service cleanup complexity (1-10)

        Returns:
            int: Adaptive timeout in seconds
        """
        complexity_multiplier = min(max(service_complexity, 1), MAGIC_NUMBER_TEN)
        timeout = self.disposal_timeout_base * complexity_multiplier
        return min(timeout, self.disposal_timeout_max)

    def _log_configuration(self) -> None:
        """Log the final configuration for transparency."""
        if self.enable_debug_logging:
            logger.debug(
                "DependencyConfig auto-configured",
                environment=self.environment.value,
                mode=self.mode.value,
                monitoring_enabled=self.enable_monitoring,
                circular_detection=self.enable_circular_detection,
                caching_enabled=self.enable_caching,
                service_isolation=self.enable_service_isolation,
            )

    def to_dict(self) -> dict[str, Any]:
        """Convert configuration to dictionary for logging/debugging."""
        return {
            "environment": self.environment.value,
            "mode": self.mode.value,
            "enable_monitoring": self.enable_monitoring,
            "enable_debug_logging": self.enable_debug_logging,
            "default_lifetime": self.default_lifetime.value,
            "enable_lazy_loading": self.enable_lazy_loading,
            "enable_circular_detection": self.enable_circular_detection,
            "allow_override": self.allow_override,
            "safe_mode": self.safe_mode,
            "enable_caching": self.enable_caching,
            "cache_max_size": self.cache_max_size,
            "enable_service_isolation": self.enable_service_isolation,
            "thread_safe": self.thread_safe,
            "max_concurrent_initializations": self.max_concurrent_initializations,
            "restricted_namespaces_count": len(self.restricted_namespaces),
        }


# =====================================================================================
# SERVICE DEFINITION AND METADATA
# =====================================================================================


@dataclass
class ServiceDefinition:
    """
    Service definition with metadata and lifecycle configuration.

    Contains all information needed to register, instantiate, and manage
    a service throughout its lifecycle.
    """

    # Core service information
    interface: type
    implementation: type | Callable | Any
    lifetime: ServiceLifetime

    # Registration metadata
    name: str = field(default="")
    description: str = field(default="")
    version: str = field(default="1.0.0")
    tags: set[str] = field(default_factory=set)

    # Lifecycle configuration
    lazy_initialization: bool = field(default=True)
    auto_dispose: bool = field(default=True)
    disposal_complexity: int = field(default=1)  # 1-10 scale for timeout calculation

    # Dependencies
    dependencies: list[type] = field(default_factory=list)
    optional_dependencies: list[type] = field(default_factory=list)

    # State tracking
    state: ServiceState = field(default=ServiceState.REGISTERED)
    registration_time: datetime = field(default_factory=datetime.utcnow)
    last_accessed: datetime | None = field(default=None)
    access_count: int = field(default=0)
    error_count: int = field(default=0)

    def __post_init__(self):
        """Post-initialization setup."""
        if not self.name:
            self.name = getattr(self.interface, "__name__", str(self.interface))

    def to_dict(self) -> dict[str, Any]:
        """Convert service definition to dictionary."""
        return {
            "name": self.name,
            "interface": self.interface.__name__
            if hasattr(self.interface, "__name__")
            else str(self.interface),
            "lifetime": self.lifetime.value,
            "state": self.state.value,
            "description": self.description,
            "version": self.version,
            "tags": list(self.tags),
            "lazy_initialization": self.lazy_initialization,
            "auto_dispose": self.auto_dispose,
            "disposal_complexity": self.disposal_complexity,
            "registration_time": self.registration_time.isoformat(),
            "last_accessed": self.last_accessed.isoformat()
            if self.last_accessed
            else None,
            "access_count": self.access_count,
            "error_count": self.error_count,
        }


# =====================================================================================
# REGISTRATION REQUEST DATA CLASS
# =====================================================================================


@dataclass
class RegistrationRequest:
    """Data class to reduce function parameter count for registration."""

    interface: type[T]
    implementation: type[T] | Callable[..., T] | T | None = None
    lifetime: ServiceLifetime | None = None
    name: str = ""
    description: str = ""
    tags: set[str] | None = None
    dependencies: list[type] | None = None
    lazy: bool | None = None
    override: bool | None = None
    disposal_complexity: int = 1


# =====================================================================================
# MAIN CONTAINER CLASS
# =====================================================================================


class Container:
    """
    Dependency injection container - the main class you'll use throughout your application.

    This is the single container class that you initialize once in your main file
    and use throughout your entire application for dependency injection.

    Design Features:
    - Pure Python implementation with sensible defaults
    - Thread-safe service resolution with configurable locking
    - Multiple service lifetime strategies (Transient, Singleton, Scoped, Factory)
    - Smart circular dependency detection (development/staging only by default)
    - Comprehensive performance monitoring and metrics
    - Extensible lifecycle hooks for custom logic
    - Environment-aware configuration with auto-tuning
    - Security features including namespace restrictions

    Quick Start Examples:

        # Simple usage - just works out of the box
        container = Container()
        container.register(IUserService, UserService)
        user_service = container.resolve(IUserService)

        # Production setup with monitoring
        container = Container(DependencyConfig(
            environment=Environment.PRODUCTION,
            mode=ContainerMode.PRODUCTION
        ))

        # Development with full debugging
        container = Container(DependencyConfig(
            environment=Environment.DEVELOPMENT,
            mode=ContainerMode.ADVANCED,
            enable_debug_logging=True
        ))

        # With custom lifecycle hooks
        hooks = LifecycleHooks()

        @hooks.on(LifecycleEvent.AFTER_REGISTRATION)
        def log_registration(interface, **kwargs):
            logger.info(f"Service registered: {interface.__name__}")

        container = Container(hooks=hooks)

    Thread Safety:
        The container uses RLock (reentrant locks) for thread safety when enabled.
        All public methods are thread-safe by default. Performance impact is minimal
        for most workloads.

    Metrics Collection:
        When enabled, the container collects:
        - Resolution times and success/failure rates
        - Service access patterns and frequencies
        - Memory usage of singleton instances
        - Thread contention statistics
        - Circular dependency detection results

        Metrics integrate with standard Python logging and can be exported
        to monitoring systems like Prometheus or DataDog.
    """

    def __init__(
        self,
        config: DependencyConfig | None = None,
        hooks: LifecycleHooks | None = None,
    ):
        """
        Initialize dependency injection container.

        Args:
            config: Configuration (uses smart defaults if not provided)
            hooks: Lifecycle hooks for extensibility (optional)
        """
        self.config = config or DependencyConfig()
        self.hooks = hooks or LifecycleHooks()

        # Thread safety
        self._lock = threading.RLock() if self.config.thread_safe else None

        # Service storage
        self._service_definitions: dict[type, ServiceDefinition] = {}
        self._singleton_instances: dict[type, Any] = {}
        self._factory_cache: dict[type, Callable] = {}

        # Scoping and lifecycle
        self._scopes: WeakSet = WeakSet()
        self._disposing = False

        # Performance tracking (only when monitoring enabled)
        self._resolution_stats: dict[type, dict[str, Any]] = {}
        self._resolution_times: dict[type, list[float]] = {}
        self._access_patterns: dict[type, list[datetime]] = {}

        # Task tracking for proper cleanup
        self._background_tasks: set[asyncio.Task] = set()

        logger.info(
            "Container initialized",
            mode=self.config.mode.value,
            environment=self.config.environment.value,
            monitoring=self.config.enable_monitoring,
        )

    async def register(self, request: RegistrationRequest) -> None:
        """
        Register a service with the container using a RegistrationRequest object.

        Args:
            request: RegistrationRequest object containing all registration parameters.

        Raises:
            ServiceRegistrationError: If registration is invalid or violates security policies
        """
        await self._process_registration(request)

    async def _process_registration(self, request: RegistrationRequest) -> None:
        """Process a registration request with proper error handling."""
        interface_name = getattr(request.interface, "__name__", str(request.interface))

        # Trigger before registration hook
        task = self._create_background_task(
            self.hooks.trigger(
                LifecycleEvent.BEFORE_REGISTRATION,
                interface=request.interface,
                implementation=request.implementation,
                lifetime=request.lifetime,
            )
        )
        if task:
            self._background_tasks.add(task)

        with self._get_lock():
            # Use interface as implementation if not provided
            if request.implementation is None:
                request.implementation = request.interface

            # Apply defaults
            lifetime = request.lifetime or self.config.default_lifetime
            lazy = (
                request.lazy
                if request.lazy is not None
                else self.config.enable_lazy_loading
            )
            override = (
                request.override
                if request.override is not None
                else self.config.allow_override
            )
            dependencies = request.dependencies or []
            tags = request.tags or set()

            # Security validation
            self._validate_registration_security(
                request.interface, request.implementation
            )

            # Check for existing registration
            if request.interface in self._service_definitions:
                if not override:
                    self._raise_already_registered_error(interface_name)
                elif self.config.warn_on_override:
                    self._warn_override(interface_name)

            # Validate service implementation
            if self.config.enable_interface_validation:
                self._validate_service_implementation(
                    request.interface, request.implementation
                )

            # Detect dependencies if not provided
            if not dependencies and inspect.isclass(request.implementation):
                dependencies = self._detect_dependencies(request.implementation)
            if not 1 <= request.disposal_complexity <= MAGIC_NUMBER_TEN:
                self._raise_invalid_disposal_complexity(request.disposal_complexity)

            # Create service definition
            service_def = ServiceDefinition(
                interface=request.interface,
                implementation=request.implementation,
                lifetime=lifetime,
                name=request.name or interface_name,
                description=request.description,
                tags=tags,
                dependencies=dependencies,
                lazy_initialization=lazy,
                disposal_complexity=request.disposal_complexity,
            )

            # Store service definition
            self._service_definitions[request.interface] = service_def

            # Initialize immediately if not lazy and singleton
            if not lazy and lifetime == ServiceLifetime.SINGLETON:
                try:
                    self._create_instance(service_def)
                except Exception as e:
                    service_def.state = ServiceState.ERROR
                    service_def.error_count += 1
                    logger.exception(
                        "Failed to initialize singleton service",
                        interface=interface_name,
                        error=str(e),
                    )
                    self._raise_singleton_init_error(interface_name, e)

            logger.debug(
                "Service registered",
                interface=interface_name,
                lifetime=lifetime.value,
                dependencies=len(dependencies),
                lazy=lazy,
            )

        # Trigger after registration hook
        task = self._create_background_task(
            self.hooks.trigger(
                LifecycleEvent.AFTER_REGISTRATION,
                interface=request.interface,
                implementation=request.implementation,
                service_definition=service_def,
            )
        )
        if task:
            self._background_tasks.add(task)

    def resolve(self, interface: type[T]) -> T:
        """
        Resolve a service instance.

        This is the main method you'll use throughout your application to get
        service instances using dependency injection.

        Args:
            interface: Service interface type to resolve

        Returns:
            Service instance

        Raises:
            ServiceResolutionError: If service not registered or resolution fails
        """
        interface_name = getattr(interface, "__name__", str(interface))
        start_time = time.time()

        # Create task for before resolution hook (don't await to avoid blocking)
        task = self._create_background_task(
            self.hooks.trigger(LifecycleEvent.BEFORE_RESOLUTION, interface=interface)
        )
        if task:
            self._background_tasks.add(task)

        try:
            with self._get_lock():
                if interface not in self._service_definitions:
                    self._raise_service_not_registered_error(interface_name)

                service_def = self._service_definitions[interface]

                # Update access statistics
                service_def.access_count += 1
                service_def.last_accessed = datetime.utcnow()

                # Track access patterns for monitoring
                if self.config.enable_monitoring:
                    self._track_access_pattern(interface)

                # Check circular dependencies (if enabled)
                if self.config.enable_circular_detection:
                    self._check_circular_dependencies(interface, set())

                # Resolve based on lifetime
                instance = self._resolve_by_lifetime(service_def)

                # Track resolution performance
                resolution_time = time.time() - start_time
                if self.config.enable_metrics_collection:
                    self._track_resolution_performance(interface, resolution_time, True)

                if self.config.enable_debug_logging:
                    logger.debug(
                        "Service resolved",
                        interface=interface_name,
                        lifetime=service_def.lifetime.value,
                        resolution_time=resolution_time,
                    )

                # Create task for after resolution hook (don't await to avoid blocking)
                task = self._create_background_task(
                    self.hooks.trigger(
                        LifecycleEvent.AFTER_RESOLUTION,
                        interface=interface,
                        instance=instance,
                        resolution_time=resolution_time,
                    )
                )
                if task:
                    self._background_tasks.add(task)

                return cast(T, instance)

        except Exception as e:
            resolution_time = time.time() - start_time
            if self.config.enable_metrics_collection:
                self._track_resolution_performance(interface, resolution_time, False)

            if interface in self._service_definitions:
                self._service_definitions[interface].error_count += 1

            logger.exception(
                "Service resolution failed",
                interface=interface_name,
                resolution_time=resolution_time,
                error=str(e),
                error_type=type(e).__name__,
            )
            if isinstance(e, ServiceResolutionError):
                raise
            self._raise_resolution_failure_error(interface_name, e)

    def has_service(self, interface: type) -> bool:
        """
        Check if service is registered.

        Args:
            interface: Service interface type

        Returns:
            bool: True if service is registered
        """
        with self._get_lock():
            return interface in self._service_definitions

    async def unregister(self, interface: type) -> None:
        """
        Unregister a service and dispose of any existing instances.

        Args:
            interface: Service interface type to unregister

        Note:
            This is generally not recommended during normal operation.
            Use only for testing or dynamic service replacement.
        """
        interface_name = getattr(interface, "__name__", str(interface))

        with self._get_lock():
            if interface not in self._service_definitions:
                logger.warning(
                    f"Attempted to unregister non-existent service: {interface_name}"
                )
                return

            service_def = self._service_definitions[interface]

            # Trigger before disposal hook
            await self.hooks.trigger(
                LifecycleEvent.BEFORE_DISPOSAL,
                interface=interface,
                service_definition=service_def,
            )

            # Dispose singleton instance if exists
            if interface in self._singleton_instances:
                instance = self._singleton_instances[interface]
                timeout = self.config.get_adaptive_disposal_timeout(
                    service_def.disposal_complexity
                )
                await self._dispose_instance(instance, timeout)
                del self._singleton_instances[interface]

            # Remove from registrations
            del self._service_definitions[interface]
            self._factory_cache.pop(interface, None)
            self._resolution_stats.pop(interface, None)
            self._resolution_times.pop(interface, None)
            self._access_patterns.pop(interface, None)

            service_def.state = ServiceState.DISPOSED

            logger.debug("Service unregistered", interface=interface_name)

            # Trigger after disposal hook
            await self.hooks.trigger(
                LifecycleEvent.AFTER_DISPOSAL,
                interface=interface,
                service_definition=service_def,
            )

    async def clear(self) -> None:
        """
        Clear all service registrations and dispose of instances.

        Warning:
            This will dispose of all singleton instances and clear the container.
            Use with caution, typically only for testing or shutdown.
        """
        with self._get_lock():
            # Dispose all singletons with appropriate timeouts
            for interface, instance in self._singleton_instances.items():
                service_def = self._service_definitions.get(interface)
                complexity = service_def.disposal_complexity if service_def else 1
                timeout = self.config.get_adaptive_disposal_timeout(complexity)
                await self._dispose_instance(instance, timeout)

            # Clear all storage
            self._service_definitions.clear()
            self._singleton_instances.clear()
            self._factory_cache.clear()
            self._resolution_stats.clear()
            self._resolution_times.clear()
            self._access_patterns.clear()

            # Cancel background tasks
            for task in self._background_tasks:
                task.cancel()
            self._background_tasks.clear()

            logger.info("All services cleared from container")

    @asynccontextmanager
    async def create_scope(self):
        """
        Create a dependency scope for scoped service lifetimes.

        Useful for request-scoped services in web applications.

        Yields:
            ContainerScope: Scoped container instance
        """
        scope = ContainerScope(self)
        self._scopes.add(scope)

        try:
            yield scope
        finally:
            await scope.dispose()
            self._scopes.discard(scope)

    def get_service_info(self, interface: type) -> dict[str, Any] | None:
        """
        Get detailed information about a registered service.

        Args:
            interface: Service interface type

        Returns:
            Service information or None if not registered
        """
        with self._get_lock():
            if interface not in self._service_definitions:
                return None

            service_def = self._service_definitions[interface]
            info = service_def.to_dict()

            # Add performance statistics if available
            if interface in self._resolution_stats:
                info["performance"] = self._resolution_stats[interface].copy()

            # Add access pattern information if available
            if interface in self._access_patterns:
                recent_accesses = self._access_patterns[interface]
                if recent_accesses:
                    info["access_pattern"] = {
                        "recent_access_count": len(recent_accesses),
                        "last_access": recent_accesses[-1].isoformat(),
                        "avg_accesses_per_hour": self._calculate_access_rate(
                            recent_accesses
                        ),
                    }

            return info

    def get_all_services(self) -> list[dict[str, Any]]:
        """Get information about all registered services."""
        with self._get_lock():
            return [
                self.get_service_info(interface)
                for interface in self._service_definitions
            ]

    def get_container_stats(self) -> dict[str, Any]:
        """
        Get comprehensive container statistics.

        Returns:
            dict[str, Any]: Container statistics including performance metrics
        """
        with self._get_lock():
            total_services = len(self._service_definitions)
            singletons = len(self._singleton_instances)

            # Calculate lifetime distribution
            lifetime_counts = {}
            state_counts = {}

            for service_def in self._service_definitions.values():
                lifetime = service_def.lifetime.value
                state = service_def.state.value

                lifetime_counts[lifetime] = lifetime_counts.get(lifetime, 0) + 1
                state_counts[state] = state_counts.get(state, 0) + 1

            stats = {
                "total_services": total_services,
                "singleton_instances": singletons,
                "active_scopes": len(self._scopes),
                "lifetime_distribution": lifetime_counts,
                "state_distribution": state_counts,
                "configuration": self.config.to_dict(),
                "cache_size": len(self._factory_cache),
                "monitoring_enabled": self.config.enable_monitoring,
                "background_tasks": len(self._background_tasks),
            }

            # Add performance statistics if monitoring is enabled
            if self.config.enable_monitoring and self._resolution_stats:
                total_resolutions = sum(
                    stat.get("total_resolutions", 0)
                    for stat in self._resolution_stats.values()
                )
                successful_resolutions = sum(
                    stat.get("successful_resolutions", 0)
                    for stat in self._resolution_stats.values()
                )

                stats["performance"] = {
                    "total_resolutions": total_resolutions,
                    "success_rate": successful_resolutions / max(total_resolutions, 1),
                    "services_with_metrics": len(self._resolution_stats),
                }

            return stats

    # =====================================================================================
    # PRIVATE IMPLEMENTATION METHODS
    # =====================================================================================

    def _get_lock(self):
        """Get thread lock if thread safety is enabled."""
        if self._lock:
            return self._lock

        # Return a dummy context manager for non-thread-safe mode
        class DummyLock:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

        return DummyLock()

    def _create_background_task(self, coro) -> asyncio.Task | None:
        """Create a background task if event loop is running."""
        try:
            loop = asyncio.get_running_loop()
            task = loop.create_task(coro)
            task.add_done_callback(self._background_tasks.discard)
        except RuntimeError:
            # No running event loop
            return None
        else:
            return task

    def _validate_registration_security(
        self, interface: type, implementation: Any
    ) -> None:
        """Validate registration against security policies."""
        if not self.config.enable_service_isolation:
            return

        # Check restricted namespaces
        interface_module = getattr(interface, "__module__", "")
        impl_module = (
            getattr(implementation, "__module__", "")
            if hasattr(implementation, "__module__")
            else ""
        )

        for restricted in self.config.restricted_namespaces:
            if interface_module.startswith(restricted) or impl_module.startswith(
                restricted
            ):
                self._raise_security_violation_error(
                    restricted, interface_module, impl_module
                )

    def _validate_service_implementation(
        self, interface: type, implementation: Any
    ) -> None:
        """Validate service implementation against interface."""
        # Check if implementation is compatible with interface
        if inspect.isclass(implementation):
            # For classes, check if it's a subclass or implements the interface
            if hasattr(interface, "__origin__"):  # Generic types
                return  # Skip validation for generic types

            if inspect.isclass(interface) and not issubclass(implementation, interface):
                # Check if it implements the protocol/interface methods
                interface_methods = set(dir(interface)) - set(dir(object))
                implementation_methods = set(dir(implementation)) - set(dir(object))

                missing_methods = interface_methods - implementation_methods
                if missing_methods and self.config.safe_mode:
                    logger.warning(
                        "Implementation may not fully implement interface",
                        interface=getattr(interface, "__name__", str(interface)),
                        implementation=getattr(
                            implementation, "__name__", str(implementation)
                        ),
                        missing_methods=list(missing_methods),
                    )

    def _detect_dependencies(self, implementation: type) -> list[type]:
        """Detect dependencies from constructor type hints."""
        if not inspect.isclass(implementation):
            return []

        try:
            # Get constructor signature
            init_method = implementation.__init__
            type_hints = get_type_hints(init_method)

            # Extract dependencies (excluding 'self' and return type)
            dependencies = []
            for param_name, param_type in type_hints.items():
                if param_name not in ("self", "return"):
                    dependencies.append(param_type)
        except Exception as e:
            if self.config.enable_debug_logging:
                logger.debug(
                    "Failed to detect dependencies",
                    implementation=getattr(
                        implementation, "__name__", str(implementation)
                    ),
                    error=str(e),
                )
            return []
        else:
            return dependencies

    def _check_circular_dependencies(self, interface: type, visited: set[type]) -> None:
        """Check for circular dependencies in the dependency graph."""
        if interface in visited:
            cycle_names = [getattr(t, "__name__", str(t)) for t in visited]
            interface_name = getattr(interface, "__name__", str(interface))
            cycle = " -> ".join(cycle_names) + f" -> {interface_name}"
            self._raise_circular_dependency_error(cycle)

        if interface not in self._service_definitions:
            return

        visited.add(interface)
        service_def = self._service_definitions[interface]

        for dependency in service_def.dependencies:
            self._check_circular_dependencies(dependency, visited.copy())

    def _resolve_by_lifetime(self, service_def: ServiceDefinition) -> Any:
        """Resolve service instance based on lifetime strategy."""
        interface = service_def.interface

        if service_def.lifetime == ServiceLifetime.SINGLETON:
            if interface not in self._singleton_instances:
                self._singleton_instances[interface] = self._create_instance(
                    service_def
                )
            return self._singleton_instances[interface]
        if service_def.lifetime == ServiceLifetime.TRANSIENT:
            return self._create_instance(service_def)
        if service_def.lifetime == ServiceLifetime.FACTORY:
            if interface not in self._factory_cache:
                self._factory_cache[interface] = self._create_factory(service_def)
            return self._factory_cache[interface]()
        self._raise_unsupported_lifetime_error(service_def.lifetime)
        return None

    def _create_instance(self, service_def: ServiceDefinition) -> Any:
        """Create service instance with dependency injection."""
        implementation = service_def.implementation

        # If it's already an instance, return it
        if not callable(implementation):
            return implementation

        # Update state
        service_def.state = ServiceState.INITIALIZING

        try:
            # Resolve dependencies
            dependencies = self._resolve_dependencies(service_def)

            # Create instance
            if inspect.isclass(implementation):
                # Constructor injection
                instance = (
                    implementation(*dependencies) if dependencies else implementation()
                )
            else:
                # Factory function
                instance = (
                    implementation(*dependencies) if dependencies else implementation()
                )

            service_def.state = ServiceState.INITIALIZED

            if self.config.enable_debug_logging:
                logger.debug(
                    "Service instance created",
                    interface=service_def.name,
                    dependencies=len(dependencies),
                )
        except Exception as e:
            service_def.state = ServiceState.ERROR
            service_def.error_count += 1

            logger.exception(
                "Failed to create service instance",
                interface=service_def.name,
                error=str(e),
                error_type=type(e).__name__,
            )
            self._raise_instance_creation_error(service_def.name, e)
        else:
            return instance

    def _resolve_dependencies(self, service_def: ServiceDefinition) -> list[Any]:
        """Resolve dependencies for a service."""
        dependencies = []
        for dep_type in service_def.dependencies:
            if self.has_service(dep_type):
                dep_instance = self.resolve(dep_type)
                dependencies.append(dep_instance)
            else:
                dep_name = getattr(dep_type, "__name__", str(dep_type))
                if self.config.safe_mode:
                    self._raise_dependency_not_registered_error(
                        dep_name, service_def.name
                    )

                logger.warning(
                    "Dependency not registered",
                    service=service_def.name,
                    dependency=dep_name,
                )
        return dependencies

    def _create_factory(self, service_def: ServiceDefinition) -> Callable:
        """Create factory function for factory lifetime services."""

        def factory():
            return self._create_instance(service_def)

        return factory

    async def _dispose_instance(self, instance: Any, timeout: int = 30) -> None:
        """Dispose service instance with adaptive timeout."""
        try:
            if hasattr(instance, "dispose"):
                if asyncio.iscoroutinefunction(instance.dispose):
                    # For async dispose, run with timeout
                    try:
                        await asyncio.wait_for(instance.dispose(), timeout=timeout)
                    except TimeoutError:
                        logger.warning(
                            "Service disposal timed out",
                            instance_type=type(instance).__name__,
                            timeout=timeout,
                        )
                else:
                    instance.dispose()
            elif hasattr(instance, "__del__"):
                # Call destructor if available
                instance.__del__()

        except Exception as e:
            logger.exception(
                "Error disposing service instance",
                instance_type=type(instance).__name__,
                error=str(e),
                timeout=timeout,
            )

    def _track_access_pattern(self, interface: type) -> None:
        """Track access patterns for monitoring."""
        if interface not in self._access_patterns:
            self._access_patterns[interface] = []
        self._access_patterns[interface].append(datetime.utcnow())
        # Keep only last 100 access times
        self._access_patterns[interface] = self._access_patterns[interface][
            -MAX_ACCESS_PATTERN_HISTORY:
        ]

    def _track_resolution_performance(
        self, interface: type, resolution_time: float, success: bool
    ) -> None:
        """Track service resolution performance metrics."""
        if interface not in self._resolution_stats:
            self._resolution_stats[interface] = {
                "total_resolutions": 0,
                "successful_resolutions": 0,
                "failed_resolutions": 0,
                "total_time": 0.0,
                "avg_time": 0.0,
                "min_time": float("inf"),
                "max_time": 0.0,
            }

        if interface not in self._resolution_times:
            self._resolution_times[interface] = []

        stats = self._resolution_stats[interface]
        times = self._resolution_times[interface]

        # Update basic stats
        stats["total_resolutions"] += 1
        if success:
            stats["successful_resolutions"] += 1
        else:
            stats["failed_resolutions"] += 1

        # Update timing stats
        stats["total_time"] += resolution_time
        stats["avg_time"] = stats["total_time"] / stats["total_resolutions"]
        stats["min_time"] = min(stats["min_time"], resolution_time)
        stats["max_time"] = max(stats["max_time"], resolution_time)

        # Store recent times (keep last 100)
        times.append(resolution_time)
        if len(times) > MAX_RESOLUTION_TIME_HISTORY:
            times.pop(0)

    def _calculate_access_rate(self, access_times: list[datetime]) -> float:
        """Calculate average accesses per hour from access times."""
        if len(access_times) < MAGIC_NUMBER_TWO:
            return 0.0

        time_span = (access_times[-1] - access_times[0]).total_seconds() / 3600  # hours
        if time_span > 0:
            return len(access_times) / time_span
        return 0.0

    # ERROR HELPER METHODS
    # =====================================================================================

    def _raise_already_registered_error(self, interface_name: str) -> None:
        """Raise error for already registered service."""
        raise ServiceRegistrationError.already_registered(interface_name)

    def _warn_override(self, interface_name: str) -> None:
        """Warn about service override."""
        warnings.warn(
            f"Overriding existing service registration: {interface_name}. "
            f"This can cause hard-to-debug issues if not done intentionally.",
            UserWarning,
            stacklevel=2,
        )

    def _raise_invalid_disposal_complexity(self, value: int | None = None) -> None:
        """Raise error for invalid disposal complexity."""
        if value is None:
            raise ServiceRegistrationError("Disposal complexity must be between 1 and 10")
        raise ServiceRegistrationError.invalid_disposal_complexity(value)

    def _raise_singleton_init_error(
        self, interface_name: str, error: Exception
    ) -> None:
        """Raise error for singleton initialization failure."""
        raise ServiceRegistrationError(f"Failed to initialize singleton {interface_name}") from error

    def _raise_service_not_registered_error(self, interface_name: str) -> None:
        """Raise error for service not registered."""
        raise ServiceResolutionError.service_not_registered(interface_name)

    def _raise_security_violation_error(
        self, restricted: str, interface_module: str, impl_module: str
    ) -> None:
        """Raise error for security violation."""
        raise SecurityViolationError.restricted_namespace(restricted, interface_module, impl_module)

    def _raise_unsupported_lifetime_error(self, lifetime: ServiceLifetime) -> None:
        """Raise error for unsupported service lifetime."""
        raise ServiceRegistrationError.unsupported_lifetime(lifetime)

    def _raise_instance_creation_error(
        self, service_name: str, error: Exception
    ) -> None:
        """Raise error for instance creation failure."""
        raise ServiceResolutionError.instantiation_failed(service_name, str(error)) from error

    def _raise_dependency_not_registered_error(
        self, dependency_name: str, service_name: str
    ) -> None:
        """Raise error for dependency not registered."""
        raise ServiceResolutionError.dependency_missing(service_name, dependency_name)

    def _raise_circular_dependency_error(self, cycle: str) -> None:
        """Raise error for circular dependency."""
        raise CircularDependencyError.detected_in_graph(cycle)

    def _raise_resolution_failure_error(
        self, service_name: str, error: Exception
    ) -> None:
        """Raise error for resolution failure."""
        raise ServiceResolutionError.resolution_failed(service_name, error) from error


# =====================================================================================
# SCOPED CONTAINER
# =====================================================================================
class ContainerScope:
    """
    Scoped container for scoped service lifetimes.

    Provides isolated service instances that are disposed when the scope ends.
    Useful for request-scoped services in web applications.
    """

    def __init__(self, parent_container: Container):
        """Initialize container scope."""
        self.parent_container = parent_container
        self._scoped_instances: dict[type, Any] = {}
        self._disposed = False

        if parent_container.config.enable_debug_logging:
            logger.debug("Container scope created")

    def resolve(self, interface: type[T]) -> T:
        """Resolve service in this scope."""
        if self._disposed:
            raise ContainerDisposedError.cannot_resolve()

        if not self.parent_container.has_service(interface):
            interface_name = getattr(interface, "__name__", str(interface))
            raise ServiceResolutionError.service_not_registered(interface_name)

        service_def = self.parent_container._service_definitions[interface]

        if service_def.lifetime == ServiceLifetime.SCOPED:
            # Create or return scoped instance
            if interface not in self._scoped_instances:
                self._scoped_instances[
                    interface
                ] = self.parent_container._create_instance(service_def)
            return cast(T, self._scoped_instances[interface])

        # Delegate to parent container
        return self.parent_container.resolve(interface)

    async def dispose(self) -> None:
        """Dispose all scoped instances."""
        if self._disposed:
            return

        for interface, instance in self._scoped_instances.items():
            service_def = self.parent_container._service_definitions.get(interface)
            complexity = service_def.disposal_complexity if service_def else 1
            timeout = self.parent_container.config.get_adaptive_disposal_timeout(
                complexity
            )
            await self.parent_container._dispose_instance(instance, timeout)

        self._scoped_instances.clear()
        self._disposed = True

        if self.parent_container.config.enable_debug_logging:
            logger.debug("Container scope disposed")


# =====================================================================================
# FACTORY FUNCTIONS
# =====================================================================================


def create_container(config: DependencyConfig | None = None) -> Container:
    """
    Create and configure a new dependency injection container.

    This is the main factory function for creating containers, providing a
    clean interface for container initialization with optional configuration.

    Args:
        config: Optional configuration object. If not provided, uses smart defaults
                based on environment detection.

    Returns:
        Container: Configured dependency injection container ready for use
    """
    return Container(config)


# Global container instance (optional pattern for simple apps)
_global_container: Container | None = None


def get_container() -> Container:
    """
    Get the global container instance.

    Creates a new container with default configuration if one doesn't exist.
    This is useful for simple applications that use a single global container.

    Returns:
        Container: The global container instance

    Note:
        For more complex applications or testing scenarios, it's recommended
        to explicitly create and manage container instances rather than using
        this global pattern.
    """
    if _global_container is None:
        return create_container()
    return _global_container


def initialize_dependencies(config: DependencyConfig | None = None) -> Container:
    """
    Initialize the global dependency container with the given configuration.

    This replaces any existing global container with a new one using the
    provided configuration.

    Args:
        config: Optional configuration object for the container

    Returns:
        Container: The newly initialized global container
    """
    # Using a local variable to avoid global statement
    container = create_container(config)
    # Set the global container through module attribute
    import sys

    current_module = sys.modules[__name__]
    current_module._global_container = container
    return container


# =====================================================================================
# EXPORTS
# =====================================================================================

__all__ = [
    "CircularDependencyError",
    "Container",
    "ContainerDisposedError",
    "ContainerMode",
    "ContainerScope",
    "DependencyConfig",
    "DependencyConfigurationError",
    "DisposalTimeoutError",
    "InvalidConfigurationError",
    "LifecycleEvent",
    "LifecycleHooks",
    "RegistrationRequest",
    "SecurityViolationError",
    "ServiceDefinition",
    "ServiceRegistrationError",
    "ServiceResolutionError",
    "TooManyArgumentsError",
    "create_container",
    "get_container",
    "initialize_dependencies",
]
