"""
Base Internal Adapter Interface

This module provides the base interface for internal module communication adapters
following DDD principles. Internal adapters are used for module-to-module communication
without creating direct dependencies between modules.

Key Principles:
- No foreign keys between modules
- Communication only through module contracts
- Async/await for all operations
- Comprehensive error handling
- Performance monitoring
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, TypeVar, Generic
import asyncio
from datetime import datetime
from uuid import UUID

from app.core.errors import InfrastructureError
from app.core.logging import get_logger

logger = get_logger(__name__)

T = TypeVar('T')


class InternalAdapterError(InfrastructureError):
    """Base exception for internal adapter operations."""
    
    default_code = "INTERNAL_ADAPTER_ERROR"
    default_detail = "Internal adapter operation failed"
    status_code = 500
    retryable = True


class ModuleNotAvailableError(InternalAdapterError):
    """Raised when target module is not available."""
    
    default_code = "MODULE_NOT_AVAILABLE"
    default_detail = "Target module is not available"
    status_code = 503
    retryable = True


class ContractViolationError(InternalAdapterError):
    """Raised when module contract is violated."""
    
    default_code = "CONTRACT_VIOLATION"
    default_detail = "Module contract violation"
    status_code = 400
    retryable = False


class BaseInternalAdapter(ABC):
    """
    Base class for internal module communication adapters.
    
    Provides common functionality for module-to-module communication
    including error handling, logging, and performance monitoring.
    """
    
    def __init__(self, module_name: str, target_module: str):
        """
        Initialize internal adapter.
        
        Args:
            module_name: Name of the source module
            target_module: Name of the target module
        """
        self.module_name = module_name
        self.target_module = target_module
        self._is_available = True
        self._last_health_check = None
        self._call_count = 0
        self._error_count = 0
        
        logger.info(
            "Internal adapter initialized",
            source_module=module_name,
            target_module=target_module
        )
    
    @abstractmethod
    async def health_check(self) -> bool:
        """
        Check if target module is healthy and available.
        
        Returns:
            bool: True if module is healthy, False otherwise
        """
        pass
    
    async def _execute_with_resilience(
        self,
        operation: str,
        func: Any,
        *args,
        **kwargs
    ) -> Any:
        """
        Execute operation with resilience patterns.
        
        Includes:
        - Health checking
        - Error handling
        - Performance monitoring
        - Logging
        
        Args:
            operation: Name of the operation
            func: Function to execute
            *args: Positional arguments for function
            **kwargs: Keyword arguments for function
            
        Returns:
            Result from function execution
            
        Raises:
            InternalAdapterError: If operation fails
        """
        start_time = datetime.utcnow()
        self._call_count += 1
        
        try:
            # Check module availability
            if not self._is_available:
                # Try health check if enough time has passed
                if self._should_retry_health_check():
                    self._is_available = await self.health_check()
                
                if not self._is_available:
                    raise ModuleNotAvailableError(
                        f"{self.target_module} module is not available"
                    )
            
            # Execute the operation
            logger.debug(
                "Executing internal adapter operation",
                source_module=self.module_name,
                target_module=self.target_module,
                operation=operation
            )
            
            result = await func(*args, **kwargs)
            
            # Log success
            duration = (datetime.utcnow() - start_time).total_seconds()
            logger.debug(
                "Internal adapter operation completed",
                source_module=self.module_name,
                target_module=self.target_module,
                operation=operation,
                duration_seconds=duration
            )
            
            return result
            
        except Exception as e:
            self._error_count += 1
            duration = (datetime.utcnow() - start_time).total_seconds()
            
            # Log error
            logger.exception(
                "Internal adapter operation failed",
                source_module=self.module_name,
                target_module=self.target_module,
                operation=operation,
                duration_seconds=duration,
                error=str(e)
            )
            
            # Mark module as unavailable if too many errors
            if self._error_count > 5:
                self._is_available = False
                self._last_health_check = datetime.utcnow()
            
            # Re-raise with context
            if isinstance(e, InternalAdapterError):
                raise
            else:
                raise InternalAdapterError(
                    f"Operation '{operation}' failed: {str(e)}"
                ) from e
    
    def _should_retry_health_check(self) -> bool:
        """Check if enough time has passed to retry health check."""
        if self._last_health_check is None:
            return True
        
        # Retry after 30 seconds
        elapsed = (datetime.utcnow() - self._last_health_check).total_seconds()
        return elapsed > 30
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get adapter statistics."""
        return {
            "source_module": self.module_name,
            "target_module": self.target_module,
            "is_available": self._is_available,
            "call_count": self._call_count,
            "error_count": self._error_count,
            "error_rate": self._error_count / max(self._call_count, 1),
            "last_health_check": self._last_health_check.isoformat() 
                if self._last_health_check else None
        }


class AsyncContextAdapter(BaseInternalAdapter):
    """Base adapter with async context management support."""
    
    def __init__(self, module_name: str, target_module: str):
        super().__init__(module_name, target_module)
        self._session = None
    
    async def __aenter__(self):
        """Enter async context."""
        await self._initialize_session()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Exit async context."""
        await self._cleanup_session()
    
    @abstractmethod
    async def _initialize_session(self):
        """Initialize any required session resources."""
        pass
    
    @abstractmethod
    async def _cleanup_session(self):
        """Clean up session resources."""
        pass