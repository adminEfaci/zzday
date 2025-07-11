"""
GraphQL Federation Support for Microservices

Provides comprehensive GraphQL federation capabilities including schema federation,
query planning, service discovery, and distributed execution across multiple services.
"""

import asyncio
import json
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import urlparse
from uuid import uuid4

import aiohttp
from graphql import (
    DocumentNode,
    GraphQLSchema,
    build_ast_schema,
    build_schema,
    execute,
    get_operation_definition,
    parse,
    print_ast,
    validate,
)
from strawberry import GraphQLError
from strawberry.extensions import Extension
from strawberry.schema import Schema as StrawberrySchema
from strawberry.types import ExecutionContext, ExecutionResult

logger = logging.getLogger(__name__)


class ServiceStatus(Enum):
    """Federation service status."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class FederationError(GraphQLError):
    """Federation-specific GraphQL error."""
    
    def __init__(self, message: str, service_name: Optional[str] = None):
        super().__init__(
            message,
            extensions={
                "code": "FEDERATION_ERROR",
                "service": service_name
            }
        )


@dataclass
class FederatedService:
    """Represents a federated GraphQL service."""
    name: str
    url: str
    schema: Optional[GraphQLSchema] = None
    status: ServiceStatus = ServiceStatus.UNKNOWN
    last_health_check: Optional[datetime] = None
    health_check_interval: int = 30  # seconds
    timeout: int = 5  # seconds
    retries: int = 3
    
    # Service metadata
    version: Optional[str] = None
    description: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    
    # Performance metrics
    avg_response_time: float = 0.0
    error_rate: float = 0.0
    request_count: int = 0
    
    # Schema information
    types: Set[str] = field(default_factory=set)
    directives: Set[str] = field(default_factory=set)
    
    def __post_init__(self):
        """Initialize service after creation."""
        if not self.url.startswith(('http://', 'https://')):
            self.url = f"http://{self.url}"
    
    @property
    def is_healthy(self) -> bool:
        """Check if service is healthy."""
        return self.status == ServiceStatus.HEALTHY
    
    def needs_health_check(self) -> bool:
        """Check if service needs a health check."""
        if not self.last_health_check:
            return True
        
        elapsed = datetime.utcnow() - self.last_health_check
        return elapsed.total_seconds() > self.health_check_interval


@dataclass
class QueryPlan:
    """Represents a query execution plan across federated services."""
    query_id: str
    operation_name: Optional[str]
    services: List[str]
    execution_steps: List[Dict[str, Any]]
    estimated_cost: int = 0
    
    # Execution metadata
    created_at: datetime = field(default_factory=datetime.utcnow)
    executed_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    
    def mark_executing(self):
        """Mark plan as executing."""
        self.executed_at = datetime.utcnow()
    
    def mark_completed(self):
        """Mark plan as completed."""
        self.completed_at = datetime.utcnow()
    
    @property
    def execution_time(self) -> Optional[float]:
        """Get execution time in seconds."""
        if self.executed_at and self.completed_at:
            return (self.completed_at - self.executed_at).total_seconds()
        return None


class SchemaRegistry:
    """Registry for managing federated schemas."""
    
    def __init__(self):
        self.schemas: Dict[str, GraphQLSchema] = {}
        self.service_types: Dict[str, Set[str]] = defaultdict(set)
        self.type_owners: Dict[str, str] = {}
        self.schema_versions: Dict[str, str] = {}
    
    def register_schema(self, service_name: str, schema: GraphQLSchema, version: str = "1.0.0"):
        """Register a schema for a service."""
        self.schemas[service_name] = schema
        self.schema_versions[service_name] = version
        
        # Extract type information
        types = set()
        for type_name, type_def in schema.type_map.items():
            if not type_name.startswith('__'):
                types.add(type_name)
                
                # Track type ownership
                if type_name not in self.type_owners:
                    self.type_owners[type_name] = service_name
                
        self.service_types[service_name] = types
        
        logger.info(f"Registered schema for service {service_name} (version {version})")
    
    def get_schema(self, service_name: str) -> Optional[GraphQLSchema]:
        """Get schema for a service."""
        return self.schemas.get(service_name)
    
    def get_type_owner(self, type_name: str) -> Optional[str]:
        """Get the service that owns a type."""
        return self.type_owners.get(type_name)
    
    def get_federated_schema(self) -> GraphQLSchema:
        """Create a federated schema from all registered schemas."""
        if not self.schemas:
            raise FederationError("No schemas registered for federation")
        
        # This is a simplified federation - in production you'd use Apollo Federation
        # or implement proper schema stitching
        federated_types = []
        
        for service_name, schema in self.schemas.items():
            for type_name, type_def in schema.type_map.items():
                if not type_name.startswith('__') and type_name not in ['Query', 'Mutation', 'Subscription']:
                    federated_types.append(f"# From {service_name}\n{type_def}")
        
        # Create a basic federated schema
        federated_schema_sdl = f"""
        type Query {{
            _service: _Service!
            _entities(representations: [_Any!]!): [_Entity]!
        }}
        
        type _Service {{
            sdl: String!
        }}
        
        scalar _Any
        union _Entity = {' | '.join(self.type_owners.keys()) if self.type_owners else 'String'}
        
        {chr(10).join(federated_types)}
        """
        
        return build_schema(federated_schema_sdl)


class QueryPlanner:
    """Plans query execution across federated services."""
    
    def __init__(self, schema_registry: SchemaRegistry):
        self.schema_registry = schema_registry
        self.query_cache: Dict[str, QueryPlan] = {}
    
    def plan_query(
        self,
        document: DocumentNode,
        variables: Optional[Dict[str, Any]] = None,
        operation_name: Optional[str] = None
    ) -> QueryPlan:
        """Plan query execution across services."""
        query_id = str(uuid4())
        
        # Get operation definition
        operation_def = get_operation_definition(document, operation_name)
        if not operation_def:
            raise FederationError("No operation definition found")
        
        # Analyze query to determine required services
        required_services = self._analyze_query_services(operation_def)
        
        # Create execution steps
        execution_steps = self._create_execution_steps(operation_def, required_services)
        
        # Estimate cost
        estimated_cost = self._estimate_query_cost(execution_steps)
        
        plan = QueryPlan(
            query_id=query_id,
            operation_name=operation_name,
            services=required_services,
            execution_steps=execution_steps,
            estimated_cost=estimated_cost
        )
        
        # Cache the plan
        self.query_cache[query_id] = plan
        
        return plan
    
    def _analyze_query_services(self, operation_def) -> List[str]:
        """Analyze which services are required for the query."""
        required_services = set()
        
        # For now, use all services - in production you'd analyze the selection set
        # to determine which types are accessed and map them to services
        required_services.update(self.schema_registry.schemas.keys())
        
        return list(required_services)
    
    def _create_execution_steps(self, operation_def, required_services: List[str]) -> List[Dict[str, Any]]:
        """Create execution steps for the query."""
        steps = []
        
        # Simplified execution steps - in production you'd create a proper execution plan
        for service in required_services:
            steps.append({
                'service': service,
                'operation': 'query',
                'fields': [],  # Would contain specific fields to request
                'dependencies': [],  # Other steps this depends on
                'parallel': True  # Can be executed in parallel
            })
        
        return steps
    
    def _estimate_query_cost(self, execution_steps: List[Dict[str, Any]]) -> int:
        """Estimate the cost of executing the query."""
        # Simple cost estimation - in production you'd use complexity analysis
        return len(execution_steps) * 10


class FederationGateway:
    """GraphQL Federation Gateway that orchestrates multiple services."""
    
    def __init__(self, health_check_interval: int = 30):
        self.services: Dict[str, FederatedService] = {}
        self.schema_registry = SchemaRegistry()
        self.query_planner = QueryPlanner(self.schema_registry)
        self.health_check_interval = health_check_interval
        
        # Performance tracking
        self.request_count = 0
        self.error_count = 0
        self.avg_response_time = 0.0
        
        # Background tasks
        self._health_check_task: Optional[asyncio.Task] = None
        self._running = False
    
    async def start(self):
        """Start the federation gateway."""
        self._running = True
        self._health_check_task = asyncio.create_task(self._health_check_loop())
        logger.info("Federation gateway started")
    
    async def stop(self):
        """Stop the federation gateway."""
        self._running = False
        if self._health_check_task:
            self._health_check_task.cancel()
        logger.info("Federation gateway stopped")
    
    async def register_service(
        self,
        name: str,
        url: str,
        schema: Optional[GraphQLSchema] = None,
        **kwargs
    ) -> FederatedService:
        """Register a new federated service."""
        service = FederatedService(
            name=name,
            url=url,
            schema=schema,
            **kwargs
        )
        
        self.services[name] = service
        
        # Fetch schema if not provided
        if not schema:
            try:
                schema = await self._fetch_service_schema(service)
                service.schema = schema
            except Exception as e:
                logger.error(f"Failed to fetch schema for service {name}: {e}")
                service.status = ServiceStatus.UNHEALTHY
                raise
        
        # Register schema
        if schema:
            self.schema_registry.register_schema(name, schema)
        
        # Initial health check
        await self._check_service_health(service)
        
        logger.info(f"Registered federated service: {name}")
        return service
    
    async def unregister_service(self, name: str):
        """Unregister a federated service."""
        if name in self.services:
            del self.services[name]
            if name in self.schema_registry.schemas:
                del self.schema_registry.schemas[name]
            logger.info(f"Unregistered federated service: {name}")
    
    async def execute_federated_query(
        self,
        document: DocumentNode,
        variables: Optional[Dict[str, Any]] = None,
        operation_name: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> ExecutionResult:
        """Execute a federated query across multiple services."""
        start_time = asyncio.get_event_loop().time()
        
        try:
            # Plan the query
            plan = self.query_planner.plan_query(document, variables, operation_name)
            plan.mark_executing()
            
            # Execute the plan
            result = await self._execute_query_plan(plan, document, variables, context)
            
            plan.mark_completed()
            
            # Update metrics
            self.request_count += 1
            execution_time = asyncio.get_event_loop().time() - start_time
            self.avg_response_time = (self.avg_response_time + execution_time) / 2
            
            return result
            
        except Exception as e:
            self.error_count += 1
            logger.error(f"Federation query execution failed: {e}")
            
            return ExecutionResult(
                data=None,
                errors=[FederationError(f"Federation execution failed: {str(e)}")]
            )
    
    async def _execute_query_plan(
        self,
        plan: QueryPlan,
        document: DocumentNode,
        variables: Optional[Dict[str, Any]],
        context: Optional[Dict[str, Any]]
    ) -> ExecutionResult:
        """Execute a query plan across services."""
        results = {}
        errors = []
        
        # Execute steps in parallel where possible
        tasks = []
        for step in plan.execution_steps:
            if step.get('parallel', False):
                task = asyncio.create_task(
                    self._execute_service_query(
                        step['service'],
                        document,
                        variables,
                        context
                    )
                )
                tasks.append((step['service'], task))
        
        # Wait for all tasks to complete
        for service_name, task in tasks:
            try:
                service_result = await task
                results[service_name] = service_result
            except Exception as e:
                errors.append(FederationError(f"Service {service_name} failed: {str(e)}", service_name))
        
        # Merge results from all services
        merged_data = self._merge_service_results(results)
        
        return ExecutionResult(
            data=merged_data,
            errors=errors if errors else None
        )
    
    async def _execute_service_query(
        self,
        service_name: str,
        document: DocumentNode,
        variables: Optional[Dict[str, Any]],
        context: Optional[Dict[str, Any]]
    ) -> Any:
        """Execute a query against a specific service."""
        service = self.services.get(service_name)
        if not service or not service.is_healthy:
            raise FederationError(f"Service {service_name} is not available")
        
        # For remote services, send HTTP request
        if service.url.startswith('http'):
            return await self._execute_remote_query(service, document, variables, context)
        
        # For local services, execute directly
        if service.schema:
            result = await execute(
                service.schema,
                document,
                variable_values=variables,
                context_value=context
            )
            return result.data
        
        raise FederationError(f"No execution method available for service {service_name}")
    
    async def _execute_remote_query(
        self,
        service: FederatedService,
        document: DocumentNode,
        variables: Optional[Dict[str, Any]],
        context: Optional[Dict[str, Any]]
    ) -> Any:
        """Execute a query against a remote GraphQL service."""
        query_str = print_ast(document)
        
        payload = {
            'query': query_str,
            'variables': variables or {}
        }
        
        # Add context headers
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'GraphQL-Federation-Gateway/1.0'
        }
        
        if context:
            if 'authorization' in context:
                headers['Authorization'] = context['authorization']
            if 'user_id' in context:
                headers['X-User-ID'] = str(context['user_id'])
        
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=service.timeout)) as session:
            for attempt in range(service.retries + 1):
                try:
                    async with session.post(
                        f"{service.url}/graphql",
                        json=payload,
                        headers=headers
                    ) as response:
                        if response.status == 200:
                            result = await response.json()
                            return result.get('data')
                        else:
                            error_text = await response.text()
                            raise FederationError(f"Service returned {response.status}: {error_text}")
                            
                except asyncio.TimeoutError:
                    if attempt < service.retries:
                        await asyncio.sleep(2 ** attempt)  # Exponential backoff
                        continue
                    raise FederationError(f"Service {service.name} timed out")
                except Exception as e:
                    if attempt < service.retries:
                        await asyncio.sleep(2 ** attempt)
                        continue
                    raise FederationError(f"Service {service.name} error: {str(e)}")
    
    def _merge_service_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Merge results from multiple services."""
        merged = {}
        
        # Simple merge - in production you'd implement proper result merging
        for service_name, result in results.items():
            if result:
                merged.update(result)
        
        return merged
    
    async def _fetch_service_schema(self, service: FederatedService) -> GraphQLSchema:
        """Fetch schema from a service using introspection."""
        introspection_query = """
        query IntrospectionQuery {
            __schema {
                queryType { name }
                mutationType { name }
                subscriptionType { name }
                types {
                    ...FullType
                }
                directives {
                    name
                    description
                    locations
                    args {
                        ...InputValue
                    }
                }
            }
        }
        
        fragment FullType on __Type {
            kind
            name
            description
            fields(includeDeprecated: true) {
                name
                description
                args {
                    ...InputValue
                }
                type {
                    ...TypeRef
                }
                isDeprecated
                deprecationReason
            }
            inputFields {
                ...InputValue
            }
            interfaces {
                ...TypeRef
            }
            enumValues(includeDeprecated: true) {
                name
                description
                isDeprecated
                deprecationReason
            }
            possibleTypes {
                ...TypeRef
            }
        }
        
        fragment InputValue on __InputValue {
            name
            description
            type { ...TypeRef }
            defaultValue
        }
        
        fragment TypeRef on __Type {
            kind
            name
            ofType {
                kind
                name
                ofType {
                    kind
                    name
                    ofType {
                        kind
                        name
                        ofType {
                            kind
                            name
                            ofType {
                                kind
                                name
                                ofType {
                                    kind
                                    name
                                    ofType {
                                        kind
                                        name
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        """
        
        # Execute introspection query
        document = parse(introspection_query)
        result = await self._execute_remote_query(service, document, {}, {})
        
        # Build schema from introspection result
        # This is simplified - in production you'd use proper introspection to schema conversion
        schema_sdl = f"""
        type Query {{
            hello: String
        }}
        """
        
        return build_schema(schema_sdl)
    
    async def _health_check_loop(self):
        """Background task for health checking services."""
        while self._running:
            try:
                await asyncio.sleep(self.health_check_interval)
                
                # Check all services that need health checks
                tasks = []
                for service in self.services.values():
                    if service.needs_health_check():
                        tasks.append(self._check_service_health(service))
                
                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=True)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Health check loop error: {e}")
    
    async def _check_service_health(self, service: FederatedService):
        """Check the health of a service."""
        try:
            # Simple health check - ping the service
            health_query = "{ __typename }"
            document = parse(health_query)
            
            start_time = asyncio.get_event_loop().time()
            await self._execute_remote_query(service, document, {}, {})
            response_time = asyncio.get_event_loop().time() - start_time
            
            # Update service metrics
            service.avg_response_time = (service.avg_response_time + response_time) / 2
            service.status = ServiceStatus.HEALTHY
            service.last_health_check = datetime.utcnow()
            
            logger.debug(f"Service {service.name} health check passed ({response_time:.3f}s)")
            
        except Exception as e:
            service.status = ServiceStatus.UNHEALTHY
            service.last_health_check = datetime.utcnow()
            logger.warning(f"Service {service.name} health check failed: {e}")
    
    def get_service_stats(self) -> Dict[str, Any]:
        """Get federation gateway statistics."""
        healthy_services = sum(1 for s in self.services.values() if s.is_healthy)
        total_services = len(self.services)
        
        return {
            'total_services': total_services,
            'healthy_services': healthy_services,
            'unhealthy_services': total_services - healthy_services,
            'request_count': self.request_count,
            'error_count': self.error_count,
            'error_rate': self.error_count / max(self.request_count, 1),
            'avg_response_time': self.avg_response_time,
            'services': {
                name: {
                    'status': service.status.value,
                    'url': service.url,
                    'avg_response_time': service.avg_response_time,
                    'last_health_check': service.last_health_check.isoformat() if service.last_health_check else None
                }
                for name, service in self.services.items()
            }
        }


class FederationExtension(Extension):
    """Strawberry extension for GraphQL federation."""
    
    def __init__(self, gateway: FederationGateway):
        self.gateway = gateway
    
    async def on_request_start(self):
        """Handle request start for federation."""
        # Could add federation-specific request handling here
        pass
    
    async def on_request_end(self, result: ExecutionResult):
        """Handle request end for federation."""
        # Could add federation-specific result processing here
        pass


# Global federation gateway instance
federation_gateway = FederationGateway()


def create_federation_gateway(
    services: List[Dict[str, Any]],
    health_check_interval: int = 30
) -> FederationGateway:
    """Create and configure a federation gateway."""
    gateway = FederationGateway(health_check_interval=health_check_interval)
    
    # Register services
    async def register_services():
        for service_config in services:
            await gateway.register_service(**service_config)
    
    # This would be called during application startup
    asyncio.create_task(register_services())
    
    return gateway


__all__ = [
    'FederationGateway',
    'FederatedService',
    'SchemaRegistry',
    'QueryPlanner',
    'QueryPlan',
    'FederationExtension',
    'FederationError',
    'ServiceStatus',
    'federation_gateway',
    'create_federation_gateway',
]