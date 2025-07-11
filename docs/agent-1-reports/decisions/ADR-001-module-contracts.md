# ADR-001: Module Communication via Contracts

**Status**: Accepted  
**Date**: 2025-07-09  
**Author**: Agent 1 - Architecture & Integration Specialist

## Context

The Ezzday identity platform is designed as a modular system with four core modules: Identity, Audit, Integration, and Notification. However, analysis revealed that modules were directly importing from each other's domain layers, creating tight coupling and violating the principles of hexagonal architecture.

### Problems Identified:
1. **Direct Domain Imports**: Modules importing domain entities, events, and value objects from other modules
2. **Tight Coupling**: Changes in one module's domain break other modules
3. **Testing Complexity**: Cannot test modules in isolation
4. **Deployment Issues**: Cannot deploy modules independently
5. **No Clear API**: Module boundaries are unclear and inconsistent

## Decision

We will implement a **Contract-Based Module Communication** pattern where:

1. Each module defines a public contract with events, commands, and queries
2. Modules communicate only through these contracts, never through direct imports
3. Internal adapters translate between contracts and domain objects
4. All cross-module communication uses the event bus with contract events

### Key Components:

1. **Module Contracts** (`ModuleContract`)
   - Define public API for each module
   - Include events, commands, and queries
   - Versioned for compatibility

2. **Contract Registry** (`ContractRegistry`)
   - Central registry for all module contracts
   - Enables discovery without direct dependencies
   - Validates contract compatibility

3. **Internal Adapters** (`InternalModuleAdapter`)
   - Each module has adapters for modules it depends on
   - Subscribe to contract events
   - Send commands and queries through contracts

4. **Event Translators** (`EventTranslator`)
   - Translate domain events to contract events
   - Translate contract events to domain events
   - Maintain mapping between event types

## Consequences

### Positive:
- **True Module Independence**: Modules can evolve independently
- **Clear APIs**: Explicit contracts define module capabilities
- **Testability**: Modules can be tested in isolation with mock contracts
- **Deployment Flexibility**: Modules can be deployed separately
- **Version Compatibility**: Contracts can be versioned for backward compatibility
- **Documentation**: Contracts serve as living documentation

### Negative:
- **Initial Complexity**: More code required for adapters and translators
- **Performance Overhead**: Additional translation layer
- **Learning Curve**: Developers must understand contract patterns
- **Maintenance**: Contracts must be kept in sync with implementation

## Implementation

### Phase 1: Core Infrastructure (Complete)
- ✅ Created contract base classes
- ✅ Implemented contract registry
- ✅ Created internal adapter base class
- ✅ Implemented event translator base

### Phase 2: Module Contracts
- ✅ Identity module contract (complete)
- 🔄 Audit module contract (pending)
- 🔄 Integration module contract (pending)
- 🔄 Notification module contract (pending)

### Phase 3: Internal Adapters
- ✅ Audit → Identity adapter (complete)
- 🔄 Notification → Identity adapter (pending)
- 🔄 Other module adapters as needed

### Phase 4: Migration
- 🔄 Replace direct imports with adapter usage
- 🔄 Update event handlers to use contracts
- 🔄 Add contract validation to CI/CD

## Example

### Before (Direct Import):
```python
# In audit module - VIOLATES BOUNDARIES
from app.modules.identity.domain.entities.user.user_events import LoginSuccessful

class LoginEventHandler:
    async def handle(self, event: LoginSuccessful):
        # Direct coupling to Identity's domain
        pass
```

### After (Contract-Based):
```python
# In audit module - RESPECTS BOUNDARIES
from app.modules.audit.infrastructure.internal import IdentityAdapter

class AuditService:
    def __init__(self, identity_adapter: IdentityAdapter):
        self._identity_adapter = identity_adapter
        
    # Events handled through adapter
    # No direct imports from Identity module
```

## Alternatives Considered

1. **Shared Kernel Pattern**
   - Rejected: Still creates coupling through shared code
   
2. **Direct HTTP/gRPC Communication**
   - Rejected: Too much overhead for in-process communication
   
3. **Database Views**
   - Rejected: Couples modules at database level

## References

- [Hexagonal Architecture](https://alistair.cockburn.us/hexagonal-architecture/)
- [Domain-Driven Design](https://martinfowler.com/tags/domain%20driven%20design.html)
- [Microservices Patterns](https://microservices.io/patterns/)

## Review

This ADR should be reviewed:
- When adding new modules
- When module communication patterns change
- After 6 months of implementation experience