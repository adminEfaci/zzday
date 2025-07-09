# Agent 1 - Architecture & Integration Reports

This directory contains all architecture analysis, decisions, and implementation reports from Agent 1.

## Directory Structure

### `/daily/`
Daily progress reports and session plans tracking architecture work.

### `/issues/`
Identified architectural violations and technical debt items requiring attention.

### `/decisions/`
Architecture Decision Records (ADRs) documenting key architectural choices.

### `/architecture/`
Architecture analysis documents, patterns, and guidelines for the system.

## Key Documents

1. **Module Dependency Analysis** - Comprehensive analysis of cross-module dependencies
2. **Architecture Violations Report** - All identified violations of architectural principles
3. **Integration Patterns Guide** - Standard patterns for module integration
4. **Technical Debt Register** - Ongoing registry of architectural debt

## Architecture Principles

1. **Hexagonal Architecture** - All modules follow ports & adapters pattern
2. **Module Independence** - No direct module-to-module dependencies
3. **Event-Driven Communication** - Cross-module communication only via events
4. **Single External Gateway** - Only Integration module accesses external services
5. **Contract-Based Integration** - All module interactions through defined contracts

## Quick Links

- [Session Plans](./daily/)
- [Architecture Violations](./issues/)
- [Architecture Decision Records](./decisions/)
- [Architecture Guidelines](./architecture/)