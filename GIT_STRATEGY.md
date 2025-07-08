# Git Branching Strategy for Multi-Agent Iterative Analysis

## Overview

This document defines the Git branching strategy for the iterative codebase analysis project using multiple agents. The strategy supports 5+ agents working in parallel on different aspects of the analysis while maintaining clear boundaries and merge procedures.

## Agent Roles and Responsibilities

### 1. **Architecture Agent** (Branch: `analysis/architecture`)
- **Responsibility**: Analyze overall system architecture, DDD boundaries, and hexagonal architecture compliance
- **Focus Areas**:
  - Domain layer integrity
  - Application layer patterns
  - Infrastructure layer boundaries
  - Cross-module dependencies

### 2. **Domain Agent** (Branch: `analysis/domain`)
- **Responsibility**: Deep dive into domain models, entities, value objects, and aggregates
- **Focus Areas**:
  - Entity relationships
  - Value object immutability
  - Aggregate boundaries
  - Domain events and rules

### 3. **Service Agent** (Branch: `analysis/services`)
- **Responsibility**: Analyze application services, command/query handlers, and use cases
- **Focus Areas**:
  - Service layer patterns
  - CQRS implementation
  - Command and query segregation
  - Service dependencies

### 4. **Infrastructure Agent** (Branch: `analysis/infrastructure`)
- **Responsibility**: Review infrastructure implementations, repositories, and external integrations
- **Focus Areas**:
  - Repository implementations
  - Database models
  - External service adapters
  - Infrastructure contracts

### 5. **Interface Agent** (Branch: `analysis/interfaces`)
- **Responsibility**: Analyze contracts, ports, adapters, and API boundaries
- **Focus Areas**:
  - Interface definitions
  - Contract compliance
  - Adapter implementations
  - API consistency

### 6. **Testing Agent** (Branch: `analysis/testing`)
- **Responsibility**: Review test coverage, test patterns, and quality assurance
- **Focus Areas**:
  - Unit test coverage
  - Integration test patterns
  - Test doubles usage
  - Test data builders

### 7. **Documentation Agent** (Branch: `analysis/documentation`)
- **Responsibility**: Consolidate findings, create living documentation, and maintain tracking logs
- **Focus Areas**:
  - Analysis reports consolidation
  - Living documentation updates
  - Cross-agent findings correlation
  - Progress tracking

## Branch Structure

```
master (protected)
│
├── analysis/coordination (main analysis branch)
│   │
│   ├── analysis/architecture
│   ├── analysis/domain
│   ├── analysis/services
│   ├── analysis/infrastructure
│   ├── analysis/interfaces
│   ├── analysis/testing
│   └── analysis/documentation
│
├── review/staging (pre-master review branch)
│
└── hotfix/critical-findings (for urgent fixes)
```

## Workflow Process

### 1. Initial Setup Phase
```bash
# Create coordination branch from master
git checkout -b analysis/coordination

# Create agent branches from coordination
git checkout -b analysis/architecture
git checkout -b analysis/domain
git checkout -b analysis/services
git checkout -b analysis/infrastructure
git checkout -b analysis/interfaces
git checkout -b analysis/testing
git checkout -b analysis/documentation
```

### 2. Agent Work Phase
Each agent works independently on their branch:
```bash
# Agent switches to their branch
git checkout analysis/[agent-area]

# Agent creates analysis file
# Creates: docs/analysis/[agent-area]/[module]_analysis.md

# Agent commits their work
git add docs/analysis/[agent-area]/*
git commit -m "analysis([agent-area]): [specific analysis completed]"

# Agent pushes to remote
git push -u origin analysis/[agent-area]
```

### 3. Coordination Sync Phase (Daily)
```bash
# Coordination agent merges all agent work
git checkout analysis/coordination

# Merge each agent's work
git merge analysis/architecture --no-ff -m "merge: architecture analysis updates"
git merge analysis/domain --no-ff -m "merge: domain analysis updates"
git merge analysis/services --no-ff -m "merge: services analysis updates"
git merge analysis/infrastructure --no-ff -m "merge: infrastructure analysis updates"
git merge analysis/interfaces --no-ff -m "merge: interfaces analysis updates"
git merge analysis/testing --no-ff -m "merge: testing analysis updates"
git merge analysis/documentation --no-ff -m "merge: documentation updates"

# Push coordination branch
git push origin analysis/coordination
```

### 4. Review Phase (Weekly)
```bash
# Create review branch
git checkout analysis/coordination
git checkout -b review/week-[number]

# Consolidate findings
# Create: docs/analysis/weekly-reports/week-[number]-report.md

# Push for review
git push -u origin review/week-[number]
```

### 5. Master Integration Phase
```bash
# After review approval
git checkout master
git merge review/week-[number] --no-ff -m "feat(analysis): week [number] analysis integration"
git push origin master
```

## File Organization

```
docs/
├── analysis/
│   ├── architecture/
│   │   ├── identity_module_analysis.md
│   │   ├── audit_module_analysis.md
│   │   └── cross_module_dependencies.md
│   ├── domain/
│   │   ├── entities_analysis.md
│   │   ├── value_objects_analysis.md
│   │   └── aggregates_analysis.md
│   ├── services/
│   │   ├── command_handlers_analysis.md
│   │   ├── query_handlers_analysis.md
│   │   └── application_services_analysis.md
│   ├── infrastructure/
│   │   ├── repositories_analysis.md
│   │   ├── external_services_analysis.md
│   │   └── persistence_analysis.md
│   ├── interfaces/
│   │   ├── contracts_analysis.md
│   │   ├── ports_adapters_analysis.md
│   │   └── api_boundaries_analysis.md
│   ├── testing/
│   │   ├── unit_tests_analysis.md
│   │   ├── integration_tests_analysis.md
│   │   └── test_coverage_report.md
│   ├── documentation/
│   │   ├── living_documentation.md
│   │   ├── tracking_log.md
│   │   └── findings_summary.md
│   └── weekly-reports/
│       ├── week-1-report.md
│       └── week-2-report.md
```

## Commit Message Convention

All commits must follow this pattern:
```
<type>(<scope>): <subject>

<body>

<footer>
```

Types:
- `analysis`: New analysis findings
- `fix`: Corrections to previous analysis
- `docs`: Documentation updates
- `merge`: Merge commits
- `review`: Review consolidations

Examples:
```bash
analysis(architecture): identify DDD boundary violations in identity module
fix(domain): correct entity relationship mapping for User aggregate
docs(tracking): update progress tracking for week 1
merge: consolidate agent findings for coordination review
```

## Merge Strategy

### 1. Agent to Coordination Merges
- **Frequency**: Daily
- **Strategy**: No-fast-forward (`--no-ff`)
- **Conflict Resolution**: Coordination agent resolves
- **Review**: Peer review by another agent

### 2. Coordination to Review Merges
- **Frequency**: Weekly
- **Strategy**: Create new review branch
- **Consolidation**: Documentation agent creates summary
- **Approval**: Requires 2 agent approvals

### 3. Review to Master Merges
- **Frequency**: After review approval
- **Strategy**: No-fast-forward with detailed message
- **Requirements**: 
  - All findings documented
  - Tracking log updated
  - No unresolved conflicts
  - Admin approval

## Conflict Resolution

### Priority Order
1. Architecture decisions override others
2. Domain model integrity is paramount
3. Interface contracts must be preserved
4. Service implementations can adapt
5. Infrastructure can be refactored

### Resolution Process
```bash
# When conflict occurs
git checkout analysis/coordination
git merge analysis/[agent-branch]

# If conflicts exist
# 1. Review conflicting analyses
# 2. Consult with relevant agents
# 3. Document resolution rationale
# 4. Complete merge with explanation

git add .
git commit -m "merge: resolve [agent1] and [agent2] analysis conflicts

Conflicts resolved by:
- [explanation of resolution]
- [rationale for decisions]
"
```

## Progress Tracking

### Individual Agent Tracking
Each agent maintains their own progress file:
```markdown
# Agent Progress: [Agent Name]
## Current Sprint: Week [X]

### Completed
- [ ] Module: Identity - Domain Analysis
- [ ] Module: Identity - Service Analysis

### In Progress
- [ ] Module: Audit - Domain Analysis

### Blocked
- [ ] Module: Integration - Awaiting clarification on...
```

### Coordination Tracking
Coordination agent maintains master tracking:
```markdown
# Master Progress Tracking
## Week [X] Status

| Agent | Modules Completed | In Progress | Blocked |
|-------|------------------|-------------|---------|
| Architecture | 3 | 2 | 0 |
| Domain | 2 | 3 | 1 |
...
```

## Communication Protocol

### 1. Daily Standup (via commits)
Each agent commits a daily status:
```bash
git commit --allow-empty -m "status([agent]): daily update - completed X, working on Y, blocked by Z"
```

### 2. Cross-Agent Communication
Use Git notes for discussions:
```bash
git notes add -m "question(@domain-agent): How should we handle aggregate boundaries in notification module?"
```

### 3. Urgent Issues
Create hotfix branch for critical findings:
```bash
git checkout -b hotfix/critical-architecture-violation
# Document finding
git commit -m "hotfix: critical DDD violation in [module]"
```

## Implementation Commands

### Phase 1: Initialize Strategy
```bash
# You run this to set up the strategy
git add GIT_STRATEGY.md
git commit -m "docs: add comprehensive Git strategy for multi-agent analysis"
git push origin master
```

### Phase 2: Create Branch Structure
```bash
# You instruct me to create branches
"Create the analysis branch structure as defined in GIT_STRATEGY.md"
```

### Phase 3: Agent Assignment
```bash
# You assign me to specific agent role
"Act as [Architecture Agent] and begin analysis on [specific module]"
```

### Phase 4: Work Execution
```bash
# You provide files for analysis
"Analyze the following file as [Agent Role]: [file path]"
```

### Phase 5: Progress Review
```bash
# You request status
"Show current analysis progress across all agents"
```

## Success Metrics

1. **Coverage**: All modules analyzed by relevant agents
2. **Consistency**: No conflicting analyses between agents
3. **Completeness**: All findings documented and tracked
4. **Quality**: Peer-reviewed and validated findings
5. **Timeliness**: Weekly milestones met

## Next Steps

1. Commit this strategy document
2. Create the branch structure
3. Initialize agent working directories
4. Begin iterative analysis process

---
*This is a living document and will be updated as the analysis progresses.*