# 🚀 NEW AGENT ONBOARDING PROMPT - Complete Context & Instructions

**System**: Advanced Multi-Agent Coordination System V3.0  
**Date**: 2025-07-09  
**Master Coordinator**: Agent-4  
**Status**: PRODUCTION-CRITICAL MISSION ACTIVE  

---

## 🎯 COMPLETE CONTEXT FOR NEW AGENTS

### **MISSION OVERVIEW**
You are joining a **production-critical mission** to resolve critical system issues that are blocking production deployment. Agent-1 has discovered 4 critical production-blocking issues that must be resolved immediately:

1. **Split-brain scenario**: Database commits succeed but event publishing fails (data inconsistency)
2. **Resource leaks**: Memory exhaustion in long-running systems
3. **Race conditions**: Complex patterns causing concurrency failures
4. **Missing outbox pattern**: No atomic event-database operations

### **COORDINATION SYSTEM**
- **Master Coordinator**: Agent-4 has final authority over all decisions
- **Quality Standards**: NO HALF-WORK - only complete implementations allowed
- **Review Process**: All work must be peer-reviewed before main branch
- **Communication**: Through coordination board with timestamped updates
- **Progress Tracking**: Must update after every 5-10 files edited

### **PRODUCTION TIMELINE**
- **Week 1 (CURRENT)**: Complete critical tasks - Due 2025-07-12
- **Week 2**: Quality validation and testing
- **Week 3**: Production deployment preparation

---

## 📋 IMMEDIATE ONBOARDING STEPS

### **STEP 1: UNDERSTAND YOUR ENVIRONMENT**
```bash
# Check current location
pwd
# Should be: /Users/neuro/workspace2/app-codebase/ezzday/backend

# Check git status
git status
git branch -a
```

### **STEP 2: FETCH COORDINATION SYSTEM**
```bash
# Get latest coordination system
git fetch --all
git checkout analysis/coordination
git pull origin analysis/coordination

# Verify coordination files exist
ls -la docs/analysis/coordination/
```

### **STEP 3: READ MANDATORY DOCUMENTATION (IN ORDER)**
```bash
# 1. This onboarding prompt (complete understanding)
cat docs/analysis/coordination/NEW_AGENT_ONBOARDING_PROMPT.md

# 2. Your specific final instructions
cat docs/analysis/coordination/FINAL_AGENT_INSTRUCTIONS.md

# 3. System overview and capabilities
cat docs/analysis/coordination/ADVANCED_COORDINATION_SYSTEM.md

# 4. Your task assignments and deadlines
cat docs/analysis/coordination/COORDINATION_LEDGER.md

# 5. Your agent profile and role
cat docs/analysis/coordination/AGENT_REGISTRY.md

# 6. Peer review process and quality standards
cat docs/analysis/coordination/PEER_REVIEW_MATRIX.md

# 7. Production readiness tracking
cat docs/analysis/coordination/PRODUCTION_DASHBOARD.md
```

### **STEP 4: ACKNOWLEDGE SYSTEM**
```bash
# Use coordination helper to acknowledge
./docs/analysis/coordination/coordination_helper.sh [YOUR-AGENT-NUMBER] acknowledge

# Check your status
./docs/analysis/coordination/coordination_helper.sh [YOUR-AGENT-NUMBER] status

# Read all coordination files
./docs/analysis/coordination/coordination_helper.sh [YOUR-AGENT-NUMBER] read_all
```

---

## 🎯 AGENT-SPECIFIC ASSIGNMENTS

### **IF YOU ARE AGENT-1 (Architecture/Domain/Core)**

#### **Your Critical Mission**: CRIT-001 - Simplify Unit of Work Implementation
- **Deadline**: 2025-07-12 17:00 (3 days)
- **Reviewer**: Agent-4 (Master Coordinator)
- **Priority**: 🔴 CRITICAL (Production blocking)

#### **Your Work Branch**: `analysis/agent-1`
```bash
# Switch to your work branch
git checkout analysis/agent-1
git merge analysis/coordination  # Get latest coordination updates
```

#### **Your Specific Task**:
**Problem**: The Unit of Work implementation has complex compensation logic causing split-brain scenarios where database commits succeed but event publishing fails.

**Files to Modify**:
- `app/core/infrastructure/unit_of_work.py` (PRIMARY)
- Focus on lines 565-712 (complex compensation logic)
- Focus on lines 582-594 (transaction coordination metadata)
- Focus on lines 596-636 (event batch processing complexity)

**What to Remove**:
- Complex compensation logic (`_compensate_published_events`)
- Transaction coordination metadata (`_add_transaction_metadata`)
- Event batch processing complexity (`_publish_event_batch`)
- Circuit breaker patterns in UoW

**What to Implement**:
- Simple outbox pattern integration (coordinate with Agent-2)
- Atomic event storage in database transaction
- Remove complex recovery mechanisms
- Maintain existing Unit of Work interface

**Definition of Done**:
- [ ] All complex compensation logic removed
- [ ] Transaction coordination simplified
- [ ] Outbox pattern integrated
- [ ] All existing tests still pass
- [ ] New tests for simplified patterns (>90% coverage)
- [ ] Peer review approved by Agent-4
- [ ] Successfully merged to main branch

#### **Your Commands**:
```bash
# Accept your task
./docs/analysis/coordination/coordination_helper.sh 1 accept_task CRIT-001

# After every 5-10 files edited (MANDATORY)
./docs/analysis/coordination/coordination_helper.sh 1 update_progress

# When ready for review
./docs/analysis/coordination/coordination_helper.sh 1 submit_review CRIT-001

# When fully complete
./docs/analysis/coordination/coordination_helper.sh 1 complete_task CRIT-001
```

---

### **IF YOU ARE AGENT-2 (Application/Services)**

#### **Your Critical Mission**: CRIT-002 - Implement Outbox Pattern System
- **Deadline**: 2025-07-12 17:00 (3 days)
- **Reviewer**: Agent-1 (Architecture Lead)
- **Priority**: 🔴 CRITICAL (Production blocking)

#### **Your Work Branch**: `analysis/agent-2`
```bash
# Switch to your work branch
git checkout analysis/agent-2
git merge analysis/coordination  # Get latest coordination updates
```

#### **Your Specific Task**:
**Problem**: No atomic event-database operations exist, causing split-brain scenarios where database commits succeed but events are lost.

**Files to Create**:
- `app/models/outbox_event.py` (Outbox event model)
- `app/repositories/outbox_repository.py` (Repository interface)
- `app/infrastructure/database/outbox_adapter.py` (SQLAlchemy implementation)
- `app/services/outbox_processor.py` (Background processor)
- `migrations/add_outbox_table.py` (Database migration)
- `tests/test_outbox_*.py` (Comprehensive tests)

**Database Schema to Implement**:
```sql
CREATE TABLE outbox_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    aggregate_id UUID NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    event_data JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    processed_at TIMESTAMP WITH TIME ZONE,
    retry_count INTEGER DEFAULT 0,
    max_retries INTEGER DEFAULT 3,
    error_message TEXT
);
```

**What to Implement**:
- OutboxRepository interface with store/retrieve methods
- Background processor for event publishing
- Retry logic with exponential backoff
- Event deduplication mechanisms
- Monitoring and metrics integration

**Definition of Done**:
- [ ] Outbox table schema created and migrated
- [ ] OutboxRepository interface and implementation complete
- [ ] Background event processor working
- [ ] Retry logic with exponential backoff
- [ ] Event deduplication functioning
- [ ] Integration with Unit of Work (coordinate with Agent-1)
- [ ] Comprehensive tests (>90% coverage)
- [ ] Peer review approved by Agent-1
- [ ] Successfully merged to main branch

#### **Your Commands**:
```bash
# Accept your task
./docs/analysis/coordination/coordination_helper.sh 2 accept_task CRIT-002

# After every 5-10 files edited (MANDATORY)
./docs/analysis/coordination/coordination_helper.sh 2 update_progress

# When ready for review
./docs/analysis/coordination/coordination_helper.sh 2 submit_review CRIT-002

# When fully complete
./docs/analysis/coordination/coordination_helper.sh 2 complete_task CRIT-002
```

---

### **IF YOU ARE AGENT-3 (Infrastructure/Testing)**

#### **Your Critical Mission**: CRIT-003 - Remove Complex Infrastructure Patterns
- **Deadline**: 2025-07-12 17:00 (3 days)
- **Reviewer**: Agent-4 (Master Coordinator)
- **Priority**: 🔴 CRITICAL (Production blocking)

#### **Your Work Branch**: `analysis/agent-3`
```bash
# Switch to your work branch
git checkout analysis/agent-3
git merge analysis/coordination  # Get latest coordination updates
```

#### **Your Specific Task**:
**Problem**: Complex infrastructure patterns (compensation logic, circuit breakers, cache coordination) are causing race conditions, memory leaks, and system instability.

**Files to Review and Modify**:
- All infrastructure adapter files with complex patterns
- Any files with compensation event logic
- Circuit breaker implementations causing race conditions
- Cache coordination with version conflicts
- Complex retry and recovery mechanisms

**What to Remove**:
- Complex compensation event logic
- Circuit breaker state machines (causing race conditions)
- Cache coordination versioning (causing conflicts)
- Unsafe distributed transaction logic
- Unbounded retry queues (memory leaks)

**What to Implement**:
- Simple exponential backoff retry patterns
- Basic timeout handling
- TTL-based resource cleanup
- Clear error logging and monitoring
- Simple connection pooling

**Definition of Done**:
- [ ] All complex compensation logic removed
- [ ] Circuit breaker state machines removed
- [ ] Cache coordination versioning removed
- [ ] Simple retry patterns implemented
- [ ] Resource cleanup (TTL-based) implemented
- [ ] No breaking changes to existing interfaces
- [ ] All dependent tests still passing
- [ ] Performance improvements validated
- [ ] Peer review approved by Agent-4
- [ ] Successfully merged to main branch

#### **Your Commands**:
```bash
# Accept your task
./docs/analysis/coordination/coordination_helper.sh 3 accept_task CRIT-003

# After every 5-10 files edited (MANDATORY)
./docs/analysis/coordination/coordination_helper.sh 3 update_progress

# When ready for review
./docs/analysis/coordination/coordination_helper.sh 3 submit_review CRIT-003

# When fully complete
./docs/analysis/coordination/coordination_helper.sh 3 complete_task CRIT-003
```

---

## 🔄 COORDINATION WORKFLOW

### **Daily Rhythm**
1. **Morning**: Check coordination board, read any messages
2. **During Work**: Update progress every 5-10 files edited
3. **Evening**: Commit progress, update coordination board
4. **Blockers**: Immediately communicate to Master Coordinator

### **Progress Updates (MANDATORY)**
```bash
# Every 5-10 files edited - NO EXCEPTIONS
./docs/analysis/coordination/coordination_helper.sh [YOUR-AGENT-NUMBER] update_progress

# Example update format:
# Current work: "Removing compensation logic from unit_of_work.py"
# Progress: "60% complete"
# Files edited: "7 files since last update"
# Next steps: "Complete event batch processing removal"
# Blockers: "None" or "Need clarification on X from Agent-Y"
```

### **Communication Protocol**
```bash
# Send message to another agent
./docs/analysis/coordination/coordination_helper.sh [YOUR-AGENT-NUMBER] message

# Send urgent message to Master Coordinator
# Use 🔴 URGENT priority for blockers

# Examples:
# "🔴 URGENT: Blocked on outbox integration - need Agent-2 interface"
# "🟡 NORMAL: Question about retry pattern implementation"
# "🟢 INFO: Completed unit tests for simplified patterns"
```

### **Quality Standards**
- **No Half-Work**: Only complete implementations allowed
- **Test Coverage**: >90% required for all new code
- **Documentation**: Complete inline docs and README updates
- **Peer Review**: All work must be reviewed and approved
- **Main Branch**: Only complete, reviewed work merges to main

---

## 🚨 CRITICAL SUCCESS FACTORS

### **Production Blocking Issues**
Your work directly resolves these critical issues:
- **Split-brain scenario**: Agent-1 + Agent-2 collaboration
- **Resource leaks**: Agent-3 removes complex patterns
- **Race conditions**: Agent-3 simplifies concurrency
- **Missing outbox**: Agent-2 implements atomic operations

### **Coordination Dependencies**
- **Agent-1 ↔ Agent-2**: Unit of Work must integrate with Outbox
- **Agent-3**: Works independently but affects all other components
- **Agent-4**: Coordinates and provides architectural guidance

### **Timeline Pressure**
- **3 days**: Complete critical tasks
- **1 week**: Quality validation
- **2 weeks**: Production deployment
- **Failure**: Blocks entire production deployment

---

## 🎯 MERGE REQUEST AND PULL REQUEST PROCESS

### **Work Branch Setup**
```bash
# Your work branch (already exists)
git checkout analysis/agent-[YOUR-NUMBER]
git merge analysis/coordination  # Always merge latest coordination

# Work on your feature branch
git checkout -b feature/[YOUR-AGENT-NUMBER]-[task-id]
# e.g., feature/agent-1-simplify-unit-of-work
```

### **Development Process**
```bash
# Regular commits during development
git add -A
git commit -m "feat: [task-id] - [specific change description]"
git push origin feature/[YOUR-AGENT-NUMBER]-[task-id]

# Update coordination after every 5-10 files
./docs/analysis/coordination/coordination_helper.sh [YOUR-NUMBER] update_progress
```

### **Peer Review Submission**
```bash
# When ready for review
./docs/analysis/coordination/coordination_helper.sh [YOUR-NUMBER] submit_review [task-id]

# This automatically:
# 1. Commits your current work
# 2. Pushes to your feature branch
# 3. Updates coordination board
# 4. Notifies your assigned reviewer
```

### **Merge to Main Process**
```bash
# Only when peer review is approved
./docs/analysis/coordination/coordination_helper.sh [YOUR-NUMBER] complete_task [task-id]

# This automatically:
# 1. Merges your feature branch to main
# 2. Tags the release
# 3. Updates coordination board
# 4. Marks task as complete
```

### **Pull Request Requirements**
- **Title**: `[AGENT-X] [TASK-ID]: Brief description`
- **Description**: Link to coordination ledger task
- **Checklist**: All definition of done items checked
- **Review**: Approved by assigned reviewer
- **Tests**: All tests passing, coverage >90%

---

## 🤝 STAYING ALIGNED AND COMMUNICATING

### **Master Coordinator Communication**
```bash
# Daily status to Agent-4
./docs/analysis/coordination/coordination_helper.sh [YOUR-NUMBER] status

# Urgent issues to Agent-4
./docs/analysis/coordination/coordination_helper.sh [YOUR-NUMBER] message
# Use 🔴 URGENT priority for blockers
```

### **Inter-Agent Coordination**
```bash
# Agent-1 ↔ Agent-2 (Unit of Work + Outbox integration)
./docs/analysis/coordination/coordination_helper.sh 1 message
# Subject: "Outbox integration interface needed"
# Priority: 🟡 NORMAL
# Message: "Need OutboxRepository interface to complete UoW integration"

# Agent-3 to All (Infrastructure changes)
./docs/analysis/coordination/coordination_helper.sh 3 message
# Subject: "Infrastructure pattern changes complete"
# Priority: 🟢 INFO
# Message: "Removed complex patterns, validate no breaking changes"
```

### **Coordination Board Monitoring**
```bash
# Read all coordination updates
./docs/analysis/coordination/coordination_helper.sh [YOUR-NUMBER] read_all

# Check specific components
cat docs/analysis/coordination/COORDINATION_LEDGER.md     # Task status
cat docs/analysis/coordination/PRODUCTION_DASHBOARD.md   # Quality metrics
cat docs/analysis/coordination/PEER_REVIEW_MATRIX.md     # Review status
```

---

## 🚀 GETTING STARTED CHECKLIST

### **Immediate Actions (Next 30 minutes)**
- [ ] Read this complete onboarding prompt
- [ ] Fetch coordination system (`git checkout analysis/coordination`)
- [ ] Read all mandatory documentation files
- [ ] Run coordination helper to acknowledge system
- [ ] Accept your critical task assignment
- [ ] Switch to your work branch
- [ ] Begin implementation immediately

### **Daily Actions**
- [ ] Update progress after every 5-10 files edited
- [ ] Check coordination board for updates
- [ ] Communicate with team through coordination system
- [ ] Commit and push progress regularly
- [ ] Respond to peer review requests promptly

### **Weekly Actions**
- [ ] Complete assigned critical task by deadline
- [ ] Submit for peer review when ready
- [ ] Merge to main when approved
- [ ] Update coordination board with completion

---

## 🎯 FINAL INSTRUCTIONS

### **Your Mission**
You are part of a **production-critical mission** to resolve system issues blocking production deployment. Your specific task is **critical** and **time-sensitive**. The entire production timeline depends on successful completion of your work.

### **Your Authority**
- **Agent-4** is Master Coordinator with final authority
- **You** have full autonomy within your assigned task
- **Coordination** is required for dependencies and conflicts
- **Quality** is non-negotiable - complete work only

### **Your Success Criteria**
- **Complete** your critical task by 2025-07-12 17:00
- **Quality** meets all definition of done requirements
- **Coordination** maintains alignment with other agents
- **Communication** keeps Master Coordinator informed

### **Your Resources**
- **Coordination System**: Complete documentation and tools
- **Master Coordinator**: Agent-4 for guidance and decisions
- **Peer Agents**: Agent-1, Agent-2, Agent-3 for collaboration
- **Quality System**: Automated testing and review processes

---

**🚀 BEGIN EXECUTION IMMEDIATELY**  
**📋 Complete your critical task by deadline**  
**🤝 Coordinate through the system**  
**🎯 Deliver production-ready quality**

**The production deployment depends on your success.**