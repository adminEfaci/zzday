# 🎯 MASTER ORCHESTRATOR INSTRUCTIONS - Agent Command Protocol

**Master Orchestrator**: Agent-4 (Coordination/Presentation/Documentation)  
**Date**: 2025-07-09 17:40  
**Status**: ACTIVE COMMAND  
**Authority**: All agents report to Agent-4  

---

## 🚨 IMMEDIATE ACTIONS REQUIRED

### **ALL AGENTS - EXECUTE IMMEDIATELY**

#### **STEP 1: ACKNOWLEDGE COMMAND AUTHORITY**
```bash
# 1. Fetch latest coordination system
git fetch --all
git checkout analysis/coordination
git pull origin analysis/coordination

# 2. Read Master Orchestrator instructions
cat docs/analysis/coordination/MASTER_ORCHESTRATOR_INSTRUCTIONS.md
```

#### **STEP 2: TRANSITION TO NEW SYSTEM**
```bash
# 3. Read coordination strategy
cat docs/analysis/coordination/MASTER_COORDINATION_STRATEGY.md

# 4. Read live coordination board
cat docs/analysis/coordination/LIVE_COORDINATION_BOARD.md

# 5. Read system migration instructions
cat docs/analysis/coordination/AGENT_NOTIFICATION_NEW_SYSTEM.md
```

#### **STEP 3: REPORT TO MASTER ORCHESTRATOR**
Update your progress in `LIVE_COORDINATION_BOARD.md` with:

```markdown
### [2025-07-09 XX:XX] Agent-X to Agent-4 (Master Orchestrator)
**Subject**: New coordination system acknowledgment  
**Message**: Understood new system, read all documentation, ready for command protocol  
**Status**: Awaiting specific task assignments  
**Current Work**: [What you're currently working on]  
**Files Edited Today**: [Number of files]  
**Blockers**: [Any current blockers]  
**Next**: Awaiting Master Orchestrator task assignments
```

---

## 🎯 COMMAND STRUCTURE

### **Master Orchestrator: Agent-4**
**Authority**: Final decision making, task assignment, coordination oversight  
**Responsibilities**:
- Assign and prioritize all tasks
- Resolve conflicts and blockers
- Monitor progress and performance
- Make architectural decisions
- Coordinate emergency responses

### **Agent-1 (Architecture/Domain/Core)**
**Reports to**: Agent-4 (Master Orchestrator)  
**Current Assignment**: 🔴 URGENT - Simplify Unit of Work, remove complex patterns  
**Deadline**: End of week  
**Reporting Schedule**: After every 5-10 files edited

### **Agent-2 (Application/Services)**
**Reports to**: Agent-4 (Master Orchestrator)  
**Current Assignment**: 🔴 URGENT - Implement outbox table and repository  
**Deadline**: End of week  
**Reporting Schedule**: After every 5-10 files edited

### **Agent-3 (Infrastructure/Testing)**
**Reports to**: Agent-4 (Master Orchestrator)  
**Current Assignment**: 🔴 URGENT - Remove complex compensation logic  
**Deadline**: End of week  
**Reporting Schedule**: After every 5-10 files edited

---

## 📋 CURRENT COMMAND ASSIGNMENTS

### **CRITICAL MISSION: Resolve Production-Blocking Issues**

#### **Agent-1 - IMMEDIATE ORDERS**
1. **Simplify Unit of Work** (app/core/infrastructure/unit_of_work.py)
   - Remove complex compensation logic (lines 565-712)
   - Remove transaction coordination metadata (lines 582-594)
   - Remove event batch processing complexity (lines 596-636)
   - Implement simple outbox pattern integration
   - **Progress Reports**: After every 5 files edited

2. **Coordinate with Agent-2**
   - Provide outbox table requirements
   - Review outbox repository interface
   - Integrate outbox pattern into Unit of Work
   - **Status Updates**: Daily via coordination board

3. **Architectural Decisions**
   - Focus on simple, proven patterns
   - Remove over-engineered solutions
   - Document simplified architecture
   - **Deliverables**: Simplified Unit of Work by Friday

#### **Agent-2 - IMMEDIATE ORDERS**
1. **Implement Outbox Table** (URGENT)
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

2. **Create OutboxRepository Interface**
   - `store_events()` method
   - `get_unprocessed_events()` method
   - `mark_processed()` method
   - `increment_retry()` method
   - **Progress Reports**: After every 5 files edited

3. **Background Event Processor**
   - Process unprocessed events
   - Implement retry logic
   - Handle failed events
   - **Deliverables**: Working outbox system by Friday

#### **Agent-3 - IMMEDIATE ORDERS**
1. **Remove Complex Patterns** (URGENT)
   - Delete compensation event logic
   - Remove circuit breaker state machines
   - Remove cache coordination versioning
   - Remove unsafe distributed transaction logic
   - **Progress Reports**: After every 5 files edited

2. **Replace with Simple Patterns**
   - Simple exponential backoff retry
   - Basic timeout handling
   - Clear error logging
   - TTL-based cleanup
   - **Deliverables**: Simplified infrastructure by Friday

3. **Testing Support**
   - Create tests for simplified patterns
   - Validate system reliability
   - Performance testing
   - **Status Updates**: Daily via coordination board

---

## 🔄 REPORTING PROTOCOL

### **Mandatory Reporting Schedule**
- **After every 5-10 files edited**
- **Daily status updates**
- **Immediate reporting for blockers**
- **End of day completion summary**

### **Progress Report Format**
```markdown
### [TIMESTAMP] Agent-X to Agent-4 (Master Orchestrator)
**Subject**: Progress Report - [Current Work]  
**Files Edited**: [Number since last report]  
**Status**: 🔄 IN_PROGRESS / ✅ COMPLETED / 🚫 BLOCKED  
**Current Work**: [Specific task being worked on]  
**Progress**: [Percentage complete]  
**Completed**: [What was finished]  
**Next**: [Next steps]  
**Blockers**: [Any issues preventing progress]  
**ETA**: [Estimated completion time]  
**Help Needed**: [Specific assistance required]
```

### **Blocker Escalation Protocol**
```markdown
### 🚫 [TIMESTAMP] Agent-X to Agent-4 (Master Orchestrator)
**Subject**: BLOCKER - [Issue description]  
**Priority**: 🔴 URGENT  
**Issue**: [Detailed description of blocker]  
**Impact**: [How it affects timeline]  
**Attempted Solutions**: [What was tried]  
**Help Needed**: [Specific assistance required]  
**Timeline**: [When blocker must be resolved]
```

---

## 🎯 PERFORMANCE METRICS

### **Success Criteria**
- **Response Time**: < 2 hours for Master Orchestrator queries
- **Progress Updates**: Every 5-10 files edited
- **Task Completion**: Within assigned deadlines
- **Quality**: No regressions, proper testing

### **Performance Tracking**
- **Daily**: Progress toward weekly goals
- **Weekly**: Major milestone completion
- **Real-time**: Blocker resolution
- **Continuous**: Code quality and testing

---

## 🚨 EMERGENCY PROTOCOLS

### **Critical Issue Response**
1. **Immediate Notification**: Update coordination board with 🔴 URGENT
2. **Master Orchestrator Alert**: Direct message to Agent-4
3. **Work Suspension**: Stop all non-critical work
4. **Coordinated Response**: Follow Master Orchestrator directives

### **Conflict Resolution**
1. **Escalate to Master Orchestrator**: Agent-4 makes final decisions
2. **Document Conflicts**: In coordination board
3. **Implement Decisions**: Follow Master Orchestrator directives
4. **Move Forward**: No prolonged discussions

---

## 🤝 COMMUNICATION RULES

### **Direct Communication with Master Orchestrator**
- **Method**: LIVE_COORDINATION_BOARD.md communication log
- **Format**: Professional, clear, specific
- **Response Time**: Master Orchestrator responds within 2 hours
- **Escalation**: Tag 🔴 URGENT for immediate attention

### **Inter-Agent Communication**
- **Coordination Required**: All inter-agent communication via coordination board
- **Master Orchestrator Visibility**: All communication visible to Agent-4
- **Conflict Resolution**: Escalate to Master Orchestrator immediately

---

## 📖 MANDATORY ACTIONS - EXECUTE NOW

### **STEP 1**: Read all coordination documentation
### **STEP 2**: Update your progress in LIVE_COORDINATION_BOARD.md
### **STEP 3**: Begin your assigned critical tasks
### **STEP 4**: Report progress after every 5-10 files edited
### **STEP 5**: Coordinate through Master Orchestrator for all decisions

---

## 🎯 FINAL AUTHORITY

**Master Orchestrator (Agent-4) has final authority on:**
- Task prioritization and assignment
- Architectural decisions
- Conflict resolution
- Timeline and deadline management
- Resource allocation and coordination
- Emergency response protocols

**All agents must:**
- Follow Master Orchestrator directives
- Report progress as specified
- Escalate blockers immediately
- Maintain professional communication
- Focus on assigned critical tasks

---

**🎯 ACKNOWLEDGMENT REQUIRED**  
**📖 All agents must acknowledge these instructions in LIVE_COORDINATION_BOARD.md**  
**⏱️ Begin execution immediately**  
**🤝 Report to Master Orchestrator after reading**

**This is active command protocol. Execute immediately.**