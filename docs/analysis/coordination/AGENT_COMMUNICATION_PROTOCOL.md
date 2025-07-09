# 📡 Agent Communication Protocol via Git

**Version**: 1.0  
**Created**: 2025-07-09  
**Author**: Agent-4 (Coordination)  
**Purpose**: Enable asynchronous inter-agent communication without interrupting work

## Communication Structure

```
docs/
└── analysis/
    └── coordination/
        └── agent_messages/
            ├── inbox/
            │   ├── agent-1/
            │   ├── agent-2/
            │   ├── agent-3/
            │   └── agent-4/
            └── announcements/
                └── daily_notices.md
```

## Message Format

### Standard Message Template
```markdown
# [PRIORITY] Message from Agent-X to Agent-Y

**Date**: 2025-07-09 HH:MM  
**Subject**: [Brief subject]  
**Priority**: 🔴 URGENT | 🟡 NORMAL | 🟢 INFO  
**Response Needed**: YES/NO by [time]

## Message
[Your message here]

## Action Items
- [ ] Specific action 1
- [ ] Specific action 2

## Context
[Any relevant context or links]

---
**Message ID**: [timestamp-sender-receiver]
```

## Communication Workflow

### 1. Sending a Message
```bash
# Create message file
echo "[Message content]" > docs/analysis/coordination/agent_messages/inbox/agent-Y/message_[timestamp]_from_agent-X.md

# Add and commit
git add docs/analysis/coordination/agent_messages/inbox/agent-Y/*
git commit -m "[Message] Agent-X to Agent-Y: [Subject]"
git push origin analysis/agent-X
```

### 2. Checking Messages
```bash
# Pull latest changes
git pull origin analysis/coordination

# Check your inbox
ls docs/analysis/coordination/agent_messages/inbox/agent-[your-number]/

# Read messages
cat docs/analysis/coordination/agent_messages/inbox/agent-[your-number]/*.md
```

### 3. Acknowledging Messages
```bash
# Mark as read by moving to processed
mkdir -p docs/analysis/coordination/agent_messages/inbox/agent-[your-number]/processed
mv docs/analysis/coordination/agent_messages/inbox/agent-[your-number]/message_*.md \
   docs/analysis/coordination/agent_messages/inbox/agent-[your-number]/processed/

# Commit acknowledgment
git add -A
git commit -m "[ACK] Agent-Y acknowledged messages from Agent-X"
git push
```

## Priority Levels

### 🔴 URGENT (Check every hour)
- Blocking issues
- Critical dependencies
- Security concerns
- Production risks

### 🟡 NORMAL (Check every 2-3 hours)
- Standard questions
- Code reviews
- Pattern clarifications
- Non-blocking help

### 🟢 INFO (Check at convenience)
- FYI updates
- Documentation notes
- Best practices
- General announcements

## Agent-Specific Communication Channels

### Agent-1 → Agent-3 Channel
**Purpose**: Architecture guidance for infrastructure
```bash
# Agent-1 shares repository patterns
docs/analysis/coordination/agent_messages/patterns/repository_design_v1.md
```

### Agent-3 → Agent-2 Channel  
**Purpose**: Infrastructure updates affecting services
```bash
# Agent-3 notifies about SQLRepository progress
docs/analysis/coordination/agent_messages/updates/sqlrepository_status.md
```

### Agent-4 → All Channel
**Purpose**: Coordination announcements
```bash
# Daily announcements
docs/analysis/coordination/agent_messages/announcements/daily_notices.md
```

## Git Tree Communication Commands

### Setup Communication Tree
```bash
# Initial setup (Agent-4 will create)
mkdir -p docs/analysis/coordination/agent_messages/{inbox/{agent-1,agent-2,agent-3,agent-4},announcements,patterns,updates}

# Create .gitkeep files
find docs/analysis/coordination/agent_messages -type d -exec touch {}/.gitkeep \;

# Initial commit
git add docs/analysis/coordination/agent_messages
git commit -m "[Setup] Agent communication protocol initialized"
git push origin analysis/agent-4
```

### Quick Message Scripts

#### Send Message Function
```bash
# Add to your .bashrc or .zshrc
send_agent_message() {
    local to_agent=$1
    local priority=$2
    local subject=$3
    local message=$4
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local from_agent="agent-4"  # Change to your agent number
    
    cat << EOF > "docs/analysis/coordination/agent_messages/inbox/${to_agent}/msg_${timestamp}_from_${from_agent}.md"
# [${priority}] Message from ${from_agent} to ${to_agent}

**Date**: $(date '+%Y-%m-%d %H:%M')  
**Subject**: ${subject}  
**Priority**: ${priority}  
**Response Needed**: YES by EOD

## Message
${message}

## Action Items
- [ ] Review and respond

---
**Message ID**: ${timestamp}-${from_agent}-${to_agent}
EOF

    git add "docs/analysis/coordination/agent_messages/inbox/${to_agent}/*"
    git commit -m "[Message] ${from_agent} to ${to_agent}: ${subject}"
    git push origin analysis/${from_agent}
}

# Usage: send_agent_message "agent-1" "🟡 NORMAL" "Repository Pattern Help" "Need guidance on SQLRepository design"
```

#### Check Messages Function
```bash
check_my_messages() {
    local my_agent="agent-4"  # Change to your agent number
    git pull origin analysis/coordination
    
    echo "=== YOUR MESSAGES ==="
    ls -la docs/analysis/coordination/agent_messages/inbox/${my_agent}/*.md 2>/dev/null || echo "No new messages"
    
    echo -e "\n=== ANNOUNCEMENTS ==="
    ls -la docs/analysis/coordination/agent_messages/announcements/*.md 2>/dev/null || echo "No announcements"
}
```

## Message Examples

### Example 1: Blocker Notification
```markdown
# [🔴 URGENT] Message from agent-3 to agent-2

**Date**: 2025-07-09 14:30  
**Subject**: SQLRepository blocking your work  
**Priority**: 🔴 URGENT  
**Response Needed**: NO

## Message
SQLRepository base class is more complex than expected. 
Current ETA: 2 more hours.

## Suggestion
You can start service analysis without waiting for repository implementation.
Focus on mapping service duplications and consolidation patterns.

## Action Items
- [x] Notified about delay
- [ ] Start parallel work on service analysis

---
**Message ID**: 20250709_1430-agent-3-agent-2
```

### Example 2: Help Request
```markdown
# [🟡 NORMAL] Message from agent-3 to agent-1

**Date**: 2025-07-09 15:00  
**Subject**: Need repository pattern guidance  
**Priority**: 🟡 NORMAL  
**Response Needed**: YES by 16:00

## Message
Working on SQLRepository base class but unsure about:
1. Should it handle transactions internally?
2. How to implement specification pattern?
3. Best approach for batch operations?

## Context
See my current implementation:
`app/core/infrastructure/repository.py` (lines 45-120)

## Action Items
- [ ] Review current implementation
- [ ] Provide pattern guidance
- [ ] Suggest improvements

---
**Message ID**: 20250709_1500-agent-3-agent-1
```

## Broadcast Patterns

### Daily Stand-up (Agent-4)
```bash
# Morning broadcast
cat << EOF > docs/analysis/coordination/agent_messages/announcements/standup_$(date +%Y%m%d).md
# Daily Stand-up - $(date '+%Y-%m-%d')

## Priorities Today
1. Agent-3: Complete SQLRepository (blocking Agent-2)
2. Agent-2: Begin service analysis 
3. Agent-1: Continue adapter implementation
4. Agent-4: Coordinate first merge cycle

## Blockers
- SQLRepository complexity (Agent-3)
- Waiting for repos (Agent-2)

## Merge Windows
- 09:00-10:00: Agent-1
- 10:00-11:00: Agent-2
- 11:00-12:00: Agent-3
- 14:00-15:00: Agent-4

---
Check your inbox for agent-specific messages!
EOF
```

## Benefits

1. **Asynchronous**: No interruption to current work
2. **Persistent**: Full history in git
3. **Traceable**: Clear communication trail
4. **Prioritized**: Urgent messages stand out
5. **Structured**: Consistent format

## Quick Start

1. Agent-4 sets up the structure (I'll do this now)
2. Each agent adds check_my_messages to their workflow
3. Check messages at priority intervals
4. Use send_agent_message for communication

This protocol allows agents to communicate effectively without interrupting deep work!