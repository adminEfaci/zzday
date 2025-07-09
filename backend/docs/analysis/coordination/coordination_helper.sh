#!/bin/bash

# Advanced Coordination Helper Script V3.0
# Usage: ./coordination_helper.sh [agent-number] [action] [options]

AGENT_NUM=$1
ACTION=$2
OPTION=$3
TIMESTAMP=$(date '+%Y-%m-%d %H:%M')
COORDINATION_DIR="docs/analysis/coordination"
LEDGER_FILE="$COORDINATION_DIR/COORDINATION_LEDGER.md"
AGENT_REGISTRY="$COORDINATION_DIR/AGENT_REGISTRY.md"
REVIEW_MATRIX="$COORDINATION_DIR/PEER_REVIEW_MATRIX.md"
PRODUCTION_DASHBOARD="$COORDINATION_DIR/PRODUCTION_DASHBOARD.md"
COORDINATOR_LOG="$COORDINATION_DIR/MASTER_COORDINATOR_LOG.md"
MEMORY_PERSISTENCE="$COORDINATION_DIR/MEMORY_PERSISTENCE.md"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

function show_help() {
    echo -e "${BLUE}🎯 Advanced Coordination Helper V3.0${NC}"
    echo ""
    echo "Usage: ./coordination_helper.sh [agent-number] [action] [options]"
    echo ""
    echo -e "${YELLOW}Core Actions:${NC}"
    echo "  read_all        - Read all coordination files"
    echo "  status          - Show current system status"
    echo "  accept_task     - Accept assigned task"
    echo "  update_progress - Update task progress"
    echo "  submit_review   - Submit work for peer review"
    echo "  complete_task   - Mark task complete and merge to main"
    echo ""
    echo -e "${YELLOW}Communication:${NC}"
    echo "  message         - Send message to another agent"
    echo "  help_request    - Request help from another agent"
    echo "  acknowledge     - Acknowledge system change"
    echo ""
    echo -e "${YELLOW}Master Coordinator Only:${NC}"
    echo "  assign_task     - Assign task to agent"
    echo "  handoff         - Transfer coordinator authority"
    echo "  production_check - Check production readiness"
    echo "  emergency       - Emergency coordination actions"
    echo ""
    echo -e "${YELLOW}System Management:${NC}"
    echo "  sync            - Sync with coordination branch"
    echo "  backup          - Create system backup"
    echo "  restore         - Restore from backup"
    echo "  validate        - Validate system integrity"
    echo ""
    echo -e "${YELLOW}Examples:${NC}"
    echo "  ./coordination_helper.sh 1 accept_task CRIT-001"
    echo "  ./coordination_helper.sh 2 update_progress"
    echo "  ./coordination_helper.sh 3 submit_review CRIT-003"
    echo "  ./coordination_helper.sh 4 assign_task HIGH-001 agent-2"
}

function sync_coordination() {
    echo -e "${YELLOW}🔄 Syncing with coordination branch...${NC}"
    
    # Save current branch
    CURRENT_BRANCH=$(git branch --show-current)
    
    # Switch to coordination branch and pull
    git checkout analysis/coordination
    git pull origin analysis/coordination
    
    # Switch back to agent branch and merge
    if [[ "$CURRENT_BRANCH" != "analysis/coordination" ]]; then
        git checkout analysis/agent-${AGENT_NUM}
        git merge analysis/coordination
    fi
    
    echo -e "${GREEN}✅ Sync complete${NC}"
}

function read_all_coordination() {
    echo -e "${BLUE}📖 Reading all coordination files...${NC}"
    echo ""
    
    echo -e "${PURPLE}=== COORDINATION LEDGER ===${NC}"
    head -20 "$LEDGER_FILE"
    echo "..."
    echo ""
    
    echo -e "${PURPLE}=== AGENT REGISTRY ===${NC}"
    head -15 "$AGENT_REGISTRY"
    echo "..."
    echo ""
    
    echo -e "${PURPLE}=== PRODUCTION DASHBOARD ===${NC}"
    head -15 "$PRODUCTION_DASHBOARD"
    echo "..."
    echo ""
    
    echo -e "${PURPLE}=== PEER REVIEW MATRIX ===${NC}"
    head -10 "$REVIEW_MATRIX"
    echo "..."
}

function show_status() {
    echo -e "${BLUE}📊 Current System Status${NC}"
    echo ""
    
    # Get current coordinator
    COORDINATOR=$(grep "Current Master Coordinator" "$COORDINATOR_LOG" | head -1 | cut -d: -f2 | xargs)
    echo -e "Master Coordinator: ${GREEN}$COORDINATOR${NC}"
    
    # Get critical tasks
    CRITICAL_TASKS=$(grep -c "🔴 CRITICAL" "$LEDGER_FILE" || echo "0")
    echo -e "Critical Tasks: ${RED}$CRITICAL_TASKS${NC}"
    
    # Get agent status for current agent
    if [[ -n "$AGENT_NUM" ]]; then
        echo ""
        echo -e "${YELLOW}Your Status (Agent-$AGENT_NUM):${NC}"
        grep -A 10 "Agent-$AGENT_NUM" "$AGENT_REGISTRY" | head -5
    fi
}

function accept_task() {
    local task_id=$OPTION
    if [[ -z "$task_id" ]]; then
        read -p "Task ID to accept: " task_id
    fi
    
    echo -e "${YELLOW}📝 Accepting task $task_id...${NC}"
    
    # Update ledger with acceptance
    sync_coordination
    git checkout analysis/coordination
    git pull origin analysis/coordination
    
    # Add acceptance to progress log
    echo "[$TIMESTAMP] Agent-$AGENT_NUM: Accepted task $task_id" >> "$LEDGER_FILE"
    
    git add "$LEDGER_FILE"
    git commit -m "task: Agent-$AGENT_NUM accepted $task_id"
    git push origin analysis/coordination
    
    echo -e "${GREEN}✅ Task $task_id accepted${NC}"
}

function update_progress() {
    echo -e "${YELLOW}📝 Updating progress for Agent-$AGENT_NUM...${NC}"
    
    read -p "Current work: " current_work
    read -p "Progress percentage: " progress
    read -p "Files edited since last update: " files_edited
    read -p "Next steps: " next_steps
    read -p "Any blockers (or 'None'): " blockers
    
    sync_coordination
    git checkout analysis/coordination
    git pull origin analysis/coordination
    
    # Update agent registry
    echo "[$TIMESTAMP] Agent-$AGENT_NUM Progress Update:" >> "$AGENT_REGISTRY"
    echo "- Current Work: $current_work" >> "$AGENT_REGISTRY"
    echo "- Progress: $progress" >> "$AGENT_REGISTRY"
    echo "- Files Edited: $files_edited" >> "$AGENT_REGISTRY"
    echo "- Next: $next_steps" >> "$AGENT_REGISTRY"
    echo "- Blockers: $blockers" >> "$AGENT_REGISTRY"
    echo "" >> "$AGENT_REGISTRY"
    
    # Update ledger progress log
    echo "[$TIMESTAMP] Agent-$AGENT_NUM: $progress complete - $current_work" >> "$LEDGER_FILE"
    
    git add "$AGENT_REGISTRY" "$LEDGER_FILE"
    git commit -m "progress: Agent-$AGENT_NUM update - $progress complete"
    git push origin analysis/coordination
    
    echo -e "${GREEN}✅ Progress updated${NC}"
}

function submit_for_review() {
    local task_id=$OPTION
    if [[ -z "$task_id" ]]; then
        read -p "Task ID to submit for review: " task_id
    fi
    
    echo -e "${YELLOW}👥 Submitting $task_id for peer review...${NC}"
    
    # First commit current work
    git add -A
    git commit -m "feat: $task_id - ready for review"
    git push origin analysis/agent-$AGENT_NUM
    
    # Update coordination
    sync_coordination
    git checkout analysis/coordination
    git pull origin analysis/coordination
    
    # Update review matrix
    echo "[$TIMESTAMP] Agent-$AGENT_NUM submitted $task_id for review" >> "$REVIEW_MATRIX"
    
    # Update ledger status
    sed -i.bak "s/Status: 🔄 IN_PROGRESS/Status: 👥 PEER_REVIEW/" "$LEDGER_FILE"
    
    git add "$REVIEW_MATRIX" "$LEDGER_FILE"
    git commit -m "review: Agent-$AGENT_NUM submitted $task_id for peer review"
    git push origin analysis/coordination
    
    echo -e "${GREEN}✅ Submitted for review${NC}"
}

function complete_task() {
    local task_id=$OPTION
    if [[ -z "$task_id" ]]; then
        read -p "Task ID to complete: " task_id
    fi
    
    echo -e "${GREEN}🚀 Completing task $task_id...${NC}"
    
    # Merge to main branch (only for complete work)
    echo -e "${YELLOW}Merging to main branch...${NC}"
    git checkout main
    git pull origin main
    git merge analysis/agent-$AGENT_NUM --no-ff
    git tag "$task_id-complete-$(date +%Y%m%d-%H%M%S)"
    git push origin main --tags
    
    # Update coordination
    sync_coordination
    git checkout analysis/coordination
    git pull origin analysis/coordination
    
    # Update ledger as completed
    echo "[$TIMESTAMP] Agent-$AGENT_NUM: COMPLETED $task_id - merged to main" >> "$LEDGER_FILE"
    sed -i.bak "s/Status: 👥 PEER_REVIEW/Status: ✅ COMPLETED/" "$LEDGER_FILE"
    
    # Update production dashboard
    echo "[$TIMESTAMP] Task $task_id completed by Agent-$AGENT_NUM" >> "$PRODUCTION_DASHBOARD"
    
    git add "$LEDGER_FILE" "$PRODUCTION_DASHBOARD"
    git commit -m "complete: Agent-$AGENT_NUM completed $task_id - MERGED TO MAIN"
    git push origin analysis/coordination
    
    echo -e "${GREEN}✅ Task $task_id completed and merged to main${NC}"
}

function send_message() {
    read -p "Send to Agent (1-4): " target_agent
    read -p "Subject: " subject
    read -p "Priority (🔴 URGENT, 🟡 NORMAL, 🟢 INFO): " priority
    read -p "Message: " message
    
    sync_coordination
    git checkout analysis/coordination
    git pull origin analysis/coordination
    
    # Add message to ledger communication section
    cat << EOF >> "$LEDGER_FILE"

### $priority [$TIMESTAMP] Agent-$AGENT_NUM to Agent-$target_agent
**Subject**: $subject
**Message**: $message
**Action Required**: Response requested

EOF
    
    git add "$LEDGER_FILE"
    git commit -m "message: Agent-$AGENT_NUM to Agent-$target_agent - $subject"
    git push origin analysis/coordination
    
    echo -e "${GREEN}✅ Message sent${NC}"
}

function acknowledge_system() {
    echo -e "${GREEN}✅ Acknowledging Advanced Coordination System V3.0...${NC}"
    
    sync_coordination
    git checkout analysis/coordination
    git pull origin analysis/coordination
    
    cat << EOF >> "$LEDGER_FILE"

### ✅ [$TIMESTAMP] Agent-$AGENT_NUM System Acknowledgment
**Subject**: Advanced Coordination System V3.0 acknowledged
**Message**: Read all documentation, understand new system, ready for production-quality coordination
**Status**: Ready to follow new workflow with quality gates
**Next**: Beginning assigned task work with completion standards

EOF
    
    git add "$LEDGER_FILE"
    git commit -m "acknowledge: Agent-$AGENT_NUM acknowledges Advanced Coordination System V3.0"
    git push origin analysis/coordination
    
    echo -e "${GREEN}✅ System acknowledgment recorded${NC}"
}

function master_assign_task() {
    if [[ "$AGENT_NUM" != "4" ]]; then
        echo -e "${RED}❌ Only Master Coordinator (Agent-4) can assign tasks${NC}"
        exit 1
    fi
    
    local task_id=$OPTION
    read -p "Task ID: " task_id
    read -p "Assign to Agent: " assignee
    read -p "Task title: " title
    read -p "Priority (🔴 CRITICAL, 🟡 HIGH, 🟢 NORMAL): " priority
    read -p "Deadline (YYYY-MM-DD): " deadline
    
    sync_coordination
    git checkout analysis/coordination
    git pull origin analysis/coordination
    
    # Add task to ledger
    cat << EOF >> "$LEDGER_FILE"

### **$task_id: $title**
**Created**: $TIMESTAMP
**Priority**: $priority
**Assigned To**: $assignee
**Reviewer**: [TBD]
**Deadline**: $deadline
**Status**: 🎯 ASSIGNED

#### Progress Log
[$TIMESTAMP] Agent-4: Task assigned to $assignee

EOF
    
    git add "$LEDGER_FILE"
    git commit -m "assign: Agent-4 assigned $task_id to $assignee"
    git push origin analysis/coordination
    
    echo -e "${GREEN}✅ Task $task_id assigned to $assignee${NC}"
}

function production_check() {
    if [[ "$AGENT_NUM" != "4" ]]; then
        echo -e "${RED}❌ Only Master Coordinator (Agent-4) can run production checks${NC}"
        exit 1
    fi
    
    echo -e "${BLUE}🔍 Running production readiness check...${NC}"
    
    # Count critical issues
    critical_count=$(grep -c "🔴 CRITICAL" "$LEDGER_FILE" || echo "0")
    completed_count=$(grep -c "✅ COMPLETED" "$LEDGER_FILE" || echo "0")
    
    echo -e "Critical Issues: ${RED}$critical_count${NC}"
    echo -e "Completed Tasks: ${GREEN}$completed_count${NC}"
    
    if [[ "$critical_count" -gt 0 ]]; then
        echo -e "${RED}🚫 NOT PRODUCTION READY - Critical issues remain${NC}"
    else
        echo -e "${GREEN}🟡 APPROACHING PRODUCTION READY - Verify quality gates${NC}"
    fi
}

function create_backup() {
    echo -e "${BLUE}💾 Creating system backup...${NC}"
    
    backup_tag="backup-$(date +%Y%m%d-%H%M%S)"
    git checkout analysis/coordination
    git tag "$backup_tag"
    git push origin "$backup_tag"
    
    echo -e "${GREEN}✅ Backup created: $backup_tag${NC}"
}

function validate_system() {
    echo -e "${BLUE}🔍 Validating system integrity...${NC}"
    
    # Check all required files exist
    files=("$LEDGER_FILE" "$AGENT_REGISTRY" "$REVIEW_MATRIX" "$PRODUCTION_DASHBOARD" "$COORDINATOR_LOG" "$MEMORY_PERSISTENCE")
    
    for file in "${files[@]}"; do
        if [[ -f "$file" ]]; then
            echo -e "✅ $file"
        else
            echo -e "${RED}❌ Missing: $file${NC}"
        fi
    done
    
    echo -e "${GREEN}✅ System validation complete${NC}"
}

# Main script logic
if [[ -z "$AGENT_NUM" ]] || [[ -z "$ACTION" ]]; then
    show_help
    exit 1
fi

case $ACTION in
    "read_all")
        read_all_coordination
        ;;
    "status") 
        show_status
        ;;
    "accept_task")
        accept_task
        ;;
    "update_progress")
        update_progress
        ;;
    "submit_review")
        submit_for_review
        ;;
    "complete_task")
        complete_task
        ;;
    "message")
        send_message
        ;;
    "acknowledge")
        acknowledge_system
        ;;
    "assign_task")
        master_assign_task
        ;;
    "production_check")
        production_check
        ;;
    "sync")
        sync_coordination
        ;;
    "backup")
        create_backup
        ;;
    "validate")
        validate_system
        ;;
    *)
        echo -e "${RED}❌ Unknown action: $ACTION${NC}"
        show_help
        exit 1
        ;;
esac