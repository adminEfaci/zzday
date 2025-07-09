#!/bin/bash

# Coordination Helper Script for Agents
# Usage: ./coordination_helper.sh [agent-number] [action]

AGENT_NUM=$1
ACTION=$2
TIMESTAMP=$(date '+%Y-%m-%d %H:%M')
COORDINATION_FILE="docs/analysis/coordination/LIVE_COORDINATION_BOARD.md"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

function show_help() {
    echo "🎯 Coordination Helper for Agents"
    echo ""
    echo "Usage: ./coordination_helper.sh [agent-number] [action]"
    echo ""
    echo "Actions:"
    echo "  read     - Read coordination board"
    echo "  update   - Update your progress (interactive)"
    echo "  message  - Send message to another agent"
    echo "  help     - Request help from another agent"
    echo "  sync     - Sync with coordination branch"
    echo ""
    echo "Examples:"
    echo "  ./coordination_helper.sh 1 read"
    echo "  ./coordination_helper.sh 2 update"
    echo "  ./coordination_helper.sh 3 message"
}

function sync_coordination() {
    echo -e "${YELLOW}🔄 Syncing with coordination branch...${NC}"
    
    # Save current branch
    CURRENT_BRANCH=$(git branch --show-current)
    
    # Switch to coordination branch
    git checkout analysis/coordination
    git pull origin analysis/coordination
    
    # Switch back to agent branch
    git checkout analysis/agent-${AGENT_NUM}
    git merge analysis/coordination
    
    echo -e "${GREEN}✅ Sync complete${NC}"
}

function read_coordination() {
    echo -e "${YELLOW}📖 Reading coordination board...${NC}"
    echo ""
    cat "$COORDINATION_FILE"
}

function update_progress() {
    echo -e "${YELLOW}📝 Updating Agent-${AGENT_NUM} progress...${NC}"
    echo ""
    
    # Get current info
    echo "Current work:"
    read -p "What are you working on? " CURRENT_WORK
    
    echo "Progress:"
    read -p "Progress percentage (e.g., 50%): " PROGRESS
    
    echo "Files edited:"
    read -p "Number of files edited since last update: " FILES_EDITED
    
    echo "Next steps:"
    read -p "What's next? " NEXT_STEPS
    
    echo "Blockers:"
    read -p "Any blockers? (or 'None'): " BLOCKERS
    
    # Update the coordination board
    sync_coordination
    
    git checkout analysis/coordination
    git pull origin analysis/coordination
    
    # Create backup
    cp "$COORDINATION_FILE" "${COORDINATION_FILE}.backup"
    
    # Update progress section (this is a simplified version - would need more robust text processing)
    echo -e "${YELLOW}📝 Please manually update your progress section in:${NC}"
    echo "$COORDINATION_FILE"
    echo ""
    echo "Update with:"
    echo "**Last Updated**: $TIMESTAMP"
    echo "**Files Edited**: $FILES_EDITED"
    echo "**Status**: 🔄 IN_PROGRESS"
    echo "**Current Work**: $CURRENT_WORK"
    echo "**Progress**: $PROGRESS"
    echo "**Next**: $NEXT_STEPS"
    echo "**Blockers**: $BLOCKERS"
    
    # Open file in editor
    ${EDITOR:-nano} "$COORDINATION_FILE"
    
    # Commit changes
    git add "$COORDINATION_FILE"
    git commit -m "update: Agent-${AGENT_NUM} progress $TIMESTAMP"
    git push origin analysis/coordination
    
    echo -e "${GREEN}✅ Progress updated and committed${NC}"
}

function send_message() {
    echo -e "${YELLOW}📢 Sending message...${NC}"
    echo ""
    
    read -p "Send to Agent (1-4): " TARGET_AGENT
    read -p "Subject: " SUBJECT
    read -p "Priority (🔴 URGENT, 🟡 NORMAL, 🟢 INFO): " PRIORITY
    read -p "Message: " MESSAGE
    read -p "Action needed: " ACTION_NEEDED
    read -p "Deadline: " DEADLINE
    
    # Sync and update
    sync_coordination
    git checkout analysis/coordination
    git pull origin analysis/coordination
    
    # Add message to communication log
    echo "" >> "$COORDINATION_FILE"
    echo "### $PRIORITY [$TIMESTAMP] Agent-${AGENT_NUM} to Agent-${TARGET_AGENT}" >> "$COORDINATION_FILE"
    echo "**Subject**: $SUBJECT" >> "$COORDINATION_FILE"
    echo "**Message**: $MESSAGE" >> "$COORDINATION_FILE"
    echo "**Action**: $ACTION_NEEDED" >> "$COORDINATION_FILE"
    echo "**Deadline**: $DEADLINE" >> "$COORDINATION_FILE"
    echo "" >> "$COORDINATION_FILE"
    
    git add "$COORDINATION_FILE"
    git commit -m "message: Agent-${AGENT_NUM} to Agent-${TARGET_AGENT} - $SUBJECT"
    git push origin analysis/coordination
    
    echo -e "${GREEN}✅ Message sent and committed${NC}"
}

function request_help() {
    echo -e "${YELLOW}❓ Requesting help...${NC}"
    echo ""
    
    read -p "Request help from Agent (1-4): " TARGET_AGENT
    read -p "Subject: " SUBJECT
    read -p "Question: " QUESTION
    read -p "Context/Files: " CONTEXT
    read -p "Deadline: " DEADLINE
    
    # Sync and update
    sync_coordination
    git checkout analysis/coordination
    git pull origin analysis/coordination
    
    # Add to help requests section
    echo "" >> "$COORDINATION_FILE"
    echo "### ❓ [$TIMESTAMP] Agent-${AGENT_NUM} to Agent-${TARGET_AGENT}" >> "$COORDINATION_FILE"
    echo "**Subject**: $SUBJECT" >> "$COORDINATION_FILE"
    echo "**Question**: $QUESTION" >> "$COORDINATION_FILE"
    echo "**Context**: $CONTEXT" >> "$COORDINATION_FILE"
    echo "**Deadline**: $DEADLINE" >> "$COORDINATION_FILE"
    echo "" >> "$COORDINATION_FILE"
    
    git add "$COORDINATION_FILE"
    git commit -m "help: Agent-${AGENT_NUM} requests help from Agent-${TARGET_AGENT} - $SUBJECT"
    git push origin analysis/coordination
    
    echo -e "${GREEN}✅ Help request sent and committed${NC}"
}

# Main script logic
if [ -z "$AGENT_NUM" ] || [ -z "$ACTION" ]; then
    show_help
    exit 1
fi

case $ACTION in
    "read")
        read_coordination
        ;;
    "update")
        update_progress
        ;;
    "message")
        send_message
        ;;
    "help")
        request_help
        ;;
    "sync")
        sync_coordination
        ;;
    *)
        echo -e "${RED}❌ Unknown action: $ACTION${NC}"
        show_help
        exit 1
        ;;
esac