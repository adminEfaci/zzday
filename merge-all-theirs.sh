#!/bin/bash

branches=(
    "analysis/agent-1"
    "analysis/agent-2"
    "analysis/agent-3"
    "analysis/agent-4"
    "analysis/architecture"
    "analysis/coordination"
    "analysis/documentation"
    "analysis/domain"
    "analysis/infrastructure"
    "analysis/interfaces"
    "analysis/main"
    "analysis/services"
    "analysis/testing"
    "implementation/documentation"
    "implementation/infrastructure"
    "implementation/interfaces"
    "implementation/services"
)

for branch in "${branches[@]}"; do
    echo "Merging $branch (accepting their changes)..."
    git merge $branch --strategy-option=theirs --no-edit
    if [ $? -eq 0 ]; then
        echo "✅ $branch merged successfully!"
    else
        echo "❌ Error merging $branch"
        exit 1
    fi
done

echo "🎉 All branches merged! Pushing to master..."
git push origin master
