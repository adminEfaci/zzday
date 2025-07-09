#!/bin/bash

branches=(
    "implementation/interfaces"
    "implementation/services"
)

for branch in "${branches[@]}"; do
    echo "Merging $branch..."
    git merge $branch --strategy-option=theirs --no-edit
    
    if [ $? -ne 0 ]; then
        echo "Conflict detected, forcing their changes..."
        # Force accept all their changes
        git status --porcelain | grep "^UU" | awk '{print $2}' | xargs git checkout --theirs
        git status --porcelain | grep "^UA" | awk '{print $2}' | xargs git add
        git status --porcelain | grep "^AU" | awk '{print $2}' | xargs git rm
        git add .
        git merge --continue --no-edit
    fi
    
    echo "✅ $branch merged!"
done

echo "🎉 All branches merged! Pushing..."
git push origin master
