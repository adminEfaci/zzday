#!/bin/bash

echo "Resolving all conflicts by accepting incoming changes..."

# Handle different conflict types
git status --porcelain | while read -r status file; do
    case "$status" in
        "UU "*) # Both modified
            echo "Both modified: $file - taking theirs"
            git checkout --theirs "$file"
            ;;
        "UA "*) # Added by us (not in their branch)
            echo "Added by us: $file - removing"
            git rm "$file"
            ;;
        "AU "*) # Added by them
            echo "Added by them: $file - accepting"
            git add "$file"
            ;;
        "DU "*) # Deleted by us
            echo "Deleted by us: $file - keeping deleted"
            git rm "$file"
            ;;
        "UD "*) # Deleted by them
            echo "Deleted by them: $file - accepting deletion"
            git rm "$file"
            ;;
        "DD "*) # Both deleted
            echo "Both deleted: $file - accepting"
            git rm "$file"
            ;;
        "AA "*) # Both added
            echo "Both added: $file - taking theirs"
            git checkout --theirs "$file"
            ;;
    esac
done

# Stage all changes
git add -A

# Show what we're about to commit
echo "Changes staged:"
git status --short

# Continue merge
git merge --continue --no-edit
