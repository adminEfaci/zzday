#!/bin/bash

# =====================================
# CONFIGURATION - Edit this to your needs
# =====================================
DEFAULT_ROOT="/Users/neuro/workspace2/app-codebase/ezzday/backend/app/modules/identity/"

# =====================================
# USAGE EXAMPLES:
# 
# Interactive mode:
#   ./script.sh
#   Then enter: domain/interfaces
#   Then enter: domain/services
#
# Command line mode:
#   ./script.sh domain/interfaces domain/services
#   ./script.sh /full/absolute/path domain/relative
#
# Creates ONE "all" folder where script runs with ALL files
# =====================================

# Function to display usage
show_usage() {
    echo "Usage: $0 [folder_path1] [folder_path2] ..."
    echo "Or run without arguments to enter paths interactively"
    echo ""
    echo "DEFAULT ROOT: $DEFAULT_ROOT"
    echo ""
    echo "You can enter:"
    echo "  • Relative paths (e.g., 'domain/interfaces') - will use default root"
    echo "  • Absolute paths (e.g., '/full/path/to/folder') - will use as-is"
    echo ""
    echo "This script will:"
    echo "  1. Generate tree.txt files for each folder (saved where script runs)"
    echo "  2. Create ONE 'all' folder where the script runs"
    echo "  3. Copy all files from ALL processed folders into the single 'all' folder"
    echo "  4. Exclude __init__.py files and __pycache__ directories"
    echo ""
}

# Function to resolve path (combine with default root if relative)
resolve_path() {
    local input_path="$1"
    
    # Expand tilde first
    input_path=$(eval echo "$input_path")
    
    # If path starts with /, it's absolute - use as-is
    if [[ "$input_path" == /* ]]; then
        echo "$input_path"
    else
        # It's relative - combine with default root
        # Remove trailing slash from default root if present
        local clean_root="${DEFAULT_ROOT%/}"
        echo "$clean_root/$input_path"
    fi
}

# Function to create safe filename from path
path_to_filename() {
    local path="$1"
    # Replace / with _ and remove leading/trailing underscores
    echo "$path" | sed 's|/|_|g' | sed 's/^_//;s/_$//'
}

# Function to check if file should be excluded
should_exclude_file() {
    local file="$1"
    local filename=$(basename "$file")
    local dirname=$(dirname "$file")
    
    # Exclude __init__.py files
    if [[ "$filename" == "__init__.py" ]]; then
        return 0  # true - exclude
    fi
    
    # Exclude anything in __pycache__ directories
    if [[ "$dirname" == *"__pycache__"* ]]; then
        return 0  # true - exclude
    fi
    
    # Exclude .pyc files
    if [[ "$filename" == *.pyc ]]; then
        return 0  # true - exclude
    fi
    
    return 1  # false - don't exclude
}

# Function to generate tree for a folder
generate_tree() {
    local folder_path="$1"
    local script_dir="$2"
    
    echo "📋 Generating tree structure for: $folder_path"
    
    # Go into the folder
    cd "$folder_path" || {
        echo "❌ Error: Cannot access directory '$folder_path'"
        return 1
    }
    
    # Create safe filename for tree
    local safe_name=$(path_to_filename "$folder_path")
    local tree_file="$script_dir/${safe_name}_tree.txt"
    
    # Generate tree structure
    if command -v tree >/dev/null 2>&1; then
        tree -I "__pycache__|*.pyc" > "$tree_file"
        echo "   Tree saved to: $tree_file"
    else
        # Fallback if tree command is not available
        find . -type d -name "__pycache__" -prune -o -type f -name "*.pyc" -prune -o -print | \
        sed 's/[^-][^\/]*\//  /g;s/^  //;s/-/|/' > "$tree_file"
        echo "   Tree saved to: $tree_file (using find fallback)"
    fi
    
    # Return to script directory
    cd "$script_dir"
}

# Main script execution
main() {
    # Get the directory where script is running
    SCRIPT_DIR=$(pwd)
    
    echo "🚀 Folder Tree and File Collector Script"
    echo "======================================="
    echo "📍 Script running from: $SCRIPT_DIR"
    echo ""
    
    # Check if arguments were provided
    if [[ $# -eq 0 ]]; then
        echo "No folder paths provided as arguments."
        echo "💡 DEFAULT ROOT: $DEFAULT_ROOT"
        echo ""
        echo "Enter relative paths (e.g., 'domain/interfaces') or absolute paths:"
        echo "One per line, empty line to finish:"
        echo ""
        
        folders=()
        while true; do
            read -r -p "📁 Enter folder path: " folder_path
            
            # Break if empty line
            if [[ -z "$folder_path" ]]; then
                break
            fi
            
            # Resolve path (combine with default root if relative)
            resolved_path=$(resolve_path "$folder_path")
            folders+=("$resolved_path")
            
            echo "   → Resolved to: $resolved_path"
        done
        
        if [[ ${#folders[@]} -eq 0 ]]; then
            echo "❌ No folders provided. Exiting."
            exit 1
        fi
    else
        # Use command line arguments and resolve paths
        folders=()
        for arg in "$@"; do
            resolved_path=$(resolve_path "$arg")
            folders+=("$resolved_path")
        done
    fi
    
    echo ""
    echo "📝 Folders to process:"
    for folder in "${folders[@]}"; do
        echo "   • $folder"
    done
    echo ""
    
    # Create 'all' folder in script directory
    ALL_DIR="$SCRIPT_DIR/all"
    if [[ ! -d "$ALL_DIR" ]]; then
        mkdir "$ALL_DIR"
        echo "📁 Created 'all' folder at: $ALL_DIR"
    else
        echo "📁 'all' folder already exists at: $ALL_DIR"
    fi
    echo ""
    
    # Process each folder
    total_files=0
    total_excluded=0
    total_duplicates=0
    
    for folder_path in "${folders[@]}"; do
        # Check if folder exists
        if [[ ! -d "$folder_path" ]]; then
            echo "❌ Error: Directory '$folder_path' does not exist!"
            continue
        fi
        
        echo "🔍 Processing: $folder_path"
        
        # Generate tree structure
        generate_tree "$folder_path" "$SCRIPT_DIR"
        
        # Copy files from this folder
        echo "📂 Copying files from: $folder_path"
        
        # Find all files (not directories) and copy them
        while IFS= read -r -d '' file; do
            # Check if file should be excluded
            if should_exclude_file "$file"; then
                echo "   ⏭️  Excluded: $file"
                ((total_excluded++))
                continue
            fi
            
            # Get just the filename
            filename=$(basename "$file")
            
            # Check if file already exists in 'all' folder
            if [[ -f "$ALL_DIR/$filename" ]]; then
                # Create unique name by adding folder info and number
                folder_name=$(basename "$folder_path")
                counter=1
                name="${filename%.*}"
                ext="${filename##*.}"
                
                # If there's no extension, handle differently
                if [[ "$name" == "$ext" ]]; then
                    new_filename="${name}_${folder_name}_$counter"
                else
                    new_filename="${name}_${folder_name}_$counter.$ext"
                fi
                
                while [[ -f "$ALL_DIR/$new_filename" ]]; do
                    ((counter++))
                    if [[ "$name" == "$ext" ]]; then
                        new_filename="${name}_${folder_name}_$counter"
                    else
                        new_filename="${name}_${folder_name}_$counter.$ext"
                    fi
                done
                
                cp "$file" "$ALL_DIR/$new_filename"
                echo "   📄 Copied: $(basename "$file") → $new_filename (renamed to avoid conflict)"
                ((total_duplicates++))
            else
                cp "$file" "$ALL_DIR/$filename"
                echo "   📄 Copied: $(basename "$file")"
            fi
            
            ((total_files++))
            
        done < <(find "$folder_path" -type f -print0)
        
        echo ""
    done
    
    echo "🎉 All folders processed successfully!"
    echo ""
    echo "📊 SUMMARY:"
    echo "   📁 All files location: $ALL_DIR"
    echo "   📄 Total files copied: $total_files"
    echo "   ⏭️  Files excluded (__init__.py, __pycache__, .pyc): $total_excluded"
    if [[ $total_duplicates -gt 0 ]]; then
        echo "   🔄 Files renamed due to conflicts: $total_duplicates"
    fi
    echo ""
    echo "📋 Tree files created:"
    for folder_path in "${folders[@]}"; do
        safe_name=$(path_to_filename "$folder_path")
        echo "   • ${safe_name}_tree.txt"
    done
}

# Handle help flag
if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    show_usage
    exit 0
fi

# Run main function with all arguments
main "$@"