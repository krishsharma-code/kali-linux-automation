#!/bin/bash

# dir_setup.sh
# This script automates the creation of a basic project directory structure.

# Check if a project name was provided.
if [ -z "$1" ]; then
    echo "Usage: ./dir_setup.sh <project_name>"
    exit 1
fi

PROJECT_NAME=$1

echo "Setting up directory structure for: $PROJECT_NAME"

# 'mkdir -p' creates parent directories as needed and avoids errors if the directory already exists.
mkdir -p "$PROJECT_NAME/src"
mkdir -p "$PROJECT_NAME/docs"
mkdir -p "$PROJECT_NAME/tests"
mkdir -p "$PROJECT_NAME/bin"

# 'touch' creates empty files.
touch "$PROJECT_NAME/README.md"
touch "$PROJECT_NAME/.gitignore"

echo "Success! Directory structure created for '$PROJECT_NAME'."
ls -R "$PROJECT_NAME"
