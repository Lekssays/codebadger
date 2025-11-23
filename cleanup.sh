#!/bin/bash
# Minimal cleanup script for CodeBadger
# Cleans codebases (except core) and CPGs

set -e

PLAYGROUND_PATH="./playground"
CODEBASES_PATH="$PLAYGROUND_PATH/codebases"
CPGS_PATH="$PLAYGROUND_PATH/cpgs"

echo "🧹 CodeBadger Cleanup"
echo "=============================="

# Clean codebases (except core)
if [ -d "$CODEBASES_PATH" ]; then
    echo "Cleaning codebases (keeping core)..."
    find "$CODEBASES_PATH" -maxdepth 1 -type d ! -name "core" ! -name "codebases" -exec rm -rf {} + 2>/dev/null || true
    echo "✓ Codebases cleaned"
else
    echo "⚠ Codebases directory not found"
fi

# Clean CPGs
if [ -d "$CPGS_PATH" ]; then
    echo "Cleaning CPGs..."
    rm -rf "$CPGS_PATH"/*
    echo "✓ CPGs cleaned"
else
    echo "⚠ CPGs directory not found"
fi

# Clean SQLite database
if [ -f "codebadger.db" ]; then
    echo "Cleaning SQLite database..."
    rm "codebadger.db"
    echo "✓ SQLite database removed"
else
    echo "⚠ SQLite database not found"
fi

echo ""
echo "✅ Cleanup complete!"
