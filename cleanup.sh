#!/bin/bash
# Minimal cleanup script for CodeBadger Toolkit
# Cleans codebases (except core), CPGs, and flushes Redis

set -e

PLAYGROUND_PATH="./playground"
CODEBASES_PATH="$PLAYGROUND_PATH/codebases"
CPGS_PATH="$PLAYGROUND_PATH/cpgs"

echo "🧹 CodeBadger Toolkit Cleanup"
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

# Flush Redis inside container
echo "Flushing Redis..."
docker exec codebadger-joern-server redis-cli FLUSHALL >/dev/null 2>&1 && echo "✓ Redis flushed" || echo "⚠ Redis flush failed (container may not be running)"

echo ""
echo "✅ Cleanup complete!"
