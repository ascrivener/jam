#!/bin/bash

# 5-Node Testnet Launch Script
# Starts 5 JAM nodes on ports 40000-40004

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_PATH="$SCRIPT_DIR/testnet.json"

# Check if config exists
if [ ! -f "$CONFIG_PATH" ]; then
    echo "Error: Config file not found at $CONFIG_PATH"
    exit 1
fi

# Create data directories
for i in {0..4}; do
    mkdir -p "$SCRIPT_DIR/data/node$i"
done

echo "Starting 5-node testnet..."
echo "Config: $CONFIG_PATH"
echo ""

# Array to store PIDs
PIDS=()

# Cleanup function
cleanup() {
    echo ""
    echo "Shutting down nodes..."
    for pid in "${PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
    done
    wait
    echo "All nodes stopped."
}

# Set trap for cleanup
trap cleanup EXIT INT TERM

# Start each node
for i in {0..4}; do
    echo "Starting Node $i on port $((40000 + i))..."
    go run "$SCRIPT_DIR/main.go" \
        --config-path="$CONFIG_PATH" \
        --dev-validator=$i \
        --data-path="$SCRIPT_DIR/data/node$i" \
        2>&1 | sed "s/^/[Node $i] /" &
    PIDS+=($!)
    
    # Small delay between node starts to avoid race conditions
    sleep 0.5
done

echo ""
echo "All 5 nodes started. Press Ctrl+C to stop."
echo ""

# Wait for all background processes
wait
