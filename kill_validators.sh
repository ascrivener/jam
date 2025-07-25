#!/bin/bash

echo "Stopping all JAM validators..."

# Kill validator processes
pkill -f "polkajam run --dev-validator"

# Give processes time to terminate
sleep 1

# Check for any remaining processes on the RPC ports
rpc_processes=$(lsof -i :19800-19805 | grep LISTEN | awk '{print $2}' | sort | uniq)

if [ ! -z "$rpc_processes" ]; then
  echo "Cleaning up RPC port processes..."
  echo "$rpc_processes" | xargs kill
  sleep 1
fi

# Final check for any remaining polkajam processes
remaining=$(ps aux | grep polkajam | grep -v grep)
if [ ! -z "$remaining" ]; then
  echo "Force killing any remaining polkajam processes..."
  pkill -9 -f polkajam
fi

# Always remove logs
echo "Cleaning up log files..."
rm -rf /tmp/jam-logs

echo "Cleaning up validator data directories..."
rm -rf /tmp/jam-validator-*
echo "Data directories removed"

echo "All validators stopped"