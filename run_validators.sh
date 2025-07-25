#!/bin/bash

# Path to the polkajam binary
POLKAJAM="./polkajam"
LOG_DIR="/tmp/jam-logs"
mkdir -p "$LOG_DIR"

# Set comprehensive trace-level logging for network components
LOG_LEVEL="info,safrole=debug,jam_node::network=trace,network=trace,sync=debug,libp2p=trace,yamux=trace,sc_network=trace,substrate_network=trace,substrate=trace,sc_peerset=trace,tls=trace,rustls=trace"

echo "Starting validators 0-5 in parallel..."

# Array to keep track of all PIDs
declare -a PIDS

# Function to run a validator as a background process
run_validator() {
  local validator_id=$1
  local data_path="/tmp/jam-validator-${validator_id}"
  local log_file="${LOG_DIR}/validator-${validator_id}.log"
  local port=$((40000 + validator_id))
  local rpc_port=$((19900 + validator_id))  # Unique RPC port for each validator
  
  # Create data directory if it doesn't exist
  mkdir -p "$data_path"
  
  echo "Starting validator $validator_id..."
  # Run the validator in the background with output to log file
  # Add RUST_LOG environment variable for detailed logging
  RUST_LOG=$LOG_LEVEL $POLKAJAM run --dev-validator $validator_id --data-path "$data_path" --rpc-port $rpc_port > "$log_file" 2>&1 &
  
  # Get process ID of the background process
  local pid=$!
  echo "Started validator $validator_id (PID: $pid) - Logs at $log_file"
  
  # Add PID to the array
  PIDS+=($pid)
}

# Launch validators 0 through 5 in parallel
for i in {1..5}; do
  run_validator $i &
done

# Wait for all the run_validator functions to complete
wait

# Give the validators a moment to start up
sleep 3

# Verify all validators are running
echo "Checking if all validators are running:"
for pid in "${PIDS[@]}"; do
  if ps -p $pid > /dev/null; then
    validator=$(ps -p $pid -o command= | grep -o "validator [0-9]" | cut -d' ' -f2)
    echo "✓ Validator $validator confirmed running (PID: $pid)"
  else
    validator=$(ps -p $pid -o command= 2>/dev/null | grep -o "validator [0-9]" | cut -d' ' -f2)
    if [ -z "$validator" ]; then
      echo "⚠️ Warning: Process $pid has terminated. Check logs for errors."
    else
      echo "⚠️ Warning: Validator $validator process (PID: $pid) terminated. Check logs for errors."
    fi
    log_file="${LOG_DIR}/validator-${validator}.log"
    if [ -f "$log_file" ]; then
      tail -n 20 "$log_file"
    fi
  fi
done

echo "All validators started. Checking processes:"
ps aux | grep "polkajam run --dev-validator" | grep -v grep

echo "You can now run validator 0 in VS Code using the 'Debug Jamzilla' configuration."
echo "Logs are available in $LOG_DIR"
