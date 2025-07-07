FROM alpine:latest

WORKDIR /app

# Copy the fuzzserver and fuzzclient executables to the container
COPY fuzzserver-amd64-linux /app/fuzzserver
COPY fuzzclient-amd64-linux /app/fuzzclient

# Make sure executables are runnable
RUN chmod +x /app/fuzzserver /app/fuzzclient

# Create data directory
RUN mkdir -p /app/data

# Create test vectors directory
RUN mkdir -p /app/jam-test-vectors/traces/reports-l1

# Copy test vectors from host (relative to build context)
# Note: You need to copy or symlink test vectors to the build context first
COPY reports-l1/ /app/jam-test-vectors/traces/reports-l1/

# Create startup script that runs both server and client
RUN echo '#!/bin/sh' > /app/start.sh && \
    echo 'set -x' >> /app/start.sh && \
    echo 'echo "Starting fuzzserver..."' >> /app/start.sh && \
    echo '/app/fuzzserver -socket /app/jam_target.sock &' >> /app/start.sh && \
    echo 'server_pid=$!' >> /app/start.sh && \
    echo 'echo "Waiting for server to start..."' >> /app/start.sh && \
    echo 'sleep 2' >> /app/start.sh && \
    echo 'echo "Starting fuzzclient..."' >> /app/start.sh && \
    echo '/app/fuzzclient -socket /app/jam_target.sock -vectors /app/jam-test-vectors/traces/reports-l1' >> /app/start.sh && \
    echo 'client_status=$?' >> /app/start.sh && \
    echo 'echo "Client exited with status: $client_status"' >> /app/start.sh && \
    echo 'kill $server_pid' >> /app/start.sh && \
    echo 'wait $server_pid' >> /app/start.sh && \
    echo 'exit $client_status' >> /app/start.sh && \
    chmod +x /app/start.sh

# Run the startup script
ENTRYPOINT ["/app/start.sh"]