FROM alpine:latest

WORKDIR /app

# Copy the fuzzserver and fuzzclient executables to the container
COPY src/go/cmd/fuzzer/fuzzserver/fuzzserver-tiny-amd64-linux /app/fuzzserver
COPY src/go/cmd/fuzzer/fuzzclient/fuzzclient-tiny-amd64-linux /app/fuzzclient

# Make sure executables are runnable
RUN chmod +x /app/fuzzserver /app/fuzzclient

# Create test vectors directories
RUN mkdir -p /app/jam-test-vectors/traces

# Copy test vectors from host (relative to build context)
COPY jam-test-vectors/traces/ /app/jam-test-vectors/traces/

# Default test vectors (can be overridden at runtime)
ENV TEST_VECTORS=fallback

# Create startup script that runs both server and client
RUN echo '#!/bin/sh' > /app/start.sh && \
    echo 'set -x' >> /app/start.sh && \
    echo 'echo "Starting fuzzserver..."' >> /app/start.sh && \
    echo '/app/fuzzserver -socket /app/jam_target.sock &' >> /app/start.sh && \
    echo 'server_pid=$!' >> /app/start.sh && \
    echo 'echo "Waiting for server to start..."' >> /app/start.sh && \
    echo 'sleep 2' >> /app/start.sh && \
    echo 'echo "Starting fuzzclient with test vectors: $TEST_VECTORS"' >> /app/start.sh && \
    echo '/app/fuzzclient -socket /app/jam_target.sock -vectors /app/jam-test-vectors/traces/$TEST_VECTORS' >> /app/start.sh && \
    echo 'client_status=$?' >> /app/start.sh && \
    echo 'echo "Client exited with status: $client_status"' >> /app/start.sh && \
    echo 'kill $server_pid' >> /app/start.sh && \
    echo 'wait $server_pid' >> /app/start.sh && \
    echo 'exit $client_status' >> /app/start.sh && \
    chmod +x /app/start.sh

# Run the startup script
ENTRYPOINT ["/app/start.sh"]