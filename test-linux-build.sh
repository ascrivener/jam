#!/bin/bash
# Quick test script to verify build.sh works on Linux via Docker

echo "Testing build.sh on Linux (Docker)..."
echo ""

docker run --rm --platform linux/amd64 \
  -v "$(pwd):/workspace" \
  -w /workspace \
  ubuntu:22.04 bash -c "
    apt-get update -qq && \
    apt-get install -y -qq curl gcc git build-essential && \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && \
    . \$HOME/.cargo/env && \
    curl -sL https://go.dev/dl/go1.21.0.linux-amd64.tar.gz | tar -C /usr/local -xz && \
    export PATH=\$PATH:/usr/local/go/bin && \
    git config --global --add safe.directory /workspace && \
    git submodule update --init --recursive && \
    echo '=== Building ===' && \
    ./build.sh && \
    echo '=== Verifying binary ===' && \
    ls -lh bin/jamzilla-tiny && \
    file bin/jamzilla-tiny && \
    echo '=== Running conformance tests ===' && \
    cd src/go && \
    go test ./cmd/fuzzer/fuzzclient -run TestConformanceVectors -v && \
    echo '=== ALL TESTS PASSED ON LINUX ==='
  "

echo ""
echo "If you see 'BUILD SUCCESS ON LINUX' above, the build works!"
