#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

PROJECT_ROOT=$(pwd)
echo -e "${BLUE}Building Jam project at: ${PROJECT_ROOT}${NC}"

# Detect platform and set target
OS_TYPE=$(uname -s)
ARCH_TYPE=$(uname -m)

case "${OS_TYPE}-${ARCH_TYPE}" in
    Darwin-arm64|Darwin-aarch64)
        RUST_TARGET="aarch64-apple-darwin"
        ;;
    Linux-x86_64)
        RUST_TARGET="x86_64-unknown-linux-gnu"
        ;;
    *)
        echo -e "${RED}Unsupported platform: ${OS_TYPE}/${ARCH_TYPE}${NC}"
        exit 1
        ;;
esac

echo -e "${BLUE}Building for ${OS_TYPE}/${ARCH_TYPE} (${RUST_TARGET})${NC}"

# Check prerequisites
if ! command -v rustup >/dev/null 2>&1; then
    echo -e "${RED}Rust is not installed. Visit: https://rustup.rs/${NC}"
    exit 1
fi

if ! command -v go >/dev/null 2>&1; then
    echo -e "${RED}Go is not installed${NC}"
    exit 1
fi

# Build Rust FFI library
echo -e "${BLUE}Building Rust FFI library...${NC}"
cd "${PROJECT_ROOT}/src/bandersnatch_ffi"
cargo build --release --target="${RUST_TARGET}"
echo -e "${GREEN}Rust FFI library built${NC}"

# Generate constants
echo -e "${BLUE}Generating constants for tiny network...${NC}"
cd "${PROJECT_ROOT}/src/go/pkg/constants"
rm -f constants.go
go run config_gen.go -network tiny -output constants.go
echo -e "${GREEN}Constants generated${NC}"

# Build Go binary
echo -e "${BLUE}Building jamzilla-tiny...${NC}"
mkdir -p "${PROJECT_ROOT}/bin"
cd "${PROJECT_ROOT}/src/go/cmd/fuzzer/fuzzserver"

RUST_LIB="${PROJECT_ROOT}/src/bandersnatch_ffi/target/${RUST_TARGET}/release/libbandersnatch_ffi.a"
CGO_ENABLED=1 CGO_LDFLAGS="${RUST_LIB}" \
    go build -o "${PROJECT_ROOT}/bin/jamzilla-tiny" \
    -ldflags="-s -w" -tags=netgo -trimpath

echo -e "${GREEN}Build completed successfully!${NC}"
echo -e "${BLUE}Binary: ${PROJECT_ROOT}/bin/jamzilla-tiny${NC}"
