#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Project root directory
PROJECT_ROOT=$(pwd)
echo -e "${BLUE}Building Jam project at: ${PROJECT_ROOT}${NC}"

# Set up Rust target configuration
setup_rust_targets() {
    echo -e "${BLUE}Setting up Rust cross-compilation configuration...${NC}"
    
    # Create .cargo directory if it doesn't exist
    mkdir -p ~/.cargo
    
    # Create or update config file
    cat > ~/.cargo/config.toml << EOF
[target.x86_64-unknown-linux-gnu]
linker = "x86_64-unknown-linux-gnu-gcc"
EOF
    
    echo -e "${GREEN}Rust cross-compilation config updated${NC}"
    
    # Add targets if needed
    local targets=("x86_64-unknown-linux-gnu")
    for target in "${targets[@]}"; do
        if ! rustup target list | grep -q "$target"; then
            echo -e "${BLUE}Adding Rust target for ${target}...${NC}"
            rustup target add "$target"
        fi
    done
}

# Build the Rust FFI library for a specific target
build_rust_library() {
    local target=$1
    echo -e "${BLUE}Building Rust FFI library for ${target}...${NC}"
    
    cd "${PROJECT_ROOT}/bandersnatch_ffi"
    
    # Build with appropriate flags
    cargo build --release --target="${target}"
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}Failed to build Rust FFI library for ${target}${NC}"
        return 1
    fi
    
    # For Linux, we need to make sure the library is named correctly and visible
    if [[ "$target" == "x86_64-unknown-linux-gnu" ]]; then
        # Check if the library was built
        local lib_path="target/${target}/release/libbandersnatch_ffi.a"
        if [ ! -f "$lib_path" ]; then
            echo -e "${RED}Library file not found at ${lib_path}${NC}"
            return 1
        fi
        
        # Create a directory in /tmp that the linker can find
        mkdir -p /tmp/jam_crossbuild/lib
        cp "$lib_path" /tmp/jam_crossbuild/lib/
        echo -e "${GREEN}Copied Linux library to /tmp/jam_crossbuild/lib/libbandersnatch_ffi.a${NC}"
    fi
    
    echo -e "${GREEN}Successfully built Rust FFI library for ${target}${NC}"
}

# Generate constants for the specified network
generate_constants() {
    local network=$1
    
    echo -e "${BLUE}Generating constants for network: ${network}...${NC}"
    
    # Navigate to the constants directory
    cd "${PROJECT_ROOT}/go/constants"
    
    # Clean up any existing generated files first
    rm -f constants.go
    
    # Generate constants for the specified network
    go run config_gen.go -network ${network} -output constants.go
    
    echo -e "${GREEN}Constants generated successfully for ${network}${NC}"
    cd "${PROJECT_ROOT}"
}

# Function to build Go binary
build_binary() {
    local goos=$1
    local goarch=$2
    local binary_name=$3
    local output_dir=$4
    local network=$5
    local suffix="-${network}"
    
    # Generate constants for this specific network
    generate_constants ${network}
    
    # Build the binary with suffix
    local output_name="${binary_name}${suffix}-${goarch}-${goos}"
    
    echo -e "${BLUE}Building Go binary ${output_name} for ${goos}/${goarch}...${NC}"
    
    # Save current directory
    local current_dir=$(pwd)
    
    # Navigate to the binary's directory
    cd "${output_dir}"
    
    # Set the appropriate environment variables for cross-compilation
    if [ "${goos}" == "darwin" ] && [ "${goarch}" == "arm64" ]; then
        # Native build for macOS ARM64
        go build -o "${output_name}" -ldflags="-s -w" -tags=netgo -a -installsuffix netgo -trimpath
    elif [ "${goos}" == "linux" ] && [ "${goarch}" == "amd64" ]; then
        # Cross-compile for Linux AMD64 with static linking
        # Add the temporary directory to the library path
        GOOS=linux GOARCH=amd64 CGO_ENABLED=1 CC=x86_64-unknown-linux-gnu-gcc \
        CGO_LDFLAGS="-L/tmp/jam_crossbuild/lib -static -ldl" \
        go build -o "${output_name}" -ldflags="-s -w -linkmode=external -extldflags=-static" \
          -tags="netgo,osusergo" -trimpath
    else
        echo -e "${YELLOW}Skipping unsupported target: ${goos}/${goarch}${NC}"
        cd "${current_dir}"
        return 0
    fi
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}Failed to build Go binary for ${goos}/${goarch}${NC}"
        cd "${current_dir}"
        return 1
    fi
    
    echo -e "${GREEN}Successfully built ${output_name}${NC}"
    
    # Return to the original directory
    cd "${current_dir}"
}

# Build a specific platform with both tiny and full variants
build_platform() {
    local goos=$1
    local goarch=$2
    local rust_target=$3
    
    echo -e "${BLUE}Building for platform: ${goos}/${goarch} (${rust_target})${NC}"
    
    # Build Rust library (only need to do this once per platform)
    build_rust_library "${rust_target}" || return 1
    
    # Build fuzzserver with tiny constants
    fuzzserver_dir="${PROJECT_ROOT}/go/cmd/fuzzer/fuzzserver"
    build_binary "${goos}" "${goarch}" "fuzzserver" "${fuzzserver_dir}" "tiny" || return 1
    
    # Build fuzzserver with full constants
    build_binary "${goos}" "${goarch}" "fuzzserver" "${fuzzserver_dir}" "full" || return 1
    
    echo -e "${GREEN}Platform ${goos}/${goarch} built successfully${NC}"
}

# Check if a command is available
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Install required tools
install_prerequisites() {
    echo -e "${BLUE}Checking and installing prerequisites...${NC}"
    
    # Check if we're on macOS
    if [[ "$(uname)" != "Darwin" ]]; then
        echo -e "${RED}This script is designed to run on macOS.${NC}"
        return 1
    fi
    
    # Check for Rust
    if ! command_exists rustup; then
        echo -e "${RED}Rust is not installed. Please install Rust first.${NC}"
        return 1
    fi
    
    # Check for the cross-compiler
    if ! command_exists x86_64-unknown-linux-gnu-gcc; then
        echo -e "${RED}Linux cross-compiler not found. Please install it with:${NC}"
        echo -e "brew install SergioBenitez/osxct/x86_64-unknown-linux-gnu"
        return 1
    fi
    
    echo -e "${GREEN}All prerequisites satisfied!${NC}"
    return 0
}

# Main build flow
main() {
    # Create temporary directory for cross-compilation
    mkdir -p /tmp/jam_crossbuild
    
    # Check and install prerequisites
    install_prerequisites || exit 1
    
    # Set up Rust targets and configuration
    setup_rust_targets || exit 1
    
    echo -e "${BLUE}Starting builds for all platforms...${NC}"
    
    # Build for current platform (ARM64 macOS)
    # build_platform "darwin" "arm64" "aarch64-apple-darwin" || exit 1
    
    # Build for AMD64 Linux
    build_platform "linux" "amd64" "x86_64-unknown-linux-gnu" || exit 1
    
    # Build the fuzzclient for Linux AMD64 with both tiny and full variants
    echo -e "${BLUE}Building Linux AMD64 fuzzclient variants...${NC}"
    fuzzclient_dir="${PROJECT_ROOT}/go/cmd/fuzzer/fuzzclient"
    build_binary "linux" "amd64" "fuzzclient" "${fuzzclient_dir}" "tiny" || exit 1
    build_binary "linux" "amd64" "fuzzclient" "${fuzzclient_dir}" "full" || exit 1
    echo -e "${GREEN}Successfully built fuzzclient variants for Linux AMD64${NC}"
    
    echo -e "${GREEN}All builds completed successfully!${NC}"
    echo -e "${BLUE}Binaries are available in: ${PROJECT_ROOT}/go/cmd/fuzzer/fuzzserver/ and ${PROJECT_ROOT}/go/cmd/fuzzer/fuzzclient/${NC}"
}

# Execute the main function
main
