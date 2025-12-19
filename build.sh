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


# Build the Rust FFI library for a specific target
build_rust_library() {
    local target=$1
    echo -e "${BLUE}Building Rust FFI library for ${target}...${NC}"
    
    cd "${PROJECT_ROOT}/src/bandersnatch_ffi"
    
    # Build with appropriate flags
    # Disable LTO on Linux to avoid LLVM version mismatch with system linker
    if [[ "$target" == "x86_64-unknown-linux-gnu" ]]; then
        RUSTFLAGS="-C lto=off" cargo build --release --target="${target}"
    else
        cargo build --release --target="${target}"
    fi
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}Failed to build Rust FFI library for ${target}${NC}"
        return 1
    fi
    
    # For Linux, create archive index with ranlib
    if [[ "$target" == "x86_64-unknown-linux-gnu" ]]; then
        # Check if the library was built
        local lib_path="target/${target}/release/libbandersnatch_ffi.a"
        if [ ! -f "$lib_path" ]; then
            echo -e "${RED}Library file not found at ${lib_path}${NC}"
            return 1
        fi
        
        # Run ranlib to add archive index
        ranlib "$lib_path"
        echo -e "${GREEN}Added archive index to Linux library${NC}"
    fi
    
    echo -e "${GREEN}Successfully built Rust FFI library for ${target}${NC}"
}

# Generate constants for the specified network
generate_constants() {
    local network=$1
    
    echo -e "${BLUE}Generating constants for network: ${network}...${NC}"
    
    # Navigate to the constants directory
    cd "${PROJECT_ROOT}/src/go/pkg/constants"
    
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
    local source_dir=$4
    local network=$5
    local suffix="-${network}"
    
    # Generate constants for this specific network
    generate_constants ${network}
    
    # Build the binary with suffix
    local output_name="${binary_name}${suffix}"
    
    # Create bin directory if it doesn't exist
    local bin_dir="${PROJECT_ROOT}/bin"
    mkdir -p "${bin_dir}"
    
    echo -e "${BLUE}Building Go binary ${output_name} for ${goos}/${goarch}...${NC}"
    
    # Save current directory
    local current_dir=$(pwd)
    
    # Navigate to the source directory
    cd "${source_dir}"
    
    # Build the binary
    if [ "${goos}" == "darwin" ] && [ "${goarch}" == "arm64" ]; then
        # Native build for macOS ARM64
        go build -o "${bin_dir}/${output_name}" -ldflags="-s -w" -tags=netgo -a -installsuffix netgo -trimpath
    elif [ "${goos}" == "linux" ] && [ "${goarch}" == "amd64" ]; then
        # Native build for Linux AMD64
        # Set CGO flags to find the Rust library
        local rust_lib_dir="${PROJECT_ROOT}/src/bandersnatch_ffi/target/x86_64-unknown-linux-gnu/release"
        local rust_lib="${rust_lib_dir}/libbandersnatch_ffi.a"
        
        # Verify the library exists
        if [ ! -f "${rust_lib}" ]; then
            echo -e "${RED}Rust library not found at: ${rust_lib}${NC}"
            cd "${current_dir}"
            return 1
        fi
        
        echo -e "${BLUE}Using Rust library: ${rust_lib}${NC}"
        
        # Use absolute path to the library file directly
        CGO_ENABLED=1 CGO_LDFLAGS="${rust_lib}" \
        go build -o "${bin_dir}/${output_name}" -ldflags="-s -w" -tags=netgo -trimpath
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
    
    echo -e "${GREEN}Successfully built ${output_name} -> ${bin_dir}/${output_name}${NC}"
    
    # Return to the original directory
    cd "${current_dir}"
}

# Build a specific platform with tiny variant
build_platform() {
    local goos=$1
    local goarch=$2
    local rust_target=$3
    
    echo -e "${BLUE}Building for platform: ${goos}/${goarch} (${rust_target})${NC}"
    
    # Build Rust library
    build_rust_library "${rust_target}" || return 1
    
    # Build jamzilla with tiny constants
    fuzzserver_dir="${PROJECT_ROOT}/src/go/cmd/fuzzer/fuzzserver"
    build_binary "${goos}" "${goarch}" "jamzilla" "${fuzzserver_dir}" "tiny" || return 1
    
    echo -e "${GREEN}Platform ${goos}/${goarch} built successfully${NC}"
}

# Check if a command is available
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Install required tools
install_prerequisites() {
    echo -e "${BLUE}Checking prerequisites...${NC}"
    
    # Check for Rust (required on all platforms)
    if ! command_exists rustup; then
        echo -e "${RED}Rust is not installed. Please install Rust first.${NC}"
        echo -e "Visit: https://rustup.rs/${NC}"
        return 1
    fi
    
    # Check for Go (required on all platforms)
    if ! command_exists go; then
        echo -e "${RED}Go is not installed. Please install Go first.${NC}"
        return 1
    fi
    
    echo -e "${GREEN}Prerequisites satisfied!${NC}"
    return 0
}

# Main build flow
main() {
    # Detect current platform
    local os_type=$(uname -s)
    local arch_type=$(uname -m)
    
    echo -e "${BLUE}Building for current platform: ${os_type}/${arch_type}${NC}"
    
    # Check and install prerequisites
    install_prerequisites || exit 1
    
    # Build based on platform
    if [ "$os_type" == "Darwin" ]; then
        if [ "$arch_type" == "arm64" ] || [ "$arch_type" == "aarch64" ]; then
            build_platform "darwin" "arm64" "aarch64-apple-darwin" || exit 1
        else
            echo -e "${RED}Unsupported macOS architecture: ${arch_type}${NC}"
            exit 1
        fi
    elif [ "$os_type" == "Linux" ]; then
        if [ "$arch_type" == "x86_64" ]; then
            build_platform "linux" "amd64" "x86_64-unknown-linux-gnu" || exit 1
        else
            echo -e "${RED}Unsupported Linux architecture: ${arch_type}${NC}"
            exit 1
        fi
    else
        echo -e "${RED}Unsupported operating system: ${os_type}${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}Build completed successfully!${NC}"
    echo -e "${BLUE}Binary available at: ${PROJECT_ROOT}/bin/jamzilla-tiny${NC}"
}

# Execute the main function
main "$@"
