# JAM Implementation (Jamzilla)

A high-performance implementation of the JAM (Join-Accumulate Machine) protocol in Go with Rust cryptographic primitives.

## Quick Start

```bash
# Build
./build.sh

# Run the server
./bin/jamzilla-tiny

# In another terminal, run conformance tests
cd src/go
go test ./cmd/fuzzer/fuzzclient -run TestConformanceVectors -v
```

## Prerequisites

### macOS (Development Platform)

1. **Go** (1.21 or later)
   ```bash
   brew install go
   ```

2. **Rust** (latest stable)
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

3. **Linux Cross-Compiler** (for building Linux binaries on macOS)
   ```bash
   brew install SergioBenitez/osxct/x86_64-unknown-linux-gnu
   ```

### Linux

1. **Go** (1.21 or later)
2. **Rust** (latest stable)
3. **GCC** (for CGO compilation)

## Building

### Quick Build (Current Platform)

```bash
./build.sh
```

This will build the binary for your current platform in `bin/`.

### Build for All Platforms

```bash
./build.sh --all
```

This will build:
- `bin/jamzilla-tiny-arm64-darwin` (macOS ARM64)
- `bin/jamzilla-tiny-amd64-linux` (Linux AMD64)

Note: Cross-compilation requires platform-specific tools (e.g., Linux cross-compiler on macOS)

### Manual Build (Current Platform Only)

```bash
cd src/go/cmd/fuzzer/fuzzserver
go build -o jamzilla
```

## Running

### Start the Fuzzer Interface Server

```bash
./bin/jamzilla-tiny
```

Default socket: `/tmp/jam_target.sock`

### Custom Socket Path

```bash
./bin/jamzilla-tiny --socket /path/to/custom.sock
```

### Available Options

```bash
./bin/jamzilla-tiny --help
```

## Testing

### Sending Messages to the Socket

The jamzilla server communicates via Unix socket using a binary protocol. Messages are framed with a 4-byte little-endian length prefix followed by the message payload.

Example using the fuzzclient:

```bash
# Start the server in one terminal
./bin/jamzilla-tiny

# In another terminal, run conformance tests
cd src/go
go test ./cmd/fuzzer/fuzzclient -run TestConformanceVectors -v
```

The fuzzclient can send various message types to test the server:
- **PeerInfo**: Handshake and version negotiation
- **SetState**: Initialize blockchain state
- **ImportBlock**: Process and validate blocks
- **GetState**: Retrieve current state

See `src/go/cmd/fuzzer/fuzzclient/main.go` for protocol details and message formats.

## Project Structure

```
jam/
├── bin/                          # Compiled binaries (gitignored)
├── src/
│   ├── bandersnatch_ffi/        # Rust cryptographic library
│   └── go/
│       ├── cmd/
│       │   └── fuzzer/
│       │       ├── fuzzserver/  # Main jamzilla server
│       │       └── fuzzclient/  # Test client
│       └── pkg/                 # Core JAM implementation
├── jam-conformance/             # Conformance test vectors (submodule)
├── build.sh                     # Cross-platform build script
└── README.md                    # This file
```

## Development

### VS Code Launch Configurations

The project includes VS Code launch configurations for debugging:

- **JAM Fuzzserver**: Debug the main server
- **TestFuzzerVersion**: Run version compatibility tests
- **TestStateTransitions**: Run state transition conformance tests

### Profiling

CPU profiling is available via the fuzzer interface. Profiles are written to `cpu.prof` and can be analyzed with:

```bash
go tool pprof -http=:8080 cpu.prof
```

## Network Configurations

The build system supports two network configurations:

- **tiny**: Minimal validator set for testing (default)
- **full**: Full production validator set (commented out in build.sh)

To switch configurations, edit `build.sh` and uncomment the desired variant.

## Architecture

- **Language**: Go with Rust FFI for cryptographic operations
- **Database**: Pebble (LevelDB-compatible key-value store)
- **Networking**: QUIC-based protocol (JAMNP-S)
- **VM**: Custom PVM (Polkadot Virtual Machine) implementation

## License

See LICENSE file for details.
