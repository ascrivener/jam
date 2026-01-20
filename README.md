# JAM Implementation (Jamzilla)

A high-performance implementation of the JAM (Join-Accumulate Machine) protocol in Go with Rust cryptographic primitives.

> **Platform Requirements**: This implementation requires **Linux x86-64** due to JIT compilation and memory protection features (mmap/mprotect). macOS and Windows are not supported.

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

### macOS

1. **Go** (1.21 or later)
   ```bash
   brew install go
   ```

2. **Rust** (latest stable)
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

### Linux

1. **Go** (1.21 or later)
2. **Rust** (latest stable)
3. **GCC** (for CGO compilation)
   ```bash
   sudo apt-get install build-essential
   ```

## Building

### Build

```bash
./build.sh
```

This will build `bin/jamzilla-tiny` for your current platform.

### Manual Build

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
