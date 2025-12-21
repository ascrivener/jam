package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConformanceVectors(t *testing.T) {
	t.Log("Starting conformance test vectors...")

	// Get the path to the test vectors directory
	vectorsDir := os.Getenv("TEST_VECTORS_DIR")
	if vectorsDir == "" {
		// Default to the conformance directory
		vectorsDir = filepath.Join("..", "..", "..", "..", "..", "jam-test-vectors", "traces")
	}

	// Check if we should use socket mode (default is in-process)
	useSocket := os.Getenv("USE_SOCKET") == "true"
	inProcess := !useSocket

	// Create fuzzer client
	fuzzer := NewFuzzerClient("/tmp/jam_target.sock", inProcess)
	if err := fuzzer.Connect(); err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer fuzzer.Disconnect()

	// Run the conformance test
	fuzzer.testDisputes(t, vectorsDir)
}

func TestFuzzerVersion(t *testing.T) {
	dir := os.Getenv("TEST_DIR")

	fuzzer := NewFuzzerClient("", true)
	if err := fuzzer.Connect(); err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer fuzzer.Disconnect()

	fuzzer.testFuzzerVersion(t, dir)
}
