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
		vectorsDir = filepath.Join("..", "..", "..", "..", "jam-conformance", "fuzz-reports", "0.6.7")
	}

	// Create fuzzer client in in-process mode
	fuzzer := NewFuzzerClient("/tmp/jam_target.sock", true) // empty socket path, in-process mode
	if err := fuzzer.Connect(); err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer fuzzer.Disconnect()

	// Run the conformance test
	fuzzer.testDisputes(t, vectorsDir)
}

func TestStateTransitions(t *testing.T) {
	t.Log("Starting state transitions test vectors...")

	// Get the path to the test vectors directory
	vectorsDir := os.Getenv("TEST_VECTORS_DIR")
	if vectorsDir == "" {
		// Default to the conformance directory
		vectorsDir = filepath.Join("..", "..", "..", "..", "jam-test-vectors", "traces", "fallback")
	}

	// Create fuzzer client in in-process mode
	fuzzer := NewFuzzerClient("", true) // empty socket path, in-process mode
	if err := fuzzer.Connect(); err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer fuzzer.Disconnect()

	// Run the conformance test
	fuzzer.testStateTransitions(t, vectorsDir)
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
