package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConformanceVectors(t *testing.T) {
	t.Log("Starting conformance test vectors...")

	vectorsDir := os.Getenv("TEST_VECTORS_DIR")
	if vectorsDir == "" {
		vectorsDir = filepath.Join("..", "..", "..", "..", "..", "jam-test-vectors", "traces")
	}

	useSocket := os.Getenv("USE_SOCKET") == "true"
	inProcess := !useSocket

	fuzzer := NewFuzzerClient("/tmp/jam_target.sock", inProcess)
	if err := fuzzer.Connect(); err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer fuzzer.Disconnect()

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
