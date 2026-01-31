//go:build !linux || !amd64

// Package jit provides stub types for non-Linux platforms.
// The real JIT implementation is only available on linux/amd64.
package jit

// ProgramContext is a stub for non-Linux platforms
type ProgramContext struct{}
