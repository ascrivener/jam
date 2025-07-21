package pvm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"jam/pkg/ram"
	"jam/pkg/types"
)

// PVMTestVector represents a test case for the PVM
type PVMTestVector struct {
	// Test metadata
	Name string `json:"name"`

	// Initial state
	InitialRegs    []uint64                `json:"initial-regs"`
	InitialPC      uint64                  `json:"initial-pc"`
	InitialPageMap []PVMTestVectorPageMap  `json:"initial-page-map"`
	InitialMemory  []PVMTestVectorMemBlock `json:"initial-memory"`
	InitialGas     uint64                  `json:"initial-gas"`
	Program        json.RawMessage         `json:"program"` // Use RawMessage to correctly handle numeric array

	// Expected outcomes
	ExpectedStatus string                  `json:"expected-status"` // "ok", "panic", etc.
	ExpectedRegs   []uint64                `json:"expected-regs"`
	ExpectedPC     uint64                  `json:"expected-pc"`
	ExpectedMemory []PVMTestVectorMemBlock `json:"expected-memory"`
	ExpectedGas    uint64                  `json:"expected-gas"`
}

// PVMTestVectorPageMap describes a memory page mapping
type PVMTestVectorPageMap struct {
	Address    uint64 `json:"address"`
	Length     uint64 `json:"length"`
	IsWritable bool   `json:"is-writable"`
}

// PVMTestVectorMemBlock describes a block of memory content
type PVMTestVectorMemBlock struct {
	Address  uint64          `json:"address"`
	Contents json.RawMessage `json:"contents"` // Use RawMessage for numeric array
}

// Preprocess converts JSON numeric arrays to byte slices for Program and Contents fields
func (tv *PVMTestVector) Preprocess() error {
	// Handle program bytes
	var programNums []byte
	if err := json.Unmarshal(tv.Program, &programNums); err != nil {
		return fmt.Errorf("failed to parse program bytes: %w", err)
	}
	tv.Program = nil // Clear raw data

	// Handle memory contents
	for i := range tv.InitialMemory {
		var contentNums []byte
		if err := json.Unmarshal(tv.InitialMemory[i].Contents, &contentNums); err != nil {
			return fmt.Errorf("failed to parse memory contents for block %d: %w", i, err)
		}
		tv.InitialMemory[i].Contents = nil
	}

	for i := range tv.ExpectedMemory {
		var contentNums []byte
		if err := json.Unmarshal(tv.ExpectedMemory[i].Contents, &contentNums); err != nil {
			return fmt.Errorf("failed to parse expected memory contents for block %d: %w", i, err)
		}
		tv.ExpectedMemory[i].Contents = nil
	}

	return nil
}

// GetProgramBytes returns the program bytes
func (tv *PVMTestVector) GetProgramBytes() ([]byte, error) {
	var bytes []byte
	if err := json.Unmarshal(tv.Program, &bytes); err != nil {
		return nil, fmt.Errorf("failed to get program bytes: %w", err)
	}
	return bytes, nil
}

// GetMemoryContents returns memory contents for a block
func (block *PVMTestVectorMemBlock) GetContents() ([]byte, error) {
	var bytes []byte
	if err := json.Unmarshal(block.Contents, &bytes); err != nil {
		return nil, fmt.Errorf("failed to get memory contents: %w", err)
	}
	return bytes, nil
}

// LoadPVMTestVector loads a test vector from a JSON file
func LoadPVMTestVector(path string) (*PVMTestVector, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read test vector file: %w", err)
	}

	var testVector PVMTestVector
	if err := json.Unmarshal(data, &testVector); err != nil {
		return nil, fmt.Errorf("failed to parse test vector JSON: %w", err)
	}

	return &testVector, nil
}

// LoadPVMTestVectors loads all test vectors from a directory
func LoadPVMTestVectors(dirPath string) ([]*PVMTestVector, error) {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read test vectors directory: %w", err)
	}

	var testVectors []*PVMTestVector
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		testVector, err := LoadPVMTestVector(filepath.Join(dirPath, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("failed to load test vector %s: %w", entry.Name(), err)
		}

		testVectors = append(testVectors, testVector)
	}

	return testVectors, nil
}

func pvmFromTestVector(testVector *PVMTestVector) (*PVM, error) {
	// Get program bytes
	programBytes, err := testVector.GetProgramBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to get program bytes: %w", err)
	}

	// Create a RAM instance
	ramInstance := ram.NewEmptyRAM()

	// Create registers array from initial values
	var registers [13]types.Register
	for i, val := range testVector.InitialRegs {
		if i < len(registers) {
			registers[i] = types.Register(val)
		}
	}

	return NewPVM(programBytes, registers, ramInstance, types.Register(testVector.InitialPC), types.GasValue(testVector.InitialGas)), nil
}

// TestPVMWithDirectoryTestVectors runs all test vectors from a specific directory
func TestPVMWithDirectoryTestVectors(t *testing.T) {
	testVectorsDir := "/Users/adamscrivener/Projects/jam/pkg/jamtestvectorspvm/pvm/programs"

	// Load all test vectors from the directory
	testVectors, err := LoadPVMTestVectors(testVectorsDir)
	if err != nil {
		t.Fatalf("Failed to load test vectors: %v", err)
	}

	if len(testVectors) == 0 {
		t.Fatalf("No test vectors found in directory: %s", testVectorsDir)
	}

	t.Logf("Found %d test vectors in %s", len(testVectors), testVectorsDir)

	// Run each test vector
	for _, testVector := range testVectors {
		t.Run(testVector.Name, func(t *testing.T) {
			// Create PVM from test vector
			pvm, err := pvmFromTestVector(testVector)
			if err != nil {
				t.Fatalf("Failed to create PVM from test vector: %v", err)
			}

			// Setup memory pages (if not already done in pvmFromTestVector)
			for _, page := range testVector.InitialPageMap {
				accessType := ram.Inaccessible
				if page.IsWritable {
					accessType = ram.Mutable
				} else {
					accessType = ram.Immutable
				}
				pvm.State.RAM.MutateAccessRange(page.Address, page.Length, accessType, ram.NoWrap)
			}

			// Setup memory contents (if not already done in pvmFromTestVector)
			for _, memBlock := range testVector.InitialMemory {
				contents, err := memBlock.GetContents()
				if err != nil {
					t.Fatalf("Failed to get memory contents: %v", err)
				}
				pvm.State.RAM.MutateRange(memBlock.Address, contents, ram.NoWrap, false)
			}

			// // Run the PVM and track if it panicked
			// var exitReason ExitReason
			// var exitedWithPanic bool

			// func() {
			// 	defer func() {
			// 		if r := recover(); r != nil {
			// 			exitedWithPanic = true
			// 			t.Logf("PVM panicked: %v", r)
			// 		}
			// 	}()

			// 	// Run the PVM
			// 	exitReason = pvm.Ψ()
			// }()

			exitReason := pvm.Ψ()

			// Check exit status
			switch testVector.ExpectedStatus {
			case "ok":
				if exitReason.IsSimple() && *exitReason.SimpleExitReason != ExitGo {
					t.Errorf("Expected normal termination, but got exit reason: %v", exitReason)
				}
			case "panic":
				if !exitReason.IsSimple() || *exitReason.SimpleExitReason != ExitPanic {
					t.Errorf("Expected panic, but got exit reason: %v", exitReason)
				}
			default:
				t.Logf("Unknown expected status: %s", testVector.ExpectedStatus)
			}

			// // Skip further checks if panicked
			// if exitedWithPanic {
			// 	return
			// }

			// Check PC
			// if pvm.InstructionCounter != Register(testVector.ExpectedPC) {
			// 	t.Errorf("PC mismatch: got %d, want %d", pvm.InstructionCounter, testVector.ExpectedPC)
			// }

			// Check registers
			for i, expected := range testVector.ExpectedRegs {
				if i < len(pvm.State.Registers) && pvm.State.Registers[i] != types.Register(expected) {
					t.Errorf("Register %d mismatch: got %d, want %d", i, pvm.State.Registers[i], expected)
				}
			}

			// Check gas
			// if pvm.State.Gas != types.SignedGasValue(testVector.ExpectedGas) {
			// 	t.Errorf("Gas mismatch: got %d, want %d", pvm.State.Gas, testVector.ExpectedGas)
			// }

			// Check memory state
			for _, expectedMem := range testVector.ExpectedMemory {
				expectedContents, err := expectedMem.GetContents()
				if err != nil {
					t.Fatalf("Failed to get expected memory contents: %v", err)
				}

				// Read the actual memory from the same address
				actualContents := pvm.State.RAM.InspectRange(expectedMem.Address, uint64(len(expectedContents)), ram.NoWrap, false)

				// Compare memory contents
				if !bytes.Equal(actualContents, expectedContents) {
					t.Errorf("Memory content mismatch at address %d:", expectedMem.Address)
					t.Errorf("  Got:  %v", actualContents)
					t.Errorf("  Want: %v", expectedContents)
				}
			}

			// Help garbage collector by clearing references
			pvm.State.RAM = nil
			pvm.State = nil
			pvm = nil

			// Force garbage collection after each test
			runtime.GC()
		})
	}
}
