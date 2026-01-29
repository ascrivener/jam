package jit

import (
	"jam/pkg/types"
	"testing"
	"unsafe"
)

// TestSimpleLoadImm tests that load_imm correctly sets a register
func TestSimpleLoadImm(t *testing.T) {
	runtime, err := NewRuntime()
	if err != nil {
		t.Fatalf("Failed to create runtime: %v", err)
	}

	// Create a simple program: load_imm R0, 42; then exit
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 42, SkipLength: 0, BeginsBlock: true}, // load_imm R0, 42
		{PC: 1, Opcode: 0, SkipLength: 0},                                    // trap (causes panic exit)
	}

	err = runtime.CompileProgram(instructions, nil)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := runtime.GetBlock(0)
	if block == nil {
		t.Fatal("No block compiled for PC 0")
	}

	t.Logf("Block compiled: StartPC=%d, EndPC=%d, EntryPoint=0x%x, CodeSize=%d",
		block.StartPC, block.EndPC, block.EntryPoint, block.CodeSize)

	if block.EntryPoint == 0 {
		t.Fatal("EntryPoint is null!")
	}

	// Dump first 32 bytes of generated code
	codePtr := (*[32]byte)(unsafe.Pointer(block.EntryPoint))
	t.Logf("Code bytes: %x", codePtr[:])

	// Create state with FakeRAM - avoids 4GB mmap
	fakeRAM := &FakeRAM{buffer: make([]byte, 4096)}
	state := &State{
		Gas:       100,
		Registers: [13]types.Register{},
		RAM:       fakeRAM,
	}

	// Execute
	statePtr := unsafe.Pointer(state)
	exitEncoded, _ := runtime.ExecuteBlock(block, statePtr)

	// Check R0 was set to 42
	if state.Registers[0] != 42 {
		t.Errorf("R0 = %d, want 42", state.Registers[0])
	}

	// Should have exited with panic (trap instruction)
	if exitEncoded != 2 {
		t.Errorf("exitEncoded = %d, want 2 (panic)", exitEncoded)
	}

	t.Logf("R0 = %d, exit = %d, gas = %d", state.Registers[0], exitEncoded, state.Gas)
}

// TestAddRegisters tests add_64 instruction
func TestAddRegisters(t *testing.T) {
	runtime, err := NewRuntime()
	if err != nil {
		t.Fatalf("Failed to create runtime: %v", err)
	}

	// Program: R0=10, R1=32, R2=R0+R1, trap
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 10, SkipLength: 0, BeginsBlock: true}, // load_imm R0, 10
		{PC: 1, Opcode: 51, Ra: 1, Vx: 32, SkipLength: 0},                    // load_imm R1, 32
		{PC: 2, Opcode: 200, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0},             // add_64 R2, R0, R1
		{PC: 3, Opcode: 0, SkipLength: 0},                                    // trap
	}

	err = runtime.CompileProgram(instructions, nil)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := runtime.GetBlock(0)
	if block == nil {
		t.Fatal("No block compiled for PC 0")
	}

	fakeRAM := &FakeRAM{buffer: make([]byte, 4096)}
	state := &State{
		Gas:       100,
		Registers: [13]types.Register{},
		RAM:       fakeRAM,
	}

	statePtr := unsafe.Pointer(state)
	exitEncoded, _ := runtime.ExecuteBlock(block, statePtr)

	if state.Registers[0] != 10 {
		t.Errorf("R0 = %d, want 10", state.Registers[0])
	}
	if state.Registers[1] != 32 {
		t.Errorf("R1 = %d, want 32", state.Registers[1])
	}
	if state.Registers[2] != 42 {
		t.Errorf("R2 = %d, want 42 (10+32)", state.Registers[2])
	}

	if exitEncoded != 2 {
		t.Errorf("exitEncoded = %d, want 2 (panic)", exitEncoded)
	}

	t.Logf("R0=%d, R1=%d, R2=%d, exit=%d",
		state.Registers[0], state.Registers[1], state.Registers[2], exitEncoded)
}

// TestGasDeduction tests that gas is decremented
func TestGasDeduction(t *testing.T) {
	runtime, err := NewRuntime()
	if err != nil {
		t.Fatalf("Failed to create runtime: %v", err)
	}

	// 3 instructions before trap
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 1, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 51, Ra: 1, Vx: 2, SkipLength: 0},
		{PC: 2, Opcode: 51, Ra: 2, Vx: 3, SkipLength: 0},
		{PC: 3, Opcode: 0, SkipLength: 0}, // trap
	}

	err = runtime.CompileProgram(instructions, nil)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := runtime.GetBlock(0)
	fakeRAM := &FakeRAM{buffer: make([]byte, 4096)}
	state := &State{
		Gas:       100,
		Registers: [13]types.Register{},
		RAM:       fakeRAM,
	}

	statePtr := unsafe.Pointer(state)
	runtime.ExecuteBlock(block, statePtr)

	// Should have consumed 4 gas (3 load_imm + 1 trap)
	expectedGas := types.SignedGasValue(100 - 4)
	if state.Gas != expectedGas {
		t.Errorf("Gas = %d, want %d", state.Gas, expectedGas)
	}

	t.Logf("Gas remaining: %d", state.Gas)
}

// TestSubtract tests sub_64 instruction
func TestSubtract(t *testing.T) {
	runtime, err := NewRuntime()
	if err != nil {
		t.Fatalf("Failed to create runtime: %v", err)
	}

	// R0=100, R1=37, R2=R0-R1 (should be 63)
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 100, SkipLength: 0, BeginsBlock: true}, // load_imm R0, 100
		{PC: 1, Opcode: 51, Ra: 1, Vx: 37, SkipLength: 0},                     // load_imm R1, 37
		{PC: 2, Opcode: 201, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0},              // sub_64 R2, R0, R1
		{PC: 3, Opcode: 0, SkipLength: 0},                                     // trap
	}

	err = runtime.CompileProgram(instructions, nil)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := runtime.GetBlock(0)
	state := newTestState()
	runtime.ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[2] != 63 {
		t.Errorf("R2 = %d, want 63 (100-37)", state.Registers[2])
	}
	t.Logf("R0=%d, R1=%d, R2=%d", state.Registers[0], state.Registers[1], state.Registers[2])
}

// TestMultiply tests mul_64 instruction
func TestMultiply(t *testing.T) {
	runtime, err := NewRuntime()
	if err != nil {
		t.Fatalf("Failed to create runtime: %v", err)
	}

	// R0=7, R1=6, R2=R0*R1 (should be 42)
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 7, SkipLength: 0, BeginsBlock: true}, // load_imm R0, 7
		{PC: 1, Opcode: 51, Ra: 1, Vx: 6, SkipLength: 0},                    // load_imm R1, 6
		{PC: 2, Opcode: 202, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0},            // mul_64 R2, R0, R1
		{PC: 3, Opcode: 0, SkipLength: 0},                                   // trap
	}

	err = runtime.CompileProgram(instructions, nil)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := runtime.GetBlock(0)
	state := newTestState()
	runtime.ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[2] != 42 {
		t.Errorf("R2 = %d, want 42 (7*6)", state.Registers[2])
	}
	t.Logf("R0=%d, R1=%d, R2=%d", state.Registers[0], state.Registers[1], state.Registers[2])
}

// TestBitwiseAnd tests and instruction
func TestBitwiseAnd(t *testing.T) {
	runtime, err := NewRuntime()
	if err != nil {
		t.Fatalf("Failed to create runtime: %v", err)
	}

	// R0=0xFF, R1=0x0F, R2=R0&R1 (should be 0x0F)
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 0xFF, SkipLength: 0, BeginsBlock: true}, // load_imm R0, 0xFF
		{PC: 1, Opcode: 51, Ra: 1, Vx: 0x0F, SkipLength: 0},                    // load_imm R1, 0x0F
		{PC: 2, Opcode: 210, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0},               // and R2, R0, R1
		{PC: 3, Opcode: 0, SkipLength: 0},                                      // trap
	}

	err = runtime.CompileProgram(instructions, nil)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := runtime.GetBlock(0)
	state := newTestState()
	runtime.ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[2] != 0x0F {
		t.Errorf("R2 = 0x%x, want 0x0F", state.Registers[2])
	}
	t.Logf("R0=0x%x, R1=0x%x, R2=0x%x", state.Registers[0], state.Registers[1], state.Registers[2])
}

// TestSpilledRegisters tests registers R6-R12 which are memory-backed
func TestSpilledRegisters(t *testing.T) {
	runtime, err := NewRuntime()
	if err != nil {
		t.Fatalf("Failed to create runtime: %v", err)
	}

	// Load values into spilled registers R6, R7, R8
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 6, Vx: 66, SkipLength: 0, BeginsBlock: true}, // load_imm R6, 66
		{PC: 1, Opcode: 51, Ra: 7, Vx: 77, SkipLength: 0},                    // load_imm R7, 77
		{PC: 2, Opcode: 51, Ra: 8, Vx: 88, SkipLength: 0},                    // load_imm R8, 88
		{PC: 3, Opcode: 200, Rd: 9, Ra: 6, Rb: 7, SkipLength: 0},             // add_64 R9, R6, R7
		{PC: 4, Opcode: 0, SkipLength: 0},                                    // trap
	}

	err = runtime.CompileProgram(instructions, nil)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := runtime.GetBlock(0)
	state := newTestState()
	runtime.ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[6] != 66 {
		t.Errorf("R6 = %d, want 66", state.Registers[6])
	}
	if state.Registers[7] != 77 {
		t.Errorf("R7 = %d, want 77", state.Registers[7])
	}
	if state.Registers[8] != 88 {
		t.Errorf("R8 = %d, want 88", state.Registers[8])
	}
	if state.Registers[9] != 143 {
		t.Errorf("R9 = %d, want 143 (66+77)", state.Registers[9])
	}
	t.Logf("R6=%d, R7=%d, R8=%d, R9=%d",
		state.Registers[6], state.Registers[7], state.Registers[8], state.Registers[9])
}

// TestMoveRegister tests move_reg instruction
func TestMoveRegister(t *testing.T) {
	runtime, err := NewRuntime()
	if err != nil {
		t.Fatalf("Failed to create runtime: %v", err)
	}

	// R0=42, R1=R0
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 42, SkipLength: 0, BeginsBlock: true}, // load_imm R0, 42
		{PC: 1, Opcode: 100, Rd: 1, Ra: 0, SkipLength: 0},                    // move_reg R1, R0
		{PC: 2, Opcode: 0, SkipLength: 0},                                    // trap
	}

	err = runtime.CompileProgram(instructions, nil)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := runtime.GetBlock(0)
	state := newTestState()
	runtime.ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[0] != 42 {
		t.Errorf("R0 = %d, want 42", state.Registers[0])
	}
	if state.Registers[1] != 42 {
		t.Errorf("R1 = %d, want 42 (copied from R0)", state.Registers[1])
	}
	t.Logf("R0=%d, R1=%d", state.Registers[0], state.Registers[1])
}

// TestOutOfGas tests that execution stops when gas runs out
func TestOutOfGas(t *testing.T) {
	runtime, err := NewRuntime()
	if err != nil {
		t.Fatalf("Failed to create runtime: %v", err)
	}

	// 5 instructions but only 3 gas
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 1, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 51, Ra: 1, Vx: 2, SkipLength: 0},
		{PC: 2, Opcode: 51, Ra: 2, Vx: 3, SkipLength: 0},
		{PC: 3, Opcode: 51, Ra: 3, Vx: 4, SkipLength: 0},
		{PC: 4, Opcode: 0, SkipLength: 0}, // trap
	}

	err = runtime.CompileProgram(instructions, nil)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := runtime.GetBlock(0)
	state := newTestState()
	state.Gas = 3 // Only 3 gas

	exitEncoded, nextPC := runtime.ExecuteBlock(block, unsafe.Pointer(state))

	// Should exit with OutOfGas (3) after executing 3 instructions
	if exitEncoded != 3 {
		t.Errorf("exitEncoded = %d, want 3 (OutOfGas)", exitEncoded)
	}
	t.Logf("exit=%d, nextPC=%d, gas=%d, R0=%d, R1=%d, R2=%d",
		exitEncoded, nextPC, state.Gas, state.Registers[0], state.Registers[1], state.Registers[2])
}

// TestBitwiseXor tests xor instruction
func TestBitwiseXor(t *testing.T) {
	runtime, err := NewRuntime()
	if err != nil {
		t.Fatalf("Failed to create runtime: %v", err)
	}

	// R0=0xFF, R1=0xAA, R2=R0^R1 (should be 0x55)
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 0xFF, SkipLength: 0, BeginsBlock: true}, // load_imm R0, 0xFF
		{PC: 1, Opcode: 51, Ra: 1, Vx: 0xAA, SkipLength: 0},                    // load_imm R1, 0xAA
		{PC: 2, Opcode: 211, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0},               // xor R2, R0, R1
		{PC: 3, Opcode: 0, SkipLength: 0},                                      // trap
	}

	err = runtime.CompileProgram(instructions, nil)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := runtime.GetBlock(0)
	state := newTestState()
	runtime.ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[2] != 0x55 {
		t.Errorf("R2 = 0x%x, want 0x55", state.Registers[2])
	}
	t.Logf("R0=0x%x ^ R1=0x%x = R2=0x%x", state.Registers[0], state.Registers[1], state.Registers[2])
}

// TestBitwiseOr tests or instruction
func TestBitwiseOr(t *testing.T) {
	runtime, err := NewRuntime()
	if err != nil {
		t.Fatalf("Failed to create runtime: %v", err)
	}

	// R0=0xF0, R1=0x0F, R2=R0|R1 (should be 0xFF)
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 0xF0, SkipLength: 0, BeginsBlock: true}, // load_imm R0, 0xF0
		{PC: 1, Opcode: 51, Ra: 1, Vx: 0x0F, SkipLength: 0},                    // load_imm R1, 0x0F
		{PC: 2, Opcode: 212, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0},               // or R2, R0, R1
		{PC: 3, Opcode: 0, SkipLength: 0},                                      // trap
	}

	err = runtime.CompileProgram(instructions, nil)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := runtime.GetBlock(0)
	state := newTestState()
	runtime.ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[2] != 0xFF {
		t.Errorf("R2 = 0x%x, want 0xFF", state.Registers[2])
	}
	t.Logf("R0=0x%x | R1=0x%x = R2=0x%x", state.Registers[0], state.Registers[1], state.Registers[2])
}

// TestShiftLeft tests shlo_l_64 instruction
func TestShiftLeft(t *testing.T) {
	runtime, err := NewRuntime()
	if err != nil {
		t.Fatalf("Failed to create runtime: %v", err)
	}

	// R0=1, R1=4, R2=R0<<R1 (should be 16)
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 1, SkipLength: 0, BeginsBlock: true}, // load_imm R0, 1
		{PC: 1, Opcode: 51, Ra: 1, Vx: 4, SkipLength: 0},                    // load_imm R1, 4
		{PC: 2, Opcode: 207, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0},            // shlo_l_64 R2, R0, R1
		{PC: 3, Opcode: 0, SkipLength: 0},                                   // trap
	}

	err = runtime.CompileProgram(instructions, nil)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := runtime.GetBlock(0)
	state := newTestState()
	runtime.ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[2] != 16 {
		t.Errorf("R2 = %d, want 16 (1<<4)", state.Registers[2])
	}
	t.Logf("R0=%d << R1=%d = R2=%d", state.Registers[0], state.Registers[1], state.Registers[2])
}

// TestShiftRight tests shlo_r_64 instruction
func TestShiftRight(t *testing.T) {
	runtime, err := NewRuntime()
	if err != nil {
		t.Fatalf("Failed to create runtime: %v", err)
	}

	// R0=256, R1=4, R2=R0>>R1 (should be 16)
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 256, SkipLength: 0, BeginsBlock: true}, // load_imm R0, 256
		{PC: 1, Opcode: 51, Ra: 1, Vx: 4, SkipLength: 0},                      // load_imm R1, 4
		{PC: 2, Opcode: 208, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0},              // shlo_r_64 R2, R0, R1
		{PC: 3, Opcode: 0, SkipLength: 0},                                     // trap
	}

	err = runtime.CompileProgram(instructions, nil)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := runtime.GetBlock(0)
	state := newTestState()
	runtime.ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[2] != 16 {
		t.Errorf("R2 = %d, want 16 (256>>4)", state.Registers[2])
	}
	t.Logf("R0=%d >> R1=%d = R2=%d", state.Registers[0], state.Registers[1], state.Registers[2])
}

// TestDivision tests div_u_64 instruction
func TestDivision(t *testing.T) {
	runtime, err := NewRuntime()
	if err != nil {
		t.Fatalf("Failed to create runtime: %v", err)
	}

	// R0=100, R1=7, R2=R0/R1 (should be 14)
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 100, SkipLength: 0, BeginsBlock: true}, // load_imm R0, 100
		{PC: 1, Opcode: 51, Ra: 1, Vx: 7, SkipLength: 0},                      // load_imm R1, 7
		{PC: 2, Opcode: 203, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0},              // div_u_64 R2, R0, R1
		{PC: 3, Opcode: 0, SkipLength: 0},                                     // trap
	}

	err = runtime.CompileProgram(instructions, nil)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := runtime.GetBlock(0)
	state := newTestState()
	runtime.ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[2] != 14 {
		t.Errorf("R2 = %d, want 14 (100/7)", state.Registers[2])
	}
	t.Logf("R0=%d / R1=%d = R2=%d", state.Registers[0], state.Registers[1], state.Registers[2])
}

// TestRemainder tests rem_u_64 instruction
func TestRemainder(t *testing.T) {
	runtime, err := NewRuntime()
	if err != nil {
		t.Fatalf("Failed to create runtime: %v", err)
	}

	// R0=100, R1=7, R2=R0%R1 (should be 2)
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 100, SkipLength: 0, BeginsBlock: true}, // load_imm R0, 100
		{PC: 1, Opcode: 51, Ra: 1, Vx: 7, SkipLength: 0},                      // load_imm R1, 7
		{PC: 2, Opcode: 205, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0},              // rem_u_64 R2, R0, R1
		{PC: 3, Opcode: 0, SkipLength: 0},                                     // trap
	}

	err = runtime.CompileProgram(instructions, nil)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := runtime.GetBlock(0)
	state := newTestState()
	runtime.ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[2] != 2 {
		t.Errorf("R2 = %d, want 2 (100%%7)", state.Registers[2])
	}
	t.Logf("R0=%d %% R1=%d = R2=%d", state.Registers[0], state.Registers[1], state.Registers[2])
}

// TestChainedOperations tests multiple operations in sequence
func TestChainedOperations(t *testing.T) {
	runtime, err := NewRuntime()
	if err != nil {
		t.Fatalf("Failed to create runtime: %v", err)
	}

	// Compute: ((5 + 3) * 2) - 1 = 15
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 5, SkipLength: 0, BeginsBlock: true}, // R0 = 5
		{PC: 1, Opcode: 51, Ra: 1, Vx: 3, SkipLength: 0},                    // R1 = 3
		{PC: 2, Opcode: 200, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0},            // R2 = R0 + R1 = 8
		{PC: 3, Opcode: 51, Ra: 3, Vx: 2, SkipLength: 0},                    // R3 = 2
		{PC: 4, Opcode: 202, Rd: 4, Ra: 2, Rb: 3, SkipLength: 0},            // R4 = R2 * R3 = 16
		{PC: 5, Opcode: 51, Ra: 5, Vx: 1, SkipLength: 0},                    // R5 = 1
		{PC: 6, Opcode: 201, Rd: 0, Ra: 4, Rb: 5, SkipLength: 0},            // R0 = R4 - R5 = 15
		{PC: 7, Opcode: 0, SkipLength: 0},                                   // trap
	}

	err = runtime.CompileProgram(instructions, nil)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := runtime.GetBlock(0)
	state := newTestState()
	runtime.ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[0] != 15 {
		t.Errorf("R0 = %d, want 15 ((5+3)*2-1)", state.Registers[0])
	}
	if state.Registers[2] != 8 {
		t.Errorf("R2 = %d, want 8", state.Registers[2])
	}
	if state.Registers[4] != 16 {
		t.Errorf("R4 = %d, want 16", state.Registers[4])
	}
	t.Logf("Final: R0=%d, R2=%d, R4=%d", state.Registers[0], state.Registers[2], state.Registers[4])
}

// TestAllRegisters tests that all 13 registers work correctly
func TestAllRegisters(t *testing.T) {
	runtime, err := NewRuntime()
	if err != nil {
		t.Fatalf("Failed to create runtime: %v", err)
	}

	// Load unique values into all 13 registers
	instructions := make([]*ParsedInstruction, 14)
	for i := 0; i < 13; i++ {
		instructions[i] = &ParsedInstruction{
			PC: types.Register(i), Opcode: 51, Ra: i, Vx: types.Register(i * 11), SkipLength: 0,
			BeginsBlock: i == 0, // First instruction begins a block
		}
	}
	instructions[13] = &ParsedInstruction{PC: 13, Opcode: 0, SkipLength: 0} // trap

	err = runtime.CompileProgram(instructions, nil)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := runtime.GetBlock(0)
	state := newTestState()
	runtime.ExecuteBlock(block, unsafe.Pointer(state))

	for i := 0; i < 13; i++ {
		expected := types.Register(i * 11)
		if state.Registers[i] != expected {
			t.Errorf("R%d = %d, want %d", i, state.Registers[i], expected)
		}
	}
	t.Logf("All registers: %v", state.Registers)
}

// TestBranchEqual tests branch_eq instruction (taken branch)
func TestBranchEqualTaken(t *testing.T) {
	runtime, err := NewRuntime()
	if err != nil {
		t.Fatalf("Failed to create runtime: %v", err)
	}

	// R0=5, R1=5, if R0==R1 goto PC 4, else continue
	// PC 0: load_imm R0, 5
	// PC 1: load_imm R1, 5
	// PC 2: branch_eq R0, R1 -> PC 4
	// PC 3: load_imm R2, 999 (should be skipped)
	// PC 4: load_imm R2, 42
	// PC 5: trap
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 5, SkipLength: 0, BeginsBlock: true},   // load_imm R0, 5
		{PC: 1, Opcode: 51, Ra: 1, Vx: 5, SkipLength: 0},                      // load_imm R1, 5
		{PC: 2, Opcode: 170, Ra: 0, Rb: 1, Vx: 4, SkipLength: 0},              // branch_eq R0, R1, target=4
		{PC: 3, Opcode: 51, Ra: 2, Vx: 999, SkipLength: 0, BeginsBlock: true}, // load_imm R2, 999 (fallthrough)
		{PC: 4, Opcode: 51, Ra: 2, Vx: 42, SkipLength: 0, BeginsBlock: true},  // load_imm R2, 42 (branch target)
		{PC: 5, Opcode: 0, SkipLength: 0},                                     // trap
	}

	err = runtime.CompileProgram(instructions, nil)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	state := newTestState()
	runUntilExit(t, runtime, state)

	if state.Registers[2] != 42 {
		t.Errorf("R2 = %d, want 42 (branch should skip 999)", state.Registers[2])
	}
	t.Logf("R0=%d, R1=%d, R2=%d (branch taken)", state.Registers[0], state.Registers[1], state.Registers[2])
}

// TestBranchEqualNotTaken tests branch_eq instruction (not taken)
func TestBranchEqualNotTaken(t *testing.T) {
	runtime, err := NewRuntime()
	if err != nil {
		t.Fatalf("Failed to create runtime: %v", err)
	}

	// R0=5, R1=7, if R0==R1 goto PC 4 (not taken), continue to PC 3
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 5, SkipLength: 0, BeginsBlock: true},  // load_imm R0, 5
		{PC: 1, Opcode: 51, Ra: 1, Vx: 7, SkipLength: 0},                     // load_imm R1, 7
		{PC: 2, Opcode: 170, Ra: 0, Rb: 1, Vx: 4, SkipLength: 0},             // branch_eq R0, R1, target=4
		{PC: 3, Opcode: 51, Ra: 2, Vx: 42, SkipLength: 0, BeginsBlock: true}, // load_imm R2, 42 (fallthrough)
		{PC: 4, Opcode: 0, SkipLength: 0, BeginsBlock: true},                 // trap (branch target)
	}

	err = runtime.CompileProgram(instructions, nil)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	state := newTestState()
	runUntilExit(t, runtime, state)

	if state.Registers[2] != 42 {
		t.Errorf("R2 = %d, want 42 (branch not taken)", state.Registers[2])
	}
	t.Logf("R0=%d, R1=%d, R2=%d (branch not taken)", state.Registers[0], state.Registers[1], state.Registers[2])
}

// TestBranchNotEqual tests branch_ne instruction
func TestBranchNotEqual(t *testing.T) {
	runtime, err := NewRuntime()
	if err != nil {
		t.Fatalf("Failed to create runtime: %v", err)
	}

	// R0=5, R1=7, if R0!=R1 goto PC 4 (taken)
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 5, SkipLength: 0, BeginsBlock: true},   // load_imm R0, 5
		{PC: 1, Opcode: 51, Ra: 1, Vx: 7, SkipLength: 0},                      // load_imm R1, 7
		{PC: 2, Opcode: 171, Ra: 0, Rb: 1, Vx: 4, SkipLength: 0},              // branch_ne R0, R1, target=4
		{PC: 3, Opcode: 51, Ra: 2, Vx: 999, SkipLength: 0, BeginsBlock: true}, // load_imm R2, 999 (fallthrough)
		{PC: 4, Opcode: 51, Ra: 2, Vx: 42, SkipLength: 0, BeginsBlock: true},  // load_imm R2, 42 (branch target)
		{PC: 5, Opcode: 0, SkipLength: 0},                                     // trap
	}

	err = runtime.CompileProgram(instructions, nil)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	state := newTestState()
	runUntilExit(t, runtime, state)

	if state.Registers[2] != 42 {
		t.Errorf("R2 = %d, want 42 (branch_ne taken)", state.Registers[2])
	}
	t.Logf("R0=%d, R1=%d, R2=%d", state.Registers[0], state.Registers[1], state.Registers[2])
}

// TestBranchLessThan tests branch_lt_u instruction
func TestBranchLessThan(t *testing.T) {
	runtime, err := NewRuntime()
	if err != nil {
		t.Fatalf("Failed to create runtime: %v", err)
	}

	// R0=3, R1=7, if R0<R1 goto PC 4 (taken)
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 3, SkipLength: 0, BeginsBlock: true},   // load_imm R0, 3
		{PC: 1, Opcode: 51, Ra: 1, Vx: 7, SkipLength: 0},                      // load_imm R1, 7
		{PC: 2, Opcode: 172, Ra: 0, Rb: 1, Vx: 4, SkipLength: 0},              // branch_lt_u R0, R1, target=4
		{PC: 3, Opcode: 51, Ra: 2, Vx: 999, SkipLength: 0, BeginsBlock: true}, // load_imm R2, 999 (fallthrough)
		{PC: 4, Opcode: 51, Ra: 2, Vx: 42, SkipLength: 0, BeginsBlock: true},  // load_imm R2, 42 (branch target)
		{PC: 5, Opcode: 0, SkipLength: 0},                                     // trap
	}

	err = runtime.CompileProgram(instructions, nil)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	state := newTestState()
	runUntilExit(t, runtime, state)

	if state.Registers[2] != 42 {
		t.Errorf("R2 = %d, want 42 (branch_lt_u taken)", state.Registers[2])
	}
	t.Logf("R0=%d < R1=%d, R2=%d", state.Registers[0], state.Registers[1], state.Registers[2])
}

// TestBranchGreaterEqual tests branch_ge_u instruction
func TestBranchGreaterEqual(t *testing.T) {
	runtime, err := NewRuntime()
	if err != nil {
		t.Fatalf("Failed to create runtime: %v", err)
	}

	// R0=10, R1=7, if R0>=R1 goto PC 4 (taken)
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 10, SkipLength: 0, BeginsBlock: true},  // load_imm R0, 10
		{PC: 1, Opcode: 51, Ra: 1, Vx: 7, SkipLength: 0},                      // load_imm R1, 7
		{PC: 2, Opcode: 174, Ra: 0, Rb: 1, Vx: 4, SkipLength: 0},              // branch_ge_u R0, R1, target=4
		{PC: 3, Opcode: 51, Ra: 2, Vx: 999, SkipLength: 0, BeginsBlock: true}, // load_imm R2, 999 (fallthrough)
		{PC: 4, Opcode: 51, Ra: 2, Vx: 42, SkipLength: 0, BeginsBlock: true},  // load_imm R2, 42 (branch target)
		{PC: 5, Opcode: 0, SkipLength: 0},                                     // trap
	}

	err = runtime.CompileProgram(instructions, nil)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	state := newTestState()
	runUntilExit(t, runtime, state)

	if state.Registers[2] != 42 {
		t.Errorf("R2 = %d, want 42 (branch_ge_u taken)", state.Registers[2])
	}
	t.Logf("R0=%d >= R1=%d, R2=%d", state.Registers[0], state.Registers[1], state.Registers[2])
}

// TestUnconditionalJump tests jump instruction
func TestUnconditionalJump(t *testing.T) {
	runtime, err := NewRuntime()
	if err != nil {
		t.Fatalf("Failed to create runtime: %v", err)
	}

	// PC 0: jump to PC 2
	// PC 1: load_imm R0, 999 (skipped)
	// PC 2: load_imm R0, 42
	// PC 3: trap
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 40, Vx: 2, SkipLength: 0, BeginsBlock: true},          // jump to PC 2
		{PC: 1, Opcode: 51, Ra: 0, Vx: 999, SkipLength: 0, BeginsBlock: true}, // load_imm R0, 999 (fallthrough)
		{PC: 2, Opcode: 51, Ra: 0, Vx: 42, SkipLength: 0, BeginsBlock: true},  // load_imm R0, 42 (jump target)
		{PC: 3, Opcode: 0, SkipLength: 0},                                     // trap
	}

	err = runtime.CompileProgram(instructions, nil)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	state := newTestState()
	runUntilExit(t, runtime, state)

	if state.Registers[0] != 42 {
		t.Errorf("R0 = %d, want 42 (jump should skip 999)", state.Registers[0])
	}
	t.Logf("R0=%d (jumped over 999)", state.Registers[0])
}

// TestSimpleLoop tests a simple loop: sum 1+2+3+4+5 = 15
func TestSimpleLoop(t *testing.T) {
	runtime, err := NewRuntime()
	if err != nil {
		t.Fatalf("Failed to create runtime: %v", err)
	}

	// R0 = sum (starts at 0)
	// R1 = counter (starts at 5)
	// R2 = 1 (decrement value)
	// Loop: R0 = R0 + R1; R1 = R1 - R2; if R1 != 0 goto loop
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 0, SkipLength: 0, BeginsBlock: true}, // R0 = 0 (sum)
		{PC: 1, Opcode: 51, Ra: 1, Vx: 5, SkipLength: 0},                    // R1 = 5 (counter)
		{PC: 2, Opcode: 51, Ra: 2, Vx: 1, SkipLength: 0},                    // R2 = 1
		{PC: 3, Opcode: 51, Ra: 3, Vx: 0, SkipLength: 0},                    // R3 = 0 (for comparison)
		// Loop start (PC 4):
		{PC: 4, Opcode: 200, Rd: 0, Ra: 0, Rb: 1, SkipLength: 0, BeginsBlock: true}, // R0 = R0 + R1 (loop target)
		{PC: 5, Opcode: 201, Rd: 1, Ra: 1, Rb: 2, SkipLength: 0},                    // R1 = R1 - 1
		{PC: 6, Opcode: 171, Ra: 1, Rb: 3, Vx: 4, SkipLength: 0},                    // if R1 != R3 goto PC 4
		{PC: 7, Opcode: 0, SkipLength: 0, BeginsBlock: true},                        // trap (fallthrough)
	}

	err = runtime.CompileProgram(instructions, nil)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	state := newTestState()
	state.Gas = 50 // Need more gas for loop
	runUntilExit(t, runtime, state)

	// Sum should be 5+4+3+2+1 = 15
	if state.Registers[0] != 15 {
		t.Errorf("R0 = %d, want 15 (sum 5+4+3+2+1)", state.Registers[0])
	}
	if state.Registers[1] != 0 {
		t.Errorf("R1 = %d, want 0 (counter should be 0)", state.Registers[1])
	}
	t.Logf("Loop result: R0=%d (sum), R1=%d (counter), gas=%d",
		state.Registers[0], state.Registers[1], state.Gas)
}

// TestDivisionByZero tests that division by zero returns max value
func TestDivisionByZero(t *testing.T) {
	runtime, err := NewRuntime()
	if err != nil {
		t.Fatalf("Failed to create runtime: %v", err)
	}

	// R0=100, R1=0, R2=R0/R1 (should be max uint64)
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 100, SkipLength: 0, BeginsBlock: true}, // load_imm R0, 100
		{PC: 1, Opcode: 51, Ra: 1, Vx: 0, SkipLength: 0},                      // load_imm R1, 0
		{PC: 2, Opcode: 203, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0},              // div_u_64 R2, R0, R1
		{PC: 3, Opcode: 0, SkipLength: 0},                                     // trap
	}

	err = runtime.CompileProgram(instructions, nil)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := runtime.GetBlock(0)
	state := newTestState()
	runtime.ExecuteBlock(block, unsafe.Pointer(state))

	// Division by zero should return max uint64
	maxUint64 := types.Register(^uint64(0))
	if state.Registers[2] != maxUint64 {
		t.Errorf("R2 = %d, want %d (max uint64 for div by zero)", state.Registers[2], maxUint64)
	}
	t.Logf("100 / 0 = %d (max uint64)", state.Registers[2])
}

// TestRemainderByZero tests that remainder by zero returns dividend
func TestRemainderByZero(t *testing.T) {
	runtime, err := NewRuntime()
	if err != nil {
		t.Fatalf("Failed to create runtime: %v", err)
	}

	// R0=100, R1=0, R2=R0%R1 (should be R0)
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 100, SkipLength: 0, BeginsBlock: true}, // load_imm R0, 100
		{PC: 1, Opcode: 51, Ra: 1, Vx: 0, SkipLength: 0},                      // load_imm R1, 0
		{PC: 2, Opcode: 205, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0},              // rem_u_64 R2, R0, R1
		{PC: 3, Opcode: 0, SkipLength: 0},                                     // trap
	}

	err = runtime.CompileProgram(instructions, nil)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := runtime.GetBlock(0)
	state := newTestState()
	runtime.ExecuteBlock(block, unsafe.Pointer(state))

	// Remainder by zero should return dividend
	if state.Registers[2] != 100 {
		t.Errorf("R2 = %d, want 100 (dividend for rem by zero)", state.Registers[2])
	}
	t.Logf("100 %% 0 = %d", state.Registers[2])
}

// TestSignedBranchLessThan tests branch_lt_s with negative numbers
func TestSignedBranchLessThan(t *testing.T) {
	runtime, err := NewRuntime()
	if err != nil {
		t.Fatalf("Failed to create runtime: %v", err)
	}

	// R0=-5 (as signed), R1=3, if R0 < R1 (signed) goto PC 4 (should be taken)
	// -5 as uint64 is a large positive number, so unsigned compare would fail
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: types.Register(^uint64(4)), SkipLength: 0, BeginsBlock: true}, // load_imm R0, -5 (two's complement)
		{PC: 1, Opcode: 51, Ra: 1, Vx: 3, SkipLength: 0},                                             // load_imm R1, 3
		{PC: 2, Opcode: 173, Ra: 0, Rb: 1, Vx: 4, SkipLength: 0},                                     // branch_lt_s R0, R1, target=4
		{PC: 3, Opcode: 51, Ra: 2, Vx: 999, SkipLength: 0, BeginsBlock: true},                        // load_imm R2, 999 (fallthrough)
		{PC: 4, Opcode: 51, Ra: 2, Vx: 42, SkipLength: 0, BeginsBlock: true},                         // load_imm R2, 42 (branch target)
		{PC: 5, Opcode: 0, SkipLength: 0},                                                            // trap
	}

	err = runtime.CompileProgram(instructions, nil)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	state := newTestState()
	runUntilExit(t, runtime, state)

	if state.Registers[2] != 42 {
		t.Errorf("R2 = %d, want 42 (signed -5 < 3 should be true)", state.Registers[2])
	}
	t.Logf("Signed: %d < %d = true, R2=%d", int64(state.Registers[0]), state.Registers[1], state.Registers[2])
}

// TestSignedBranchGreaterEqual tests branch_ge_s with negative numbers
func TestSignedBranchGreaterEqual(t *testing.T) {
	runtime, err := NewRuntime()
	if err != nil {
		t.Fatalf("Failed to create runtime: %v", err)
	}

	// R0=3, R1=-5 (as signed), if R0 >= R1 (signed) goto PC 4 (should be taken)
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 3, SkipLength: 0, BeginsBlock: true},       // load_imm R0, 3
		{PC: 1, Opcode: 51, Ra: 1, Vx: types.Register(^uint64(4)), SkipLength: 0}, // load_imm R1, -5 (two's complement)
		{PC: 2, Opcode: 175, Ra: 0, Rb: 1, Vx: 4, SkipLength: 0},                  // branch_ge_s R0, R1, target=4
		{PC: 3, Opcode: 51, Ra: 2, Vx: 999, SkipLength: 0, BeginsBlock: true},     // load_imm R2, 999 (fallthrough)
		{PC: 4, Opcode: 51, Ra: 2, Vx: 42, SkipLength: 0, BeginsBlock: true},      // load_imm R2, 42 (branch target)
		{PC: 5, Opcode: 0, SkipLength: 0},                                         // trap
	}

	err = runtime.CompileProgram(instructions, nil)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	state := newTestState()
	runUntilExit(t, runtime, state)

	if state.Registers[2] != 42 {
		t.Errorf("R2 = %d, want 42 (signed 3 >= -5 should be true)", state.Registers[2])
	}
	t.Logf("Signed: %d >= %d = true, R2=%d", state.Registers[0], int64(state.Registers[1]), state.Registers[2])
}

// TestDynamicJump tests jump_ind with a dynamic jump table
func TestDynamicJump(t *testing.T) {
	runtime, err := NewRuntime()
	if err != nil {
		t.Fatalf("Failed to create runtime: %v", err)
	}

	// Create a dynamic jump table: index 0 -> PC 4, index 1 -> PC 6
	// Alignment factor is 2, so addresses are: 2, 4, 6, 8...
	// Address 2 (index 0) -> PC 4
	// Address 4 (index 1) -> PC 6
	dynamicJumpTable := []types.Register{4, 6}

	// R0 = 2 (aligned address, maps to index 0 -> PC 4)
	// jump_ind R0, 0 -> should jump to PC 4
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 2, SkipLength: 0, BeginsBlock: true},   // load_imm R0, 2
		{PC: 1, Opcode: 50, Ra: 0, Vx: 0, SkipLength: 0},                      // jump_ind R0, 0
		{PC: 2, Opcode: 51, Ra: 1, Vx: 999, SkipLength: 0, BeginsBlock: true}, // skipped
		{PC: 3, Opcode: 0, SkipLength: 0},                                     // trap (skipped)
		{PC: 4, Opcode: 51, Ra: 1, Vx: 42, SkipLength: 0, BeginsBlock: true},  // target from table
		{PC: 5, Opcode: 0, SkipLength: 0},                                     // trap
		{PC: 6, Opcode: 51, Ra: 1, Vx: 77, SkipLength: 0, BeginsBlock: true},  // alternate target
		{PC: 7, Opcode: 0, SkipLength: 0},                                     // trap
	}

	err = runtime.CompileProgram(instructions, dynamicJumpTable)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	state := newTestState()
	exitCode := runUntilExitWithTable(t, runtime, state, dynamicJumpTable, instructions)

	// Should have jumped to PC 4, setting R1=42
	if state.Registers[1] != 42 {
		t.Errorf("R1 = %d, want 42 (dynamic jump to PC 4), exit=%d", state.Registers[1], exitCode)
	}
	t.Logf("Dynamic jump: address %d -> PC 4, R1=%d, exit=%d", state.Registers[0], state.Registers[1], exitCode)
}

// TestDynamicJumpSecondEntry tests jump_ind with second table entry
func TestDynamicJumpSecondEntry(t *testing.T) {
	runtime, err := NewRuntime()
	if err != nil {
		t.Fatalf("Failed to create runtime: %v", err)
	}

	// Same table as above
	dynamicJumpTable := []types.Register{4, 6}

	// R0 = 4 (aligned address, maps to index 1 -> PC 6)
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 4, SkipLength: 0, BeginsBlock: true},   // load_imm R0, 4
		{PC: 1, Opcode: 50, Ra: 0, Vx: 0, SkipLength: 0},                      // jump_ind R0, 0
		{PC: 2, Opcode: 51, Ra: 1, Vx: 999, SkipLength: 0, BeginsBlock: true}, // skipped
		{PC: 3, Opcode: 0, SkipLength: 0},                                     // trap (skipped)
		{PC: 4, Opcode: 51, Ra: 1, Vx: 42, SkipLength: 0, BeginsBlock: true},  // alternate target
		{PC: 5, Opcode: 0, SkipLength: 0},                                     // trap
		{PC: 6, Opcode: 51, Ra: 1, Vx: 77, SkipLength: 0, BeginsBlock: true},  // target from table
		{PC: 7, Opcode: 0, SkipLength: 0},                                     // trap
	}

	err = runtime.CompileProgram(instructions, dynamicJumpTable)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	state := newTestState()
	runUntilExitWithTable(t, runtime, state, dynamicJumpTable, instructions)

	// Should have jumped to PC 6, setting R1=77
	if state.Registers[1] != 77 {
		t.Errorf("R1 = %d, want 77 (dynamic jump to PC 6)", state.Registers[1])
	}
	t.Logf("Dynamic jump: address %d -> PC 6, R1=%d", state.Registers[0], state.Registers[1])
}

// TestHostCallReentry tests ecalli with re-entry after host function
func TestHostCallReentry(t *testing.T) {
	runtime, err := NewRuntime()
	if err != nil {
		t.Fatalf("Failed to create runtime: %v", err)
	}

	// PC 0: load_imm R0, 42
	// PC 1: ecalli 0 (Gas host function - sets R7 = gas)
	// PC 2: load_imm R1, 99 (after host call returns - same block, requires trampoline)
	// PC 3: trap
	// Note: PC 2 must NOT have BeginsBlock=true so that re-entry at PC 2 requires
	// a trampoline to jump mid-block rather than finding a separate block.
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 42, SkipLength: 0, BeginsBlock: true}, // load_imm R0, 42
		{PC: 1, Opcode: 10, Vx: 0, SkipLength: 0},                            // ecalli 0 (Gas)
		{PC: 2, Opcode: 51, Ra: 1, Vx: 99, SkipLength: 0},                    // load_imm R1, 99 (mid-block)
		{PC: 3, Opcode: 0, SkipLength: 0},                                    // trap
	}

	err = runtime.CompileProgram(instructions, nil)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	state := newTestState()
	state.Gas = 50
	exitCode := runUntilExitWithHostCall(t, runtime, state, instructions)

	// R0 should be 42 (set before host call)
	if state.Registers[0] != 42 {
		t.Errorf("R0 = %d, want 42", state.Registers[0])
	}
	// R7 should have gas value from host call (simulated)
	if state.Registers[7] == 0 {
		t.Errorf("R7 = 0, expected gas value from host call")
	}
	// R1 should be 99 (set after host call returned)
	if state.Registers[1] != 99 {
		t.Errorf("R1 = %d, want 99 (after host call re-entry)", state.Registers[1])
	}
	t.Logf("Host call re-entry: R0=%d, R7=%d (gas), R1=%d, exit=%d",
		state.Registers[0], state.Registers[7], state.Registers[1], exitCode)
}

// TestStartFromMidBlockPC tests starting execution from a mid-block PC (requires trampoline)
func TestStartFromMidBlockPC(t *testing.T) {
	runtime, err := NewRuntime()
	if err != nil {
		t.Fatalf("Failed to create runtime: %v", err)
	}

	// Compile a block starting at PC 0, but we'll start execution at PC 2
	// PC 0: load_imm R0, 11
	// PC 1: load_imm R1, 22
	// PC 2: load_imm R2, 33 (we start here)
	// PC 3: load_imm R3, 44
	// PC 4: trap
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 11, SkipLength: 0, BeginsBlock: true}, // load_imm R0, 11
		{PC: 1, Opcode: 51, Ra: 1, Vx: 22, SkipLength: 0},                    // load_imm R1, 22
		{PC: 2, Opcode: 51, Ra: 2, Vx: 33, SkipLength: 0},                    // load_imm R2, 33
		{PC: 3, Opcode: 51, Ra: 3, Vx: 44, SkipLength: 0},                    // load_imm R3, 44
		{PC: 4, Opcode: 0, SkipLength: 0},                                    // trap
	}

	err = runtime.CompileProgram(instructions, nil)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	state := newTestState()
	state.Gas = 100

	// Start execution at PC 2 (mid-block) - requires trampoline
	block := runtime.GetBlock(2)
	if block == nil {
		t.Fatal("GetBlock(2) returned nil - trampoline generation failed")
	}

	// Verify it's a trampoline (StartPC == EndPC == 2, small code size)
	if block.StartPC != 2 || block.EndPC != 2 {
		t.Errorf("Expected trampoline with StartPC=EndPC=2, got StartPC=%d, EndPC=%d", block.StartPC, block.EndPC)
	}

	exitEncoded, _ := runtime.ExecuteBlock(block, unsafe.Pointer(state))

	// R0 and R1 should be 0 (not executed - we started at PC 2)
	if state.Registers[0] != 0 {
		t.Errorf("R0 = %d, want 0 (should not have executed PC 0)", state.Registers[0])
	}
	if state.Registers[1] != 0 {
		t.Errorf("R1 = %d, want 0 (should not have executed PC 1)", state.Registers[1])
	}
	// R2 and R3 should be set (executed from PC 2 onwards)
	if state.Registers[2] != 33 {
		t.Errorf("R2 = %d, want 33", state.Registers[2])
	}
	if state.Registers[3] != 44 {
		t.Errorf("R3 = %d, want 44", state.Registers[3])
	}

	t.Logf("Mid-block start: R0=%d, R1=%d, R2=%d, R3=%d, exit=%d",
		state.Registers[0], state.Registers[1], state.Registers[2], state.Registers[3], exitEncoded)
}

// TestNegativeArithmetic tests arithmetic with negative numbers
func TestNegativeArithmetic(t *testing.T) {
	runtime, err := NewRuntime()
	if err != nil {
		t.Fatalf("Failed to create runtime: %v", err)
	}

	// R0=10, R1=15, R2=R0-R1 (should be -5 as signed)
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 10, SkipLength: 0, BeginsBlock: true}, // load_imm R0, 10
		{PC: 1, Opcode: 51, Ra: 1, Vx: 15, SkipLength: 0},                    // load_imm R1, 15
		{PC: 2, Opcode: 201, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0},             // sub_64 R2, R0, R1
		{PC: 3, Opcode: 0, SkipLength: 0},                                    // trap
	}

	err = runtime.CompileProgram(instructions, nil)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := runtime.GetBlock(0)
	state := newTestState()
	runtime.ExecuteBlock(block, unsafe.Pointer(state))

	// 10 - 15 = -5 (as signed)
	expected := types.Register(^uint64(4)) // -5 in two's complement
	if state.Registers[2] != expected {
		t.Errorf("R2 = %d (signed: %d), want -5", state.Registers[2], int64(state.Registers[2]))
	}
	t.Logf("10 - 15 = %d (signed)", int64(state.Registers[2]))
}

// Helper to create test state
func newTestState() *State {
	return &State{
		Gas:       100,
		Registers: [13]types.Register{},
		RAM:       &FakeRAM{buffer: make([]byte, 4096)},
	}
}

// runUntilExit executes blocks until we hit a terminal exit (panic/halt/out-of-gas)
// This is a simplified version that needs a PVM for djump() - for now we'll create a minimal one
func runUntilExit(t *testing.T, rt *Runtime, state *State) uint64 {
	return runUntilExitWithTable(t, rt, state, nil, nil)
}

// runUntilExitWithTable executes blocks with dynamic jump table support
func runUntilExitWithTable(t *testing.T, rt *Runtime, state *State, dynamicJumpTable []types.Register, instructions []*ParsedInstruction) uint64 {
	statePtr := unsafe.Pointer(state)
	pc := types.Register(0)

	for i := 0; i < 1000; i++ { // Safety limit
		block := rt.GetBlock(pc)
		if block == nil {
			t.Fatalf("No block for PC %d", pc)
		}

		exitEncoded, nextPC := rt.ExecuteBlock(block, statePtr)

		// Check for complex exits (high bit set)
		if exitEncoded&0x8000000000000000 != 0 {
			exitType := (exitEncoded >> 56) & 0x7F
			param := types.Register(exitEncoded & 0x00FFFFFFFFFFFFFF)

			if exitType == 1 { // DynamicJump
				// Simplified djump logic for tests
				a := uint32(param)

				// Special halt value
				if a == (1<<32)-(1<<16) {
					return 1 // Halt
				}

				// Validate alignment and bounds
				if a == 0 || dynamicJumpTable == nil {
					return 2 // Panic
				}

				const alignmentFactor = 2 // DynamicAddressAlignmentFactor
				if a%alignmentFactor != 0 {
					return 2 // Panic
				}

				maxAddr := uint32(len(dynamicJumpTable) * alignmentFactor)
				if a > maxAddr {
					return 2 // Panic
				}

				// Compute index and get target
				index := (a / alignmentFactor) - 1
				if int(index) >= len(dynamicJumpTable) {
					return 2 // Panic
				}
				target := dynamicJumpTable[index]

				// Validate target is a valid block start
				if instructions != nil && int(target) < len(instructions) {
					if instructions[target] == nil || !instructions[target].BeginsBlock {
						return 2 // Panic
					}
				}

				pc = target
				continue
			}

			// Other complex exits not handled in tests
			t.Fatalf("Unhandled complex exit type %d", exitType)
		}

		// Check for terminal exits
		if exitEncoded == 1 || exitEncoded == 2 || exitEncoded == 3 {
			// Halt(1), Panic(2), OutOfGas(3)
			return exitEncoded
		}

		// exitEncoded == 0 means Go (continue at nextPC)
		pc = types.Register(nextPC)
	}

	t.Fatal("Loop limit exceeded")
	return 0
}

// runUntilExitWithHostCall executes blocks with host call support
func runUntilExitWithHostCall(t *testing.T, rt *Runtime, state *State, instructions []*ParsedInstruction) uint64 {
	statePtr := unsafe.Pointer(state)
	pc := types.Register(0)

	for i := 0; i < 1000; i++ { // Safety limit
		block := rt.GetBlock(pc)
		if block == nil {
			t.Fatalf("No block for PC %d", pc)
		}

		exitEncoded, nextPC := rt.ExecuteBlock(block, statePtr)

		// Check for complex exits (high bit set)
		if exitEncoded&0x8000000000000000 != 0 {
			exitType := (exitEncoded >> 56) & 0x7F
			param := types.Register(exitEncoded & 0x00FFFFFFFFFFFFFF)

			if exitType == 0 { // HostCall
				// Simulate Gas host function (ID 0): R7 = gas
				if param == 0 {
					state.Registers[7] = types.Register(state.Gas)
				}
				// Continue at nextPC
				pc = types.Register(nextPC)
				continue
			}

			if exitType == 1 { // DynamicJump - not handled here
				t.Fatalf("Unexpected DynamicJump in host call test")
			}

			// Other complex exits
			t.Fatalf("Unhandled complex exit type %d", exitType)
		}

		// Check for terminal exits
		if exitEncoded == 1 || exitEncoded == 2 || exitEncoded == 3 {
			return exitEncoded
		}

		// exitEncoded == 0 means Go (continue at nextPC)
		pc = types.Register(nextPC)
	}

	t.Fatal("Loop limit exceeded")
	return 0
}

// State mirrors pvm.State for testing
type State struct {
	Gas       types.SignedGasValue
	Registers [13]types.Register
	RAM       *FakeRAM
}

// FakeRAM mimics ram.RAM layout for testing without 4GB mmap
type FakeRAM struct {
	buffer []byte // First field, same as ram.RAM
}
