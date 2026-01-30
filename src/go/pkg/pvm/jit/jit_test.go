package jit

import (
	"jam/pkg/ram"
	"jam/pkg/types"
	"testing"
	"unsafe"
)

// TestSimpleLoadImm tests that load_imm correctly sets a register
func TestSimpleLoadImm(t *testing.T) {

	// Create a simple program: load_imm R0, 42; then exit
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 42, SkipLength: 0, BeginsBlock: true}, // load_imm R0, 42
		{PC: 1, Opcode: 0, SkipLength: 0},                                    // trap (causes panic exit)
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
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
	exitEncoded, _ := ExecuteBlock(block, statePtr)

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

	// Program: R0=10, R1=32, R2=R0+R1, trap
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 10, SkipLength: 0, BeginsBlock: true}, // load_imm R0, 10
		{PC: 1, Opcode: 51, Ra: 1, Vx: 32, SkipLength: 0},                    // load_imm R1, 32
		{PC: 2, Opcode: 200, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0},             // add_64 R2, R0, R1
		{PC: 3, Opcode: 0, SkipLength: 0},                                    // trap
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
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
	exitEncoded, _ := ExecuteBlock(block, statePtr)

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

	// 3 instructions before trap
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 1, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 51, Ra: 1, Vx: 2, SkipLength: 0},
		{PC: 2, Opcode: 51, Ra: 2, Vx: 3, SkipLength: 0},
		{PC: 3, Opcode: 0, SkipLength: 0}, // trap
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	fakeRAM := &FakeRAM{buffer: make([]byte, 4096)}
	state := &State{
		Gas:       100,
		Registers: [13]types.Register{},
		RAM:       fakeRAM,
	}

	statePtr := unsafe.Pointer(state)
	ExecuteBlock(block, statePtr)

	// Should have consumed 4 gas (3 load_imm + 1 trap)
	expectedGas := types.SignedGasValue(100 - 4)
	if state.Gas != expectedGas {
		t.Errorf("Gas = %d, want %d", state.Gas, expectedGas)
	}

	t.Logf("Gas remaining: %d", state.Gas)
}

// TestSubtract tests sub_64 instruction
func TestSubtract(t *testing.T) {

	// R0=100, R1=37, R2=R0-R1 (should be 63)
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 100, SkipLength: 0, BeginsBlock: true}, // load_imm R0, 100
		{PC: 1, Opcode: 51, Ra: 1, Vx: 37, SkipLength: 0},                     // load_imm R1, 37
		{PC: 2, Opcode: 201, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0},              // sub_64 R2, R0, R1
		{PC: 3, Opcode: 0, SkipLength: 0},                                     // trap
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[2] != 63 {
		t.Errorf("R2 = %d, want 63 (100-37)", state.Registers[2])
	}
	t.Logf("R0=%d, R1=%d, R2=%d", state.Registers[0], state.Registers[1], state.Registers[2])
}

// TestMultiply tests mul_64 instruction
func TestMultiply(t *testing.T) {

	// R0=7, R1=6, R2=R0*R1 (should be 42)
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 7, SkipLength: 0, BeginsBlock: true}, // load_imm R0, 7
		{PC: 1, Opcode: 51, Ra: 1, Vx: 6, SkipLength: 0},                    // load_imm R1, 6
		{PC: 2, Opcode: 202, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0},            // mul_64 R2, R0, R1
		{PC: 3, Opcode: 0, SkipLength: 0},                                   // trap
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[2] != 42 {
		t.Errorf("R2 = %d, want 42 (7*6)", state.Registers[2])
	}
	t.Logf("R0=%d, R1=%d, R2=%d", state.Registers[0], state.Registers[1], state.Registers[2])
}

// TestBitwiseAnd tests and instruction
func TestBitwiseAnd(t *testing.T) {

	// R0=0xFF, R1=0x0F, R2=R0&R1 (should be 0x0F)
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 0xFF, SkipLength: 0, BeginsBlock: true}, // load_imm R0, 0xFF
		{PC: 1, Opcode: 51, Ra: 1, Vx: 0x0F, SkipLength: 0},                    // load_imm R1, 0x0F
		{PC: 2, Opcode: 210, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0},               // and R2, R0, R1
		{PC: 3, Opcode: 0, SkipLength: 0},                                      // trap
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[2] != 0x0F {
		t.Errorf("R2 = 0x%x, want 0x0F", state.Registers[2])
	}
	t.Logf("R0=0x%x, R1=0x%x, R2=0x%x", state.Registers[0], state.Registers[1], state.Registers[2])
}

// TestSpilledRegisters tests registers R6-R12 which are memory-backed
func TestSpilledRegisters(t *testing.T) {

	// Load values into spilled registers R6, R7, R8
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 6, Vx: 66, SkipLength: 0, BeginsBlock: true}, // load_imm R6, 66
		{PC: 1, Opcode: 51, Ra: 7, Vx: 77, SkipLength: 0},                    // load_imm R7, 77
		{PC: 2, Opcode: 51, Ra: 8, Vx: 88, SkipLength: 0},                    // load_imm R8, 88
		{PC: 3, Opcode: 200, Rd: 9, Ra: 6, Rb: 7, SkipLength: 0},             // add_64 R9, R6, R7
		{PC: 4, Opcode: 0, SkipLength: 0},                                    // trap
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

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

	// R0=42, R1=R0
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 42, SkipLength: 0, BeginsBlock: true}, // load_imm R0, 42
		{PC: 1, Opcode: 100, Rd: 1, Ra: 0, SkipLength: 0},                    // move_reg R1, R0
		{PC: 2, Opcode: 0, SkipLength: 0},                                    // trap
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

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

	// 5 instructions but only 3 gas
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 1, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 51, Ra: 1, Vx: 2, SkipLength: 0},
		{PC: 2, Opcode: 51, Ra: 2, Vx: 3, SkipLength: 0},
		{PC: 3, Opcode: 51, Ra: 3, Vx: 4, SkipLength: 0},
		{PC: 4, Opcode: 0, SkipLength: 0}, // trap
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	state.Gas = 3 // Only 3 gas

	exitEncoded, nextPC := ExecuteBlock(block, unsafe.Pointer(state))

	// Should exit with OutOfGas (3) after executing 3 instructions
	if exitEncoded != 3 {
		t.Errorf("exitEncoded = %d, want 3 (OutOfGas)", exitEncoded)
	}
	t.Logf("exit=%d, nextPC=%d, gas=%d, R0=%d, R1=%d, R2=%d",
		exitEncoded, nextPC, state.Gas, state.Registers[0], state.Registers[1], state.Registers[2])
}

// TestBitwiseXor tests xor instruction
func TestBitwiseXor(t *testing.T) {

	// R0=0xFF, R1=0xAA, R2=R0^R1 (should be 0x55)
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 0xFF, SkipLength: 0, BeginsBlock: true}, // load_imm R0, 0xFF
		{PC: 1, Opcode: 51, Ra: 1, Vx: 0xAA, SkipLength: 0},                    // load_imm R1, 0xAA
		{PC: 2, Opcode: 211, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0},               // xor R2, R0, R1
		{PC: 3, Opcode: 0, SkipLength: 0},                                      // trap
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[2] != 0x55 {
		t.Errorf("R2 = 0x%x, want 0x55", state.Registers[2])
	}
	t.Logf("R0=0x%x ^ R1=0x%x = R2=0x%x", state.Registers[0], state.Registers[1], state.Registers[2])
}

// TestBitwiseOr tests or instruction
func TestBitwiseOr(t *testing.T) {

	// R0=0xF0, R1=0x0F, R2=R0|R1 (should be 0xFF)
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 0xF0, SkipLength: 0, BeginsBlock: true}, // load_imm R0, 0xF0
		{PC: 1, Opcode: 51, Ra: 1, Vx: 0x0F, SkipLength: 0},                    // load_imm R1, 0x0F
		{PC: 2, Opcode: 212, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0},               // or R2, R0, R1
		{PC: 3, Opcode: 0, SkipLength: 0},                                      // trap
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[2] != 0xFF {
		t.Errorf("R2 = 0x%x, want 0xFF", state.Registers[2])
	}
	t.Logf("R0=0x%x | R1=0x%x = R2=0x%x", state.Registers[0], state.Registers[1], state.Registers[2])
}

// TestShiftLeft tests shlo_l_64 instruction
func TestShiftLeft(t *testing.T) {

	// R0=1, R1=4, R2=R0<<R1 (should be 16)
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 1, SkipLength: 0, BeginsBlock: true}, // load_imm R0, 1
		{PC: 1, Opcode: 51, Ra: 1, Vx: 4, SkipLength: 0},                    // load_imm R1, 4
		{PC: 2, Opcode: 207, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0},            // shlo_l_64 R2, R0, R1
		{PC: 3, Opcode: 0, SkipLength: 0},                                   // trap
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[2] != 16 {
		t.Errorf("R2 = %d, want 16 (1<<4)", state.Registers[2])
	}
	t.Logf("R0=%d << R1=%d = R2=%d", state.Registers[0], state.Registers[1], state.Registers[2])
}

// TestShiftRight tests shlo_r_64 instruction
func TestShiftRight(t *testing.T) {

	// R0=256, R1=4, R2=R0>>R1 (should be 16)
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 256, SkipLength: 0, BeginsBlock: true}, // load_imm R0, 256
		{PC: 1, Opcode: 51, Ra: 1, Vx: 4, SkipLength: 0},                      // load_imm R1, 4
		{PC: 2, Opcode: 208, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0},              // shlo_r_64 R2, R0, R1
		{PC: 3, Opcode: 0, SkipLength: 0},                                     // trap
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[2] != 16 {
		t.Errorf("R2 = %d, want 16 (256>>4)", state.Registers[2])
	}
	t.Logf("R0=%d >> R1=%d = R2=%d", state.Registers[0], state.Registers[1], state.Registers[2])
}

// TestDivision tests div_u_64 instruction
func TestDivision(t *testing.T) {

	// R0=100, R1=7, R2=R0/R1 (should be 14)
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 100, SkipLength: 0, BeginsBlock: true}, // load_imm R0, 100
		{PC: 1, Opcode: 51, Ra: 1, Vx: 7, SkipLength: 0},                      // load_imm R1, 7
		{PC: 2, Opcode: 203, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0},              // div_u_64 R2, R0, R1
		{PC: 3, Opcode: 0, SkipLength: 0},                                     // trap
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[2] != 14 {
		t.Errorf("R2 = %d, want 14 (100/7)", state.Registers[2])
	}
	t.Logf("R0=%d / R1=%d = R2=%d", state.Registers[0], state.Registers[1], state.Registers[2])
}

// TestRemainder tests rem_u_64 instruction
func TestRemainder(t *testing.T) {

	// R0=100, R1=7, R2=R0%R1 (should be 2)
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 100, SkipLength: 0, BeginsBlock: true}, // load_imm R0, 100
		{PC: 1, Opcode: 51, Ra: 1, Vx: 7, SkipLength: 0},                      // load_imm R1, 7
		{PC: 2, Opcode: 205, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0},              // rem_u_64 R2, R0, R1
		{PC: 3, Opcode: 0, SkipLength: 0},                                     // trap
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[2] != 2 {
		t.Errorf("R2 = %d, want 2 (100%%7)", state.Registers[2])
	}
	t.Logf("R0=%d %% R1=%d = R2=%d", state.Registers[0], state.Registers[1], state.Registers[2])
}

// TestChainedOperations tests multiple operations in sequence
func TestChainedOperations(t *testing.T) {

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

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

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

	// Load unique values into all 13 registers
	instructions := make([]*ParsedInstruction, 14)
	for i := 0; i < 13; i++ {
		instructions[i] = &ParsedInstruction{
			PC: types.Register(i), Opcode: 51, Ra: i, Vx: types.Register(i * 11), SkipLength: 0,
			BeginsBlock: i == 0, // First instruction begins a block
		}
	}
	instructions[13] = &ParsedInstruction{PC: 13, Opcode: 0, SkipLength: 0} // trap

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

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

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	state := newTestState()
	runUntilExit(t, ctx, state)

	if state.Registers[2] != 42 {
		t.Errorf("R2 = %d, want 42 (branch should skip 999)", state.Registers[2])
	}
	t.Logf("R0=%d, R1=%d, R2=%d (branch taken)", state.Registers[0], state.Registers[1], state.Registers[2])
}

// TestBranchEqualNotTaken tests branch_eq instruction (not taken)
func TestBranchEqualNotTaken(t *testing.T) {

	// R0=5, R1=7, if R0==R1 goto PC 4 (not taken), continue to PC 3
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 5, SkipLength: 0, BeginsBlock: true},  // load_imm R0, 5
		{PC: 1, Opcode: 51, Ra: 1, Vx: 7, SkipLength: 0},                     // load_imm R1, 7
		{PC: 2, Opcode: 170, Ra: 0, Rb: 1, Vx: 4, SkipLength: 0},             // branch_eq R0, R1, target=4
		{PC: 3, Opcode: 51, Ra: 2, Vx: 42, SkipLength: 0, BeginsBlock: true}, // load_imm R2, 42 (fallthrough)
		{PC: 4, Opcode: 0, SkipLength: 0, BeginsBlock: true},                 // trap (branch target)
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	state := newTestState()
	runUntilExit(t, ctx, state)

	if state.Registers[2] != 42 {
		t.Errorf("R2 = %d, want 42 (branch not taken)", state.Registers[2])
	}
	t.Logf("R0=%d, R1=%d, R2=%d (branch not taken)", state.Registers[0], state.Registers[1], state.Registers[2])
}

// TestBranchNotEqual tests branch_ne instruction
func TestBranchNotEqual(t *testing.T) {

	// R0=5, R1=7, if R0!=R1 goto PC 4 (taken)
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 5, SkipLength: 0, BeginsBlock: true},   // load_imm R0, 5
		{PC: 1, Opcode: 51, Ra: 1, Vx: 7, SkipLength: 0},                      // load_imm R1, 7
		{PC: 2, Opcode: 171, Ra: 0, Rb: 1, Vx: 4, SkipLength: 0},              // branch_ne R0, R1, target=4
		{PC: 3, Opcode: 51, Ra: 2, Vx: 999, SkipLength: 0, BeginsBlock: true}, // load_imm R2, 999 (fallthrough)
		{PC: 4, Opcode: 51, Ra: 2, Vx: 42, SkipLength: 0, BeginsBlock: true},  // load_imm R2, 42 (branch target)
		{PC: 5, Opcode: 0, SkipLength: 0},                                     // trap
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	state := newTestState()
	runUntilExit(t, ctx, state)

	if state.Registers[2] != 42 {
		t.Errorf("R2 = %d, want 42 (branch_ne taken)", state.Registers[2])
	}
	t.Logf("R0=%d, R1=%d, R2=%d", state.Registers[0], state.Registers[1], state.Registers[2])
}

// TestBranchLessThan tests branch_lt_u instruction
func TestBranchLessThan(t *testing.T) {

	// R0=3, R1=7, if R0<R1 goto PC 4 (taken)
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 3, SkipLength: 0, BeginsBlock: true},   // load_imm R0, 3
		{PC: 1, Opcode: 51, Ra: 1, Vx: 7, SkipLength: 0},                      // load_imm R1, 7
		{PC: 2, Opcode: 172, Ra: 0, Rb: 1, Vx: 4, SkipLength: 0},              // branch_lt_u R0, R1, target=4
		{PC: 3, Opcode: 51, Ra: 2, Vx: 999, SkipLength: 0, BeginsBlock: true}, // load_imm R2, 999 (fallthrough)
		{PC: 4, Opcode: 51, Ra: 2, Vx: 42, SkipLength: 0, BeginsBlock: true},  // load_imm R2, 42 (branch target)
		{PC: 5, Opcode: 0, SkipLength: 0},                                     // trap
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	state := newTestState()
	runUntilExit(t, ctx, state)

	if state.Registers[2] != 42 {
		t.Errorf("R2 = %d, want 42 (branch_lt_u taken)", state.Registers[2])
	}
	t.Logf("R0=%d < R1=%d, R2=%d", state.Registers[0], state.Registers[1], state.Registers[2])
}

// TestBranchGreaterEqual tests branch_ge_u instruction
func TestBranchGreaterEqual(t *testing.T) {

	// R0=10, R1=7, if R0>=R1 goto PC 4 (taken)
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 10, SkipLength: 0, BeginsBlock: true},  // load_imm R0, 10
		{PC: 1, Opcode: 51, Ra: 1, Vx: 7, SkipLength: 0},                      // load_imm R1, 7
		{PC: 2, Opcode: 174, Ra: 0, Rb: 1, Vx: 4, SkipLength: 0},              // branch_ge_u R0, R1, target=4
		{PC: 3, Opcode: 51, Ra: 2, Vx: 999, SkipLength: 0, BeginsBlock: true}, // load_imm R2, 999 (fallthrough)
		{PC: 4, Opcode: 51, Ra: 2, Vx: 42, SkipLength: 0, BeginsBlock: true},  // load_imm R2, 42 (branch target)
		{PC: 5, Opcode: 0, SkipLength: 0},                                     // trap
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	state := newTestState()
	runUntilExit(t, ctx, state)

	if state.Registers[2] != 42 {
		t.Errorf("R2 = %d, want 42 (branch_ge_u taken)", state.Registers[2])
	}
	t.Logf("R0=%d >= R1=%d, R2=%d", state.Registers[0], state.Registers[1], state.Registers[2])
}

// TestUnconditionalJump tests jump instruction
func TestUnconditionalJump(t *testing.T) {

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

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	state := newTestState()
	runUntilExit(t, ctx, state)

	if state.Registers[0] != 42 {
		t.Errorf("R0 = %d, want 42 (jump should skip 999)", state.Registers[0])
	}
	t.Logf("R0=%d (jumped over 999)", state.Registers[0])
}

// TestSimpleLoop tests a simple loop: sum 1+2+3+4+5 = 15
func TestSimpleLoop(t *testing.T) {

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

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	// Dump the loop block's x86 code
	loopBlock := ctx.GetBlock(4)
	if loopBlock != nil {
		t.Logf("Loop block (PC 4-6): %d bytes at 0x%x", loopBlock.CodeSize, loopBlock.EntryPoint)
		// Get the code bytes from executable memory
		codeBytes := ctx.execMem.GetBytes(loopBlock.EntryPoint, loopBlock.CodeSize)
		t.Logf("x86 hex: %x", codeBytes)
	}

	state := newTestState()
	state.Gas = 50 // Need more gas for loop
	runUntilExit(t, ctx, state)

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

	// R0=100, R1=0, R2=R0/R1 (should be max uint64)
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 100, SkipLength: 0, BeginsBlock: true}, // load_imm R0, 100
		{PC: 1, Opcode: 51, Ra: 1, Vx: 0, SkipLength: 0},                      // load_imm R1, 0
		{PC: 2, Opcode: 203, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0},              // div_u_64 R2, R0, R1
		{PC: 3, Opcode: 0, SkipLength: 0},                                     // trap
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	// Division by zero should return max uint64
	maxUint64 := types.Register(^uint64(0))
	if state.Registers[2] != maxUint64 {
		t.Errorf("R2 = %d, want %d (max uint64 for div by zero)", state.Registers[2], maxUint64)
	}
	t.Logf("100 / 0 = %d (max uint64)", state.Registers[2])
}

// TestRemainderByZero tests that remainder by zero returns dividend
func TestRemainderByZero(t *testing.T) {

	// R0=100, R1=0, R2=R0%R1 (should be R0)
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 100, SkipLength: 0, BeginsBlock: true}, // load_imm R0, 100
		{PC: 1, Opcode: 51, Ra: 1, Vx: 0, SkipLength: 0},                      // load_imm R1, 0
		{PC: 2, Opcode: 205, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0},              // rem_u_64 R2, R0, R1
		{PC: 3, Opcode: 0, SkipLength: 0},                                     // trap
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	// Remainder by zero should return dividend
	if state.Registers[2] != 100 {
		t.Errorf("R2 = %d, want 100 (dividend for rem by zero)", state.Registers[2])
	}
	t.Logf("100 %% 0 = %d", state.Registers[2])
}

// TestSignedBranchLessThan tests branch_lt_s with negative numbers
func TestSignedBranchLessThan(t *testing.T) {

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

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	state := newTestState()
	runUntilExit(t, ctx, state)

	if state.Registers[2] != 42 {
		t.Errorf("R2 = %d, want 42 (signed -5 < 3 should be true)", state.Registers[2])
	}
	t.Logf("Signed: %d < %d = true, R2=%d", int64(state.Registers[0]), state.Registers[1], state.Registers[2])
}

// TestSignedBranchGreaterEqual tests branch_ge_s with negative numbers
func TestSignedBranchGreaterEqual(t *testing.T) {

	// R0=3, R1=-5 (as signed), if R0 >= R1 (signed) goto PC 4 (should be taken)
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 3, SkipLength: 0, BeginsBlock: true},       // load_imm R0, 3
		{PC: 1, Opcode: 51, Ra: 1, Vx: types.Register(^uint64(4)), SkipLength: 0}, // load_imm R1, -5 (two's complement)
		{PC: 2, Opcode: 175, Ra: 0, Rb: 1, Vx: 4, SkipLength: 0},                  // branch_ge_s R0, R1, target=4
		{PC: 3, Opcode: 51, Ra: 2, Vx: 999, SkipLength: 0, BeginsBlock: true},     // load_imm R2, 999 (fallthrough)
		{PC: 4, Opcode: 51, Ra: 2, Vx: 42, SkipLength: 0, BeginsBlock: true},      // load_imm R2, 42 (branch target)
		{PC: 5, Opcode: 0, SkipLength: 0},                                         // trap
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	state := newTestState()
	runUntilExit(t, ctx, state)

	if state.Registers[2] != 42 {
		t.Errorf("R2 = %d, want 42 (signed 3 >= -5 should be true)", state.Registers[2])
	}
	t.Logf("Signed: %d >= %d = true, R2=%d", state.Registers[0], int64(state.Registers[1]), state.Registers[2])
}

// TestDynamicJump tests jump_ind with a dynamic jump table
func TestDynamicJump(t *testing.T) {

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

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	state := newTestState()
	exitCode := runUntilExitWithTable(t, ctx, state, dynamicJumpTable, instructions)

	// Should have jumped to PC 4, setting R1=42
	if state.Registers[1] != 42 {
		t.Errorf("R1 = %d, want 42 (dynamic jump to PC 4), exit=%d", state.Registers[1], exitCode)
	}
	t.Logf("Dynamic jump: address %d -> PC 4, R1=%d, exit=%d", state.Registers[0], state.Registers[1], exitCode)
}

// TestDynamicJumpSecondEntry tests jump_ind with second table entry
func TestDynamicJumpSecondEntry(t *testing.T) {

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

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	state := newTestState()
	runUntilExitWithTable(t, ctx, state, dynamicJumpTable, instructions)

	// Should have jumped to PC 6, setting R1=77
	if state.Registers[1] != 77 {
		t.Errorf("R1 = %d, want 77 (dynamic jump to PC 6)", state.Registers[1])
	}
	t.Logf("Dynamic jump: address %d -> PC 6, R1=%d", state.Registers[0], state.Registers[1])
}

// TestHostCallReentry tests ecalli with re-entry after host function
func TestHostCallReentry(t *testing.T) {

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

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	state := newTestState()
	state.Gas = 50
	exitCode := runUntilExitWithHostCall(t, ctx, state, instructions)

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

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	state := newTestState()
	state.Gas = 100

	// Start execution at PC 2 (mid-block) - requires trampoline
	block := ctx.GetBlock(2)
	if block == nil {
		t.Fatal("GetBlock(2) returned nil - trampoline generation failed")
	}

	// Verify it's a trampoline (StartPC == EndPC == 2, small code size)
	if block.StartPC != 2 || block.EndPC != 2 {
		t.Errorf("Expected trampoline with StartPC=EndPC=2, got StartPC=%d, EndPC=%d", block.StartPC, block.EndPC)
	}

	exitEncoded, _ := ExecuteBlock(block, unsafe.Pointer(state))

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

	// R0=10, R1=15, R2=R0-R1 (should be -5 as signed)
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 10, SkipLength: 0, BeginsBlock: true}, // load_imm R0, 10
		{PC: 1, Opcode: 51, Ra: 1, Vx: 15, SkipLength: 0},                    // load_imm R1, 15
		{PC: 2, Opcode: 201, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0},             // sub_64 R2, R0, R1
		{PC: 3, Opcode: 0, SkipLength: 0},                                    // trap
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	// 10 - 15 = -5 (as signed)
	expected := types.Register(^uint64(4)) // -5 in two's complement
	if state.Registers[2] != expected {
		t.Errorf("R2 = %d (signed: %d), want -5", state.Registers[2], int64(state.Registers[2]))
	}
	t.Logf("10 - 15 = %d (signed)", int64(state.Registers[2]))
}

// TestMemoryLoadStore tests memory load and store operations
func TestMemoryLoadStore(t *testing.T) {

	// Test: store value to memory, then load it back
	// PC 0: load_imm R0, 0xDEADBEEF
	// PC 1: store_u32 R0, addr=100 (store R0 to memory[100])
	// PC 2: load_u32 R1, addr=100 (load memory[100] to R1)
	// PC 3: trap
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 0xDEADBEEF, SkipLength: 0, BeginsBlock: true}, // load_imm R0, 0xDEADBEEF
		{PC: 1, Opcode: 61, Ra: 0, Vx: 100, SkipLength: 0},                           // store_u32 R0, addr=100
		{PC: 2, Opcode: 56, Ra: 1, Vx: 100, SkipLength: 0},                           // load_u32 R1, addr=100
		{PC: 3, Opcode: 0, SkipLength: 0},                                            // trap
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	// R1 should have the value we stored
	if state.Registers[1] != 0xDEADBEEF {
		t.Errorf("R1 = 0x%X, want 0xDEADBEEF", state.Registers[1])
	}
	t.Logf("Memory store/load: R0=0x%X stored, R1=0x%X loaded", state.Registers[0], state.Registers[1])
}

// TestMemoryLoadStoreIndirect tests indirect memory operations (base + offset)
func TestMemoryLoadStoreIndirect(t *testing.T) {

	// Test: store value using indirect addressing, then load it back
	// PC 0: load_imm R0, 50 (base address)
	// PC 1: load_imm R1, 0xCAFEBABE (value to store)
	// PC 2: store_ind_u32 R1, R0, offset=50 (store R1 to memory[R0+50] = memory[100])
	// PC 3: load_ind_u32 R2, R0, offset=50 (load memory[R0+50] to R2)
	// PC 4: trap
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 50, SkipLength: 0, BeginsBlock: true}, // load_imm R0, 50
		{PC: 1, Opcode: 51, Ra: 1, Vx: 0xCAFEBABE, SkipLength: 0},            // load_imm R1, 0xCAFEBABE
		{PC: 2, Opcode: 122, Ra: 1, Rb: 0, Vx: 50, SkipLength: 0},            // store_ind_u32 R1, R0, 50
		{PC: 3, Opcode: 128, Ra: 2, Rb: 0, Vx: 50, SkipLength: 0},            // load_ind_u32 R2, R0, 50
		{PC: 4, Opcode: 0, SkipLength: 0},                                    // trap
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	// R2 should have the value we stored
	if state.Registers[2] != 0xCAFEBABE {
		t.Errorf("R2 = 0x%X, want 0xCAFEBABE", state.Registers[2])
	}
	t.Logf("Indirect memory: base=%d, offset=50, stored=0x%X, loaded=0x%X",
		state.Registers[0], state.Registers[1], state.Registers[2])
}

// TestMemorySignedLoad tests sign-extending loads
func TestMemorySignedLoad(t *testing.T) {

	// Test: store a negative 8-bit value, load it with sign extension
	// PC 0: load_imm R0, 0xFF (which is -1 as signed byte)
	// PC 1: store_u8 R0, addr=100
	// PC 2: load_i8 R1, addr=100 (sign-extended load)
	// PC 3: load_u8 R2, addr=100 (zero-extended load)
	// PC 4: trap
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 0xFF, SkipLength: 0, BeginsBlock: true}, // load_imm R0, 0xFF
		{PC: 1, Opcode: 59, Ra: 0, Vx: 100, SkipLength: 0},                     // store_u8 R0, addr=100
		{PC: 2, Opcode: 53, Ra: 1, Vx: 100, SkipLength: 0},                     // load_i8 R1, addr=100 (signed)
		{PC: 3, Opcode: 52, Ra: 2, Vx: 100, SkipLength: 0},                     // load_u8 R2, addr=100 (unsigned)
		{PC: 4, Opcode: 0, SkipLength: 0},                                      // trap
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	// R1 should be -1 (sign-extended)
	expectedSigned := types.Register(^uint64(0)) // -1 in two's complement
	if state.Registers[1] != expectedSigned {
		t.Errorf("R1 (signed) = %d, want -1", int64(state.Registers[1]))
	}
	// R2 should be 255 (zero-extended)
	if state.Registers[2] != 0xFF {
		t.Errorf("R2 (unsigned) = %d, want 255", state.Registers[2])
	}
	t.Logf("Signed load: R1=%d (signed), R2=%d (unsigned)", int64(state.Registers[1]), state.Registers[2])
}

// TestMemoryInvalidAccess tests that accessing inaccessible memory returns PageFault exit
func TestMemoryInvalidAccess(t *testing.T) {

	// Try to load from address 0 (in the inaccessible first 64KB zone)
	// PC 0: load_u32 R0, addr=0
	// PC 1: trap (should not reach here)
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 56, Ra: 0, Vx: 0, SkipLength: 0, BeginsBlock: true}, // load_u32 R0, addr=0
		{PC: 1, Opcode: 0, SkipLength: 0},                                   // trap
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	// Create state with real RAM (4GB mmap with mprotect)
	realRAM := ram.NewEmptyRAM(true) // JIT mode uses hardware protection
	state := &StateWithRealRAM{
		Gas:       100,
		Registers: [13]types.Register{},
		RAM:       realRAM,
	}

	block := ctx.GetBlock(0)
	exitEncoded, _ := ExecuteBlock(block, unsafe.Pointer(state))

	// Check for PageFault exit (exitType=2, high bit set)
	// The signal handler sets RAX = 0x82XXXXXX... where lower bits contain faulting address
	exitType := (exitEncoded >> 56) & 0x7F
	if exitEncoded&0x8000000000000000 == 0 || exitType != 2 {
		t.Errorf("Expected PageFault (exitType=2), got exitEncoded=0x%x, exitType=%d", exitEncoded, exitType)
	}
	faultAddr := exitEncoded & 0x00FFFFFFFFFFFFFF
	t.Logf("Invalid memory access correctly returned PageFault exit, faulting address=0x%x", faultAddr)
}

// StateWithRealRAM uses real ram.RAM for memory fault testing
type StateWithRealRAM struct {
	Gas       types.SignedGasValue
	Registers [13]types.Register
	RAM       *ram.RAM
}

// TestSbrkBasic tests the sbrk instruction for heap allocation
func TestSbrkBasic(t *testing.T) {

	// Program:
	// PC 0: load_imm R0, 1       ; request 1 page
	// PC 1: sbrk R1, R0          ; R1 = old heap end (or MaxUint64 on failure)
	// PC 2: trap                 ; exit
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 1, SkipLength: 0, BeginsBlock: true}, // load_imm R0, 1
		{PC: 1, Opcode: 101, Rd: 1, Ra: 0, SkipLength: 0},                   // sbrk R1, R0
		{PC: 2, Opcode: 0, SkipLength: 0},                                   // trap
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	// Create state with real RAM that has a heap initialized
	// Use NewRAM with some initial data to set up BeginningOfHeap
	realRAM := ram.NewRAM(
		[]byte{1, 2, 3, 4}, // readData (read-only section)
		[]byte{5, 6, 7, 8}, // writeData (initial heap data)
		[]byte{},           // arguments
		0,                  // z (extra heap pages)
		4096,               // stackSize
		true,               // hardwareProtection (JIT mode)
	)

	// Get the initial heap end before sbrk
	initialHeapEnd := uint64(0)
	if realRAM.BeginningOfHeap != nil {
		initialHeapEnd = uint64(*realRAM.BeginningOfHeap)
	}
	t.Logf("Initial heap end: 0x%x", initialHeapEnd)

	state := &StateWithRealRAM{
		Gas:       10000,
		Registers: [13]types.Register{},
		RAM:       realRAM,
	}

	block := ctx.GetBlock(0)
	exitEncoded, _ := ExecuteBlock(block, unsafe.Pointer(state))

	// Should exit with Panic (trap instruction) - exit code 2
	// Note: sbrk is a more expensive instruction, so we need more gas
	if exitEncoded != 2 {
		t.Errorf("Expected Panic exit (2), got %d (0x%x)", exitEncoded, exitEncoded)
	}

	// R1 should contain the old heap end (before allocation)
	result := state.Registers[1]
	t.Logf("sbrk returned: 0x%x", result)

	// If sbrk succeeded, result should be the initial heap end
	if result == 0xFFFFFFFFFFFFFFFF {
		t.Errorf("sbrk failed (returned MaxUint64), expected success")
	} else if result != types.Register(initialHeapEnd) {
		t.Errorf("sbrk returned 0x%x, expected initial heap end 0x%x", result, initialHeapEnd)
	}

	// Verify heap was extended by 1 page (4096 bytes)
	if realRAM.BeginningOfHeap != nil {
		newHeapEnd := uint64(*realRAM.BeginningOfHeap)
		expectedNewEnd := initialHeapEnd + 4096
		if newHeapEnd != expectedNewEnd {
			t.Errorf("New heap end = 0x%x, expected 0x%x", newHeapEnd, expectedNewEnd)
		}
		t.Logf("New heap end: 0x%x (extended by %d bytes)", newHeapEnd, newHeapEnd-initialHeapEnd)
	}
}

// TestSbrkNoHeap tests sbrk when no heap is initialized (should return MaxUint64)
func TestSbrkNoHeap(t *testing.T) {

	// Program:
	// PC 0: load_imm R0, 1       ; request 1 page
	// PC 1: sbrk R1, R0          ; R1 = MaxUint64 (no heap)
	// PC 2: trap                 ; exit
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 1, SkipLength: 0, BeginsBlock: true}, // load_imm R0, 1
		{PC: 1, Opcode: 101, Rd: 1, Ra: 0, SkipLength: 0},                   // sbrk R1, R0
		{PC: 2, Opcode: 0, SkipLength: 0},                                   // trap
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	// Create state with empty RAM (no heap initialized)
	realRAM := ram.NewEmptyRAM(true) // JIT mode uses hardware protection

	state := &StateWithRealRAM{
		Gas:       100,
		Registers: [13]types.Register{},
		RAM:       realRAM,
	}

	block := ctx.GetBlock(0)
	exitEncoded, _ := ExecuteBlock(block, unsafe.Pointer(state))

	// Should exit with Panic (trap instruction)
	if exitEncoded != 2 {
		t.Errorf("Expected Panic exit (2), got %d", exitEncoded)
	}

	// R1 should be MaxUint64 (sbrk failed because no heap)
	result := state.Registers[1]
	if result != 0xFFFFFFFFFFFFFFFF {
		t.Errorf("sbrk returned 0x%x, expected MaxUint64 (0xFFFFFFFFFFFFFFFF)", result)
	}
	t.Logf("sbrk correctly returned MaxUint64 for uninitialized heap")
}

// TestSbrkZeroPages tests sbrk with zero pages (should return current heap without modification)
func TestSbrkZeroPages(t *testing.T) {

	// Program:
	// PC 0: load_imm R0, 0       ; request 0 pages
	// PC 1: sbrk R1, R0          ; R1 = current heap end (no change)
	// PC 2: trap                 ; exit
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 0, SkipLength: 0, BeginsBlock: true}, // load_imm R0, 0
		{PC: 1, Opcode: 101, Rd: 1, Ra: 0, SkipLength: 0},                   // sbrk R1, R0
		{PC: 2, Opcode: 0, SkipLength: 0},                                   // trap
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	// Create state with real RAM that has a heap initialized
	realRAM := ram.NewRAM(
		[]byte{1, 2, 3, 4}, // readData
		[]byte{5, 6, 7, 8}, // writeData
		[]byte{},           // arguments
		0,                  // z
		4096,               // stackSize
		true,               // hardwareProtection (JIT mode)
	)

	initialHeapEnd := uint64(0)
	if realRAM.BeginningOfHeap != nil {
		initialHeapEnd = uint64(*realRAM.BeginningOfHeap)
	}

	state := &StateWithRealRAM{
		Gas:       100,
		Registers: [13]types.Register{},
		RAM:       realRAM,
	}

	block := ctx.GetBlock(0)
	ExecuteBlock(block, unsafe.Pointer(state))

	// R1 should contain the current heap end (unchanged)
	result := state.Registers[1]
	if result != types.Register(initialHeapEnd) {
		t.Errorf("sbrk(0) returned 0x%x, expected 0x%x", result, initialHeapEnd)
	}

	// Heap should not have changed
	if realRAM.BeginningOfHeap != nil {
		newHeapEnd := uint64(*realRAM.BeginningOfHeap)
		if newHeapEnd != initialHeapEnd {
			t.Errorf("Heap changed from 0x%x to 0x%x after sbrk(0)", initialHeapEnd, newHeapEnd)
		}
	}
	t.Logf("sbrk(0) correctly returned heap end 0x%x without modification", result)
}

// TestLoadImm64 tests load_imm_64 instruction (opcode 20)
func TestLoadImm64(t *testing.T) {

	// load_imm_64 can load full 64-bit values
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 20, Ra: 0, Vx: 0x123456789ABCDEF0, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[0] != 0x123456789ABCDEF0 {
		t.Errorf("R0 = 0x%X, want 0x123456789ABCDEF0", state.Registers[0])
	}
	t.Logf("load_imm_64: R0 = 0x%X", state.Registers[0])
}

// TestStoreImmU8 tests store_imm_u8 instruction (opcode 30)
func TestStoreImmU8(t *testing.T) {

	// store_imm_u8: store immediate byte to address
	// Vx = address, Vy = value (per compiler.go line 344)
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 30, Vx: 100, Vy: 0xAB, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 52, Ra: 0, Vx: 100, SkipLength: 0}, // load_u8 R0, addr=100
		{PC: 2, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[0] != 0xAB {
		t.Errorf("R0 = 0x%X, want 0xAB", state.Registers[0])
	}
	t.Logf("store_imm_u8: stored 0xAB, loaded R0 = 0x%X", state.Registers[0])
}

// TestStoreImmU32 tests store_imm_u32 instruction (opcode 32)
func TestStoreImmU32(t *testing.T) {

	// Vx = address, Vy = value
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 32, Vx: 100, Vy: 0xDEADBEEF, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 56, Ra: 0, Vx: 100, SkipLength: 0}, // load_u32 R0, addr=100
		{PC: 2, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[0] != 0xDEADBEEF {
		t.Errorf("R0 = 0x%X, want 0xDEADBEEF", state.Registers[0])
	}
	t.Logf("store_imm_u32: stored 0xDEADBEEF, loaded R0 = 0x%X", state.Registers[0])
}

// TestLoadImmJump tests load_imm_jump instruction (opcode 80)
func TestLoadImmJump(t *testing.T) {

	// load_imm_jump: Ra = Vx, then jump to Vy
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 80, Ra: 0, Vx: 42, Vy: 2, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 51, Ra: 0, Vx: 999, SkipLength: 0, BeginsBlock: true}, // skipped
		{PC: 2, Opcode: 0, SkipLength: 0, BeginsBlock: true},                  // trap
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	state := newTestState()
	runUntilExit(t, ctx, state)

	if state.Registers[0] != 42 {
		t.Errorf("R0 = %d, want 42", state.Registers[0])
	}
	t.Logf("load_imm_jump: R0 = %d (jumped over 999)", state.Registers[0])
}

// TestBranchEqImm tests branch_eq_imm instruction (opcode 81)
func TestBranchEqImm(t *testing.T) {

	// branch_eq_imm: if Ra == Vx then jump to Vy
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 42, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 81, Ra: 0, Vx: 42, Vy: 3, SkipLength: 0}, // if R0 == 42 goto 3
		{PC: 2, Opcode: 51, Ra: 1, Vx: 999, SkipLength: 0, BeginsBlock: true},
		{PC: 3, Opcode: 51, Ra: 1, Vx: 100, SkipLength: 0, BeginsBlock: true},
		{PC: 4, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	state := newTestState()
	runUntilExit(t, ctx, state)

	if state.Registers[1] != 100 {
		t.Errorf("R1 = %d, want 100 (branch_eq_imm taken)", state.Registers[1])
	}
}

// TestBranchNeImm tests branch_ne_imm instruction (opcode 82)
func TestBranchNeImm(t *testing.T) {

	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 42, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 82, Ra: 0, Vx: 99, Vy: 3, SkipLength: 0}, // if R0 != 99 goto 3
		{PC: 2, Opcode: 51, Ra: 1, Vx: 999, SkipLength: 0, BeginsBlock: true},
		{PC: 3, Opcode: 51, Ra: 1, Vx: 100, SkipLength: 0, BeginsBlock: true},
		{PC: 4, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	state := newTestState()
	runUntilExit(t, ctx, state)

	if state.Registers[1] != 100 {
		t.Errorf("R1 = %d, want 100 (branch_ne_imm taken)", state.Registers[1])
	}
}

// TestBranchLtUImm tests branch_lt_u_imm instruction (opcode 83)
func TestBranchLtUImm(t *testing.T) {

	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 5, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 83, Ra: 0, Vx: 10, Vy: 3, SkipLength: 0}, // if R0 < 10 goto 3
		{PC: 2, Opcode: 51, Ra: 1, Vx: 999, SkipLength: 0, BeginsBlock: true},
		{PC: 3, Opcode: 51, Ra: 1, Vx: 100, SkipLength: 0, BeginsBlock: true},
		{PC: 4, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	state := newTestState()
	runUntilExit(t, ctx, state)

	if state.Registers[1] != 100 {
		t.Errorf("R1 = %d, want 100 (branch_lt_u_imm taken)", state.Registers[1])
	}
}

// TestCountSetBits64 tests count_set_bits_64 instruction (opcode 102)
func TestCountSetBits64(t *testing.T) {

	// 0xFF has 8 bits set
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 0xFF, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 102, Rd: 1, Ra: 0, SkipLength: 0}, // R1 = popcnt(R0)
		{PC: 2, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[1] != 8 {
		t.Errorf("R1 = %d, want 8 (popcnt 0xFF)", state.Registers[1])
	}
}

// TestLeadingZeroBits64 tests leading_zero_bits_64 instruction (opcode 104)
func TestLeadingZeroBits64(t *testing.T) {

	// 0x0100000000000000 has 7 leading zeros
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 20, Ra: 0, Vx: 0x0100000000000000, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 104, Rd: 1, Ra: 0, SkipLength: 0}, // R1 = lzcnt(R0)
		{PC: 2, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[1] != 7 {
		t.Errorf("R1 = %d, want 7 (lzcnt 0x0100000000000000)", state.Registers[1])
	}
}

// TestTrailingZeroBits64 tests trailing_zero_bits_64 instruction (opcode 106)
func TestTrailingZeroBits64(t *testing.T) {

	// 0x80 = 0b10000000 has 7 trailing zeros
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 0x80, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 106, Rd: 1, Ra: 0, SkipLength: 0}, // R1 = tzcnt(R0)
		{PC: 2, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[1] != 7 {
		t.Errorf("R1 = %d, want 7 (tzcnt 0x80)", state.Registers[1])
	}
}

// TestSignedDivision tests div_s_64 instruction (opcode 204)
func TestSignedDivision(t *testing.T) {

	// -100 / 7 = -14 (truncated toward zero)
	neg100 := types.Register(^uint64(99)) // -100 in two's complement
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 20, Ra: 0, Vx: neg100, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 51, Ra: 1, Vx: 7, SkipLength: 0},
		{PC: 2, Opcode: 204, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0}, // div_s_64
		{PC: 3, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	expected := types.Register(^uint64(13)) // -14
	if state.Registers[2] != expected {
		t.Errorf("R2 = %d, want -14", int64(state.Registers[2]))
	}
	t.Logf("-100 / 7 = %d", int64(state.Registers[2]))
}

// TestSignedRemainder tests rem_s_64 instruction (opcode 206)
func TestSignedRemainder(t *testing.T) {

	// -100 % 7 = -2
	neg100 := types.Register(^uint64(99))
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 20, Ra: 0, Vx: neg100, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 51, Ra: 1, Vx: 7, SkipLength: 0},
		{PC: 2, Opcode: 206, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0}, // rem_s_64
		{PC: 3, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	expected := types.Register(^uint64(1)) // -2
	if state.Registers[2] != expected {
		t.Errorf("R2 = %d, want -2", int64(state.Registers[2]))
	}
	t.Logf("-100 %% 7 = %d", int64(state.Registers[2]))
}

// TestArithmeticShiftRight tests shar_r_64 instruction (opcode 209)
func TestArithmeticShiftRight(t *testing.T) {

	// -16 >> 2 = -4 (arithmetic shift preserves sign)
	neg16 := types.Register(^uint64(15))
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 20, Ra: 0, Vx: neg16, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 51, Ra: 1, Vx: 2, SkipLength: 0},
		{PC: 2, Opcode: 209, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0}, // shar_r_64
		{PC: 3, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	expected := types.Register(^uint64(3)) // -4
	if state.Registers[2] != expected {
		t.Errorf("R2 = %d, want -4", int64(state.Registers[2]))
	}
	t.Logf("-16 >> 2 (arithmetic) = %d", int64(state.Registers[2]))
}

// TestAdd32 tests add_32 instruction (opcode 190)
func TestAdd32(t *testing.T) {

	// 32-bit add with overflow: 0xFFFFFFFF + 1 = 0 (wraps)
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 0xFFFFFFFF, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 51, Ra: 1, Vx: 1, SkipLength: 0},
		{PC: 2, Opcode: 190, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0}, // add_32
		{PC: 3, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	// 32-bit add wraps and zero-extends to 64-bit
	if state.Registers[2] != 0 {
		t.Errorf("R2 = 0x%X, want 0 (32-bit wrap)", state.Registers[2])
	}
}

// TestMul32 tests mul_32 instruction (opcode 192)
func TestMul32(t *testing.T) {

	// 32-bit multiply: 0x10000 * 0x10000 = 0 (overflow, only low 32 bits)
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 0x10000, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 51, Ra: 1, Vx: 0x10000, SkipLength: 0},
		{PC: 2, Opcode: 192, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0}, // mul_32
		{PC: 3, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	// 0x10000 * 0x10000 = 0x100000000, but 32-bit truncates to 0
	if state.Registers[2] != 0 {
		t.Errorf("R2 = 0x%X, want 0 (32-bit overflow)", state.Registers[2])
	}
}

// TestMemoryU64 tests 64-bit memory operations
func TestMemoryU64(t *testing.T) {

	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 20, Ra: 0, Vx: 0x123456789ABCDEF0, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 62, Ra: 0, Vx: 100, SkipLength: 0}, // store_u64 R0, addr=100
		{PC: 2, Opcode: 58, Ra: 1, Vx: 100, SkipLength: 0}, // load_u64 R1, addr=100
		{PC: 3, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[1] != 0x123456789ABCDEF0 {
		t.Errorf("R1 = 0x%X, want 0x123456789ABCDEF0", state.Registers[1])
	}
}

// TestMemoryU16 tests 16-bit memory operations
func TestMemoryU16(t *testing.T) {

	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 0xABCD, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 60, Ra: 0, Vx: 100, SkipLength: 0}, // store_u16 R0, addr=100
		{PC: 2, Opcode: 54, Ra: 1, Vx: 100, SkipLength: 0}, // load_u16 R1, addr=100
		{PC: 3, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[1] != 0xABCD {
		t.Errorf("R1 = 0x%X, want 0xABCD", state.Registers[1])
	}
}

// TestSignExtend8 tests sign_extend_8 instruction (opcode 108)
func TestSignExtend8(t *testing.T) {

	// 0x80 sign-extended from 8 bits = -128
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 0x80, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 108, Rd: 1, Ra: 0, SkipLength: 0},
		{PC: 2, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	expected := types.Register(^uint64(127)) // -128
	if state.Registers[1] != expected {
		t.Errorf("R1 = %d, want -128", int64(state.Registers[1]))
	}
}

// TestReverseBytes tests reverse_bytes instruction (opcode 111)
func TestReverseBytes(t *testing.T) {

	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 20, Ra: 0, Vx: 0x0102030405060708, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 111, Rd: 1, Ra: 0, SkipLength: 0}, // bswap
		{PC: 2, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[1] != 0x0807060504030201 {
		t.Errorf("R1 = 0x%X, want 0x0807060504030201", state.Registers[1])
	}
}

// TestRotateLeft64 tests rot_l_64 instruction (opcode 220)
func TestRotateLeft64(t *testing.T) {

	// Rotate 0x0000000000000001 left by 4 = 0x0000000000000010
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 0x01, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 51, Ra: 1, Vx: 4, SkipLength: 0},
		{PC: 2, Opcode: 220, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0}, // rot_l_64
		{PC: 3, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[2] != 0x10 {
		t.Errorf("R2 = 0x%X, want 0x10", state.Registers[2])
	}
}

// TestCmovIz tests cmov_iz instruction (opcode 218)
func TestCmovIz(t *testing.T) {

	// cmov_iz: Rd = Ra if Rb == 0, else Rd unchanged
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 42, SkipLength: 0, BeginsBlock: true}, // R0 = 42 (value)
		{PC: 1, Opcode: 51, Ra: 1, Vx: 0, SkipLength: 0},                     // R1 = 0 (condition)
		{PC: 2, Opcode: 51, Ra: 2, Vx: 99, SkipLength: 0},                    // R2 = 99 (initial)
		{PC: 3, Opcode: 218, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0},             // cmov_iz R2, R0, R1
		{PC: 4, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	// R1 == 0, so R2 should be set to R0 (42)
	if state.Registers[2] != 42 {
		t.Errorf("R2 = %d, want 42 (cmov_iz with zero condition)", state.Registers[2])
	}
}

// TestSetLtU tests set_lt_u instruction (opcode 216)
func TestSetLtU(t *testing.T) {

	// set_lt_u: Rd = (Ra < Rb) ? 1 : 0 (unsigned)
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 5, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 51, Ra: 1, Vx: 10, SkipLength: 0},
		{PC: 2, Opcode: 216, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0}, // R2 = (5 < 10)
		{PC: 3, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[2] != 1 {
		t.Errorf("R2 = %d, want 1 (5 < 10)", state.Registers[2])
	}
}

// TestMulUpperUU tests mul_upper_u_u instruction (opcode 214)
func TestMulUpperUU(t *testing.T) {

	// 0x8000000000000000 * 2 = 0x10000000000000000, high 64 bits = 1
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 20, Ra: 0, Vx: 0x8000000000000000, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 51, Ra: 1, Vx: 2, SkipLength: 0},
		{PC: 2, Opcode: 214, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0}, // mul_upper_u_u
		{PC: 3, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[2] != 1 {
		t.Errorf("R2 = %d, want 1 (high bits of 0x8000000000000000 * 2)", state.Registers[2])
	}
}

// TestMaxSigned tests max instruction (opcode 227)
func TestMaxSigned(t *testing.T) {

	// max(-5, 3) = 3 (signed)
	neg5 := types.Register(^uint64(4))
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 20, Ra: 0, Vx: neg5, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 51, Ra: 1, Vx: 3, SkipLength: 0},
		{PC: 2, Opcode: 227, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0}, // max (signed)
		{PC: 3, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[2] != 3 {
		t.Errorf("R2 = %d, want 3 (max(-5, 3))", int64(state.Registers[2]))
	}
}

// TestMinUnsigned tests min_u instruction (opcode 230)
func TestMinUnsigned(t *testing.T) {

	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 100, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 51, Ra: 1, Vx: 50, SkipLength: 0},
		{PC: 2, Opcode: 230, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0}, // min_u
		{PC: 3, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[2] != 50 {
		t.Errorf("R2 = %d, want 50 (min(100, 50))", state.Registers[2])
	}
}

// TestDivByZero64 tests division by zero returns all 1s
func TestDivByZero64(t *testing.T) {

	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 100, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 51, Ra: 1, Vx: 0, SkipLength: 0},
		{PC: 2, Opcode: 203, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0}, // div_u_64
		{PC: 3, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	expected := types.Register(0xFFFFFFFFFFFFFFFF)
	if state.Registers[2] != expected {
		t.Errorf("R2 = 0x%X, want 0xFFFFFFFFFFFFFFFF (div by zero)", state.Registers[2])
	}
}

// TestAndInv tests and_inv instruction (opcode 224)
func TestAndInv(t *testing.T) {

	// 0xFF & ~0x0F = 0xF0
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 0xFF, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 51, Ra: 1, Vx: 0x0F, SkipLength: 0},
		{PC: 2, Opcode: 224, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0}, // and_inv
		{PC: 3, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[2] != 0xF0 {
		t.Errorf("R2 = 0x%X, want 0xF0", state.Registers[2])
	}
}

// TestXnor tests xnor instruction (opcode 226)
func TestXnor(t *testing.T) {

	// ~(0xFF ^ 0xFF) = ~0 = all 1s
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 0xFF, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 51, Ra: 1, Vx: 0xFF, SkipLength: 0},
		{PC: 2, Opcode: 226, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0}, // xnor
		{PC: 3, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	expected := types.Register(0xFFFFFFFFFFFFFFFF)
	if state.Registers[2] != expected {
		t.Errorf("R2 = 0x%X, want 0xFFFFFFFFFFFFFFFF", state.Registers[2])
	}
}

// TestAddImm64 tests add_imm_64 instruction (opcode 149)
func TestAddImm64(t *testing.T) {

	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 1, Vx: 100, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 149, Ra: 0, Rb: 1, Vx: 50, SkipLength: 0}, // add_imm_64
		{PC: 2, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[0] != 150 {
		t.Errorf("R0 = %d, want 150", state.Registers[0])
	}
}

// TestSetLtUImm tests set_lt_u_imm instruction (opcode 136)
func TestSetLtUImm(t *testing.T) {

	// set_lt_u_imm: Ra = (Rb < Vx) ? 1 : 0
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 1, Vx: 5, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 136, Ra: 0, Rb: 1, Vx: 10, SkipLength: 0}, // R0 = (5 < 10)
		{PC: 2, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[0] != 1 {
		t.Errorf("R0 = %d, want 1 (5 < 10)", state.Registers[0])
	}
}

// TestSetGtSImm tests set_gt_s_imm instruction (opcode 143)
func TestSetGtSImm(t *testing.T) {

	// set_gt_s_imm: Ra = (Rb > Vx) ? 1 : 0 (signed)
	// 5 > -10 = true (signed comparison)
	neg10 := types.Register(^uint64(9))
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 1, Vx: 5, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 20, Ra: 2, Vx: neg10, SkipLength: 0},
		{PC: 2, Opcode: 143, Ra: 0, Rb: 1, Vx: neg10, SkipLength: 0}, // R0 = (5 > -10)
		{PC: 3, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[0] != 1 {
		t.Errorf("R0 = %d, want 1 (5 > -10 signed)", state.Registers[0])
	}
}

// TestCmovNz tests cmov_nz instruction (opcode 219)
func TestCmovNz(t *testing.T) {

	// cmov_nz: Rd = Ra if Rb != 0
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 42, SkipLength: 0, BeginsBlock: true}, // R0 = 42 (value)
		{PC: 1, Opcode: 51, Ra: 1, Vx: 1, SkipLength: 0},                     // R1 = 1 (nonzero condition)
		{PC: 2, Opcode: 51, Ra: 2, Vx: 99, SkipLength: 0},                    // R2 = 99 (initial)
		{PC: 3, Opcode: 219, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0},             // cmov_nz R2, R0, R1
		{PC: 4, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	// R1 != 0, so R2 should be set to R0 (42)
	if state.Registers[2] != 42 {
		t.Errorf("R2 = %d, want 42 (cmov_nz with nonzero condition)", state.Registers[2])
	}
}

// TestStoreImmIndU32 tests store_imm_ind_u32 instruction (opcode 72)
func TestStoreImmIndU32(t *testing.T) {

	// store_imm_ind: store Vy to address (Ra + Vx)
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 100, SkipLength: 0, BeginsBlock: true}, // R0 = 100 (base)
		{PC: 1, Opcode: 72, Ra: 0, Vx: 8, Vy: 0xCAFEBABE, SkipLength: 0},      // store 0xCAFEBABE at R0+8
		{PC: 2, Opcode: 56, Ra: 1, Vx: 108, SkipLength: 0},                    // load_u32 R1, addr=108
		{PC: 3, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[1] != 0xCAFEBABE {
		t.Errorf("R1 = 0x%X, want 0xCAFEBABE", state.Registers[1])
	}
}

// TestNegAddImm64 tests neg_add_imm_64 instruction (opcode 154)
func TestNegAddImm64(t *testing.T) {

	// neg_add_imm_64: Ra = Vx - Rb
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 1, Vx: 30, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 154, Ra: 0, Rb: 1, Vx: 100, SkipLength: 0}, // R0 = 100 - 30 = 70
		{PC: 2, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[0] != 70 {
		t.Errorf("R0 = %d, want 70 (100 - 30)", state.Registers[0])
	}
}

// TestShloLImm64 tests shlo_l_imm_64 instruction (opcode 151)
func TestShloLImm64(t *testing.T) {

	// shlo_l_imm_64: Ra = Rb << (Vx % 64)
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 1, Vx: 1, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 151, Ra: 0, Rb: 1, Vx: 4, SkipLength: 0}, // R0 = 1 << 4 = 16
		{PC: 2, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[0] != 16 {
		t.Errorf("R0 = %d, want 16 (1 << 4)", state.Registers[0])
	}
}

// TestMulUpperSS tests mul_upper_s_s instruction (opcode 213)
func TestMulUpperSS(t *testing.T) {

	// -1 * -1 = 1, high bits = 0
	neg1 := types.Register(^uint64(0))
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 20, Ra: 0, Vx: neg1, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 20, Ra: 1, Vx: neg1, SkipLength: 0},
		{PC: 2, Opcode: 213, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0}, // mul_upper_s_s
		{PC: 3, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	// -1 * -1 = 1, which fits in low 64 bits, so high = 0
	if state.Registers[2] != 0 {
		t.Errorf("R2 = %d, want 0 (high bits of -1 * -1)", int64(state.Registers[2]))
	}
}

// TestMulUpperSU tests mul_upper_s_u instruction (opcode 215)
func TestMulUpperSU(t *testing.T) {

	// -1 (signed) * 2 (unsigned) = -2, high bits = -1
	neg1 := types.Register(^uint64(0))
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 20, Ra: 0, Vx: neg1, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 51, Ra: 1, Vx: 2, SkipLength: 0},
		{PC: 2, Opcode: 215, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0}, // mul_upper_s_u
		{PC: 3, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	// -1 * 2 = -2, high 64 bits = -1 (0xFFFFFFFFFFFFFFFF)
	expected := types.Register(^uint64(0))
	if state.Registers[2] != expected {
		t.Errorf("R2 = 0x%X, want 0x%X (high bits of -1 * 2)", state.Registers[2], expected)
	}
}

// TestOrInv tests or_inv instruction (opcode 225)
func TestOrInv(t *testing.T) {

	// 0x00 | ~0xFF = ~0xFF = 0xFFFFFFFFFFFFFF00
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 0x00, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 51, Ra: 1, Vx: 0xFF, SkipLength: 0},
		{PC: 2, Opcode: 225, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0}, // or_inv
		{PC: 3, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	expected := types.Register(^uint64(0xFF))
	if state.Registers[2] != expected {
		t.Errorf("R2 = 0x%X, want 0x%X", state.Registers[2], expected)
	}
}

// TestAndImm tests and_imm instruction (opcode 132)
func TestAndImm(t *testing.T) {

	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 1, Vx: 0xFF, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 132, Ra: 0, Rb: 1, Vx: 0x0F, SkipLength: 0}, // R0 = R1 & 0x0F
		{PC: 2, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[0] != 0x0F {
		t.Errorf("R0 = 0x%X, want 0x0F", state.Registers[0])
	}
}

// TestXorImm tests xor_imm instruction (opcode 133)
func TestXorImm(t *testing.T) {

	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 1, Vx: 0xFF, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 133, Ra: 0, Rb: 1, Vx: 0xF0, SkipLength: 0}, // R0 = R1 ^ 0xF0
		{PC: 2, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[0] != 0x0F {
		t.Errorf("R0 = 0x%X, want 0x0F", state.Registers[0])
	}
}

// TestOrImm tests or_imm instruction (opcode 134)
func TestOrImm(t *testing.T) {

	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 1, Vx: 0x0F, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 134, Ra: 0, Rb: 1, Vx: 0xF0, SkipLength: 0}, // R0 = R1 | 0xF0
		{PC: 2, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[0] != 0xFF {
		t.Errorf("R0 = 0x%X, want 0xFF", state.Registers[0])
	}
}

// TestAddImm32 tests add_imm_32 instruction (opcode 131)
func TestAddImm32(t *testing.T) {

	// 32-bit add with sign extension: 0x7FFFFFFF + 1 = 0x80000000 (negative when sign-extended)
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 1, Vx: 0x7FFFFFFF, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 131, Ra: 0, Rb: 1, Vx: 1, SkipLength: 0}, // R0 = (int32)(R1 + 1)
		{PC: 2, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	// 0x80000000 sign-extended = 0xFFFFFFFF80000000
	expected := types.Register(0xFFFFFFFF80000000)
	if state.Registers[0] != expected {
		t.Errorf("R0 = 0x%X, want 0x%X", state.Registers[0], expected)
	}
}

// TestMulImm32 tests mul_imm_32 instruction (opcode 135)
func TestMulImm32(t *testing.T) {

	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 1, Vx: 100, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 135, Ra: 0, Rb: 1, Vx: 3, SkipLength: 0}, // R0 = (int32)(R1 * 3)
		{PC: 2, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[0] != 300 {
		t.Errorf("R0 = %d, want 300", state.Registers[0])
	}
}

// TestNegAddImm32 tests neg_add_imm_32 instruction (opcode 141)
func TestNegAddImm32(t *testing.T) {

	// neg_add_imm_32: Ra = (int32)(Vx - Rb)
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 1, Vx: 30, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 141, Ra: 0, Rb: 1, Vx: 100, SkipLength: 0}, // R0 = (int32)(100 - 30)
		{PC: 2, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[0] != 70 {
		t.Errorf("R0 = %d, want 70", state.Registers[0])
	}
}

// TestShloLImm32 tests shlo_l_imm_32 instruction (opcode 138)
func TestShloLImm32(t *testing.T) {

	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 1, Vx: 1, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 138, Ra: 0, Rb: 1, Vx: 31, SkipLength: 0}, // R0 = (int32)(1 << 31)
		{PC: 2, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	// 1 << 31 = 0x80000000, sign-extended = 0xFFFFFFFF80000000
	expected := types.Register(0xFFFFFFFF80000000)
	if state.Registers[0] != expected {
		t.Errorf("R0 = 0x%X, want 0x%X", state.Registers[0], expected)
	}
}

// TestShloRImm32 tests shlo_r_imm_32 instruction (opcode 139)
func TestShloRImm32(t *testing.T) {

	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 1, Vx: 0x80000000, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 139, Ra: 0, Rb: 1, Vx: 4, SkipLength: 0}, // R0 = (int32)(0x80000000 >> 4)
		{PC: 2, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	// 0x80000000 >> 4 = 0x08000000, sign-extended = 0x08000000
	if state.Registers[0] != 0x08000000 {
		t.Errorf("R0 = 0x%X, want 0x08000000", state.Registers[0])
	}
}

// TestSharRImm32 tests shar_r_imm_32 instruction (opcode 140)
func TestSharRImm32(t *testing.T) {

	// Arithmetic shift right preserves sign
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 1, Vx: 0x80000000, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 140, Ra: 0, Rb: 1, Vx: 4, SkipLength: 0}, // R0 = (int32)(0x80000000 >> 4) arithmetic
		{PC: 2, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	// 0x80000000 (as int32 = -2147483648) >> 4 = 0xF8000000 (-134217728)
	// sign-extended to 64-bit = 0xFFFFFFFFF8000000
	expected := types.Register(0xFFFFFFFFF8000000)
	if state.Registers[0] != expected {
		t.Errorf("R0 = 0x%X, want 0x%X", state.Registers[0], expected)
	}
}

// TestShloLImmAlt32 tests shlo_l_imm_alt_32 instruction (opcode 144)
func TestShloLImmAlt32(t *testing.T) {

	// Alt version: Ra = (int32)(Vx << (Rb % 32))
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 1, Vx: 4, SkipLength: 0, BeginsBlock: true}, // shift amount
		{PC: 1, Opcode: 144, Ra: 0, Rb: 1, Vx: 1, SkipLength: 0},            // R0 = (int32)(1 << 4)
		{PC: 2, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[0] != 16 {
		t.Errorf("R0 = %d, want 16", state.Registers[0])
	}
}

// TestCmovIzImm tests cmov_iz_imm instruction (opcode 147)
func TestCmovIzImm(t *testing.T) {

	// cmov_iz_imm: Ra = Vx if Rb == 0
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 99, SkipLength: 0, BeginsBlock: true}, // R0 = 99 (initial)
		{PC: 1, Opcode: 51, Ra: 1, Vx: 0, SkipLength: 0},                     // R1 = 0 (condition)
		{PC: 2, Opcode: 147, Ra: 0, Rb: 1, Vx: 42, SkipLength: 0},            // if R1==0, R0 = 42
		{PC: 3, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[0] != 42 {
		t.Errorf("R0 = %d, want 42", state.Registers[0])
	}
}

// TestCmovNzImm tests cmov_nz_imm instruction (opcode 148)
func TestCmovNzImm(t *testing.T) {

	// cmov_nz_imm: Ra = Vx if Rb != 0
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 99, SkipLength: 0, BeginsBlock: true}, // R0 = 99 (initial)
		{PC: 1, Opcode: 51, Ra: 1, Vx: 1, SkipLength: 0},                     // R1 = 1 (nonzero)
		{PC: 2, Opcode: 148, Ra: 0, Rb: 1, Vx: 42, SkipLength: 0},            // if R1!=0, R0 = 42
		{PC: 3, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[0] != 42 {
		t.Errorf("R0 = %d, want 42", state.Registers[0])
	}
}

// TestRotR64Imm tests rot_r_64_imm instruction (opcode 158)
func TestRotR64Imm(t *testing.T) {

	// Rotate 0x01 right by 4 = 0x1000000000000000
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 1, Vx: 0x01, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 158, Ra: 0, Rb: 1, Vx: 4, SkipLength: 0}, // R0 = ror(R1, 4)
		{PC: 2, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	expected := types.Register(0x1000000000000000)
	if state.Registers[0] != expected {
		t.Errorf("R0 = 0x%X, want 0x%X", state.Registers[0], expected)
	}
}

// TestRotR32Imm tests rot_r_32_imm instruction (opcode 160)
func TestRotR32Imm(t *testing.T) {

	// Rotate 0x01 right by 4 (32-bit) = 0x10000000
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 1, Vx: 0x01, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 160, Ra: 0, Rb: 1, Vx: 4, SkipLength: 0}, // R0 = (int32)ror32(R1, 4)
		{PC: 2, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	// 0x10000000 sign-extended
	if state.Registers[0] != 0x10000000 {
		t.Errorf("R0 = 0x%X, want 0x10000000", state.Registers[0])
	}
}

// TestDiv32ByZero tests 32-bit division by zero
func TestDiv32ByZero(t *testing.T) {

	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 100, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 51, Ra: 1, Vx: 0, SkipLength: 0},
		{PC: 2, Opcode: 193, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0}, // div_u_32
		{PC: 3, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	expected := types.Register(0xFFFFFFFFFFFFFFFF)
	if state.Registers[2] != expected {
		t.Errorf("R2 = 0x%X, want 0xFFFFFFFFFFFFFFFF", state.Registers[2])
	}
}

// TestRem32 tests rem_u_32 instruction (opcode 195)
func TestRem32(t *testing.T) {

	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 17, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 51, Ra: 1, Vx: 5, SkipLength: 0},
		{PC: 2, Opcode: 195, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0}, // rem_u_32
		{PC: 3, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	// 17 % 5 = 2
	if state.Registers[2] != 2 {
		t.Errorf("R2 = %d, want 2", state.Registers[2])
	}
}

// TestMaxU tests max_u instruction (opcode 228)
func TestMaxU(t *testing.T) {

	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 50, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 51, Ra: 1, Vx: 100, SkipLength: 0},
		{PC: 2, Opcode: 228, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0}, // max_u
		{PC: 3, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[2] != 100 {
		t.Errorf("R2 = %d, want 100", state.Registers[2])
	}
}

// TestMinS tests min instruction (opcode 229)
func TestMinS(t *testing.T) {

	// min(-5, 3) = -5 (signed)
	neg5 := types.Register(^uint64(4))
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 20, Ra: 0, Vx: neg5, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 51, Ra: 1, Vx: 3, SkipLength: 0},
		{PC: 2, Opcode: 229, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0}, // min (signed)
		{PC: 3, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[2] != neg5 {
		t.Errorf("R2 = %d, want -5", int64(state.Registers[2]))
	}
}

// TestStoreImmU16 tests store_imm_u16 instruction (opcode 31)
func TestStoreImmU16(t *testing.T) {

	// store_imm_u16: store immediate 16-bit value to address
	// Vx = address, Vy = value
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 31, Vx: 100, Vy: 0xABCD, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 54, Ra: 0, Vx: 100, SkipLength: 0}, // load_u16 R0, addr=100
		{PC: 2, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[0] != 0xABCD {
		t.Errorf("R0 = 0x%X, want 0xABCD", state.Registers[0])
	}
}

// TestStoreImmU64 tests store_imm_u64 instruction (opcode 33)
func TestStoreImmU64(t *testing.T) {

	// store_imm_u64: store immediate 64-bit value to address
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 33, Vx: 100, Vy: 0x123456789ABCDEF0, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 58, Ra: 0, Vx: 100, SkipLength: 0}, // load_u64 R0, addr=100
		{PC: 2, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[0] != 0x123456789ABCDEF0 {
		t.Errorf("R0 = 0x%X, want 0x123456789ABCDEF0", state.Registers[0])
	}
}

// TestLoadI16 tests load_i16 instruction (opcode 55)
func TestLoadI16(t *testing.T) {

	// Store 0x8000 (negative in 16-bit signed), load with sign extension
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 31, Vx: 100, Vy: 0x8000, SkipLength: 0, BeginsBlock: true}, // store_imm_u16
		{PC: 1, Opcode: 55, Ra: 0, Vx: 100, SkipLength: 0},                         // load_i16 R0, addr=100
		{PC: 2, Opcode: 54, Ra: 1, Vx: 100, SkipLength: 0},                         // load_u16 R1, addr=100
		{PC: 3, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	// R0 should be sign-extended: 0x8000 -> 0xFFFFFFFFFFFF8000 (-32768)
	expectedSigned := types.Register(0xFFFFFFFFFFFF8000)
	if state.Registers[0] != expectedSigned {
		t.Errorf("R0 (signed) = 0x%X, want 0x%X", state.Registers[0], expectedSigned)
	}
	// R1 should be zero-extended: 0x8000
	if state.Registers[1] != 0x8000 {
		t.Errorf("R1 (unsigned) = 0x%X, want 0x8000", state.Registers[1])
	}
}

// TestLoadI32 tests load_i32 instruction (opcode 57)
func TestLoadI32(t *testing.T) {

	// Store 0x80000000 (negative in 32-bit signed), load with sign extension
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 32, Vx: 100, Vy: 0x80000000, SkipLength: 0, BeginsBlock: true}, // store_imm_u32
		{PC: 1, Opcode: 57, Ra: 0, Vx: 100, SkipLength: 0},                             // load_i32 R0, addr=100
		{PC: 2, Opcode: 56, Ra: 1, Vx: 100, SkipLength: 0},                             // load_u32 R1, addr=100
		{PC: 3, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	// R0 should be sign-extended: 0x80000000 -> 0xFFFFFFFF80000000
	expectedSigned := types.Register(0xFFFFFFFF80000000)
	if state.Registers[0] != expectedSigned {
		t.Errorf("R0 (signed) = 0x%X, want 0x%X", state.Registers[0], expectedSigned)
	}
	// R1 should be zero-extended: 0x80000000
	if state.Registers[1] != 0x80000000 {
		t.Errorf("R1 (unsigned) = 0x%X, want 0x80000000", state.Registers[1])
	}
}

// TestStoreImmIndU8 tests store_imm_ind_u8 instruction (opcode 70)
func TestStoreImmIndU8(t *testing.T) {

	// store_imm_ind: store Vy to address (Ra + Vx)
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 100, SkipLength: 0, BeginsBlock: true}, // R0 = 100 (base)
		{PC: 1, Opcode: 70, Ra: 0, Vx: 8, Vy: 0xAB, SkipLength: 0},            // store 0xAB at R0+8
		{PC: 2, Opcode: 52, Ra: 1, Vx: 108, SkipLength: 0},                    // load_u8 R1, addr=108
		{PC: 3, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[1] != 0xAB {
		t.Errorf("R1 = 0x%X, want 0xAB", state.Registers[1])
	}
}

// TestStoreImmIndU16 tests store_imm_ind_u16 instruction (opcode 71)
func TestStoreImmIndU16(t *testing.T) {

	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 100, SkipLength: 0, BeginsBlock: true}, // R0 = 100 (base)
		{PC: 1, Opcode: 71, Ra: 0, Vx: 8, Vy: 0xABCD, SkipLength: 0},          // store 0xABCD at R0+8
		{PC: 2, Opcode: 54, Ra: 1, Vx: 108, SkipLength: 0},                    // load_u16 R1, addr=108
		{PC: 3, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[1] != 0xABCD {
		t.Errorf("R1 = 0x%X, want 0xABCD", state.Registers[1])
	}
}

// TestStoreImmIndU64 tests store_imm_ind_u64 instruction (opcode 73)
func TestStoreImmIndU64(t *testing.T) {

	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 100, SkipLength: 0, BeginsBlock: true},    // R0 = 100 (base)
		{PC: 1, Opcode: 73, Ra: 0, Vx: 8, Vy: 0x123456789ABCDEF0, SkipLength: 0}, // store at R0+8
		{PC: 2, Opcode: 58, Ra: 1, Vx: 108, SkipLength: 0},                       // load_u64 R1, addr=108
		{PC: 3, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[1] != 0x123456789ABCDEF0 {
		t.Errorf("R1 = 0x%X, want 0x123456789ABCDEF0", state.Registers[1])
	}
}

// TestLoadIndU8 tests load_ind_u8 instruction (opcode 124)
func TestLoadIndU8(t *testing.T) {

	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 30, Vx: 108, Vy: 0xAB, SkipLength: 0, BeginsBlock: true}, // store_imm_u8
		{PC: 1, Opcode: 51, Ra: 1, Vx: 100, SkipLength: 0},                       // R1 = base
		{PC: 2, Opcode: 124, Ra: 0, Rb: 1, Vx: 8, SkipLength: 0},                 // load R0 from R1+8
		{PC: 3, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[0] != 0xAB {
		t.Errorf("R0 = 0x%X, want 0xAB", state.Registers[0])
	}
}

// TestLoadIndI8 tests load_ind_i8 instruction (opcode 125)
func TestLoadIndI8(t *testing.T) {

	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 30, Vx: 108, Vy: 0x80, SkipLength: 0, BeginsBlock: true}, // store_imm_u8 (0x80 = -128 signed)
		{PC: 1, Opcode: 51, Ra: 1, Vx: 100, SkipLength: 0},                       // R1 = base
		{PC: 2, Opcode: 125, Ra: 0, Rb: 1, Vx: 8, SkipLength: 0},                 // load_ind_i8 R0 from R1+8
		{PC: 3, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	expected := types.Register(0xFFFFFFFFFFFFFF80) // -128 sign-extended
	if state.Registers[0] != expected {
		t.Errorf("R0 = 0x%X, want 0x%X", state.Registers[0], expected)
	}
}

// TestLoadIndU16 tests load_ind_u16 instruction (opcode 126)
func TestLoadIndU16(t *testing.T) {

	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 31, Vx: 108, Vy: 0xABCD, SkipLength: 0, BeginsBlock: true}, // store_imm_u16
		{PC: 1, Opcode: 51, Ra: 1, Vx: 100, SkipLength: 0},                         // R1 = base
		{PC: 2, Opcode: 126, Ra: 0, Rb: 1, Vx: 8, SkipLength: 0},                   // load R0 from R1+8
		{PC: 3, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[0] != 0xABCD {
		t.Errorf("R0 = 0x%X, want 0xABCD", state.Registers[0])
	}
}

// TestLoadIndI16 tests load_ind_i16 instruction (opcode 127)
func TestLoadIndI16(t *testing.T) {

	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 31, Vx: 108, Vy: 0x8000, SkipLength: 0, BeginsBlock: true}, // store_imm_u16 (0x8000 = -32768 signed)
		{PC: 1, Opcode: 51, Ra: 1, Vx: 100, SkipLength: 0},                         // R1 = base
		{PC: 2, Opcode: 127, Ra: 0, Rb: 1, Vx: 8, SkipLength: 0},                   // load_ind_i16 R0 from R1+8
		{PC: 3, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	expected := types.Register(0xFFFFFFFFFFFF8000) // -32768 sign-extended
	if state.Registers[0] != expected {
		t.Errorf("R0 = 0x%X, want 0x%X", state.Registers[0], expected)
	}
}

// TestLoadIndI32 tests load_ind_i32 instruction (opcode 129)
func TestLoadIndI32(t *testing.T) {

	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 32, Vx: 108, Vy: 0x80000000, SkipLength: 0, BeginsBlock: true}, // store_imm_u32
		{PC: 1, Opcode: 51, Ra: 1, Vx: 100, SkipLength: 0},                             // R1 = base
		{PC: 2, Opcode: 129, Ra: 0, Rb: 1, Vx: 8, SkipLength: 0},                       // load_ind_i32 R0 from R1+8
		{PC: 3, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	expected := types.Register(0xFFFFFFFF80000000) // sign-extended
	if state.Registers[0] != expected {
		t.Errorf("R0 = 0x%X, want 0x%X", state.Registers[0], expected)
	}
}

// TestLoadIndU64 tests load_ind_u64 instruction (opcode 130)
func TestLoadIndU64(t *testing.T) {

	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 33, Vx: 108, Vy: 0x123456789ABCDEF0, SkipLength: 0, BeginsBlock: true}, // store_imm_u64
		{PC: 1, Opcode: 51, Ra: 1, Vx: 100, SkipLength: 0},                                     // R1 = base
		{PC: 2, Opcode: 130, Ra: 0, Rb: 1, Vx: 8, SkipLength: 0},                               // load_ind_u64 R0 from R1+8
		{PC: 3, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[0] != 0x123456789ABCDEF0 {
		t.Errorf("R0 = 0x%X, want 0x123456789ABCDEF0", state.Registers[0])
	}
}

// TestBranchLtSImm tests branch_lt_s_imm instruction (opcode 84)
func TestBranchLtSImm(t *testing.T) {

	neg5 := types.Register(^uint64(4)) // -5
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 20, Ra: 0, Vx: neg5, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 84, Ra: 0, Vx: 0, Vy: 3, SkipLength: 0}, // if R0 < 0 (signed) goto 3
		{PC: 2, Opcode: 51, Ra: 1, Vx: 999, SkipLength: 0, BeginsBlock: true},
		{PC: 3, Opcode: 51, Ra: 1, Vx: 100, SkipLength: 0, BeginsBlock: true},
		{PC: 4, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	state := newTestState()
	runUntilExit(t, ctx, state)

	if state.Registers[1] != 100 {
		t.Errorf("R1 = %d, want 100 (branch_lt_s_imm taken)", state.Registers[1])
	}
}

// TestBranchGeSImm tests branch_ge_s_imm instruction (opcode 85)
func TestBranchGeSImm(t *testing.T) {

	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 5, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 85, Ra: 0, Vx: 0, Vy: 3, SkipLength: 0}, // if R0 >= 0 (signed) goto 3
		{PC: 2, Opcode: 51, Ra: 1, Vx: 999, SkipLength: 0, BeginsBlock: true},
		{PC: 3, Opcode: 51, Ra: 1, Vx: 100, SkipLength: 0, BeginsBlock: true},
		{PC: 4, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	state := newTestState()
	runUntilExit(t, ctx, state)

	if state.Registers[1] != 100 {
		t.Errorf("R1 = %d, want 100 (branch_ge_s_imm taken)", state.Registers[1])
	}
}

// TestBranchGeUImm tests branch_ge_u_imm instruction (opcode 86)
func TestBranchGeUImm(t *testing.T) {

	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 10, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 86, Ra: 0, Vx: 5, Vy: 3, SkipLength: 0}, // if R0 >= 5 goto 3
		{PC: 2, Opcode: 51, Ra: 1, Vx: 999, SkipLength: 0, BeginsBlock: true},
		{PC: 3, Opcode: 51, Ra: 1, Vx: 100, SkipLength: 0, BeginsBlock: true},
		{PC: 4, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	state := newTestState()
	runUntilExit(t, ctx, state)

	if state.Registers[1] != 100 {
		t.Errorf("R1 = %d, want 100 (branch_ge_u_imm taken)", state.Registers[1])
	}
}

// TestBranchLtUAltImm tests branch_lt_u_alt_imm instruction (opcode 87)
func TestBranchLtUAltImm(t *testing.T) {

	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 10, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 87, Ra: 0, Vx: 5, Vy: 3, SkipLength: 0}, // if 5 < R0 goto 3
		{PC: 2, Opcode: 51, Ra: 1, Vx: 999, SkipLength: 0, BeginsBlock: true},
		{PC: 3, Opcode: 51, Ra: 1, Vx: 100, SkipLength: 0, BeginsBlock: true},
		{PC: 4, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	state := newTestState()
	runUntilExit(t, ctx, state)

	if state.Registers[1] != 100 {
		t.Errorf("R1 = %d, want 100 (branch_lt_u_alt_imm taken)", state.Registers[1])
	}
}

// TestBranchLtSAltImm tests branch_lt_s_alt_imm instruction (opcode 88)
func TestBranchLtSAltImm(t *testing.T) {

	neg5 := types.Register(^uint64(4)) // -5
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 5, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 88, Ra: 0, Vx: neg5, Vy: 3, SkipLength: 0}, // if -5 < R0 (signed) goto 3
		{PC: 2, Opcode: 51, Ra: 1, Vx: 999, SkipLength: 0, BeginsBlock: true},
		{PC: 3, Opcode: 51, Ra: 1, Vx: 100, SkipLength: 0, BeginsBlock: true},
		{PC: 4, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	state := newTestState()
	runUntilExit(t, ctx, state)

	if state.Registers[1] != 100 {
		t.Errorf("R1 = %d, want 100 (branch_lt_s_alt_imm taken)", state.Registers[1])
	}
}

// TestBranchGeUAltImm tests branch_ge_u_alt_imm instruction (opcode 89)
func TestBranchGeUAltImm(t *testing.T) {

	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 5, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 89, Ra: 0, Vx: 10, Vy: 3, SkipLength: 0}, // if 10 >= R0 goto 3
		{PC: 2, Opcode: 51, Ra: 1, Vx: 999, SkipLength: 0, BeginsBlock: true},
		{PC: 3, Opcode: 51, Ra: 1, Vx: 100, SkipLength: 0, BeginsBlock: true},
		{PC: 4, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	state := newTestState()
	runUntilExit(t, ctx, state)

	if state.Registers[1] != 100 {
		t.Errorf("R1 = %d, want 100 (branch_ge_u_alt_imm taken)", state.Registers[1])
	}
}

// TestBranchGeSAltImm tests branch_ge_s_alt_imm instruction (opcode 90)
func TestBranchGeSAltImm(t *testing.T) {

	neg5 := types.Register(^uint64(4)) // -5
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 20, Ra: 0, Vx: neg5, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 90, Ra: 0, Vx: 5, Vy: 3, SkipLength: 0}, // if 5 >= R0 (signed) goto 3
		{PC: 2, Opcode: 51, Ra: 1, Vx: 999, SkipLength: 0, BeginsBlock: true},
		{PC: 3, Opcode: 51, Ra: 1, Vx: 100, SkipLength: 0, BeginsBlock: true},
		{PC: 4, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	state := newTestState()
	runUntilExit(t, ctx, state)

	if state.Registers[1] != 100 {
		t.Errorf("R1 = %d, want 100 (branch_ge_s_alt_imm taken)", state.Registers[1])
	}
}

// TestCountSetBits32 tests count_set_bits_32 instruction (opcode 103)
func TestCountSetBits32(t *testing.T) {

	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 0xFF, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 103, Rd: 1, Ra: 0, SkipLength: 0}, // R1 = popcnt32(R0)
		{PC: 2, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[1] != 8 {
		t.Errorf("R1 = %d, want 8 (popcnt32 of 0xFF)", state.Registers[1])
	}
}

// TestLeadingZeroBits32 tests leading_zero_bits_32 instruction (opcode 105)
func TestLeadingZeroBits32(t *testing.T) {

	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 0x00010000, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 105, Rd: 1, Ra: 0, SkipLength: 0}, // R1 = lzcnt32(R0)
		{PC: 2, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[1] != 15 {
		t.Errorf("R1 = %d, want 15 (lzcnt32 0x00010000)", state.Registers[1])
	}
}

// TestTrailingZeroBits32 tests trailing_zero_bits_32 instruction (opcode 107)
func TestTrailingZeroBits32(t *testing.T) {

	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 0x00010000, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 107, Rd: 1, Ra: 0, SkipLength: 0}, // R1 = tzcnt32(R0)
		{PC: 2, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[1] != 16 {
		t.Errorf("R1 = %d, want 16 (tzcnt32 0x00010000)", state.Registers[1])
	}
}

// TestSignExtend16Op tests sign_extend_16 instruction (opcode 109)
func TestSignExtend16Op(t *testing.T) {

	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 0x8000, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 109, Rd: 1, Ra: 0, SkipLength: 0},
		{PC: 2, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	expected := types.Register(0xFFFFFFFFFFFF8000) // -32768
	if state.Registers[1] != expected {
		t.Errorf("R1 = 0x%X, want 0x%X", state.Registers[1], expected)
	}
}

// TestZeroExtend16Op tests zero_extend_16 instruction (opcode 110)
func TestZeroExtend16Op(t *testing.T) {

	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 20, Ra: 0, Vx: 0xFFFFFFFFFFFF8000, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 110, Rd: 1, Ra: 0, SkipLength: 0},
		{PC: 2, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[1] != 0x8000 {
		t.Errorf("R1 = 0x%X, want 0x8000", state.Registers[1])
	}
}

// TestStoreIndU8Op tests store_ind_u8 instruction (opcode 120)
func TestStoreIndU8Op(t *testing.T) {

	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 0xAB, SkipLength: 0, BeginsBlock: true}, // R0 = value
		{PC: 1, Opcode: 51, Ra: 1, Vx: 100, SkipLength: 0},                     // R1 = base
		{PC: 2, Opcode: 120, Ra: 0, Rb: 1, Vx: 8, SkipLength: 0},               // store R0 at R1+8
		{PC: 3, Opcode: 52, Ra: 2, Vx: 108, SkipLength: 0},                     // load_u8 R2, addr=108
		{PC: 4, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[2] != 0xAB {
		t.Errorf("R2 = 0x%X, want 0xAB", state.Registers[2])
	}
}

// TestStoreIndU16Op tests store_ind_u16 instruction (opcode 121)
func TestStoreIndU16Op(t *testing.T) {

	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 0xABCD, SkipLength: 0, BeginsBlock: true}, // R0 = value
		{PC: 1, Opcode: 51, Ra: 1, Vx: 100, SkipLength: 0},                       // R1 = base
		{PC: 2, Opcode: 121, Ra: 0, Rb: 1, Vx: 8, SkipLength: 0},                 // store R0 at R1+8
		{PC: 3, Opcode: 54, Ra: 2, Vx: 108, SkipLength: 0},                       // load_u16 R2, addr=108
		{PC: 4, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[2] != 0xABCD {
		t.Errorf("R2 = 0x%X, want 0xABCD", state.Registers[2])
	}
}

// TestStoreIndU64Op tests store_ind_u64 instruction (opcode 123)
func TestStoreIndU64Op(t *testing.T) {

	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 20, Ra: 0, Vx: 0x123456789ABCDEF0, SkipLength: 0, BeginsBlock: true}, // R0 = value
		{PC: 1, Opcode: 51, Ra: 1, Vx: 100, SkipLength: 0},                                   // R1 = base
		{PC: 2, Opcode: 123, Ra: 0, Rb: 1, Vx: 8, SkipLength: 0},                             // store R0 at R1+8
		{PC: 3, Opcode: 58, Ra: 2, Vx: 108, SkipLength: 0},                                   // load_u64 R2, addr=108
		{PC: 4, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[2] != 0x123456789ABCDEF0 {
		t.Errorf("R2 = 0x%X, want 0x123456789ABCDEF0", state.Registers[2])
	}
}

// TestSetLtSImm tests set_lt_s_imm instruction (opcode 137)
func TestSetLtSImm(t *testing.T) {

	neg5 := types.Register(^uint64(4)) // -5
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 20, Ra: 1, Vx: neg5, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 137, Ra: 0, Rb: 1, Vx: 0, SkipLength: 0}, // R0 = (-5 < 0) signed
		{PC: 2, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[0] != 1 {
		t.Errorf("R0 = %d, want 1 (-5 < 0 signed)", state.Registers[0])
	}
}

// TestSetGtUImm tests set_gt_u_imm instruction (opcode 142)
func TestSetGtUImm(t *testing.T) {

	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 1, Vx: 10, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 142, Ra: 0, Rb: 1, Vx: 5, SkipLength: 0}, // R0 = (10 > 5) unsigned
		{PC: 2, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[0] != 1 {
		t.Errorf("R0 = %d, want 1 (10 > 5)", state.Registers[0])
	}
}

// TestSetLtS tests set_lt_s instruction (opcode 217)
func TestSetLtS(t *testing.T) {

	neg5 := types.Register(^uint64(4)) // -5
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 20, Ra: 0, Vx: neg5, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 51, Ra: 1, Vx: 5, SkipLength: 0},
		{PC: 2, Opcode: 217, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0}, // R2 = (-5 < 5) signed
		{PC: 3, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[2] != 1 {
		t.Errorf("R2 = %d, want 1 (-5 < 5 signed)", state.Registers[2])
	}
}

// TestMulImm64 tests mul_imm_64 instruction (opcode 150)
func TestMulImm64(t *testing.T) {

	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 1, Vx: 7, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 150, Ra: 0, Rb: 1, Vx: 6, SkipLength: 0}, // R0 = 7 * 6
		{PC: 2, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[0] != 42 {
		t.Errorf("R0 = %d, want 42", state.Registers[0])
	}
}

// TestShloRImm64 tests shlo_r_imm_64 instruction (opcode 152)
func TestShloRImm64(t *testing.T) {

	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 1, Vx: 256, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 152, Ra: 0, Rb: 1, Vx: 4, SkipLength: 0}, // R0 = 256 >> 4
		{PC: 2, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[0] != 16 {
		t.Errorf("R0 = %d, want 16 (256 >> 4)", state.Registers[0])
	}
}

// TestSharRImm64 tests shar_r_imm_64 instruction (opcode 153)
func TestSharRImm64(t *testing.T) {

	neg16 := types.Register(^uint64(15)) // -16
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 20, Ra: 1, Vx: neg16, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 153, Ra: 0, Rb: 1, Vx: 2, SkipLength: 0}, // R0 = -16 >> 2 (arithmetic)
		{PC: 2, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	expected := types.Register(^uint64(3)) // -4
	if state.Registers[0] != expected {
		t.Errorf("R0 = %d, want -4", int64(state.Registers[0]))
	}
}

// TestShloLImmAlt64 tests shlo_l_imm_alt_64 instruction (opcode 155)
func TestShloLImmAlt64(t *testing.T) {

	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 1, Vx: 4, SkipLength: 0, BeginsBlock: true}, // shift amount
		{PC: 1, Opcode: 155, Ra: 0, Rb: 1, Vx: 1, SkipLength: 0},            // R0 = 1 << 4
		{PC: 2, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[0] != 16 {
		t.Errorf("R0 = %d, want 16 (1 << 4)", state.Registers[0])
	}
}

// TestShloRImmAlt64 tests shlo_r_imm_alt_64 instruction (opcode 156)
func TestShloRImmAlt64(t *testing.T) {

	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 1, Vx: 4, SkipLength: 0, BeginsBlock: true}, // shift amount
		{PC: 1, Opcode: 156, Ra: 0, Rb: 1, Vx: 256, SkipLength: 0},          // R0 = 256 >> 4
		{PC: 2, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[0] != 16 {
		t.Errorf("R0 = %d, want 16 (256 >> 4)", state.Registers[0])
	}
}

// TestSharRImmAlt64 tests shar_r_imm_alt_64 instruction (opcode 157)
func TestSharRImmAlt64(t *testing.T) {

	neg16 := types.Register(^uint64(15)) // -16
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 1, Vx: 2, SkipLength: 0, BeginsBlock: true}, // shift amount
		{PC: 1, Opcode: 157, Ra: 0, Rb: 1, Vx: neg16, SkipLength: 0},        // R0 = -16 >> 2 (arithmetic)
		{PC: 2, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	expected := types.Register(^uint64(3)) // -4
	if state.Registers[0] != expected {
		t.Errorf("R0 = %d, want -4", int64(state.Registers[0]))
	}
}

// TestRotR64ImmAlt tests rot_r_64_imm_alt instruction (opcode 159)
// Alt variant: Rd = ror64(Vx, Rb) - rotate immediate by register
func TestRotR64ImmAlt(t *testing.T) {

	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 1, Vx: 4, SkipLength: 0, BeginsBlock: true},       // R1 = 4 (rotate amount)
		{PC: 1, Opcode: 159, Ra: 0, Rb: 1, Vx: 0x8000000000000001, SkipLength: 0}, // R0 = ror64(0x8000000000000001, R1)
		{PC: 2, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	// 0x8000000000000001 rotated right by 4 = 0x1800000000000000
	expected := types.Register(0x1800000000000000)
	if state.Registers[0] != expected {
		t.Errorf("R0 = 0x%X, want 0x%X", state.Registers[0], expected)
	}
}

// TestRotR32ImmAlt tests rot_r_32_imm_alt instruction (opcode 161)
// Alt variant: Rd = ror32(Vx, Rb) - rotate immediate by register (sign-extended)
func TestRotR32ImmAlt(t *testing.T) {

	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 1, Vx: 4, SkipLength: 0, BeginsBlock: true}, // R1 = 4 (rotate amount)
		{PC: 1, Opcode: 161, Ra: 0, Rb: 1, Vx: 0x80000001, SkipLength: 0},   // R0 = ror32(0x80000001, 4)
		{PC: 2, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	// 0x80000001 rotated right by 4 = 0x18000000, sign-extended
	if state.Registers[0] != 0x18000000 {
		t.Errorf("R0 = 0x%X, want 0x18000000", state.Registers[0])
	}
}

// TestLoadImmJumpInd tests load_imm_jump_ind instruction (opcode 180)
func TestLoadImmJumpInd(t *testing.T) {

	dynamicJumpTable := []types.Register{4}

	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 1, Vx: 2, SkipLength: 0, BeginsBlock: true}, // R1 = 2 (address)
		{PC: 1, Opcode: 180, Ra: 0, Rb: 1, Vx: 42, Vy: 0, SkipLength: 0},    // R0 = 42, jump_ind R1
		{PC: 2, Opcode: 51, Ra: 0, Vx: 999, SkipLength: 0, BeginsBlock: true},
		{PC: 3, Opcode: 0, SkipLength: 0},
		{PC: 4, Opcode: 0, SkipLength: 0, BeginsBlock: true}, // target
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	state := newTestState()
	runUntilExitWithTable(t, ctx, state, dynamicJumpTable, instructions)

	if state.Registers[0] != 42 {
		t.Errorf("R0 = %d, want 42", state.Registers[0])
	}
}

// TestSub32 tests sub_32 instruction (opcode 191)
func TestSub32(t *testing.T) {

	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 100, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 51, Ra: 1, Vx: 37, SkipLength: 0},
		{PC: 2, Opcode: 191, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0}, // sub_32
		{PC: 3, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	if state.Registers[2] != 63 {
		t.Errorf("R2 = %d, want 63 (100-37)", state.Registers[2])
	}
}

// TestDivS32 tests div_s_32 instruction (opcode 194)
func TestDivS32(t *testing.T) {

	neg100 := types.Register(0xFFFFFFFF9C) // -100 as 32-bit sign-extended
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: neg100, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 51, Ra: 1, Vx: 7, SkipLength: 0},
		{PC: 2, Opcode: 194, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0}, // div_s_32
		{PC: 3, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	// -100 / 7 = -14 (truncated toward zero), sign-extended
	expected := types.Register(0xFFFFFFFFFFFFFFF2) // -14
	if state.Registers[2] != expected {
		t.Errorf("R2 = 0x%X (%d), want -14", state.Registers[2], int64(state.Registers[2]))
	}
}

// TestRemS32 tests rem_s_32 instruction (opcode 196)
func TestRemS32(t *testing.T) {

	neg100 := types.Register(0xFFFFFFFF9C) // -100 as 32-bit sign-extended
	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: neg100, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 51, Ra: 1, Vx: 7, SkipLength: 0},
		{PC: 2, Opcode: 196, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0}, // rem_s_32
		{PC: 3, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	// -100 % 7 = -2, sign-extended
	expected := types.Register(0xFFFFFFFFFFFFFFFE) // -2
	if state.Registers[2] != expected {
		t.Errorf("R2 = 0x%X (%d), want -2", state.Registers[2], int64(state.Registers[2]))
	}
}

// TestShloL32 tests shlo_l_32 instruction (opcode 197)
func TestShloL32(t *testing.T) {

	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 1, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 51, Ra: 1, Vx: 31, SkipLength: 0},
		{PC: 2, Opcode: 197, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0}, // shlo_l_32
		{PC: 3, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	// 1 << 31 = 0x80000000, sign-extended = 0xFFFFFFFF80000000
	expected := types.Register(0xFFFFFFFF80000000)
	if state.Registers[2] != expected {
		t.Errorf("R2 = 0x%X, want 0x%X", state.Registers[2], expected)
	}
}

// TestShloR32 tests shlo_r_32 instruction (opcode 198)
func TestShloR32(t *testing.T) {

	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 0x80000000, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 51, Ra: 1, Vx: 4, SkipLength: 0},
		{PC: 2, Opcode: 198, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0}, // shlo_r_32
		{PC: 3, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	// 0x80000000 >> 4 = 0x08000000
	if state.Registers[2] != 0x08000000 {
		t.Errorf("R2 = 0x%X, want 0x08000000", state.Registers[2])
	}
}

// TestSharR32 tests shar_r_32 instruction (opcode 199)
func TestSharR32(t *testing.T) {

	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 0x80000000, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 51, Ra: 1, Vx: 4, SkipLength: 0},
		{PC: 2, Opcode: 199, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0}, // shar_r_32
		{PC: 3, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	// 0x80000000 >> 4 (arithmetic) = 0xF8000000, sign-extended
	expected := types.Register(0xFFFFFFFFF8000000)
	if state.Registers[2] != expected {
		t.Errorf("R2 = 0x%X, want 0x%X", state.Registers[2], expected)
	}
}

// TestRotL32 tests rot_l_32 instruction (opcode 221)
func TestRotL32(t *testing.T) {

	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 0x80000001, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 51, Ra: 1, Vx: 1, SkipLength: 0},
		{PC: 2, Opcode: 221, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0}, // rot_l_32
		{PC: 3, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	// 0x80000001 rotated left by 1 = 0x00000003
	if state.Registers[2] != 0x00000003 {
		t.Errorf("R2 = 0x%X, want 0x00000003", state.Registers[2])
	}
}

// TestRotR64 tests rot_r_64 instruction (opcode 222)
func TestRotR64(t *testing.T) {

	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 0x01, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 51, Ra: 1, Vx: 4, SkipLength: 0},
		{PC: 2, Opcode: 222, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0}, // rot_r_64
		{PC: 3, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	expected := types.Register(0x1000000000000000)
	if state.Registers[2] != expected {
		t.Errorf("R2 = 0x%X, want 0x%X", state.Registers[2], expected)
	}
}

// TestRotR32 tests rot_r_32 instruction (opcode 223)
func TestRotR32(t *testing.T) {

	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 0x01, SkipLength: 0, BeginsBlock: true},
		{PC: 1, Opcode: 51, Ra: 1, Vx: 4, SkipLength: 0},
		{PC: 2, Opcode: 223, Rd: 2, Ra: 0, Rb: 1, SkipLength: 0}, // rot_r_32
		{PC: 3, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	// 0x01 rotated right by 4 (32-bit) = 0x10000000
	if state.Registers[2] != 0x10000000 {
		t.Errorf("R2 = 0x%X, want 0x10000000", state.Registers[2])
	}
}

// TestShloRImmAlt32 tests shlo_r_imm_alt_32 instruction (opcode 145)
// Alt variant: Rd = uint32(Vx) >> Rb (logical right shift, sign-extended result)
func TestShloRImmAlt32(t *testing.T) {

	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 1, Vx: 4, SkipLength: 0, BeginsBlock: true}, // R1 = 4 (shift amount)
		{PC: 1, Opcode: 145, Ra: 0, Rb: 1, Vx: 0x80000000, SkipLength: 0},   // R0 = 0x80000000 >> 4
		{PC: 2, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	// 0x80000000 >> 4 (logical) = 0x08000000, sign-extended stays 0x08000000
	if state.Registers[0] != 0x08000000 {
		t.Errorf("R0 = 0x%X, want 0x08000000", state.Registers[0])
	}
}

// TestSharRImmAlt32 tests shar_r_imm_alt_32 instruction (opcode 146)
// Alt variant: Rd = int32(Vx) >> Rb (arithmetic right shift, sign-extended result)
func TestSharRImmAlt32(t *testing.T) {

	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 1, Vx: 4, SkipLength: 0, BeginsBlock: true}, // R1 = 4 (shift amount)
		{PC: 1, Opcode: 146, Ra: 0, Rb: 1, Vx: 0x80000000, SkipLength: 0},   // R0 = int32(0x80000000) >> 4
		{PC: 2, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	block := ctx.GetBlock(0)
	state := newTestState()
	ExecuteBlock(block, unsafe.Pointer(state))

	// int32(0x80000000) = -2147483648, >> 4 (arithmetic) = 0xF8000000, sign-extended
	expected := types.Register(0xFFFFFFFFF8000000)
	if state.Registers[0] != expected {
		t.Errorf("R0 = 0x%X, want 0x%X", state.Registers[0], expected)
	}
}

// TestFallthrough tests fallthrough instruction (opcode 1)
// Fallthrough exits the current block and continues to the next instruction
func TestFallthrough(t *testing.T) {

	instructions := []*ParsedInstruction{
		{PC: 0, Opcode: 51, Ra: 0, Vx: 42, SkipLength: 0, BeginsBlock: true},  // R0 = 42
		{PC: 1, Opcode: 1, SkipLength: 0},                                     // fallthrough - exits block
		{PC: 2, Opcode: 51, Ra: 0, Vx: 100, SkipLength: 0, BeginsBlock: true}, // R0 = 100 (new block)
		{PC: 3, Opcode: 0, SkipLength: 0},
	}

	ctx, err := CompileProgram(instructions)
	if err != nil {
		t.Fatalf("Failed to compile: %v", err)
	}

	state := newTestState()
	runUntilExit(t, ctx, state)

	// After fallthrough, execution continues to PC 2, setting R0 = 100
	if state.Registers[0] != 100 {
		t.Errorf("R0 = %d, want 100 (after fallthrough)", state.Registers[0])
	}
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
func runUntilExit(t *testing.T, ctx *ProgramContext, state *State) uint64 {
	return runUntilExitWithTable(t, ctx, state, nil, nil)
}

// runUntilExitWithTable executes blocks with dynamic jump table support
func runUntilExitWithTable(t *testing.T, ctx *ProgramContext, state *State, dynamicJumpTable []types.Register, instructions []*ParsedInstruction) uint64 {
	statePtr := unsafe.Pointer(state)
	pc := types.Register(0)

	for i := 0; i < 1000; i++ { // Safety limit
		block := ctx.GetBlock(pc)
		if block == nil {
			t.Fatalf("No block for PC %d", pc)
		}

		exitEncoded, nextPC := ExecuteBlock(block, statePtr)

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
func runUntilExitWithHostCall(t *testing.T, ctx *ProgramContext, state *State, instructions []*ParsedInstruction) uint64 {
	statePtr := unsafe.Pointer(state)
	pc := types.Register(0)

	for i := 0; i < 1000; i++ { // Safety limit
		block := ctx.GetBlock(pc)
		if block == nil {
			t.Fatalf("No block for PC %d", pc)
		}

		exitEncoded, nextPC := ExecuteBlock(block, statePtr)

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
