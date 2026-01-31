//go:build linux && amd64

package jit

import (
	"jam/pkg/types"
	"sync"
	"unsafe"
)

// ProgramContext holds per-program JIT compilation state
// This keeps the executable memory alive and supports mid-block entry via trampolines
type ProgramContext struct {
	mu           sync.RWMutex
	execMem      *ExecutableMemory
	blocks       map[types.Register]*CompiledBlock
	entryPoints  []uintptr                         // slice indexed by PC for O(1) lookup (no hash)
	trampolines  map[types.Register]*CompiledBlock // mid-block entry trampolines
	compiler     *Compiler                         // for generating trampolines
	recoveryStub uintptr                           // address of fault recovery stub
}

// generateRecoveryStub creates a small code stub that properly returns to Go after a fault
func generateRecoveryStub(c *Compiler) (uintptr, error) {
	addr, buf, err := c.execMem.Allocate(64)
	if err != nil {
		return 0, err
	}

	asm := NewAssembler(buf)

	// RAX already contains the error code (set by signal handler)
	// RDX already contains nextPC (set by signal handler)
	// We need to restore callee-saved registers and return

	// Pop callee-saved registers (reverse order of prologue)
	asm.Pop(RBP)
	asm.Pop(R15)
	asm.Pop(R14)
	asm.Pop(R13)
	asm.Pop(R12)
	asm.Pop(RBX)
	asm.Ret()

	return addr, nil
}

// CompileProgram compiles all blocks in a program and returns a ProgramContext
// Each program gets its own executable memory region
func CompileProgram(instructions []*ParsedInstruction) (*ProgramContext, error) {
	// Count blocks to estimate memory needed
	blockCount := 0
	for _, instr := range instructions {
		if instr != nil && instr.BeginsBlock {
			blockCount++
		}
	}

	// Estimate memory: 128 bytes per instruction + 512 bytes per block for overhead, minimum 64KB
	estimatedSize := max(128*len(instructions)+512*blockCount, 64*1024)

	// Allocate dedicated executable memory for this program
	execMem, err := NewExecutableMemory(estimatedSize)
	if err != nil {
		return nil, err
	}

	// Create a compiler for this program
	compiler := NewCompiler(execMem)
	blocks := make(map[types.Register]*CompiledBlock)
	// Slice indexed by PC for O(1) lookup without hash overhead
	entryPoints := make([]uintptr, len(instructions))

	// Find all block entry points
	for i, instr := range instructions {
		if instr != nil && instr.BeginsBlock {
			block, err := compiler.CompileBlock(instructions, types.Register(i))
			if err != nil {
				execMem.Free()
				return nil, err
			}
			pc := types.Register(i)
			blocks[pc] = block
			entryPoints[i] = block.EntryPoint
		}
	}

	// Generate the fault recovery stub for this program
	recoveryStub, err := generateRecoveryStub(compiler)
	if err != nil {
		execMem.Free()
		return nil, err
	}

	ctx := &ProgramContext{
		execMem:      execMem,
		blocks:       blocks,
		entryPoints:  entryPoints,
		trampolines:  make(map[types.Register]*CompiledBlock),
		compiler:     compiler,
		recoveryStub: recoveryStub,
	}

	return ctx, nil
}

// Stats returns JIT compilation statistics
type Stats struct {
	BlocksCompiled int
	CodeBytes      int
	Enabled        bool
}

// --- ProgramContext methods ---

// GetBlock returns the compiled block for a given PC, or nil if not compiled
// This handles both block starts and mid-block PCs (via trampolines)
func (ctx *ProgramContext) GetBlock(pc types.Register) *CompiledBlock {
	if ctx == nil {
		return nil
	}

	// Check for exact block start (blocks map is read-only after CompileProgram)
	if block := ctx.blocks[pc]; block != nil {
		return block
	}

	// Check for cached trampoline (requires lock since trampolines are created lazily)
	ctx.mu.RLock()
	if tramp := ctx.trampolines[pc]; tramp != nil {
		ctx.mu.RUnlock()
		return tramp
	}
	ctx.mu.RUnlock()

	// Try to find a block containing this PC and generate a trampoline
	return ctx.getOrCreateTrampoline(pc)
}

// GetBlockEntryPoint returns just the entry point address for a PC
// Returns 0 if no block exists for this PC
func (ctx *ProgramContext) GetBlockEntryPoint(pc types.Register) uintptr {
	// Fast path: direct slice lookup by PC index (O(1), no hash)
	idx := int(pc)
	if idx < len(ctx.entryPoints) {
		if ep := ctx.entryPoints[idx]; ep != 0 {
			return ep
		}
	}

	// Slow path: check for trampoline (mid-block entry)
	block := ctx.GetBlock(pc)
	if block == nil {
		return 0
	}
	return block.EntryPoint
}

// GetBlocks returns a map of PC -> entry point for all compiled blocks
// (blocks map is read-only after CompileProgram, no lock needed)
func (ctx *ProgramContext) GetBlocks() map[types.Register]uintptr {
	if ctx == nil {
		return nil
	}
	result := make(map[types.Register]uintptr, len(ctx.blocks))
	for pc, block := range ctx.blocks {
		result[pc] = block.EntryPoint
	}
	return result
}

// findBlockContaining finds the block that contains the given PC (if any)
// (blocks map is read-only after CompileProgram, no lock needed)
func (ctx *ProgramContext) findBlockContaining(pc types.Register) *CompiledBlock {
	for _, block := range ctx.blocks {
		if pc >= block.StartPC && pc <= block.EndPC {
			if _, hasLabel := block.LabelOffsets[pc]; hasLabel {
				return block
			}
		}
	}
	return nil
}

// getOrCreateTrampoline generates a trampoline for mid-block entry at pc
func (ctx *ProgramContext) getOrCreateTrampoline(pc types.Register) *CompiledBlock {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()

	// Double-check after acquiring write lock (another goroutine may have created it)
	if tramp := ctx.trampolines[pc]; tramp != nil {
		return tramp
	}

	block := ctx.findBlockContaining(pc)
	if block == nil {
		return nil
	}

	labelOffset, ok := block.LabelOffsets[pc]
	if !ok {
		return nil
	}

	// Generate trampoline: prologue + jump to mid-block
	tramp, err := ctx.compiler.GenerateTrampoline(block, pc, labelOffset)
	if err != nil {
		return nil
	}

	ctx.trampolines[pc] = tramp
	return tramp
}

// Activate sets up the signal handler to use this program's code region and recovery stub
// Must be called before executing any JIT code from this program
func (ctx *ProgramContext) Activate() {
	if ctx == nil || ctx.execMem == nil {
		return
	}
	start, end := ctx.execMem.GetBounds()
	SetCodeRegion(start, end)
	SetRecoveryAddr(ctx.recoveryStub)
}

// Free releases the program's executable memory
func (ctx *ProgramContext) Free() error {
	if ctx == nil || ctx.execMem == nil {
		return nil
	}
	return ctx.execMem.Free()
}

// ExecuteBlock executes a compiled block
// Returns: (exitReason encoded, nextPC)
func ExecuteBlock(block *CompiledBlock, statePtr unsafe.Pointer) (uint64, uint64) {
	if block == nil {
		return 2, 0 // Panic
	}
	return callJITCode(block.EntryPoint, statePtr)
}

// ExecuteBlockPtr executes a compiled block given its entry point address
func ExecuteBlockPtr(entryPoint uintptr, statePtr unsafe.Pointer) (uint64, uint64) {
	if entryPoint == 0 {
		return 2, 0 // Panic
	}
	return callJITCode(entryPoint, statePtr)
}
