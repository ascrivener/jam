package jit

import (
	"jam/pkg/types"
	"unsafe"
)

// Runtime provides the interface between the JIT compiler and the PVM
type Runtime struct {
	compiler    *Compiler
	execMem     *ExecutableMemory
	blocks      map[types.Register]*CompiledBlock
	trampolines map[types.Register]*CompiledBlock // mid-block entry trampolines
	enabled     bool
}

// NewRuntime creates a new JIT runtime
func NewRuntime() (*Runtime, error) {
	execMem, err := NewExecutableMemory(DefaultCodeSize)
	if err != nil {
		return nil, err
	}

	return &Runtime{
		compiler:    NewCompiler(execMem),
		execMem:     execMem,
		blocks:      make(map[types.Register]*CompiledBlock),
		trampolines: make(map[types.Register]*CompiledBlock),
		enabled:     true,
	}, nil
}

// Enabled returns whether JIT is enabled
func (r *Runtime) Enabled() bool {
	return r != nil && r.enabled
}

// SetEnabled enables or disables JIT
func (r *Runtime) SetEnabled(enabled bool) {
	if r != nil {
		r.enabled = enabled
	}
}

// CompileProgram compiles all blocks in a program
func (r *Runtime) CompileProgram(instructions []*ParsedInstruction, dynamicJumpTable []types.Register) error {
	if r == nil || !r.enabled {
		return nil
	}

	// Find all block entry points
	for i, instr := range instructions {
		if instr != nil && instr.BeginsBlock {
			_, err := r.compiler.CompileBlock(instructions, types.Register(i), dynamicJumpTable)
			if err != nil {
				return err
			}
		}
	}

	r.blocks = r.compiler.blocks
	return nil
}

// GetBlock returns the compiled block for a given PC, or nil if not compiled
// This handles both block starts and mid-block PCs (via trampolines)
func (r *Runtime) GetBlock(pc types.Register) *CompiledBlock {
	if r == nil {
		return nil
	}

	// First check for exact block start
	if block := r.blocks[pc]; block != nil {
		return block
	}

	// Check for cached trampoline
	if tramp := r.trampolines[pc]; tramp != nil {
		return tramp
	}

	// Try to find a block containing this PC and generate a trampoline
	return r.getOrCreateTrampoline(pc)
}

// findBlockContaining finds the block that contains the given PC (if any)
func (r *Runtime) findBlockContaining(pc types.Register) *CompiledBlock {
	for _, block := range r.blocks {
		if pc >= block.StartPC && pc <= block.EndPC {
			if _, hasLabel := block.LabelOffsets[pc]; hasLabel {
				return block
			}
		}
	}
	return nil
}

// getOrCreateTrampoline generates a trampoline for mid-block entry at pc
func (r *Runtime) getOrCreateTrampoline(pc types.Register) *CompiledBlock {
	block := r.findBlockContaining(pc)
	if block == nil {
		return nil
	}

	labelOffset, ok := block.LabelOffsets[pc]
	if !ok {
		return nil
	}

	// Generate trampoline: prologue + jump to mid-block
	tramp, err := r.compiler.GenerateTrampoline(block, pc, labelOffset)
	if err != nil {
		return nil
	}

	r.trampolines[pc] = tramp
	return tramp
}

// ExecuteBlock executes a compiled block
// Returns: (exitReason encoded, nextPC)
// Exit reason encoding:
//   - If high bit is clear: simple exit (0=Go, 1=Halt, 2=Panic, 3=OutOfGas)
//   - If high bit is set: complex exit, bits 56-62 = type, bits 0-55 = parameter
func (r *Runtime) ExecuteBlock(block *CompiledBlock, statePtr unsafe.Pointer) (uint64, uint64) {
	if block == nil {
		return 2, 0 // Panic
	}

	// Call the generated code using assembly trampoline
	// The compiled code expects System V AMD64 ABI:
	//   RDI = state pointer (first argument)
	// Returns:
	//   RAX = exit reason
	//   RDX = next PC
	return callJITCode(block.EntryPoint, statePtr)
}

// Free releases all JIT resources
func (r *Runtime) Free() error {
	if r == nil || r.execMem == nil {
		return nil
	}
	return r.execMem.Free()
}

// Reset clears compiled code but keeps the runtime
func (r *Runtime) Reset() {
	if r == nil {
		return
	}
	r.blocks = make(map[types.Register]*CompiledBlock)
	r.trampolines = make(map[types.Register]*CompiledBlock)
	r.execMem.Reset()
	r.compiler = NewCompiler(r.execMem)
}

// Stats returns JIT compilation statistics
type Stats struct {
	BlocksCompiled int
	CodeBytes      int
	Enabled        bool
}

func (r *Runtime) Stats() Stats {
	if r == nil {
		return Stats{}
	}
	return Stats{
		BlocksCompiled: len(r.blocks),
		CodeBytes:      r.execMem.Used(),
		Enabled:        r.enabled,
	}
}
