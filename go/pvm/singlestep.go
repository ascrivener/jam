package pvm

import (
	"github.com/ascrivener/jam/bitsequence"
	"github.com/ascrivener/jam/types"
)

func SingleStep(instructions []byte, opcodeBitmask bitsequence.BitSequence, dynamicJumpTable []Register, instructionCounter Register, gas types.GasValue, registers [13]Register, ram RAM) (ExitReason, Register, types.SignedGasValue, [13]Register, RAM)
