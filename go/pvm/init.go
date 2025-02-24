package pvm

func init() {
	dispatchTable = map[byte]InstructionHandler{
		0:  handleTrap,
		1:  handleFallthrough,
		10: handleEcalli,
		20: handleLoadImm64,
		30: handleTwoImmValues,
		31: handleTwoImmValues,
		32: handleTwoImmValues,
		33: handleTwoImmValues,
		40: handleJump,
		50: handleOneRegOneImm,
		51: handleOneRegOneImm,
		52: handleOneRegOneImm,
		53: handleOneRegOneImm,
		54: handleOneRegOneImm,
		55: handleOneRegOneImm,
		56: handleOneRegOneImm,
		57: handleOneRegOneImm,
		58: handleOneRegOneImm,
		59: handleOneRegOneImm,
		60: handleOneRegOneImm,
		61: handleOneRegOneImm,
		62: handleOneRegOneImm,
		// ... other opcodes would be added here ...
	}
}
