package pvm

type PVM struct {
	ProgramCodeFormat []byte
	Registers         [13]Register
	Ram               *RAM
}
