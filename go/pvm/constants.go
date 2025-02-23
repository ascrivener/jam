package pvm

const PageSize = (1 << 12)

const RamSize = (1 << 32)

const NumRamPages = RamSize / PageSize

var MinValidRamIndex RamIndex = (1 << 16)

const DynamicAddressAlignmentFactor = 2

const StandardProgramInitializationZoneSize = (1 << 16)

const MaxRegister Register = (1 << 64) - 1
