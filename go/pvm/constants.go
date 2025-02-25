package pvm

const PageSize = (1 << 12)

const RamSize = (1 << 32)

const MajorZoneSize = (1 << 16)

const ArgumentsZoneSize = (1 << 24)

const NumRamPages = RamSize / PageSize

var MinValidRamIndex RamIndex = (1 << 16)

const DynamicAddressAlignmentFactor = 2

const StandardProgramInitializationZoneSize = (1 << 16)

const MaxRegister Register = (1 << 64) - 1

func TotalSizeNeededMajorZones(size int) int {
	return MajorZoneSize * ((MajorZoneSize + size - 1) / MajorZoneSize)
}

func TotalSizeNeededPages(size int) int {
	return PageSize * ((PageSize + size - 1) / PageSize)
}
