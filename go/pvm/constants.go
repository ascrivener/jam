package pvm

const DynamicAddressAlignmentFactor = 2

const MaxRegister Register = (1 << 64) - 1

const IsAuthorizedGasAllocation int = 50000000

const ErasureCodedPiecesSize int = 684

const ErasureCodedPiecesInSegment int = 6

const SegmentSize int = ErasureCodedPiecesInSegment * ErasureCodedPiecesSize

const WorkPackageManifestMaxEntries int = (1 << 11)

const TransferMemoSize int = 128

const UnreferencePreimageExpungeTimeslots int = 4800

const LookupAnchorMaxAgeTimeslots int = 1200
