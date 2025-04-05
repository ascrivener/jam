package asntypes

// Basic integer types
type U8 uint8
type U16 uint16
type U32 uint32
type U64 uint64

// TimeSlot represents a time slot identifier
type TimeSlot U32

// ValidatorIndex represents a validator index
type ValidatorIndex U16

// CoreIndex represents a core index
type CoreIndex U16

// ServiceId represents a service identifier
type ServiceId U32

// Gas represents a gas value
type Gas U64

// ByteSequence represents a variable-length byte array (as a hex string with 0x prefix)
type ByteSequence string

// ByteArray32 represents a fixed 32-byte array (as a hex string with 0x prefix)
type ByteArray32 string

// OpaqueHash represents a generic hash value (hex string with 0x prefix)
type OpaqueHash string

// Hash type aliases
type HeaderHash string
type StateRoot string
type BeefyRoot string
type WorkPackageHash string
type WorkReportHash string
type ExportsRoot string
type ErasureRoot string
type Entropy string
type AuthorizerHash string
type TicketId string

// EntropyBuffer represents an array of entropy values
type EntropyBuffer [4]Entropy
