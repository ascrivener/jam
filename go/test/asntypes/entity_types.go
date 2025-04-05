package asntypes

// ServiceInfo represents information about a service
type ServiceInfo struct {
	CodeHash   OpaqueHash `json:"code_hash" asn1:"tag:0"`
	Balance    U64        `json:"balance" asn1:"tag:1"`
	MinItemGas Gas        `json:"min_item_gas" asn1:"tag:2"`
	MinMemoGas Gas        `json:"min_memo_gas" asn1:"tag:3"`
	Bytes      U64        `json:"bytes" asn1:"tag:4"`
	Items      U32        `json:"items" asn1:"tag:5"`
}

// ReadyRecord represents a ready record for accumulation
type ReadyRecord struct {
	Report       WorkReport        `json:"report" asn1:"tag:0"`
	Dependencies []WorkPackageHash `json:"dependencies" asn1:"tag:1"`
}

// ReadyQueueItem represents an item in the ready queue
type ReadyQueueItem []ReadyRecord

// ReadyQueue represents the complete ready queue
type ReadyQueue []ReadyQueueItem

// AccumulatedQueueItem represents an item in the accumulated queue
type AccumulatedQueueItem []WorkPackageHash

// AccumulatedQueue represents the complete accumulated queue
type AccumulatedQueue []AccumulatedQueueItem
