//go:build ignore

package main

import (
	"encoding/hex"
	"fmt"

	"jam/pkg/block/header"
	"jam/pkg/serializer"
	"jam/pkg/types"
)

func main() {
	// Create a minimal genesis header
	h := header.Header{
		UnsignedHeader: header.UnsignedHeader{
			// All fields zero-initialized
			// EpochMarker and WinningTicketsMarker are nil (optional)
			// OffendersMarker is empty slice
			OffendersMarker: []types.Ed25519PublicKey{},
		},
	}

	data := serializer.Serialize(&h)
	fmt.Printf("Header size: %d bytes\n", len(data))
	fmt.Printf("Header hex: %s\n", hex.EncodeToString(data))
}
