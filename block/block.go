package block

import (
	"github.com/ascrivener/jam/extrinsics"
	"github.com/ascrivener/jam/header"
)

type Block struct {
	Header     header.Header
	Extrinsics extrinsics.Extrinsics
}
