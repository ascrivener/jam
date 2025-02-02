package block

import (
	"github.com/ascrivener/jam/block/extrinsics"
	"github.com/ascrivener/jam/block/header"
)

type Block struct {
	Header     header.Header
	Extrinsics extrinsics.Extrinsics
}
