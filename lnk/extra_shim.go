package lnk

import (
	"errors"

	"github.com/andrewstucki/fingerprint/internal"
)

func parseExtraShim(size uint32, data []byte) (*Shim, error) {
	if size < 0x00000088 {
		return nil, errors.New("invalid extra shim block size")
	}
	return &Shim{
		LayerName: internal.ReadUnicode(data, 8),
	}, nil
}
