package lnk

import (
	"errors"

	"github.com/andrewstucki/fingerprint/internal"
)

func parseExtraIconEnvironment(size uint32, data []byte) (*IconEnvironment, error) {
	if size != 0x00000314 {
		return nil, errors.New("invalid extra icon environment block size")
	}
	ansi := internal.ReadString(data[8:268], 0)
	unicode := internal.ReadUnicode(data[268:788], 0)
	return &IconEnvironment{
		ANSI:    ansi,
		Unicode: unicode,
	}, nil
}
