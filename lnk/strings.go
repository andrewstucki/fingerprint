package lnk

import (
	"encoding/binary"
	"errors"
	"io"

	"github.com/andrewstucki/fingerprint/internal"
)

func readU16Data(offset int64, r io.ReaderAt, hasUnicode bool) (uint16, []byte, error) {
	sizeData := make([]byte, 2)
	n, err := r.ReadAt(sizeData, offset)
	if err != nil {
		return 0, nil, err
	}
	if n != 2 {
		return 0, nil, errors.New("invalid size")
	}
	size := binary.LittleEndian.Uint16(sizeData)
	if hasUnicode {
		size *= 2
	}
	data := make([]byte, size)
	n, err = r.ReadAt(data, offset+2)
	if uint16(n) != size {
		return 0, nil, errors.New("invalid data")
	}
	return size, data, nil
}

func readU32Data(offset int64, r io.ReaderAt) (uint32, []byte, error) {
	sizeData := make([]byte, 4)
	n, err := r.ReadAt(sizeData, offset)
	if err != nil {
		return 0, nil, err
	}
	if n != 4 {
		return 0, nil, errors.New("invalid size")
	}
	size := binary.LittleEndian.Uint32(sizeData)
	data := make([]byte, size)
	n, err = r.ReadAt(data, offset)
	if uint32(n) != size {
		return 0, nil, errors.New("invalid data")
	}
	return size, data, nil
}

func readDataString(header *Header, flag uint32, offset int64, r io.ReaderAt) (string, int64, error) {
	if !hasFlag(header.rawLinkFlags, flag) {
		return "", offset, nil
	}
	hasUnicode := hasFlag(header.rawLinkFlags, isUnicode)
	size, data, err := readU16Data(offset, r, hasUnicode)
	if err != nil {
		return "", 0, err
	}
	if hasUnicode {
		return internal.ReadUnicode(data, 0), offset + 2 + int64(size), nil
	}
	return internal.ReadString(data, 0), offset + 2 + int64(size), nil
}
