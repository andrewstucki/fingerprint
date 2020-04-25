package pe

import (
	"encoding/binary"
	"unicode/utf16"
)

func readUnicode(data []byte) string {
	encode := []uint16{}
	offset := 0
	for {
		if len(data) < offset+1 {
			return string(utf16.Decode(encode))
		}
		value := binary.LittleEndian.Uint16(data[offset : offset+2])
		if value == 0 {
			return string(utf16.Decode(encode))
		}
		encode = append(encode, value)
		offset += 2
	}
}

func countValue(group map[string]int, value string) {
	if found, ok := group[value]; ok {
		group[value] = found + 1
		return
	}
	group[value] = 1
}
