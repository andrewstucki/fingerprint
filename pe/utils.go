package pe

import (
	"encoding/binary"
	"math"
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

func entropy(data []byte) float64 {
	cache := make(map[byte]int)
	for _, b := range data {
		if found, ok := cache[b]; ok {
			cache[b] = found + 1
		} else {
			cache[b] = 1
		}
	}

	result := 0.0
	length := len(data)
	for _, count := range cache {
		frequency := float64(count) / float64(length)
		result -= frequency * math.Log2(frequency)
	}
	return math.Round(result*100) / 100
}
