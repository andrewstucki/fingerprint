package lnk

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/andrewstucki/fingerprint/internal"
)

var (
	fontFamilies = map[uint32]string{
		0x0000: "FF_DONTCARE",
		0x0010: "FF_ROMAN",
		0x0020: "FW_SWISS",
		0x0030: "FF_MODERN",
		0x0040: "FF_SCRIPT",
		0x0050: "FF_DECORATIVE",
	}
	fontPitches = map[uint32]string{
		0x0000: "TMPF_NONE",
		0x0001: "TMPF_FIXED_PITCH",
		0x0002: "TMPF_VECTOR",
		0x0003: "TMPF_TRUETYPE",
		0x0004: "TMPF_DEVICE",
	}
	fillAttributes = map[uint32]string{
		0x0001: "FOREGROUND_BLUE",
		0x0002: "FOREGROUND_GREEN",
		0x0004: "FOREGROUND_RED",
		0x0008: "FOREGROUND_INTENSITY",
		0x0010: "BACKGROUND_BLUE",
		0x0020: "BACKGROUND_GREEN",
		0x0040: "BACKGROUND_RED",
		0x0080: "BACKGROUND_INTENSITY",
	}
)

func parseExtraConsole(size uint32, data []byte) (*Console, error) {
	if size != 0x000000cc {
		return nil, errors.New("invalid extra console block size")
	}
	return &Console{
		FillAttributes:         parseFlags(fillAttributes, uint32(binary.LittleEndian.Uint16(data[8:10]))),
		PopupFillAttributes:    parseFlags(fillAttributes, uint32(binary.LittleEndian.Uint16(data[10:12]))),
		ScreenBufferSizeX:      binary.LittleEndian.Uint16(data[12:14]),
		ScreenBufferSizeY:      binary.LittleEndian.Uint16(data[14:16]),
		WindowSizeX:            binary.LittleEndian.Uint16(data[16:18]),
		WindowSizeY:            binary.LittleEndian.Uint16(data[18:20]),
		WindowOriginX:          binary.LittleEndian.Uint16(data[20:22]),
		WindowOriginY:          binary.LittleEndian.Uint16(data[22:24]),
		FontSize:               binary.LittleEndian.Uint32(data[32:36]),
		FontFamily:             normalizeFontFamily(binary.LittleEndian.Uint32(data[36:40])),
		FontWeight:             binary.LittleEndian.Uint32(data[40:44]),
		FaceName:               internal.ReadUnicode(data[44:108], 0),
		CursorSize:             binary.LittleEndian.Uint32(data[108:112]),
		FullScreen:             normalizeBoolean(binary.LittleEndian.Uint32(data[112:116])),
		QuickEdit:              normalizeBoolean(binary.LittleEndian.Uint32(data[116:120])),
		InsertMode:             normalizeBoolean(binary.LittleEndian.Uint32(data[120:124])),
		AutoPosition:           normalizeBoolean(binary.LittleEndian.Uint32(data[124:128])),
		HistoryBufferSize:      binary.LittleEndian.Uint32(data[128:132]),
		NumberOfHistoryBuffers: binary.LittleEndian.Uint32(data[132:136]),
		HistoryNoDup:           normalizeBoolean(binary.LittleEndian.Uint32(data[136:140])),
		ColorTable:             chunkColorTable(data[140:204]),
	}, nil
}

func normalizeFontFamily(value uint32) string {
	fontTokens := []string{}
	for flag, name := range fontFamilies {
		if 0xFFF0&value == flag {
			fontTokens = append(fontTokens, name)
			break
		}
	}
	if len(fontTokens) == 0 {
		return ""
	}
	pitchValue := 0x000F & value
	for flag, name := range fontPitches {
		if hasFlag(pitchValue, flag) {
			fontTokens = append(fontTokens, name)
		}
	}
	if len(fontTokens) == 1 {
		fontTokens = append(fontTokens, "TMPF_NONE")
	}
	sort.Strings(fontTokens)
	return strings.Join(fontTokens, " | ")
}

func normalizeBoolean(value uint32) bool {
	return value != 0
}

func chunkColorTable(value []byte) []string {
	colors := make([]string, 16)
	for i := 0; i < 16; i++ {
		colors[i] = fmt.Sprintf("0x%06x", binary.LittleEndian.Uint32(value[i*4:(i+1)*4]))
	}
	return colors
}
