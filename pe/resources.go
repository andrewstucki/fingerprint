package pe

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strconv"

	"github.com/h2non/filetype"
)

const (
	rtCursor       uint32 = 1
	rtBitmap       uint32 = 2
	rtIcon         uint32 = 3
	rtMenu         uint32 = 4
	rtDialog       uint32 = 5
	rtString       uint32 = 6
	rtFontdir      uint32 = 7
	rtFont         uint32 = 8
	rtAccelerator  uint32 = 9
	rtRcdata       uint32 = 10
	rtMessagetable uint32 = 11
	rtGroupCursor  uint32 = 12
	rtGroupIcon    uint32 = 14
	rtVersion      uint32 = 16
	rtDlginclude   uint32 = 17
	rtPlugplay     uint32 = 19
	rtVxd          uint32 = 20
	rtAnicursor    uint32 = 21
	rtAniicon      uint32 = 22
	rtHTML         uint32 = 23
	rtManifest     uint32 = 24
)

var nameMap = map[uint32]string{
	rtCursor:       "RT_CURSOR",
	rtBitmap:       "RT_BITMAP",
	rtIcon:         "RT_ICON",
	rtMenu:         "RT_MENU",
	rtDialog:       "RT_DIALOG",
	rtString:       "RT_STRING",
	rtFontdir:      "RT_FONTDIR",
	rtFont:         "RT_FONT",
	rtAccelerator:  "RT_ACCELERATOR",
	rtRcdata:       "RT_RCDATA",
	rtMessagetable: "RT_MESSAGETABLE",
	rtGroupCursor:  "RT_GROUP_CURSOR",
	rtGroupIcon:    "RT_GROUP_ICON",
	rtVersion:      "RT_VERSION",
	rtDlginclude:   "RT_DLGINCLUDE",
	rtPlugplay:     "RT_PLUGPLAY",
	rtVxd:          "RT_VXD",
	rtAnicursor:    "RT_ANICURSOR",
	rtAniicon:      "RT_ANIICON",
	rtHTML:         "RT_HTML",
	rtManifest:     "RT_MANIFEST",
}

func idName(id uint32) string {
	if found, ok := nameMap[id]; ok {
		return found
	}
	return strconv.Itoa(int(id))
}

func isRVA(value uint32) bool {
	return (value & 0x80000000) > 0
}

func rvaOffset(value uint32) int {
	return int(value & 0x7fffffff)
}

// this checks if value is an rva, and if so calculates the real offset
// and then does a bounds check on the slice that is returned
func followOffset(global []byte, value uint32, requiredSize int) ([]byte, error) {
	offset := int(value)
	if isRVA(value) {
		offset = rvaOffset(value)
	}
	if len(global) < offset+requiredSize {
		return nil, errors.New("invalid data")
	}
	return global[offset:], nil
}

// a lot of the checks we do here are fairly permissive, we want to
// return as much of the parsable information as we can, so don't bother
// sanity checking things like the number of entries matching what's specified
// instead we just make sure to bounds check what we're reading and int the
// case of potential over-read, return an error
func parseDirectory(virtualAddress uint32, data []byte) ([]Resource, error) {
	return parseEntries(virtualAddress, "", data, data)
}

func parseName(global, base []byte) (string, error) {
	id := binary.LittleEndian.Uint32(base[0:4])
	if isRVA(id) {
		nameData, err := followOffset(global, id, 2)
		if err != nil {
			return "", err
		}
		nameEnd := int(binary.LittleEndian.Uint16(nameData[0:2]))*2 + 2
		if len(nameData) < nameEnd {
			return "", errors.New("invalid data")
		}
		return readUnicode(nameData[2:nameEnd]), nil
	}
	return idName(id), nil
}

func parseEntry(virtualAddress uint32, root string, global, base []byte) ([]Resource, error) {
	offset := binary.LittleEndian.Uint32(base[4:8])
	if isRVA(offset) {
		// we have a nested directory
		next, err := followOffset(global, offset, 0)
		if err != nil {
			return nil, err
		}
		return parseEntries(virtualAddress, root, global, next)
	}
	// we have a leaf resource
	language := uint16(binary.LittleEndian.Uint32(base[0:4]))
	entry, err := followOffset(global, offset, 8)
	if err != nil {
		return nil, err
	}
	entryOffset := binary.LittleEndian.Uint32(entry[0:4])
	entrySize := int(binary.LittleEndian.Uint32(entry[4:8]))
	data, err := followOffset(global, entryOffset-virtualAddress, entrySize)
	if err != nil {
		return nil, err
	}
	resourceData := data[0:entrySize]
	hash := sha256.Sum256(resourceData)
	resourceMime := "Data"
	if kind, err := filetype.Match(resourceData); err == nil && kind.MIME.Value != "" {
		resourceMime = kind.MIME.Value
	}
	return []Resource{
		Resource{Type: root, Language: languageName(language), data: resourceData, MIME: resourceMime, SHA256: hex.EncodeToString(hash[:])},
	}, nil
}

// A leaf's Type, Name, and Language IDs are determined by the path
// that is taken through directory tables to reach the leaf. The first
// table determines Type ID, the second table (pointed to by the directory
// entry in the first table) determines Name ID, and the third table
// determines Language ID.
func parseEntries(virtualAddress uint32, root string, global, base []byte) ([]Resource, error) {
	if len(base) < 16 {
		return nil, errors.New("invalid data")
	}
	resources := []Resource{}
	namedEntries := binary.LittleEndian.Uint16(base[12:14])
	idEntries := binary.LittleEndian.Uint16(base[14:16])
	numEntries := int(namedEntries + idEntries)
	entriesData := base[16:]
	if len(entriesData) < numEntries*8 {
		return nil, errors.New("invalid data")
	}

	for i := 0; i < numEntries; i++ {
		entryData := entriesData[8*i:]
		leafRoot := root

		if leafRoot == "" {
			var err error
			leafRoot, err = parseName(global, entryData)
			if err != nil {
				return nil, err
			}
		}

		entryResources, err := parseEntry(virtualAddress, leafRoot, global, entryData)
		if err != nil {
			return nil, err
		}
		resources = append(resources, entryResources...)
	}
	return resources, nil
}
