package pe

import (
	"crypto/md5"
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"path/filepath"
	"strings"
)

const emptyHash = "d41d8cd98f00b204e9800998ecf8427e"

func readString(section []byte, start int) string {
	if start < 0 || start >= len(section) {
		return ""
	}

	for end := start; end < len(section); end++ {
		if section[end] == 0 {
			return string(section[start:end])
		}
	}
	return ""
}

func importDirectory(f *pe.File) pe.DataDirectory {
	var emptyDirectory pe.DataDirectory
	if f.Machine == pe.IMAGE_FILE_MACHINE_AMD64 {
		header := f.OptionalHeader.(*pe.OptionalHeader64)
		if header.NumberOfRvaAndSizes < pe.IMAGE_DIRECTORY_ENTRY_IMPORT+1 {
			return emptyDirectory
		}
		return header.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_IMPORT]
	}
	header := f.OptionalHeader.(*pe.OptionalHeader32)
	if header.NumberOfRvaAndSizes < pe.IMAGE_DIRECTORY_ENTRY_IMPORT+1 {
		return emptyDirectory
	}
	return header.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_IMPORT]
}

func importData(f *pe.File) ([]byte, uint32, uint32, error) {
	imports := importDirectory(f)
	if imports.Size == 0 {
		return nil, 0, 0, nil
	}
	var section *pe.Section
	for _, s := range f.Sections {
		if s.VirtualAddress <= imports.VirtualAddress && imports.VirtualAddress < s.VirtualAddress+s.VirtualSize {
			section = s
			break
		}
	}
	if section == nil {
		return nil, 0, 0, nil
	}

	data, err := section.Data()
	if err != nil {
		return nil, 0, 0, err
	}

	// seek to the virtual address specified in the import data directory
	return data, imports.VirtualAddress, section.VirtualAddress, nil
}

func normalizeLibraryName(name string) string {
	name = strings.ToLower(name)
	extension := filepath.Ext(name)
	if extension == ".ocx" ||
		extension == ".sys" ||
		extension == ".dll" {
		return name[:len(name)-4]
	}
	return name
}

func imphash(f *pe.File) (map[string][]string, string, error) {
	if f.OptionalHeader == nil {
		return nil, emptyHash, nil
	}

	pe64 := f.Machine == pe.IMAGE_FILE_MACHINE_AMD64
	data, importAddress, sectionAddress, err := importData(f)
	if err != nil {
		return nil, emptyHash, err
	}
	if data == nil {
		return nil, emptyHash, nil
	}

	tableData := data[importAddress-sectionAddress:]
	offset := 0
	symbols := make(map[string][]string)
	imphashEntries := []string{}
	for len(tableData) >= offset+20 {
		directoryData := tableData[offset:]
		firstThunk := binary.LittleEndian.Uint32(directoryData[0:4])
		if firstThunk == 0 {
			break
		}

		name := binary.LittleEndian.Uint32(directoryData[12:16])
		dllOffset := int(name - sectionAddress)
		dllName := readString(data, dllOffset)
		normalizedDllName := normalizeLibraryName(dllName)
		functionOffset := int(firstThunk - sectionAddress)
		offset += 20

		for len(data) > functionOffset {
			functionData := data[functionOffset:]
			if pe64 { // 64bit
				functionAddress := binary.LittleEndian.Uint64(functionData[0:8])
				if functionAddress == 0 {
					break
				}
				if functionAddress&0x8000000000000000 > 0 { // is Ordinal
					normalizedFunctionName := strings.ToLower(lookupOrdinal(dllName, int(functionAddress&0xffffffff)))
					imphashEntries = append(imphashEntries, normalizedDllName+"."+normalizedFunctionName)
				} else {
					functionName := readString(data, int(uint32(functionAddress)-sectionAddress+2))
					symbols[dllName] = append(symbols[dllName], functionName)
					normalizedFunctionName := strings.ToLower(functionName)
					imphashEntries = append(imphashEntries, normalizedDllName+"."+normalizedFunctionName)
				}
				functionOffset += 8
			} else { // 32bit
				functionAddress := binary.LittleEndian.Uint32(functionData[0:4])
				if functionAddress == 0 {
					break
				}
				if functionAddress&0x80000000 > 0 { // is Ordinal
					normalizedFunctionName := strings.ToLower(lookupOrdinal(dllName, int(functionAddress&0x0000ffff)))
					imphashEntries = append(imphashEntries, normalizedDllName+"."+normalizedFunctionName)
				} else {
					functionName := readString(data, int(functionAddress-sectionAddress+2))
					symbols[dllName] = append(symbols[dllName], functionName)
					normalizedFunctionName := strings.ToLower(functionName)
					imphashEntries = append(imphashEntries, normalizedDllName+"."+normalizedFunctionName)
				}
				functionOffset += 4
			}
		}
	}

	hash := md5.Sum([]byte(strings.Join(imphashEntries, ",")))
	return symbols, hex.EncodeToString(hash[:]), nil
}
