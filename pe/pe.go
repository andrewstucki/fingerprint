package pe

import (
	"crypto/md5"
	"debug/pe"
	"encoding/hex"
	"io"
	"time"
)

// Section contains information about a section in a PE file.
type Section struct {
	Name           string  `json:"name"`
	VirtualAddress uint32  `json:"virtualAddress"`
	VirtualSize    uint32  `json:"virtualSize"`
	RawSize        uint32  `json:"rawSize"`
	Entropy        float64 `json:"entropy"`
	MD5            string  `json:"md5"`
}

// Header contains information found in a PE header.
type Header struct {
	CompilationTimestamp time.Time `json:"compilationTimestamp"`
	Entrypoint           uint32    `json:"entrypoint"`
	TargetMachine        string    `json:"targetMachine"`
	ContainedSections    int       `json:"containedSections"`
}

// Resource represents a resource entry embedded in a PE file.
type Resource struct {
	Type     string `json:"type"`
	Language string `json:"language"`
	SHA256   string `json:"sha256"`
	MIME     string `json:"mime"`

	data []byte
}

// VersionInfo hold keys and values parsed from the version info resource.
type VersionInfo struct {
	Name  string
	Value string
}

// Info contains high level fingerprinting an analysis of a PE file.
type Info struct {
	Sections                     []Section           `json:"sections"`
	FileVersionInfo              []VersionInfo       `json:"version_info"`
	Header                       Header              `json:"header"`
	Imports                      map[string][]string `json:"imports"`
	ContainedResourcesByType     map[string]int      `json:"containedResourcesByType"`
	ContainedResourcesByLanguage map[string]int      `json:"containedResourcesByLanguage"`
	Resources                    []Resource          `json:"resources"`
	ImpHash                      string              `json:"imphash"`
}

// Parse parses the PE and returns information about it or errors.
func Parse(r io.ReaderAt) (*Info, error) {
	peFile, err := pe.NewFile(r)
	if err != nil {
		return nil, err
	}
	// IsDLL:        (peFile.Characteristics & 0x2000) == 0x2000,
	// IsSys:        (peFile.Characteristics & 0x1000) == 0x1000,

	var architecture string
	var entrypoint uint32
	switch header := peFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		architecture = "x32"
		entrypoint = header.AddressOfEntryPoint

	case *pe.OptionalHeader64:
		architecture = "x64"
		entrypoint = header.AddressOfEntryPoint

	default:
		architecture = "unknown"
	}

	importSymbols, imphash, err := imphash(peFile)
	if err != nil {
		return nil, err
	}

	sectionSize := len(peFile.Sections)
	info := &Info{
		ImpHash: imphash,
		Header: Header{
			CompilationTimestamp: time.Unix(int64(peFile.FileHeader.TimeDateStamp), 0),
			Entrypoint:           entrypoint,
			TargetMachine:        architecture,
			ContainedSections:    sectionSize,
		},
		Sections:                     make([]Section, sectionSize),
		ContainedResourcesByType:     make(map[string]int),
		ContainedResourcesByLanguage: make(map[string]int),
		Imports:                      importSymbols,
	}
	for i, section := range peFile.Sections {
		data, err := section.Data()
		if err != nil {
			return nil, err
		}
		hashed := md5.Sum(data)
		info.Sections[i] = Section{
			Name:           section.Name,
			VirtualAddress: section.VirtualAddress,
			VirtualSize:    section.VirtualSize,
			RawSize:        section.Size,
			Entropy:        entropy(data),
			MD5:            hex.EncodeToString(hashed[:]),
		}

		if section.Name == ".rsrc" {
			resources, err := parseDirectory(section.VirtualAddress, data)
			if err != nil {
				return nil, err
			}

			info.Resources = resources
			for _, resource := range resources {
				countValue(info.ContainedResourcesByType, resource.Type)
				countValue(info.ContainedResourcesByLanguage, resource.Language)
			}

			versionInfo, err := getVersionInfoForResources(resources)
			if err != nil {
				return nil, err
			}
			info.FileVersionInfo = versionInfo
		}
	}
	return info, nil
}
