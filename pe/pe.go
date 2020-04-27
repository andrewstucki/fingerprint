package pe

import (
	"crypto/md5"
	"debug/pe"
	"encoding/hex"
	"io"
	"time"

	"github.com/andrewstucki/fingerprint/internal"
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
	CompilationTimestamp *time.Time `json:"compilationTimestamp,omitempty"`
	Entrypoint           uint32     `json:"entrypoint"`
	TargetMachine        string     `json:"targetMachine"`
	ContainedSections    int        `json:"containedSections"`
}

// Resource represents a resource entry embedded in a PE file.
type Resource struct {
	Type     string `json:"type"`
	Language string `json:"language"`
	SHA256   string `json:"sha256,omitempty"`
	MIME     string `json:"mime,omitempty"`
	Size     int    `json:"size"`

	data []byte
}

// VersionInfo hold keys and values parsed from the version info resource.
type VersionInfo struct {
	Name  string
	Value string
}

// Info contains high level fingerprinting an analysis of a PE file.
type Info struct {
	Sections                     []Section           `json:"sections,omitempty"`
	FileVersionInfo              []VersionInfo       `json:"version_info,omitempty"`
	Header                       Header              `json:"header,omitempty"`
	Imports                      map[string][]string `json:"imports,omitempty"`
	Exports                      []string            `json:"exports,omitempty"`
	ContainedResourcesByType     map[string]int      `json:"containedResourcesByType,omitempty"`
	ContainedResourcesByLanguage map[string]int      `json:"containedResourcesByLanguage,omitempty"`
	Resources                    []Resource          `json:"resources,omitempty"`
	Packer                       string              `json:"packer,omitempty"`
	ImpHash                      string              `json:"imphash,omitempty"`
}

func getPacker(f *pe.File) string {
	for _, section := range f.Sections {
		if section.Name == "UPX0" {
			return "upx"
		}
	}
	return ""
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

	exportSymbols, err := exports(peFile)
	if err != nil {
		return nil, err
	}

	importSymbols, imphash, err := imphash(peFile)
	if err != nil {
		return nil, err
	}

	sectionSize := len(peFile.Sections)
	var compiledAt *time.Time
	timestamp := int64(peFile.FileHeader.TimeDateStamp)
	if timestamp != 0 {
		compiled := time.Unix(timestamp, 0).UTC()
		compiledAt = &compiled
	}

	info := &Info{
		ImpHash: imphash,
		Header: Header{
			CompilationTimestamp: compiledAt,
			Entrypoint:           entrypoint,
			TargetMachine:        architecture,
			ContainedSections:    sectionSize,
		},
		Sections:                     make([]Section, sectionSize),
		ContainedResourcesByType:     make(map[string]int),
		ContainedResourcesByLanguage: make(map[string]int),
		Imports:                      importSymbols,
		Exports:                      exportSymbols,
		Packer:                       getPacker(peFile),
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
			Entropy:        internal.Entropy(data),
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
