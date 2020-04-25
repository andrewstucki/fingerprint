package macho

import (
	"crypto/md5"
	"debug/macho"
	"encoding/hex"
	"io"

	"github.com/andrewstucki/fingerprint/internal"
)

// Section contains information about a section in a mach-o file.
type Section struct {
	Name    string  `json:"name"`
	Address uint64  `json:"address"`
	Size    uint64  `json:"size"`
	Entropy float64 `json:"entropy,omitempty"`
	MD5     string  `json:"md5,omitempty"`
}

// Architecture represents a fat file architecture
type Architecture struct {
	CPU       string    `json:"cpu"`
	Sections  []Section `json:"sections,omitempty"`
	Libraries []string  `json:"libraries,omitempty"`
	Imports   []string  `json:"imports,omitempty"`
	Exports   []string  `json:"exports,omitempty"`
	Packer    string    `json:"packer,omitempty"`
	Symhash   string    `json:"symhash,omitempty"`
}

// Info contains high level fingerprinting an analysis of a mach-o file.
type Info struct {
	Architectures []*Architecture `json:"architectures,omitempty"`
}

// Parse parses the mach-o file and returns information about it or errors.
func Parse(r io.ReaderAt) (*Info, error) {
	machoFiles := []*macho.File{}
	machoFatFile, err := macho.NewFatFile(r)
	if err != nil {
		if err != macho.ErrNotFat {
			return nil, err
		}
		machoFile, err := macho.NewFile(r)
		if err != nil {
			return nil, err
		}
		machoFiles = append(machoFiles, machoFile)
	} else {
		for _, arch := range machoFatFile.Arches {
			machoFiles = append(machoFiles, arch.File)
		}
	}

	architectures := make([]*Architecture, len(machoFiles))
	for i, machoFile := range machoFiles {
		arch, err := parse(machoFile)
		if err != nil {
			return nil, err
		}
		architectures[i] = arch
	}
	return &Info{
		Architectures: architectures,
	}, nil
}

// the default string translations are gross
func translateCPU(cpu macho.Cpu) string {
	switch cpu {
	case macho.Cpu386:
		return "x86"
	case macho.CpuAmd64:
		return "x86_64"
	case macho.CpuArm:
		return "arm"
	case macho.CpuArm64:
		return "arm64"
	case macho.CpuPpc:
		return "ppc"
	case macho.CpuPpc64:
		return "ppc64"
	default:
		return "unknown"
	}
}

func parse(machoFile *macho.File) (*Architecture, error) {
	symhash, err := symhash(machoFile)
	if err != nil {
		return nil, err
	}
	libraries, err := machoFile.ImportedLibraries()
	if err != nil {
		return nil, err
	}
	importSymbols, err := machoFile.ImportedSymbols()
	if err != nil {
		if _, ok := err.(*macho.FormatError); !ok {
			return nil, err
		}
	}

	sections := make([]Section, len(machoFile.Sections))
	for i, section := range machoFile.Sections {
		var md5String string
		var entropy float64

		data, err := section.Data()
		if err != nil {
			if err != io.EOF {
				return nil, err
			}
		} else {
			md5hash := md5.Sum(data)
			md5String = hex.EncodeToString(md5hash[:])
			entropy = internal.Entropy(data)
		}
		sections[i] = Section{
			Name:    section.Name,
			Address: section.Addr,
			Size:    section.Size,
			Entropy: entropy,
			MD5:     md5String,
		}
	}

	return &Architecture{
		CPU:       translateCPU(machoFile.Cpu),
		Symhash:   symhash,
		Libraries: libraries,
		Imports:   importSymbols,
		Sections:  sections,
		Packer:    getPacker(machoFile),
	}, nil
}

func getPacker(machoFile *macho.File) string {
	for _, section := range machoFile.Sections {
		if section.Name == "upxTEXT" {
			return "upx"
		}
	}
	return ""
}
