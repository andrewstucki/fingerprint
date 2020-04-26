package elf

import (
	"debug/elf"
	"io/ioutil"
	"regexp"
	"sort"
	"strings"

	"github.com/knightsc/gapstone"
)

var (
	exclusionsRegex = []*regexp.Regexp{
		regexp.MustCompile(`^[_\.].*$`), // Function names starting with . or _
		regexp.MustCompile(`^.*64$`),    // x64-64 specific functions
		regexp.MustCompile(`^str.*$`),   // gcc significantly changes string functions depending on the target architecture, so we ignore them
		regexp.MustCompile(`^mem.*$`),   // gcc significantly changes string functions depending on the target architecture, so we ignore them
	}
	exclusionsString = []string{
		"__libc_start_main", // main function
		"main",              // main function	z
		"abort",             // ARM default
		"cachectl",          // MIPS default
		"cacheflush",        // MIPS default
		"puts",              // Compiler optimization (function replacement)
		"atol",              // Compiler optimization (function replacement)
		"malloc_trim",       //GNU extensions
	}
)

func canExclude(symbol elf.Symbol) bool {
	if elf.ST_TYPE(symbol.Info) != elf.STT_FUNC {
		return true
	}
	if elf.ST_BIND(symbol.Info) != elf.STB_GLOBAL {
		return true
	}
	if elf.ST_VISIBILITY(symbol.Other) != elf.STV_DEFAULT {
		return true
	}
	if symbol.Name == "" {
		return true
	}

	for _, exclusion := range exclusionsString {
		if symbol.Name == exclusion {
			return true
		}
	}
	for _, exclusion := range exclusionsRegex {
		if exclusion.MatchString(symbol.Name) {
			return true
		}
	}
	return false
}

func capstoneArgs(f *elf.File) (int, int, bool) {
	switch {
	case f.Class == elf.ELFCLASS32 && f.Machine == elf.EM_386:
		return gapstone.CS_ARCH_X86, gapstone.CS_MODE_32, true
	case f.Class == elf.ELFCLASS64 && f.Machine == elf.EM_X86_64:
		return gapstone.CS_ARCH_X86, gapstone.CS_MODE_64, true
	case f.Class == elf.ELFCLASS32 && f.Machine == elf.EM_ARM:
		return gapstone.CS_ARCH_ARM, gapstone.CS_MODE_ARM, true
	case f.Class == elf.ELFCLASS32 && f.Machine == elf.EM_MIPS:
		return gapstone.CS_ARCH_MIPS, int(gapstone.CS_MODE_MIPS32) | gapstone.CS_MODE_BIG_ENDIAN, true
	default:
		return 0, 0, false
	}
}

func isX86(f *elf.File) bool {
	return (f.Class == elf.ELFCLASS64 && f.Machine == elf.EM_X86_64) || (f.Class == elf.ELFCLASS32 && f.Machine == elf.EM_386)
}

// def get_ep_section_or_segment(elf):
//     """Get the code section/segment where the entry point is located
//     """
//
//     # get the entry point
//     ep = elf.header.e_entry
//
//     # enumerate all the sections. the code section is where the entry point
//     # falls in between the start and end address of the section
//     for section in elf.iter_sections():
//         start_offset = section.header.sh_addr
//         end_offset = start_offset + section.header.sh_size - 1
//
//         if (ep >= start_offset) and (ep <= end_offset):
//             return section
//
//     # if we reached this point, then we failed to get the code section using
//     # the above method. we use the default '.text' section
//     code_section_or_segment =  elf.get_section_by_name('.text')
//
//     if code_section_or_segment:
//         return code_section_or_segment
//
//     for segment in elf.iter_segments():
//         if segment['p_type'] == "PT_LOAD" and segment['p_flags'] == 5: # r-x segment
//             return segment
//
// 		return code_section_or_segment

func stringMember(ary []string, test string) bool {
	for _, a := range ary {
		if a == test {
			return true
		}
	}
	return false
}

// def elf_get_imagebase(elf):
//     i=0
//     while elf.iter_segments():
//         if (elf._get_segment_header(i)['p_type'] == 'PT_LOAD'):
//             return elf._get_segment_header(i)['p_vaddr']
//         i+=1

// 		return 0

func getImageBase(f *elf.File) uint64 {
	for _, segment := range f.Progs {
		if segment.Type == elf.PT_LOAD {
			return segment.Vaddr
		}
	}
	return 0
}

func extractCallDestinations(f *elf.File) ([]string, error) {
	arch, mode, found := capstoneArgs(f)
	if !found {
		return nil, nil
	}
	entryPoint := f.Entry
	var offset uint64
	var err error
	var data []byte
	for _, section := range f.Sections {
		if section.Addr <= entryPoint && section.Addr+section.Size >= entryPoint {
			offset = getImageBase(f) + section.Offset
			data, err = section.Data()
			if err != nil {
				return nil, err
			}
			break
		}
	}
	if data == nil {
		section := f.Section(".text")
		if section != nil {
			offset = getImageBase(f) + section.Offset
			data, err = section.Data()
			if err != nil {
				return nil, err
			}
		}
	}
	if data == nil {
		for _, segment := range f.Progs {
			if segment.Type == elf.PT_LOAD && segment.Flags == (elf.PF_R&elf.PF_X) {
				if entryPoint > segment.Vaddr {
					segmentData, err := ioutil.ReadAll(segment.Open())
					if err != nil {
						return nil, err
					}
					offset = entryPoint
					data = segmentData[entryPoint-segment.Vaddr:]
					break
				}
			}
		}
	}
	if data != nil {
		engine, err := gapstone.New(arch, mode)
		if err != nil {
			return nil, err
		}
		defer engine.Close()
		instructions, err := engine.Disasm(data, offset, 0)
		if err != nil {
			return nil, err
		}
		symbols := []string{}
		for _, instruction := range instructions {
			if isX86(f) && instruction.Mnemonic == "call" {
				// Consider only call to absolute addresses
				if strings.HasPrefix(instruction.OpStr, "0x") {
					address := instruction.OpStr[2:]
					if !stringMember(symbols, address) {
						symbols = append(symbols, address)
					}
				}
			} else if f.Machine == elf.EM_ARM && strings.HasPrefix(instruction.Mnemonic, "bl") {
				if strings.HasPrefix(instruction.OpStr, "#0x") {
					address := instruction.OpStr[3:]
					if !stringMember(symbols, address) {
						symbols = append(symbols, address)
					}
				}
			} else if f.Machine == elf.EM_MIPS && strings.HasPrefix(instruction.Mnemonic, "lw") {
				if strings.HasPrefix(instruction.OpStr, "$t9, ") {
					address := instruction.OpStr[8 : len(instruction.OpStr)-5]
					if !stringMember(symbols, address) {
						symbols = append(symbols, address)
					}
				}
			}
		}
		return symbols, nil
	}
	return nil, nil
}

func telfhash(elfFile *elf.File) (string, error) {
	symbols := []string{}
	dynSymbols, err := elfFile.DynamicSymbols()
	if err != nil {
		if err != elf.ErrNoSymbols {
			return "", err
		}
	}
	staticSymbols, err := elfFile.Symbols()
	if err != nil {
		if err != elf.ErrNoSymbols {
			return "", err
		}
	}
	if len(staticSymbols) == 0 && len(dynSymbols) == 0 {
		// extract symbols from call sites since we're in a static binary
		symbols, err = extractCallDestinations(elfFile)
		if err != nil {
			return "", err
		}
	} else {
		for _, symbol := range dynSymbols {
			if !canExclude(symbol) {
				symbols = append(symbols, strings.ToLower(symbol.Name))
			}
		}
		for _, symbol := range staticSymbols {
			if !canExclude(symbol) {
				symbols = append(symbols, strings.ToLower(symbol.Name))
			}
		}
		sort.Strings(symbols)
	}
	tlsh := newTlsh()
	tlsh.update([]byte(strings.Join(symbols, ",")))
	return strings.ToLower(tlsh.hash()), nil
}
