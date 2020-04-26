package elf

import (
	"debug/elf"
	"regexp"
	"sort"
	"strings"
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

func telfhash(elfFile *elf.File) (string, error) {
	// TODO: handle call sites for stripped binaries
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

	symbols := []string{}
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

	tlsh := newTlsh()
	tlsh.update([]byte(strings.Join(symbols, ",")))
	return strings.ToLower(tlsh.hash()), nil
}
