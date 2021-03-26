package macho

import (
	"crypto/md5"
	"encoding/hex"
	"sort"
	"strings"

	macho "github.com/blacktop/go-macho"
	"github.com/blacktop/go-macho/types"
)

func symhash(machoFile *macho.File) (string, error) {
	if machoFile.Magic == types.MagicFat {
		return "", nil
	}
	if machoFile.Symtab == nil {
		return "", nil
	}
	if machoFile.Dysymtab == nil {
		return "", nil
	}
	hashed := []string{}
	symbols := machoFile.Symtab.Syms
	for _, symbol := range symbols {
		if symbol.Type&0x0E == 0 {
			hashed = append(hashed, symbol.Name)
		}
	}
	sort.Strings(hashed)
	md5hash := md5.Sum([]byte(strings.Join(hashed, ",")))
	return hex.EncodeToString(md5hash[:]), nil
}
