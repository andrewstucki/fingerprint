package elf

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBinaries(t *testing.T) {
	binaries := []string{
		"hello.linux.stripped",
		"hello.linux.packed.stripped",
		"libxml2.so",
	}
	for _, binary := range binaries {
		t.Run(binary, func(t *testing.T) {
			f, err := os.Open("../fixtures/" + binary)
			require.NoError(t, err)
			defer f.Close()

			fixture, err := os.Open("../fixtures/" + binary + ".elf")
			require.NoError(t, err)
			defer fixture.Close()
			expected, err := ioutil.ReadAll(fixture)
			require.NoError(t, err)

			info, err := Parse(f)
			require.NoError(t, err)

			data, err := json.Marshal(info)
			require.NoError(t, err)

			require.JSONEq(t, string(expected), string(data))
		})
	}
}
