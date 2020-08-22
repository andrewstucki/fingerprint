package fingerprint

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBinaries(t *testing.T) {
	generate := os.Getenv("GENERATE") == "1"
	binaries := []string{
		// pe
		"calc.exe",
		"calc.packed.exe",
		"helloworld.exe",
		"avcodec.dll",
		// macho
		"main",
		"main.fat",
		"sqlite3.fat.packed",
		// elf
		"hello.linux.stripped",
		"hello.linux.packed.stripped",
		"libxml2.so",
		// lnk
		"lnk/local.directory.seven.lnk",
		"lnk/local.directory.xp.lnk",
		"lnk/local.file.darwin.lnk",
		"lnk/local.file.env.lnk",
		"lnk/local.file.exec.lnk",
		"lnk/local.file.icoset.lnk",
		"lnk/local.file.seven.lnk",
		"lnk/local.file.xp.lnk",
		"lnk/local_cmd.lnk",
		"lnk/local_unicode.lnk",
		"lnk/local_win31j.lnk",
		"lnk/microsoft.lnk",
		"lnk/native.2008srv.01.lnk",
		"lnk/native.2008srv.02.lnk",
		"lnk/native.2008srv.03.lnk",
		"lnk/native.2008srv.04.lnk",
		"lnk/native.2008srv.05.lnk",
		"lnk/native.2008srv.06.lnk",
		"lnk/native.2008srv.07.lnk",
		"lnk/native.2008srv.08.lnk",
		"lnk/native.2008srv.09.lnk",
		"lnk/native.2008srv.10.lnk",
		"lnk/native.2008srv.11.lnk",
		"lnk/native.2008srv.12.lnk",
		"lnk/native.2008srv.13.lnk",
		"lnk/native.2008srv.14.lnk",
		"lnk/native.2008srv.15.lnk",
		"lnk/native.2008srv.16.lnk",
		"lnk/native.2008srv.17.lnk",
		"lnk/native.2008srv.18.lnk",
		"lnk/native.2008srv.19.lnk",
		"lnk/native.2008srv.20.lnk",
		"lnk/native.seven.01.lnk",
		"lnk/native.seven.02.lnk",
		"lnk/native.seven.03.lnk",
		"lnk/native.seven.04.lnk",
		"lnk/native.seven.05.lnk",
		"lnk/native.seven.06.lnk",
		"lnk/native.seven.07.lnk",
		"lnk/native.seven.08.lnk",
		"lnk/native.seven.09.lnk",
		"lnk/native.seven.10.lnk",
		"lnk/native.seven.11.lnk",
		"lnk/native.seven.12.lnk",
		"lnk/native.seven.13.lnk",
		"lnk/native.seven.14.lnk",
		"lnk/native.seven.15.lnk",
		"lnk/native.seven.16.lnk",
		"lnk/native.seven.17.lnk",
		"lnk/native.seven.18.lnk",
		"lnk/native.seven.19.lnk",
		"lnk/native.seven.20.lnk",
		"lnk/native.xp.01.lnk",
		"lnk/native.xp.02.lnk",
		"lnk/native.xp.03.lnk",
		"lnk/native.xp.04.lnk",
		"lnk/native.xp.05.lnk",
		"lnk/native.xp.06.lnk",
		"lnk/native.xp.07.lnk",
		"lnk/native.xp.08.lnk",
		"lnk/native.xp.09.lnk",
		"lnk/native.xp.10.lnk",
		"lnk/native.xp.11.lnk",
		"lnk/native.xp.12.lnk",
		"lnk/native.xp.13.lnk",
		"lnk/native.xp.14.lnk",
		"lnk/native.xp.15.lnk",
		"lnk/native.xp.16.lnk",
		"lnk/native.xp.17.lnk",
		"lnk/native.xp.18.lnk",
		"lnk/native.xp.19.lnk",
		"lnk/native.xp.20.lnk",
		"lnk/net_unicode.lnk",
		"lnk/net_unicode2.lnk",
		"lnk/net_win31j.lnk",
		"lnk/remote.directory.xp.lnk",
		"lnk/remote.file.aidlist.lnk",
		"lnk/remote.file.xp.lnk",
	}
	for _, binary := range binaries {
		t.Run(binary, func(t *testing.T) {
			f, err := os.Open("./fixtures/" + binary)
			require.NoError(t, err)
			defer f.Close()
			fileInfo, err := f.Stat()
			require.NoError(t, err)

			info, err := Parse(f, int(fileInfo.Size()))
			require.NoError(t, err)

			expectedFile := "./fixtures/" + binary + ".fingerprint"
			if generate {
				data, err := json.MarshalIndent(info, "", "  ")
				require.NoError(t, err)
				require.NoError(t, ioutil.WriteFile(expectedFile, data, 0644))
			} else {
				fixture, err := os.Open(expectedFile)
				require.NoError(t, err)
				defer fixture.Close()
				expected, err := ioutil.ReadAll(fixture)
				require.NoError(t, err)

				data, err := json.Marshal(info)
				require.NoError(t, err)
				require.JSONEq(t, string(expected), string(data))
			}
		})
	}
}
