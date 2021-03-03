package fingerprint

import (
	"crypto/md5"
	"crypto/sha1"
	"encoding/hex"
	"io"
	"unicode/utf8"

	sha256 "github.com/minio/sha256-simd"

	"github.com/andrewstucki/fingerprint/elf"
	"github.com/andrewstucki/fingerprint/lnk"
	"github.com/andrewstucki/fingerprint/macho"
	"github.com/andrewstucki/fingerprint/pe"
	"github.com/h2non/filetype"
)

// size for mime detection, office file
// detection requires ~8kb to detect properly
const headerSize = 8192

var addedTypes = map[string]func([]byte) bool{
	"application/x-ms-shortcut": lnkMatcher,
}

func init() {
	for mimeType, matcher := range addedTypes {
		filetype.AddMatcher(filetype.NewType(mimeType, mimeType), matcher)
	}
}

func lnkMatcher(buf []byte) bool {
	return len(buf) > 3 && (buf[0] == 0x4C && buf[1] == 0x00 && buf[2] == 0x00 && buf[3] == 0x00)
}

// Info contains fingerprinting information.
type Info struct {
	MIME   string      `json:"mime"`
	SSDEEP string      `json:"ssdeep,omitempty"`
	MD5    string      `json:"md5"`
	SHA1   string      `json:"sha1"`
	SHA256 string      `json:"sha256"`
	Size   int         `json:"size"`
	PE     *pe.Info    `json:"pe,omitempty"`
	MachO  *macho.Info `json:"macho,omitempty"`
	Elf    *elf.Info   `json:"elf,omitempty"`
	LNK    *lnk.Info   `json:"lnk,omitempty"`
}

// Reader is the interface that must be satisfied for parsing a stream of data.
type Reader interface {
	io.ReadSeeker
	io.ReaderAt
}

func mimeFallback(r Reader) (string, error) {
	chunk := make([]byte, 256)
	for {
		n, err := r.Read(chunk)
		if err != nil {
			if err == io.EOF {
				return "text/plain", nil
			}
			return "", err
		}
		buffer := chunk[:n]
		for len(buffer) > 0 {
			if r, size := utf8.DecodeRune(buffer); r != utf8.RuneError {
				buffer = buffer[size:]
				continue
			}
			return "application/octet-stream", nil
		}
	}
}

// Parse determines the file type for the data and then enriches the information
// based off of the file type contained.
func Parse(r Reader, size int) (*Info, error) {
	header := make([]byte, headerSize)
	n, err := r.Read(header)
	if err != nil && err != io.EOF {
		return nil, err
	}
	// reset header read
	if _, err := r.Seek(0, 0); err != nil {
		return nil, err
	}

	kind, err := filetype.Match(header[:n])
	if err != nil {
		return nil, err
	}
	mime := kind.MIME.Value
	if mime == "" {
		fallback, err := mimeFallback(r)
		if err != nil {
			return nil, err
		}
		// reset mime read
		if _, err := r.Seek(0, 0); err != nil {
			return nil, err
		}
		mime = fallback
	}

	var ssdeepHash string
	if size > minFileSize {
		ssdeepHash, err = ssdeep(r, size)
		if err != nil {
			return nil, err
		}

		// reset after ssdeep calculation
		if _, err := r.Seek(0, 0); err != nil {
			return nil, err
		}
	}

	md5hash := md5.New()
	sha1hash := sha1.New()
	sha256hash := sha256.New()
	hasher := io.MultiWriter(md5hash, sha1hash, sha256hash)
	if _, err := io.Copy(hasher, r); err != nil {
		return nil, err
	}

	info := &Info{
		MIME:   mime,
		Size:   size,
		MD5:    hex.EncodeToString(md5hash.Sum(nil)),
		SHA1:   hex.EncodeToString(sha1hash.Sum(nil)),
		SHA256: hex.EncodeToString(sha256hash.Sum(nil)),
		SSDEEP: ssdeepHash,
	}

	switch mime {
	case "application/vnd.microsoft.portable-executable":
		peInfo, err := pe.Parse(r)
		if err == nil {
			info.PE = peInfo
		}
	case "application/x-mach-binary":
		machoInfo, err := macho.Parse(r)
		if err == nil {
			info.MachO = machoInfo
		}
	case "application/x-executable":
		elfInfo, err := elf.Parse(r)
		if err == nil {
			info.Elf = elfInfo
		}
	case "application/x-ms-shortcut":
		lnkInfo, err := lnk.Parse(r)
		if err == nil {
			info.LNK = lnkInfo
		}
	}

	return info, nil
}
