package fingerprint

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"unicode/utf8"

	"github.com/andrewstucki/fingerprint/pe"
	"github.com/h2non/filetype"
)

// size for mime detection, office file
// detection requires ~8kb to detect properly
const headerSize = 8192

// Info contains fingerprinting information.
type Info struct {
	MIME   string   `json:"mime"`
	SSDEEP string   `json:"ssdeep,omitempty"`
	MD5    string   `json:"md5"`
	SHA1   string   `json:"sha1"`
	SHA256 string   `json:"sha256"`
	Size   int      `json:"size"`
	PE     *pe.Info `json:"pe,omitempty"`
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
		if err != nil {
			return nil, err
		}
		info.PE = peInfo
	}

	return info, nil
}
