// MIT License
//
// portions Copyright (c) 2017 Lukas Rist
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package fingerprint

import (
	"bufio"
	"errors"
	"fmt"
)

const (
	rollingWindow uint32 = 7
	blockMin             = 3
	spamSumLength        = 64
	minFileSize          = 4096
	hashPrime     uint32 = 0x01000193
	hashInit      uint32 = 0x28021967
	b64String            = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
)

var (
	b64 = []byte(b64String)
)

type rollingState struct {
	window []byte
	h1     uint32
	h2     uint32
	h3     uint32
	n      uint32
}

func (rs *rollingState) rollSum() uint32 {
	return rs.h1 + rs.h2 + rs.h3
}

type ssdeepState struct {
	rollingState rollingState
	blockSize    int
	hashString1  string
	hashString2  string
	blockHash1   uint32
	blockHash2   uint32
}

func newSsdeepState() ssdeepState {
	return ssdeepState{
		blockHash1: hashInit,
		blockHash2: hashInit,
		rollingState: rollingState{
			window: make([]byte, rollingWindow),
		},
	}
}

func (state *ssdeepState) newRollingState() {
	state.rollingState = rollingState{}
	state.rollingState.window = make([]byte, rollingWindow)
}

func sumHash(c byte, h uint32) uint32 {
	return (h * hashPrime) ^ uint32(c)
}

func (state *ssdeepState) rollHash(c byte) {
	rs := &state.rollingState
	rs.h2 -= rs.h1
	rs.h2 += rollingWindow * uint32(c)
	rs.h1 += uint32(c)
	rs.h1 -= uint32(rs.window[rs.n])
	rs.window[rs.n] = c
	rs.n++
	if rs.n == rollingWindow {
		rs.n = 0
	}
	rs.h3 = rs.h3 << 5
	rs.h3 ^= uint32(c)
}

// getBlockSize calculates the block size based on file size
func (state *ssdeepState) setBlockSize(n int) {
	blockSize := blockMin
	for blockSize*spamSumLength < n {
		blockSize = blockSize * 2
	}
	state.blockSize = blockSize
}

func (state *ssdeepState) processByte(b byte) {
	state.blockHash1 = sumHash(b, state.blockHash1)
	state.blockHash2 = sumHash(b, state.blockHash2)
	state.rollHash(b)
	rh := int(state.rollingState.rollSum())
	if rh%state.blockSize == (state.blockSize - 1) {
		if len(state.hashString1) < spamSumLength-1 {
			state.hashString1 += string(b64[state.blockHash1%64])
			state.blockHash1 = hashInit
		}
		if rh%(state.blockSize*2) == ((state.blockSize * 2) - 1) {
			if len(state.hashString2) < spamSumLength/2-1 {
				state.hashString2 += string(b64[state.blockHash2%64])
				state.blockHash2 = hashInit
			}
		}
	}
}

func (state *ssdeepState) process(r *bufio.Reader) {
	state.newRollingState()
	b, err := r.ReadByte()
	for err == nil {
		state.processByte(b)
		b, err = r.ReadByte()
	}
}

func ssdeep(f Reader, fileSize int) (string, error) {
	if fileSize < minFileSize {
		return "", errors.New("not enough data")
	}
	state := newSsdeepState()
	state.setBlockSize(fileSize)
	for {
		if _, seekErr := f.Seek(0, 0); seekErr != nil {
			return "", seekErr
		}

		if state.blockSize < blockMin {
			return "", errors.New("block too small")
		}

		r := bufio.NewReader(f)
		state.process(r)

		if len(state.hashString1) < spamSumLength/2 {
			state.blockSize = state.blockSize / 2
			state.blockHash1 = hashInit
			state.blockHash2 = hashInit
			state.hashString1 = ""
			state.hashString2 = ""
		} else {
			rh := state.rollingState.rollSum()
			if rh != 0 {
				// Finalize the hash string with the remaining data
				state.hashString1 += string(b64[state.blockHash1%64])
				state.hashString2 += string(b64[state.blockHash2%64])
			}
			break
		}
	}
	return fmt.Sprintf("%d:%s:%s", state.blockSize, state.hashString1, state.hashString2), nil
}
