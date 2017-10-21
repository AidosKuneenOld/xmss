// Copyright (c) 2017 Aidos Developer

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package xmss

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

func generateSeed() []byte {
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		panic(err)
	}
	return seed
}

func TestHashes(t *testing.T) {
	fixed := make([]byte, 32)
	fixed[31] = 0x2
	key := generateSeed()
	m := generateSeed()
	m2 := generateSeed()

	s := sha256.New()
	s.Write(fixed)
	s.Write(key)
	s.Write(m)
	outC := s.Sum(nil)

	out := hashMsg(key, m)
	if !bytes.Equal(out, outC) {
		t.Error("incorrect hashM")
	}

	fixed[31] = 0x0
	s.Reset()
	s.Write(fixed)
	s.Write(key)
	s.Write(m)
	outC = s.Sum(nil)

	hashF(key, m, out)
	if !bytes.Equal(out, outC) {
		t.Error("incorrect hashF")
	}

	fixed[31] = 0x1
	s.Reset()
	s.Write(fixed)
	s.Write(key)
	s.Write(m)
	s.Write(m2)
	outC = s.Sum(nil)

	hashH(key, m, m2, out)
	if !bytes.Equal(out, outC) {
		t.Error("incorrect hashH")
		t.Log(out)
		t.Log(outC)
	}

	fixed[31] = 0x3
	s.Reset()
	s.Write(fixed)
	s.Write(key)
	s.Write(m)
	outC = s.Sum(nil)
	prf := newPRF(key)
	prf.sum(m, out)
	if !bytes.Equal(out, outC) {
		t.Error("incorrect prf")
	}

	s.Reset()
	s.Write(fixed)
	s.Write(key)
	s.Write(m2)
	outC = s.Sum(nil)
	prf.sum(m2, out)
	if !bytes.Equal(out, outC) {
		t.Error("incorrect prf")
	}

	fixed[31] = 0x3
	mm := make([]byte, 32)
	binary.BigEndian.PutUint32(mm[28:], 123)
	s.Reset()
	s.Write(fixed)
	s.Write(key)
	s.Write(mm)
	outC = s.Sum(nil)
	prfP := newPRF(key)
	prfP.sumInt(123, out)
	if !bytes.Equal(out, outC) {
		t.Error("incorrect prfPriv")
	}

	binary.BigEndian.PutUint32(mm[28:], 456)
	s.Reset()
	s.Write(fixed)
	s.Write(key)
	s.Write(mm)
	outC = s.Sum(nil)
	prfP.sumInt(456, out)
	if !bytes.Equal(out, outC) {
		t.Error("incorrect prfPriv")
	}

}
