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
	"crypto/rand"
	"encoding/binary"
	mrand "math/rand"

	sha256 "github.com/AidosKuneen/sha256-simd"
)

var (
	zero64 = make([]byte, 64)
	cmrand *mrand.Rand
)

const (
	adrType  = 4 + 8
	adrOTS   = 4 + 8 + 4
	adrChain = 4 + 8 + 4*2
	adrHash  = 4 + 8 + 4*3
	adrKM    = 4 + 8 + 4*4

	adrLtree  = 4 + 8 + 4
	adrHeight = 4 + 8 + 4*2
	adrIndex  = 4 + 8 + 4*3
)

type addr []byte

func (o addr) set(typee int, value uint32) {
	binary.BigEndian.PutUint32(o[typee:], value)
}

//key:arbital, m:arbital bytes
func hashMsg(key, m []byte) []byte {
	fixed := make([]byte, 32)
	fixed[31] = 0x2
	h := sha256.New()
	h.Write(fixed)
	h.Write(key)
	h.Write(m)
	return h.Sum(nil)
}

//key:32bytes, m:32bytes
func hashF(key, m, out []byte) {
	stat := []uint32{
		sha256.Init0,
		sha256.Init1,
		sha256.Init2,
		sha256.Init3,
		sha256.Init4,
		sha256.Init5,
		sha256.Init6,
		sha256.Init7,
	}
	buf := make([]byte, 64)
	copy(buf[32:], key)
	sha256.Block(stat, buf)
	copy(buf, m)
	copy(buf[32:], zero64)
	buf[32] = 0x80
	buf[62] = 0x03
	// buf[63] = 0x00
	sha256.Block(stat, buf)
	sha256.Int2Bytes(stat, out)
}

//key:32bytes, m:64bytes
func hashH(key, m1, m2, out []byte) {
	stat := []uint32{
		sha256.Init0,
		sha256.Init1,
		sha256.Init2,
		sha256.Init3,
		sha256.Init4,
		sha256.Init5,
		sha256.Init6,
		sha256.Init7,
	}
	buf := make([]byte, 64)
	buf[31] = 0x1
	copy(buf[32:], key)
	sha256.Block(stat, buf)
	copy(buf, m1)
	copy(buf[32:], m2)
	sha256.Block(stat, buf)
	copy(buf, zero64)
	buf[0] = 0x80
	buf[62] = 0x04
	// buf[63] = 0x00
	sha256.Block(stat, buf)
	sha256.Int2Bytes(stat, out)
}

//prf is for getting value from peudo random function.
type prf struct {
	seed   []byte
	block1 []uint32
}

//newPRF returns PRF.
//seed must be 32bytes.
func newPRF(seed []byte) *prf {
	if seed == nil {
		seed = make([]byte, 32)
		if _, err := rand.Read(seed); err != nil {
			panic(err)
		}
	}
	p := &prf{
		seed: seed,
	}
	p.block1 = []uint32{
		sha256.Init0,
		sha256.Init1,
		sha256.Init2,
		sha256.Init3,
		sha256.Init4,
		sha256.Init5,
		sha256.Init6,
		sha256.Init7,
	}
	buf := make([]byte, 64)
	buf[31] = 0x3
	copy(buf[32:], seed)
	sha256.Block(p.block1, buf)
	return p
}

//m:32bytes
func (p *prf) finish(buf, out []byte) {
	buf[32] = 0x80
	buf[62] = 0x03
	// buf[63] = 0x00
	stat := make([]uint32, 8)
	copy(stat, p.block1)
	sha256.Block(stat, buf)
	sha256.Int2Bytes(stat, out)
}

//m:32bytes
func (p *prf) sum(m, out []byte) {
	buf := make([]byte, 64)
	copy(buf, m)
	p.finish(buf, out)
}

func (p *prf) sumInt(m uint32, out []byte) {
	buf := make([]byte, 64)
	binary.BigEndian.PutUint32(buf[28:], m)
	p.finish(buf, out)
}

//GenerateSeed generates a new 32 bytes seed.
func GenerateSeed() []byte {
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		panic(err)
	}
	return seed
}
