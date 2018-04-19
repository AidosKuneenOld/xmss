// Copyright (c) 2018 Aidos Developer

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
	"runtime"
	"sync"
	"unsafe"
)

const (
	w     = 16
	wlen1 = 64
	wlen2 = 3
	wlen  = wlen1 + wlen2
	n     = 32
)

func base16(x []byte, basew []uint8) {
	for i := 0; i < len(basew); i++ {
		if i&1 != 0 {
			basew[i] = x[i>>1] & 0x0f
		} else {
			basew[i] = (x[i>>1] & 0xf0) >> 4
		}
	}
}

type wotsPrivKey [][]byte
type wotsPubKey [][]byte
type wotsSig [][]byte

func chain(x []byte, start, step byte, p *prf, addrs addr, out []byte) {
	copy(out, x)
	key := make([]byte, 32)
	bm := make([]byte, 32)
	xor := make([]byte, 32)
	for i := byte(0); i < step; i++ {
		addrs.set(adrHash, uint32(start+i))
		addrs.set(adrKM, 0)
		p.sum(addrs, key)
		addrs.set(adrKM, 1)
		p.sum(addrs, bm)
		xorWords(xor, out, bm)
		hashF(key, xor, out)
	}
}

func (priv wotsPrivKey) newWotsPubKey(p *prf, addrs addr, pubkey wotsPubKey) {
	for i := 0; i < len(pubkey); i++ {
		addrs.set(adrChain, uint32(i))
		chain(priv[i], 0, w-1, p, addrs, pubkey[i])
	}
}

func goChain(addrs addr, fchain func(i int, a addr)) {
	var wg sync.WaitGroup
	ncpu := runtime.GOMAXPROCS(-1)
	nitem := wlen/ncpu + 1
	for i := 0; i < ncpu; i++ {
		wg.Add(1)
		go func(i int) {
			start := i * nitem
			end := start + nitem
			if end > wlen {
				end = wlen
			}
			a := make(addr, 32)
			copy(a, addrs)
			for j := start; j < end; j++ {
				a.set(adrChain, uint32(j))
				fchain(j, a)
			}
			wg.Done()
		}(i)
	}
	wg.Wait()
}

func (priv wotsPrivKey) goNewWotsPubKey(p *prf, addrs addr, pubkey wotsPubKey) {
	goChain(addrs, func(i int, a addr) {
		chain(priv[i], 0, w-1, p, a, pubkey[i])
	})
}

const (
	toSig = iota
	toPubkey
)

func nchain(in [][]byte, m []byte, p *prf, addrs addr, typee int) [][]byte {
	out := make([][]byte, wlen)
	for i := range out {
		out[i] = make([]byte, n)
	}
	msg := make([]byte, wlen)
	base16(m, msg[:wlen1])
	var csum uint16
	for _, mm := range msg[:wlen1] {
		csum += w - 1 - uint16(mm)
	}
	csum <<= 4
	tmp := []byte{
		byte((csum & 0xff00) >> 8),
		byte((csum & 0x00ff)),
	}
	base16(tmp, msg[wlen1:])
	if typee == toSig {
		goChain(addrs, func(i int, a addr) {
			chain(in[i], 0, msg[i], p, a, out[i])
		})
	} else {
		goChain(addrs, func(i int, a addr) {
			chain(in[i], msg[i], w-1-msg[i], p, a, out[i])
		})
	}
	return out
}

func (priv wotsPrivKey) sign(m []byte, p *prf, addrs addr) wotsSig {
	return nchain(priv, m, p, addrs, toSig)
}

func (sig wotsSig) pubkey(m []byte, p *prf, addrs addr) wotsPubKey {
	return nchain(sig, m, p, addrs, toPubkey)
}

//codes below is from https://golang.org/src/crypto/cipher/xor.go
// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

const wordSize = int(unsafe.Sizeof(uintptr(0)))
const supportsUnaligned = runtime.GOARCH == "386" || runtime.GOARCH == "amd64" || runtime.GOARCH == "ppc64" || runtime.GOARCH == "ppc64le" || runtime.GOARCH == "s390x"

// fastXORWords XORs multiples of 4 or 8 bytes (depending on architecture.)
// The arguments are assumed to be of equal length.
func fastXORWords(dst, a, b []byte) {
	dw := *(*[]uintptr)(unsafe.Pointer(&dst))
	aw := *(*[]uintptr)(unsafe.Pointer(&a))
	bw := *(*[]uintptr)(unsafe.Pointer(&b))
	n := len(b) / wordSize
	for i := 0; i < n; i++ {
		dw[i] = aw[i] ^ bw[i]
	}
}

func safeXORBytes(dst, a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b[i]
	}
	return n
}

func xorWords(dst, a, b []byte) {
	if supportsUnaligned {
		fastXORWords(dst, a, b)
	} else {
		safeXORBytes(dst, a, b)
	}
}
