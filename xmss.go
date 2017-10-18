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
	"encoding/binary"
)

type xmssPrivKey struct {
	msgPRF  *prf
	wotsPRF *prf
	pubPRF  *prf
	root    []byte
}
type xmssPubKey struct {
	root []byte
	prf  *prf
}

func (x *xmssPrivKey) newWotsPrivKey(addrs addr, priv wotsPrivKey) {
	s := make([]byte, 32)
	x.wotsPRF.sum(addrs, s)
	p := newPRF(s)
	for i := range priv {
		p.sumInt(uint32(i), priv[i])
	}
}

func randHash(left, right []byte, p *prf, addrs addr, out []byte) {
	addrs.set(adrKM, 0)
	key := make([]byte, 32)
	p.sum(addrs, key)
	addrs.set(adrKM, 1)
	bm0 := make([]byte, 32)
	p.sum(addrs, bm0)
	addrs.set(adrKM, 2)
	bm1 := make([]byte, 32)
	p.sum(addrs, bm1)

	lxor := make([]byte, 32)
	xorWords(lxor, left, bm0)
	rxor := make([]byte, 32)
	xorWords(rxor, right, bm1)
	hashH(key, lxor, rxor, out)
}

func (pk wotsPubKey) ltree(p *prf, addrs addr) []byte {
	var height uint32
	addrs.set(adrHeight, 0)
	var l uint32
	for l = wlen; l > 1; l = (l >> 1) + (l & 0x1) {
		var i uint32
		for i = 0; i < l>>1; i++ {
			addrs.set(adrIndex, i)
			randHash(pk[2*i], pk[2*i+1], p, addrs, pk[i])
		}
		if l&0x1 == 1 {
			pk[l>>1] = pk[l-1]
		}
		height++
		addrs.set(adrHeight, height)
	}
	return pk[0]
}

type xmssSig struct {
	idx  uint32
	seed []byte
	r    []byte
	sig  wotsSig
	auth [][]byte
}

func (x *xmssSig) bytes() []byte {
	sigSize := 4 + n + n + wlen*n + len(x.auth)*n
	sig := make([]byte, sigSize)
	binary.BigEndian.PutUint32(sig, x.idx)
	copy(sig[4:], x.seed)
	copy(sig[4+n:], x.r)
	for i, s := range x.sig {
		copy(sig[4+n+n+i*n:], s)
	}
	for i, s := range x.auth {
		copy(sig[4+n+n+wlen*n+i*n:], s)
	}
	return sig
}

func bytes2sig(b []byte) *xmssSig {
	height := (len(b) - (4 + n + n + wlen*n)) >> 5
	sig := &xmssSig{
		idx:  binary.BigEndian.Uint32(b),
		seed: b[4 : 4+n],
		r:    b[4+n : 4+n+n],
		sig:  make([][]byte, wlen),
		auth: make([][]byte, height),
	}
	for i := 0; i < wlen; i++ {
		sig.sig[i] = b[4+n+n+i*n : 4+n+n+(i+1)*n]
	}
	for i := 0; i < height; i++ {
		sig.auth[i] = b[4+n+n+n*wlen+n*i : 4+n+n+n*wlen+n*(i+1)]
	}
	return sig
}

//Sign signs by XMSS with MerkleTree.
func (m *Merkle) Sign(msg []byte) []byte {
	index := make([]byte, 32)
	binary.BigEndian.PutUint32(index[28:], m.leaf)
	r := make([]byte, 32*3)
	m.priv.msgPRF.sum(index, r)
	copy(r[32:], m.priv.root)
	copy(r[64:], index)
	hmsg := hashMsg(r, msg)
	wsk := make(wotsPrivKey, wlen)
	for i := range wsk {
		wsk[i] = make([]byte, 32)
	}
	addrs := make(addr, 32)
	addrs.set(adrOTS, m.leaf)
	m.priv.newWotsPrivKey(addrs, wsk)
	sig := wsk.sign(hmsg, m.priv.pubPRF, addrs)
	xs := xmssSig{
		idx:  m.leaf,
		seed: m.priv.pubPRF.seed,
		r:    r[:32],
		sig:  sig,
		auth: m.auth,
	}
	out := xs.bytes()
	m.traverse()
	return out
}

//Verify verifies msg by XMSS.
func Verify(bsig, msg, bpk []byte) bool {
	sig := bytes2sig(bsig)
	pk := xmssPubKey{
		root: bpk,
		prf:  newPRF(sig.seed),
	}
	r := make([]byte, 32*3)
	copy(r, sig.r)
	copy(r[32:], pk.root)
	binary.BigEndian.PutUint32(r[64+28:], sig.idx)
	hmsg := hashMsg(r, msg)
	addrs := make(addr, 32)
	addrs.set(adrOTS, sig.idx)
	pkOTS := sig.sig.pubkey(hmsg, pk.prf, addrs)
	addrs.set(adrType, 1)
	addrs.set(adrLtree, sig.idx)
	var node0 []byte
	node0 = pkOTS.ltree(pk.prf, addrs)
	addrs.set(adrType, 2)
	addrs.set(adrLtree, 0)
	var k uint32
	idx := sig.idx
	for k = 0; k < uint32(len(sig.auth)); k++ {
		addrs.set(adrHeight, k)
		addrs.set(adrIndex, idx>>1)
		if idx&0x1 == 0 {
			randHash(node0, sig.auth[k], pk.prf, addrs, node0)
		} else {
			randHash(sig.auth[k], node0, pk.prf, addrs, node0)
		}
		idx >>= 1
	}
	return bytes.Equal(pk.root, node0)
}

// func (p *xmssPrivKey) treeHash(s uint32, addrs addr) []byte {
// 	type nh struct {
// 		node   []byte
// 		height uint32
// 	}
// 	var i uint32
// 	stack := make([]*nh, 0, 1<<p.height)
// 	sk := make(wotsPrivKey, wlen)
// 	pk := make(wotsPubKey, wlen)
// 	for j := 0; j < wlen; j++ {
// 		sk[j] = make([]byte, n)
// 		pk[j] = make([]byte, n)
// 	}
// 	for i = 0; i < 1<<p.height; i++ {
// 		addrs.set(0, adrLtree)
// 		addrs.set(adrOTS, s+i)
// 		newWotsPrivKey(p.prfP, sk)
// 		sk.newWotsPubKey(p.prf, addrs, pk)
// 		addrs.set(adrLtree, 1)
// 		addrs.set(adrLtree, s+i)
// 		node := &nh{
// 			node:   pk.ltree(p.prf, addrs),
// 			height: 0,
// 		}
// 		addrs.set(2, adrType)
// 		index := i + s
// 		addrs.set(adrIndex, index)
// 		for len(stack) > 0 && stack[len(stack)-1].height == node.height {
// 			index = (index - 1) >> 1
// 			addrs.set(adrIndex, index)
// 			randHash(stack[len(stack)-1].node, node.node, p.prf, addrs, node.node)
// 			node.height++
// 			stack = stack[:len(stack)-1]
// 			addrs.set(adrHeight, node.height)
// 		}
// 		stack = append(stack, node)
// 	}
// 	out := make([]byte, 32)
// 	copy(out, stack[len(stack)-1].node)
// 	return out
// }
