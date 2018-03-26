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
	"encoding/json"

	"github.com/vmihailenco/msgpack"
)

//PrivKey is a private key of XMSS.
type PrivKey struct {
	msgPRF  *prf //SK_PRF in draft, used to get hash of index(randomness r in draft) when signing by XMSS.
	wotsPRF *prf //S in draft, used to generate private key elements of WOTS.
	pubPRF  *prf //SEED in draft , used to make public keys of WOTS.
	root    []byte
}
type pubkey struct {
	root []byte
	prf  *prf
}
type privkey struct {
	MsgSeed  []byte
	WotsSeed []byte
	PubSeed  []byte
	Root     []byte
}

func (x *PrivKey) exports() *privkey {
	return &privkey{
		MsgSeed:  x.msgPRF.seed,
		WotsSeed: x.wotsPRF.seed,
		PubSeed:  x.pubPRF.seed,
		Root:     x.root,
	}
}
func (x *PrivKey) imports(s *privkey) {
	x.msgPRF = newPRF(s.MsgSeed)
	x.wotsPRF = newPRF(s.WotsSeed)
	x.pubPRF = newPRF(s.PubSeed)
	x.root = s.Root
}

//MarshalJSON  marshals PrivKey into valid JSON.
func (x *PrivKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(x.exports())
}

//UnmarshalJSON  unmarshals JSON to PrivKey.
func (x *PrivKey) UnmarshalJSON(b []byte) error {
	s := privkey{}
	err := json.Unmarshal(b, &s)
	if err == nil {
		x.imports(&s)
	}
	return err
}

//EncodeMsgpack  marshals PrivKey into valid msgpack.
func (x *PrivKey) EncodeMsgpack(enc *msgpack.Encoder) error {
	return enc.Encode(x.exports())
}

//DecodeMsgpack  unmarshals JSON to msgpack.
func (x *PrivKey) DecodeMsgpack(dec *msgpack.Decoder) error {
	s := privkey{}
	if err := dec.Decode(&s); err != nil {
		return err
	}
	x.imports(&s)
	return nil
}

func (x *PrivKey) newWotsPrivKey(addrs addr, priv wotsPrivKey) {
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
			copy(pk[l>>1], pk[l-1])
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
	binary.BigEndian.PutUint32(index[28:], m.Leaf)
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
	addrs.set(adrOTS, m.Leaf)
	m.priv.newWotsPrivKey(addrs, wsk)
	sig := wsk.sign(hmsg, m.priv.pubPRF, addrs)
	xs := xmssSig{
		idx:  m.Leaf,
		seed: m.priv.pubPRF.seed,
		r:    r[:32],
		sig:  sig,
		auth: m.auth,
	}
	out := xs.bytes()
	m.Traverse()
	return out
}

//Verify verifies msg by XMSS.
func Verify(bsig, msg, bpk []byte) bool {
	sig := bytes2sig(bsig)
	pk := pubkey{
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
	node0 := pkOTS.ltree(pk.prf, addrs)
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
