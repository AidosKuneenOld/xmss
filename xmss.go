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
	"errors"

	"github.com/vmihailenco/msgpack"
)

//PrivKey is a private key of XMSS.
type PrivKey struct {
	msgPRF  *prf //SK_PRF in draft, used to get hash of index(randomness r in draft) when signing by XMSS.
	wotsPRF *prf //S in draft, used to generate private key elements of WOTS.
	pubPRF  *prf //SEED in draft , used to make public keys of WOTS.
	root    []byte
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
	var s privkey
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

//DecodeMsgpack  unmarshals msgpack to PrivKey.
func (x *PrivKey) DecodeMsgpack(dec *msgpack.Decoder) error {
	var s privkey
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

type xmssSigBody struct {
	sig  wotsSig
	auth [][]byte
}

type xmssSig struct {
	idx  uint32
	seed []byte
	r    []byte
	*xmssSigBody
}

func (x *xmssSig) bytes() []byte {
	sigSize := 4 + n + n + wlen*n + len(x.auth)*n
	sig := make([]byte, sigSize)
	binary.BigEndian.PutUint32(sig, x.idx)
	copy(sig[4:], x.seed)
	copy(sig[4+n:], x.r)
	sigBody := x.xmssSigBody.bytes()
	copy(sig[4+n+n:], sigBody)
	return sig
}

func (x *xmssSigBody) bytes() []byte {
	sigSize := wlen*n + len(x.auth)*n
	sig := make([]byte, sigSize)
	for i, s := range x.sig {
		copy(sig[i*n:], s)
	}
	for i, s := range x.auth {
		copy(sig[wlen*n+i*n:], s)
	}
	return sig
}

func bytes2sig(b []byte) (*xmssSig, error) {
	height := (len(b) - (4 + n + n + wlen*n)) >> 5
	if height <= 0 {
		return nil, errors.New("invalid length of bytes")
	}
	body := bytes2sigBody(b[4+n+n:], height)
	sig := &xmssSig{
		idx:         binary.BigEndian.Uint32(b),
		seed:        b[4 : 4+n],
		r:           b[4+n : 4+n+n],
		xmssSigBody: body,
	}
	return sig, nil
}

func bytes2sigBody(b []byte, height int) *xmssSigBody {
	body := &xmssSigBody{
		sig:  make([][]byte, wlen),
		auth: make([][]byte, height),
	}
	for i := 0; i < wlen; i++ {
		body.sig[i] = b[i*n : (i+1)*n]
	}
	for i := 0; i < height; i++ {
		body.auth[i] = b[n*wlen+n*i : n*wlen+n*(i+1)]
	}
	return body
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
	sigBody := m.sign(hmsg)
	sig := &xmssSig{
		idx:         m.Leaf,
		seed:        m.priv.pubPRF.seed,
		r:           r[:32],
		xmssSigBody: sigBody,
	}
	result := sig.bytes()
	m.Traverse() //never relocate the line to above
	return result
}

func (m *Merkle) sign(hmsg []byte) *xmssSigBody {
	wsk := make(wotsPrivKey, wlen)
	for i := range wsk {
		wsk[i] = make([]byte, 32)
	}
	addrs := make(addr, 32)
	addrs.set(adrLayer, m.layer)
	addrs.setTree(m.tree)
	addrs.set(adrOTS, m.Leaf)
	m.priv.newWotsPrivKey(addrs, wsk)
	sig := wsk.sign(hmsg, m.priv.pubPRF, addrs)
	return &xmssSigBody{
		sig:  sig,
		auth: m.auth,
	}
}

//Verify verifies msg by XMSS.
func Verify(bsig, msg, bpk []byte) bool {
	sig, err := bytes2sig(bsig)
	if err != nil {
		return false
	}
	prf := newPRF(sig.seed)
	r := make([]byte, 32*3)
	copy(r, sig.r)
	copy(r[32:], bpk)
	binary.BigEndian.PutUint32(r[64+28:], sig.idx)
	hmsg := hashMsg(r, msg)
	root := rootFromSig(sig.idx, hmsg, sig.xmssSigBody, prf, 0, 0)
	return bytes.Equal(root, bpk)
}

func rootFromSig(idx uint32, hmsg []byte, body *xmssSigBody, prf *prf, layer uint32, tree uint64) []byte {
	addrs := make(addr, 32)
	addrs.set(adrLayer, layer)
	addrs.setTree(tree)
	addrs.set(adrOTS, idx)
	pkOTS := body.sig.pubkey(hmsg, prf, addrs)
	addrs.set(adrType, 1)
	addrs.set(adrLtree, idx)
	node0 := pkOTS.ltree(prf, addrs)
	addrs.set(adrType, 2)
	addrs.set(adrLtree, 0)
	var k uint32
	for k = 0; k < uint32(len(body.auth)); k++ {
		addrs.set(adrHeight, k)
		addrs.set(adrIndex, idx>>1)
		if idx&0x1 == 0 {
			randHash(node0, body.auth[k], prf, addrs, node0)
		} else {
			randHash(body.auth[k], node0, prf, addrs, node0)
		}
		idx >>= 1
	}
	return node0
}
