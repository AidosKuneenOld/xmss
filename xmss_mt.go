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
	"crypto/hmac"
	"encoding/binary"
	"encoding/json"
	"errors"

	sha256 "github.com/AidosKuneen/sha256-simd"
	"github.com/vmihailenco/msgpack"
)

//PrivKeyMT is a private key of XMSS^MT.
type PrivKeyMT struct {
	index  uint64
	merkle []*Merkle
	h      uint32
	d      uint32
}

//NewPrivKeyMT returns XMSS^MT private key.
func NewPrivKeyMT(seed []byte, h, d uint32) (*PrivKeyMT, error) {
	if h%d != 0 {
		return nil, errors.New("invalid h or d")
	}
	p := PrivKeyMT{
		merkle: make([]*Merkle, d),
		h:      h,
		d:      d,
	}
	mac := hmac.New(sha256.New, seed)
	if _, err := mac.Write([]byte{1}); err != nil {
		panic(err)
	}
	wotsSeed := mac.Sum(nil)
	mac.Reset()
	if _, err := mac.Write([]byte{2}); err != nil {
		panic(err)
	}
	msgSeed := mac.Sum(nil)
	mac.Reset()
	if _, err := mac.Write([]byte{3}); err != nil {
		panic(err)
	}
	pubSeed := mac.Sum(nil)
	p.merkle[d-1] = newMerkle(h/d, wotsSeed, msgSeed, pubSeed, d-1, 0)
	return &p, nil
}

//PublicKey returns public key (merkle root) of XMSS^MT
func (p *PrivKeyMT) PublicKey() []byte {
	priv := p.merkle[p.d-1].priv
	key := make([]byte, 1+n+n)
	key[0] = (byte(p.h / 20)) << 4
	key[0] |= byte(p.d)
	copy(key[1:], priv.root)
	copy(key[1+n:], priv.pubPRF.seed)
	return key
}

type xmssMTSig struct {
	idx  uint64
	r    []byte
	sigs []*xmssSigBody
}

func (x *xmssMTSig) bytes() []byte {
	d := len(x.sigs)
	h := len(x.sigs[0].auth) * d
	bytesPerLayer := (wlen + h/d) * n
	sigSize := 8 + n + (wlen+h/d)*n*d
	sig := make([]byte, sigSize)
	binary.BigEndian.PutUint64(sig, x.idx)
	copy(sig[8:], x.r)
	for i, body := range x.sigs {
		copy(sig[8+n+bytesPerLayer*i:], body.bytes())
	}
	return sig
}

func bytes2MTsig(b []byte, d, h uint32) (*xmssMTSig, error) {
	bytesPerLayer := (wlen + h/d) * n
	sigSize := 8 + n + bytesPerLayer*d
	if uint32(len(b)) != sigSize {
		return nil, errors.New("invalid length of bytes")
	}
	sig := &xmssMTSig{
		idx:  binary.BigEndian.Uint64(b),
		r:    b[8 : 8+n],
		sigs: make([]*xmssSigBody, d),
	}
	for i := range sig.sigs {
		start := 8 + n + uint32(i)*bytesPerLayer
		sig.sigs[i] = bytes2sigBody(b[start:start+bytesPerLayer], int(h/d))
	}
	return sig, nil
}

//Sign signs by XMSS with XMSS^MT.
func (p *PrivKeyMT) Sign(msg []byte) []byte {
	index := make([]byte, 32)
	binary.BigEndian.PutUint64(index[24:], p.index)
	mpriv := p.merkle[p.d-1].priv
	r := make([]byte, 32*3)
	mpriv.msgPRF.sum(index, r)
	copy(r[32:], mpriv.root)
	copy(r[64:], index)
	hmsg := hashMsg(r, msg)
	sig := &xmssMTSig{
		idx:  p.index,
		r:    r[:32],
		sigs: make([]*xmssSigBody, p.d),
	}
	mask := uint64((1 << (p.h / p.d)) - 1)
	idxTree := p.index >> (p.h / p.d)
	idxLeaf := uint32(p.index & mask)
	if p.merkle[0] == nil || p.merkle[0].tree != idxTree {
		p.merkle[0] = newMerkle(p.h/p.d, mpriv.wotsPRF.seed, mpriv.msgPRF.seed, mpriv.pubPRF.seed, 0, idxTree)
	}
	for p.merkle[0].Leaf < idxLeaf {
		p.merkle[0].Traverse()
	}
	sig.sigs[0] = p.merkle[0].sign(hmsg)
	root := p.merkle[0].priv.root

	for j := uint32(1); j < p.d; j++ {
		idxLeaf := uint32(idxTree & mask)
		idxTree = idxTree >> (p.h / p.d)
		if p.merkle[j] == nil || p.merkle[j].tree != idxTree {
			p.merkle[j] = newMerkle(p.h/p.d, mpriv.wotsPRF.seed, mpriv.msgPRF.seed, mpriv.pubPRF.seed, j, idxTree)
		}
		for p.merkle[j].Leaf < idxLeaf {
			p.merkle[j].Traverse()
		}
		sig.sigs[j] = p.merkle[j].sign(root)
		root = p.merkle[j].priv.root
	}

	p.index++
	return sig.bytes()
}

//VerifyMT verifies msg by XMSS^MT.
func VerifyMT(bsig, msg, bpk []byte) bool {
	pkRoot := bpk[1 : 1+n]
	seed := bpk[1+n : 1+n+n]
	h := uint32(bpk[0] & 0xf0)
	h = (h >> 4) * 20
	d := uint32(bpk[0] & 0x0f)

	sig, err := bytes2MTsig(bsig, d, h)
	if err != nil {
		return false
	}
	r := make([]byte, 32*3)
	copy(r, sig.r)
	copy(r[32:], pkRoot)
	binary.BigEndian.PutUint64(r[64+24:], sig.idx)
	hmsg := hashMsg(r, msg)
	prf := newPRF(seed)

	mask := uint64((1 << (h / d)) - 1)
	idxTree := sig.idx >> (h / d)
	idxLeaf := uint32(sig.idx & mask)
	node := rootFromSig(idxLeaf, hmsg, sig.sigs[0], prf, 0, idxTree)

	for j := uint32(1); j < d; j++ {
		idxLeaf := uint32(idxTree & mask)
		idxTree = idxTree >> (h / d)
		node = rootFromSig(idxLeaf, node, sig.sigs[j], prf, j, idxTree)
	}
	return bytes.Equal(pkRoot, node)
}

type privKeyMT struct {
	Index  uint64
	Merkle []*Merkle
	H      uint32
	D      uint32
}

func (p *PrivKeyMT) exports() *privKeyMT {
	return &privKeyMT{
		Index:  p.index,
		Merkle: p.merkle,
		H:      p.h,
		D:      p.d,
	}
}

func (p *PrivKeyMT) imports(s *privKeyMT) {
	p.index = s.Index
	p.merkle = s.Merkle
	p.h = s.H
	p.d = s.D
}

//MarshalJSON  marshals PrivKeyMT into valid JSON.
func (p *PrivKeyMT) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.exports())
}

//UnmarshalJSON  unmarshals JSON to PrivKeyMT.
func (p *PrivKeyMT) UnmarshalJSON(b []byte) error {
	var s privKeyMT
	err := json.Unmarshal(b, &s)
	if err == nil {
		p.imports(&s)
	}
	return err
}

//EncodeMsgpack  marshals PrivKeyMT into valid msgpack.
func (p *PrivKeyMT) EncodeMsgpack(enc *msgpack.Encoder) error {
	return enc.Encode(p.exports())
}

//DecodeMsgpack  unmarshals msgpack to PrivKey.
func (p *PrivKeyMT) DecodeMsgpack(dec *msgpack.Decoder) error {
	var s privKeyMT
	if err := dec.Decode(&s); err != nil {
		return err
	}
	p.imports(&s)
	return nil
}
