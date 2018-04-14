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
	if h%d != 0 || h%20 != 0 || h == 0 || d == 0 || h/20 > 15 || d > 15 {
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

//LeafNo returns the leaf no in xmss^mt.
func (p *PrivKeyMT) LeafNo() uint64 {
	return p.index
}

//SetLeafNo sets the leaf no in merkle and refresh authes..
func (p *PrivKeyMT) SetLeafNo(n uint64) error {
	if p.index < n {
		return errors.New("should not set past index")
	}
	p.index = n
	return nil
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

//PublicKeyMT for xmss^MT
type PublicKeyMT struct {
	H    uint32
	D    uint32
	Root []byte
	Seed []byte
}

//PublickeyMTHeader returns first 1 byte of public key of XMSS^MT
func PublickeyMTHeader(h, d uint32) (byte, error) {
	if h%d != 0 || h%20 != 0 || h == 0 || d == 0 ||
		h/20 > 15 || d > 15 {
		return 0, errors.New("invalid h or d")
	}
	var header byte
	header = byte(h) / 20
	header = (header << 4) | byte(d)
	return header, nil
}

//Serialize returns serialized bytes of XMSS^MT PublicKey.
func (p *PublicKeyMT) Serialize() ([]byte, error) {
	var err error
	key := make([]byte, 1+n+n)
	key[0], err = PublickeyMTHeader(p.H, p.D)
	if err != nil {
		return nil, errors.New("invalid h or d")
	}
	key[0] = byte(p.H) / 20
	key[0] = (key[0] << 4) | byte(p.D)
	copy(key[1:], p.Root)
	copy(key[1+n:], p.Seed)
	return key, nil
}

//DeserializeMT deserialized bytes to XMSS^MT PublicKey.
func DeserializeMT(key []byte) (*PublicKeyMT, error) {
	if len(key) != 65 {
		return nil, errors.New("invalid bytes length")
	}
	h := uint32(key[0] & 0xf0)
	h = (h >> 4) * 20
	d := uint32(key[0] & 0x0f)
	return &PublicKeyMT{
		H:    h,
		D:    d,
		Root: key[1:33],
		Seed: key[33:65],
	}, nil
}

//VerifyMT verifies msg by XMSS^MT.
func VerifyMT(bsig, msg, bpk []byte) bool {
	pk, err := DeserializeMT(bpk)
	if err != nil {
		return false
	}
	sig, err := bytes2MTsig(bsig, pk.D, pk.H)
	if err != nil {
		return false
	}
	r := make([]byte, 32*3)
	copy(r, sig.r)
	copy(r[32:], pk.Root)
	binary.BigEndian.PutUint64(r[64+24:], sig.idx)
	hmsg := hashMsg(r, msg)
	prf := newPRF(pk.Seed)

	mask := uint64((1 << (pk.H / pk.D)) - 1)
	idxTree := sig.idx >> (pk.H / pk.D)
	idxLeaf := uint32(sig.idx & mask)
	node := rootFromSig(idxLeaf, hmsg, sig.sigs[0], prf, 0, idxTree)

	for j := uint32(1); j < pk.D; j++ {
		idxLeaf := uint32(idxTree & mask)
		idxTree = idxTree >> (pk.H / pk.D)
		node = rootFromSig(idxLeaf, node, sig.sigs[j], prf, j, idxTree)
	}
	return bytes.Equal(pk.Root, node)
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
