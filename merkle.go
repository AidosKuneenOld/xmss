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
	"crypto/hmac"
	"encoding/json"
	"math"
	"runtime"
	"sync"

	sha256 "github.com/AidosKuneen/sha256-simd"
	"github.com/vmihailenco/msgpack"
)

//NH represents a node in a merkle tree.
type NH struct {
	node   []byte
	height uint32
	index  uint32
}

type nh struct {
	Node   []byte
	Height uint32
	Index  uint32
}

func (nn *NH) exports() *nh {
	return &nh{
		Node:   nn.node,
		Height: nn.height,
		Index:  nn.index,
	}
}
func (nn *NH) imports(sr *nh) {
	nn.node = sr.Node
	nn.height = sr.Height
	nn.index = sr.Index
}

//MarshalJSON  marshals NH into valid JSON.
func (nn *NH) MarshalJSON() ([]byte, error) {
	return json.Marshal(nn.exports())
}

//UnmarshalJSON  unmarshals NH .
func (nn *NH) UnmarshalJSON(b []byte) error {
	var sr nh
	err := json.Unmarshal(b, &sr)
	if err != nil {
		return err
	}
	nn.imports(&sr)
	return nil
}

//EncodeMsgpack  marshals NH into valid msgpack.
func (nn *NH) EncodeMsgpack(enc *msgpack.Encoder) error {
	return enc.Encode(nn.exports())
}

//DecodeMsgpack  unmarshals NH.
func (nn *NH) DecodeMsgpack(dec *msgpack.Decoder) error {
	var sr nh
	if err := dec.Decode(&sr); err != nil {
		return err
	}
	nn.imports(&sr)
	return nil
}

//Stack is a stack to use in merkle traversing.
type Stack struct {
	stack  []*NH
	height uint32
	leaf   uint32
	layer  uint32
	tree   uint64
}

type stack struct {
	Stack  []*NH
	Height uint32
	Leaf   uint32
	Layer  uint32
	Tree   uint64
}

func (s *Stack) exports() *stack {
	return &stack{
		Stack:  s.stack,
		Height: s.height,
		Leaf:   s.leaf,
		Layer:  s.layer,
		Tree:   s.tree,
	}
}

func (s *Stack) imports(sr *stack) {
	s.stack = sr.Stack
	s.height = sr.Height
	s.leaf = sr.Leaf
	s.layer = sr.Layer
	s.tree = sr.Tree
}

//MarshalJSON  marshals Stack into valid JSON.
func (s *Stack) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.exports())
}

//UnmarshalJSON  unmarshals Stack to JSON.
func (s *Stack) UnmarshalJSON(b []byte) error {
	var sr stack
	err := json.Unmarshal(b, &sr)
	if err != nil {
		return err
	}
	s.imports(&sr)
	return nil
}

//EncodeMsgpack  marshals Stack into valid msgpack.
func (s *Stack) EncodeMsgpack(enc *msgpack.Encoder) error {
	return enc.Encode(s.exports())
}

//DecodeMsgpack  unmarshals Stack to msgpack.
func (s *Stack) DecodeMsgpack(dec *msgpack.Decoder) error {
	var sr stack
	if err := dec.Decode(&sr); err != nil {
		return err
	}
	s.imports(&sr)
	return nil
}

func (s *Stack) low() uint32 {
	if len(s.stack) == 0 {
		return s.height
	}
	if s.top().height == s.height {
		return math.MaxUint32
	}
	var min uint32 = math.MaxUint32
	for _, n := range s.stack {
		if n.height < min {
			min = n.height
		}
	}
	return min
}

func (s *Stack) initialize(start uint32, height uint32) {
	s.leaf = start
	s.height = height
	s.stack = s.stack[:0]
}

func (s *Stack) newleaf(priv *PrivKey, isGo bool) {
	pk := make(wotsPubKey, wlen)
	sk := make(wotsPrivKey, wlen)
	for j := 0; j < wlen; j++ {
		pk[j] = make([]byte, n)
		sk[j] = make([]byte, n)
	}
	addrs := make(addr, 32)

	// addrs.set(adrType, 0)
	addrs.set(adrLayer, s.layer)
	addrs.setTree(s.tree)
	addrs.set(adrOTS, s.leaf)
	priv.newWotsPrivKey(addrs, sk)
	if isGo {
		sk.goNewWotsPubKey(priv.pubPRF, addrs, pk)
	} else {
		sk.newWotsPubKey(priv.pubPRF, addrs, pk)
	}
	addrs.set(adrType, 1)
	addrs.set(adrLtree, s.leaf)
	nn := pk.ltree(priv.pubPRF, addrs)
	node := &NH{
		node:   make([]byte, 32),
		height: 0,
		index:  s.leaf,
	}
	copy(node.node, nn)
	s.push(node)
	s.leaf++
}

func (s *Stack) update(nn uint64, priv *PrivKey) {
	s.updateSub(nn, priv, func() {
		s.newleaf(priv, false)
	})
}

func (s *Stack) goUpdate(nn uint64, priv *PrivKey) {
	s.updateSub(nn, priv, func() {
		s.newleaf(priv, true)
	})
}

func (s *Stack) updateSub(nn uint64, priv *PrivKey, newleaf func()) {
	if len(s.stack) > 0 && (s.stack[len(s.stack)-1].height == s.height) {
		return
	}
	addrs := make(addr, 32)
	addrs.set(adrType, 2)
	addrs.set(adrLayer, s.layer)
	addrs.setTree(s.tree)
	for i := uint64(0); i < nn; i++ {
		if len(s.stack) >= 2 {
			right := s.top()
			left := s.nextTop()
			if left.height == right.height {
				node := &NH{
					node: make([]byte, 32),
				}
				node.index = right.index >> 1
				node.height = right.height + 1
				addrs.set(adrHeight, right.height)
				addrs.set(adrIndex, node.index)
				randHash(left.node, right.node, priv.pubPRF, addrs, node.node)
				s.delete(2)
				s.push(node)
				continue
			}
		}
		newleaf()
	}
}
func (s *Stack) top() *NH {
	return s.stack[len(s.stack)-1]
}
func (s *Stack) nextTop() *NH {
	return s.stack[len(s.stack)-2]
}
func (s *Stack) push(n *NH) {
	s.stack = append(s.stack, n)
}
func (s *Stack) delete(i int) {
	for j := 0; j < i; j++ {
		s.stack[len(s.stack)-1-j] = nil
	}
	s.stack = s.stack[:len(s.stack)-i]
}

//Merkle represents MerkleTree for XMSS.
type Merkle struct {
	//Leaf is the number of unused leaf.
	Leaf   uint32
	Height uint32
	stacks []*Stack
	auth   [][]byte
	priv   *PrivKey
	layer  uint32
	tree   uint64
}

//NewMerkle makes Merkle struct from height and private seed.
func NewMerkle(h byte, seed []byte) *Merkle {
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
	return newMerkle(uint32(h), wotsSeed, msgSeed, pubSeed, 0, 0)
}
func newMerkle(h uint32, wotsSeed, msgSeed, pubSeed []byte, layer uint32, tree uint64) *Merkle {
	m := &Merkle{
		Leaf:   0,
		Height: h,
		stacks: make([]*Stack, h),
		auth:   make([][]byte, h),
		priv: &PrivKey{
			wotsPRF: newPRF(wotsSeed),
			pubPRF:  newPRF(pubSeed),
			msgPRF:  newPRF(msgSeed),
			root:    make([]byte, 32),
		},
		layer: layer,
		tree:  tree,
	}

	var wg sync.WaitGroup
	ncpu := runtime.GOMAXPROCS(-1)
	nproc := uint32(math.Log2(float64(ncpu)))
	if ncpu != (1 << nproc) {
		nproc++
	}
	if h <= nproc {
		nproc = 0
	}
	ntop := make([]*NH, (1<<nproc)-1)
	for i := uint32(1); i < (1 << nproc); i++ {
		wg.Add(1)
		go func(i uint32) {
			s := Stack{
				stack:  make([]*NH, 0, (h-nproc)+1),
				height: h - nproc,
				leaf:   (1 << (h - nproc)) * i,
				layer:  m.layer,
				tree:   m.tree,
			}
			s.update(1<<(h-nproc+1)-1, m.priv)
			ntop[i-1] = s.top()
			wg.Done()
		}(i)
	}
	s := Stack{
		stack:  make([]*NH, 0, h+1),
		height: h,
		leaf:   0,
		layer:  m.layer,
		tree:   m.tree,
	}
	for i := uint32(0); i < h; i++ {
		if i == h-nproc {
			wg.Wait()
		}
		s.update(1, m.priv)
		m.stacks[i] = &Stack{
			stack:  make([]*NH, 0, i+1),
			height: i,
			leaf:   1 << i,
			layer:  m.layer,
			tree:   m.tree,
		}
		m.stacks[i].push(s.top())
		if i < h-nproc {
			s.update(1<<(i+1)-1, m.priv)
		} else {
			s.updateSub(1<<(i-(h-nproc)+1)-1, m.priv, func() {
				n := ntop[0]
				ntop = ntop[1:]
				s.push(n)
			})
		}
		m.auth[i] = make([]byte, 32)
		copy(m.auth[i], s.top().node)
	}
	s.update(1, m.priv)
	copy(m.priv.root, s.top().node)
	return m
}

type merkle struct {
	Leaf   uint32
	Height uint32
	Auth   [][]byte
	Priv   *PrivKey
	Stacks []*Stack
	Layer  uint32
	Tree   uint64
}

func (m *Merkle) exports() *merkle {
	return &merkle{
		Leaf:   m.Leaf,
		Height: m.Height,
		Auth:   m.auth,
		Priv:   m.priv,
		Stacks: m.stacks,
		Layer:  m.layer,
		Tree:   m.tree,
	}
}

func (m *Merkle) imports(s *merkle) {
	m.Leaf = s.Leaf
	m.Height = s.Height
	m.auth = s.Auth
	m.priv = s.Priv
	m.stacks = s.Stacks
	m.layer = s.Layer
	m.tree = s.Tree
}

//MarshalJSON  marshals Merkle into valid JSON.
func (m *Merkle) MarshalJSON() ([]byte, error) {
	return json.Marshal(m.exports())
}

//UnmarshalJSON  unmarshals JSON to Merkle.
func (m *Merkle) UnmarshalJSON(b []byte) error {
	var s merkle
	err := json.Unmarshal(b, &s)
	if err == nil {
		m.imports(&s)
	}
	return err
}

//EncodeMsgpack  marshals Merkle into valid JSON.
func (m *Merkle) EncodeMsgpack(enc *msgpack.Encoder) error {
	return enc.Encode(m.exports())
}

//DecodeMsgpack  unmarshals JSON to Merkle.
func (m *Merkle) DecodeMsgpack(dec *msgpack.Decoder) error {
	var s merkle
	err := dec.Decode(&s)
	if err == nil {
		m.imports(&s)
	}
	return err
}

//PublicKey returns public key (merkle root) of XMSS
func (m *Merkle) PublicKey() []byte {
	key := make([]byte, 1+n+n)
	key[0] = byte(m.Height)
	copy(key[1:], m.priv.root)
	copy(key[1+n:], m.priv.pubPRF.seed)
	return key
}

func (m *Merkle) refreshAuth() {
	var h uint32
	for h = 0; h < m.Height; h++ {
		var pow uint32 = 1 << h
		if (m.Leaf+1)&(pow-1) == 0 {
			m.auth[h] = m.stacks[h].top().node
			startnode := ((m.Leaf + 1) + pow) ^ pow
			m.stacks[h].initialize(startnode, h)
		}
	}
}
func (m *Merkle) build() {
	var i uint32
	for i = 0; i < ((2 * m.Height) - 1); i++ {
		var min uint32 = math.MaxUint32
		var h, focus uint32
		for h = 0; h < m.Height; h++ {
			low := m.stacks[h].low()
			if low < min {
				min = low
				focus = h
			}
		}
		m.stacks[focus].goUpdate(1, m.priv)
	}
}

//Traverse refreshes auth and stacks and increment leafe number.
func (m *Merkle) Traverse() {
	m.refreshAuth()
	m.build()
	m.Leaf++
}
