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
	"encoding/json"
	"math"
	"runtime"
	"sync"
)

//NH represents a node in a merkle tree.
type NH struct {
	node   []byte
	height uint32
	index  uint32
}

//MarshalJSON  marshals NH into valid JSON.
func (nn *NH) MarshalJSON() ([]byte, error) {
	sr := struct {
		Node   []byte
		Height uint32
		Index  uint32
	}{
		Node:   nn.node,
		Height: nn.height,
		Index:  nn.index,
	}
	return json.Marshal(&sr)
}

//UnmarshalJSON  unmarshals NH to PrivKey.
func (nn *NH) UnmarshalJSON(b []byte) error {
	sr := struct {
		Node   []byte
		Height uint32
		Index  uint32
	}{}
	err := json.Unmarshal(b, &sr)
	nn.node = sr.Node
	nn.height = sr.Height
	nn.index = sr.Index
	return err
}

//Stack is a stack to use in merkle traversing.
type Stack struct {
	stack  []*NH
	height uint32
	leaf   uint32
}

//MarshalJSON  marshals Stack into valid JSON.
func (s *Stack) MarshalJSON() ([]byte, error) {
	sr := struct {
		Stack  []*NH
		Height uint32
		Leaf   uint32
	}{
		Stack:  s.stack,
		Height: s.height,
		Leaf:   s.leaf,
	}
	return json.Marshal(&sr)
}

//UnmarshalJSON  unmarshals Stack to PrivKey.
func (s *Stack) UnmarshalJSON(b []byte) error {
	sr := struct {
		Stack  []*NH
		Height uint32
		Leaf   uint32
	}{}
	err := json.Unmarshal(b, &sr)
	s.stack = sr.Stack
	s.height = sr.Height
	s.leaf = sr.Leaf
	return err
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

var skpool = sync.Pool{
	New: func() interface{} {
		sk := make(wotsPrivKey, wlen)
		for j := 0; j < wlen; j++ {
			sk[j] = make([]byte, n)
		}
		return sk
	},
}

var pkpool = sync.Pool{
	New: func() interface{} {
		pk := make(wotsPubKey, wlen)
		for j := 0; j < wlen; j++ {
			pk[j] = make([]byte, n)
		}
		return pk
	},
}

func (s *Stack) newleaf(priv *PrivKey, isGo bool) {
	sk := skpool.Get().(wotsPrivKey)
	pk := pkpool.Get().(wotsPubKey)
	addrs := make(addr, 32)

	// addrs.set(adrType, 0)
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
	skpool.Put(sk)
	pkpool.Put(pk)
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
}

//NewMerkle makes Merkle struct from height and private seed.
func NewMerkle(h uint32, seed []byte) *Merkle {
	p := newPRF(seed)
	wotsSeed := make([]byte, 32)
	msgSeed := make([]byte, 32)
	pubSeed := make([]byte, 32)
	p.sumInt(1, wotsSeed)
	p.sumInt(2, msgSeed)
	p.sumInt(3, pubSeed)
	return newMerkle(h, wotsSeed, msgSeed, pubSeed)
}
func newMerkle(h uint32, wotsSeed, msgSeed, pubSeed []byte) *Merkle {
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
	}

	var wg sync.WaitGroup
	ncpu := runtime.NumCPU()
	nproc := uint32(math.Log2(float64(ncpu)))
	if ncpu != (1 << nproc) {
		nproc++
	}
	ntop := make([]*NH, (1<<nproc)-1)
	for i := uint32(1); i < (1 << nproc); i++ {
		wg.Add(1)
		go func(i uint32) {
			s := Stack{
				stack:  make([]*NH, 0, (h-nproc)+1),
				height: h - nproc,
				leaf:   (1 << (h - nproc)) * i,
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

//MarshalJSON  marshals Merkle into valid JSON.
func (m *Merkle) MarshalJSON() ([]byte, error) {
	s := struct {
		Leaf   uint32
		Height uint32
		Auth   [][]byte
		Priv   *PrivKey
		Stacks []*Stack
	}{
		Leaf:   m.Leaf,
		Height: m.Height,
		Auth:   m.auth,
		Priv:   m.priv,
		Stacks: m.stacks,
	}

	return json.Marshal(&s)
}

//UnmarshalJSON  unmarshals JSON to PrivKey.
func (m *Merkle) UnmarshalJSON(b []byte) error {
	s := struct {
		Leaf   uint32
		Height uint32
		Auth   [][]byte
		Priv   *PrivKey
		Stacks []*Stack
	}{}
	err := json.Unmarshal(b, &s)
	if err != nil {
		return err
	}
	m.Leaf = s.Leaf
	m.Height = s.Height
	m.auth = s.Auth
	m.priv = s.Priv
	m.stacks = s.Stacks
	return nil
}

//PublicKey returns public key (merkle root) of XMSS
func (m *Merkle) PublicKey() []byte {
	return m.priv.root
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
