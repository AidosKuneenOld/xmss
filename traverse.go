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
	"math"
)

type nh struct {
	node   []byte
	height uint32
	index  uint32
}

type stack struct {
	stack  []*nh
	height uint32
	leaf   uint32
}

func (s *stack) low() uint32 {
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

func (s *stack) initialize(start uint32, height uint32) {
	s.leaf = start
	s.height = height
	s.stack = s.stack[:0]
}

func (s *stack) newleaf(priv *xmssPrivKey) {
	sk := make(wotsPrivKey, wlen)
	pk := make(wotsPubKey, wlen)
	for j := 0; j < wlen; j++ {
		sk[j] = make([]byte, n)
		pk[j] = make([]byte, n)
	}
	addrs := make(addr, 32)

	// addrs.set(adrType, 0)
	addrs.set(adrOTS, s.leaf)
	priv.newWotsPrivKey(addrs, sk)
	sk.newWotsPubKey(priv.pubPRF, addrs, pk)
	addrs.set(adrType, 1)
	addrs.set(adrLtree, s.leaf)
	node := &nh{
		node:   pk.ltree(priv.pubPRF, addrs),
		height: 0,
		index:  s.leaf,
	}
	s.push(node)
	s.leaf++
}
func (s *stack) update(nn uint64, priv *xmssPrivKey) {
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
				node := &nh{
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
		s.newleaf(priv)
	}
}
func (s *stack) top() *nh {
	return s.stack[len(s.stack)-1]
}
func (s *stack) nextTop() *nh {
	return s.stack[len(s.stack)-2]
}
func (s *stack) push(n *nh) {
	s.stack = append(s.stack, n)
}
func (s *stack) delete(i int) {
	for j := 0; j < i; j++ {
		s.stack[len(s.stack)-1-j] = nil
	}
	s.stack = s.stack[:len(s.stack)-i]
}

//Merkle represents MerkleTree for XMSS.
type Merkle struct {
	leaf   uint32
	height uint32
	stacks []*stack
	auth   [][]byte
	priv   *xmssPrivKey
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
		leaf:   0,
		height: h,
		stacks: make([]*stack, h),
		auth:   make([][]byte, h),
		priv: &xmssPrivKey{
			wotsPRF: newPRF(wotsSeed),
			pubPRF:  newPRF(pubSeed),
			msgPRF:  newPRF(msgSeed),
			root:    make([]byte, 32),
		},
	}

	s := stack{
		stack:  make([]*nh, 0, h+1),
		height: h,
		leaf:   0,
	}
	for i := uint32(0); i < h; i++ {
		s.update(1, m.priv)
		m.stacks[i] = &stack{
			height: i,
			leaf:   1 << i,
		}
		m.stacks[i].stack = make([]*nh, 0, i+1)
		m.stacks[i].push(s.top())
		s.update(1<<(i+1)-1, m.priv)
		m.auth[i] = make([]byte, 32)
		copy(m.auth[i], s.top().node)
	}
	s.update(1, m.priv)
	copy(m.priv.root, s.top().node)
	return m
}

func (m *Merkle) refreshAuth() {
	var h uint32
	for h = 0; h < m.height; h++ {
		var pow uint32 = 1 << h
		if (m.leaf+1)&(pow-1) == 0 {
			m.auth[h] = m.stacks[h].top().node
			startnode := ((m.leaf + 1) + pow) ^ pow
			m.stacks[h].initialize(startnode, h)
		}
	}
}
func (m *Merkle) build() {
	var i uint32
	for i = 0; i < ((2 * m.height) - 1); i++ {
		var min uint32 = math.MaxUint32
		var h, focus uint32
		for h = 0; h < m.height; h++ {
			low := m.stacks[h].low()
			if low < min {
				min = low
				focus = h
			}
		}
		m.stacks[focus].update(1, m.priv)
	}
}
func (m *Merkle) traverse() {
	m.refreshAuth()
	m.build()
	m.leaf++
}
