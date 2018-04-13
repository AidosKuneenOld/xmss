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
	"encoding/json"
	"runtime"
	"testing"

	"github.com/AidosKuneen/numcpu"
	"github.com/vmihailenco/msgpack"
)

func TestXMSS2(t *testing.T) {
	n := numcpu.NumCPU()
	npref := runtime.GOMAXPROCS(n)
	seed := generateSeed()
	mer := NewMerkle(10, seed)
	msg := []byte("This is a test for XMSS.")
	var pre []byte
	for i := 0; i < 1<<10; i++ {
		sig := mer.Sign(msg)
		if !Verify(sig, msg, mer.PublicKey()) {
			t.Error("XMSS sig is incorrect")
		}
		if pre != nil && bytes.Equal(pre, sig) {
			t.Error("sig must not be same")
		}
		pre = sig
	}
	runtime.GOMAXPROCS(npref)
}

func TestXMSS3(t *testing.T) {
	n := numcpu.NumCPU()
	npref := runtime.GOMAXPROCS(n)
	seed := generateSeed()
	mer := NewMerkle(10, seed)
	msg := []byte("This is a test for XMSS.")
	sig := mer.Sign(msg)
	msg[0] = 0
	if Verify(sig, msg, mer.PublicKey()) {
		t.Error("XMSS sig is incorrect")
	}
	runtime.GOMAXPROCS(npref)
}
func TestXMSS4(t *testing.T) {
	n := numcpu.NumCPU()
	npref := runtime.GOMAXPROCS(n)
	seed := generateSeed()
	mer := NewMerkle(2, seed)
	msg := []byte("This is a test for XMSS.")
	sig := mer.Sign(msg)
	if !Verify(sig, msg, mer.PublicKey()) {
		t.Error("XMSS sig is incorrect")
	}
	msg[0] = 0
	if Verify(sig, msg, mer.PublicKey()) {
		t.Error("XMSS sig is incorrect")
	}
	runtime.GOMAXPROCS(npref)
}
func TestXMSS16(t *testing.T) {
	n := numcpu.NumCPU()
	npref := runtime.GOMAXPROCS(n)
	seed := generateSeed()
	mer := NewMerkle(16, seed)
	msg := []byte("This is a test for XMSS height=16.")
	sig := mer.Sign(msg)
	if !Verify(sig, msg, mer.PublicKey()) {
		t.Error("XMSS sig is incorrect")
	}
	runtime.GOMAXPROCS(npref)
}

func TestXMSSMarshal(t *testing.T) {
	n := numcpu.NumCPU()
	npref := runtime.GOMAXPROCS(n)
	seed := generateSeed()
	mer := NewMerkle(10, seed)
	msg := []byte("This is a test for XMSS height=16.")
	dat, err := json.Marshal(mer)
	if err != nil {
		t.Error(err)
	}
	t.Log("marshalled Merkle", string(dat))
	t.Log("len of marshalled Merkle", len(dat))
	mer2 := Merkle{}
	if err = json.Unmarshal(dat, &mer2); err != nil {
		t.Error(err)
	}
	sig := mer.Sign(msg)
	sig2 := mer2.Sign(msg)
	if !bytes.Equal(sig, sig2) {
		t.Error("invlaid json marshal")
	}

	mdat, err := msgpack.Marshal(mer)
	if err != nil {
		t.Error(err)
	}
	t.Log("marshalled Merkle", len(mdat))
	mmer := Merkle{}
	if err = msgpack.Unmarshal(mdat, &mmer); err != nil {
		t.Error(err)
	}
	sig = mer.Sign(msg)
	msig := mmer.Sign(msg)
	if !bytes.Equal(sig, msig) {
		t.Error("invlaid msgpack marshal")
	}

	var buf bytes.Buffer
	enc := msgpack.NewEncoder(&buf).StructAsArray(true)
	if err = enc.Encode(mer); err != nil {
		t.Fatal(err)
	}
	t.Log("marshalled Merkle", buf.Len())
	dec := msgpack.NewDecoder(&buf)
	mmer2 := Merkle{}
	if err := dec.Decode(&mmer2); err != nil {
		t.Fatal(err)
	}
	sig = mer.Sign(msg)
	msig2 := mmer2.Sign(msg)
	if !bytes.Equal(sig, msig2) {
		t.Error("invlaid msgpack marshal")
	}

	runtime.GOMAXPROCS(npref)
}

func BenchmarkXMSS16(b *testing.B) {
	n := numcpu.NumCPU()
	npref := runtime.GOMAXPROCS(n)
	seed := generateSeed()
	b.ResetTimer()
	_ = NewMerkle(16, seed)
	runtime.GOMAXPROCS(npref)
}
func BenchmarkXMSS16Sign(b *testing.B) {
	n := numcpu.NumCPU()
	npref := runtime.GOMAXPROCS(n)
	seed := generateSeed()
	mer := NewMerkle(16, seed)
	msg := []byte("This is a test for XMSS.")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = mer.Sign(msg)
	}
	runtime.GOMAXPROCS(npref)
}
func BenchmarkXMSS16Veri(b *testing.B) {
	n := numcpu.NumCPU()
	npref := runtime.GOMAXPROCS(n)
	seed := generateSeed()
	mer := NewMerkle(16, seed)
	msg := []byte("This is a test for XMSS.")
	sig := mer.Sign(msg)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Verify(sig, msg, mer.PublicKey())
	}
	runtime.GOMAXPROCS(npref)
}

func BenchmarkXMSS20(b *testing.B) {
	n := numcpu.NumCPU()
	npref := runtime.GOMAXPROCS(n)
	seed := generateSeed()
	b.ResetTimer()
	_ = NewMerkle(20, seed)
	runtime.GOMAXPROCS(npref)
}

func BenchmarkXMSS10(b *testing.B) {
	n := numcpu.NumCPU()
	npref := runtime.GOMAXPROCS(n)
	seed := generateSeed()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewMerkle(10, seed)
	}
	runtime.GOMAXPROCS(npref)
}
func BenchmarkXMSS10Sign(b *testing.B) {
	n := numcpu.NumCPU()
	npref := runtime.GOMAXPROCS(n)
	seed := generateSeed()
	mer := NewMerkle(10, seed)
	msg := []byte("This is a test for XMSS.")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = mer.Sign(msg)
	}
	runtime.GOMAXPROCS(npref)
}
func BenchmarkXMSS10Veri(b *testing.B) {
	n := numcpu.NumCPU()
	npref := runtime.GOMAXPROCS(n)
	seed := generateSeed()
	mer := NewMerkle(10, seed)
	msg := []byte("This is a test for XMSS.")
	sig := mer.Sign(msg)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Verify(sig, msg, mer.PublicKey())
	}
	runtime.GOMAXPROCS(npref)
}
