[![Build Status](https://travis-ci.org/AidosKuneen/xmss.svg?branch=master)](https://travis-ci.org/AidosKuneen/xmss)
[![GoDoc](https://godoc.org/github.com/AidosKuneen/xmss?status.svg)](https://godoc.org/github.com/AidosKuneen/xmss)
[![GitHub license](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/AidosKuneen/xmss/master/LICENSE)
[![Coverage Status](https://coveralls.io/repos/github/AidosKuneen/xmss/badge.svg?branch=master)](https://coveralls.io/github/AidosKuneen/xmss?branch=master)

XMSS (eXtended Merkle Signature Scheme)
=====

## Overview

This library is for creating keys, signing messages and verifing the signature by XMSS and XMSS^MT in Go.

This code implements `XMSS-SHA2_*_256` and `XMSSMT-SHA2_*/*_256`
 described on  [XMSS: eXtended Merkle Signature Scheme (RFC 8391)](https://datatracker.ietf.org/doc/rfc8391/).
 This code should be much faster than the [XMSS reference code](https://github.com/joostrijneveld/xmss-reference).
 by using [SSE extention](https://github.com/minio/sha256-simd) and block level optimizations in SHA256 with multi threadings.


## Requirements

* git
* go 1.9+

are required to compile.


## Install
    $ go get -u github.com/AidosKuneen/xmss


## Usage

```go
	import "github.com/AidosKuneen/xmss"
	import	"github.com/vmihailenco/msgpack"

	seed := []byte{0x01,0x02...}
	mer := xmss.NewMerkle(10, seed)
	msg := []byte("This is a test for XMSS.")
	sig := mer.Sign(msg)
	pub := mer.PublicKey()
	if !xmss.Verify(sig, msg, pub) {
		log.Println("signature is invalid")
	}
	//output Merkle contents to json
	dat, err := json.Marshal(mer)
	//convert json to Merkle
	var mer2 xmss.Merkle
	err = json.Unmarshal(dat, &mer2)

	//output Merkle contents to msgpack format
	mdat, err := msgpack.Marshal(mer)
	//convert msgapck bin to Merkle
	var mmer xmss.Merkle
	err = msgpack.Unmarshal(mdat, &mmer)

	mt, err := xmss.NewPrivKeyMT(seed, 40, 4)
	sig := mt.Sign(msg)
	if !VerifyMT(sig, msg, mt.PublicKey(), 40, 4) {
		...
	}

```

## Performance

Using the following test environment...

```
* Compiler: go version go1.10 linux/amd64
* Kernel: Linux WS777 4.13.5-1-ARCH #1 SMP PREEMPT Fri Oct 6 09:58:47 CEST 2017 x86_64 GNU/Linux
* CPU:  Celeron(R) CPU G1840 @ 2.80GHz 
* Memory: 8 GB
```


For XMSS-SHA2_10_256, it takes 

* about 760 mS to generating a keypair,
* about 6.3 mS to sign a message,
* about 490 uS to verify a signature.

For XMSS-SHA2_16_256, it takes 

* about 46 seconds to generating a keypair,
* about 7.3 mS to sign a message,
* about 500 uS to verify a signature.


For XMSS-SHA2_20_256, it takes 
about  14 minutes to generating a keypair,

```
BenchmarkXMSS10-2                      2         759714114 ns/op
BenchmarkXMSS10Sign-2                300           6281026 ns/op
BenchmarkXMSS10Veri-2               3000            487012 ns/op
enchmarkXMSS16-2                      1        45571294167 ns/op
BenchmarkXMSS16Sign-2                300           7299528 ns/op
BenchmarkXMSS16Veri-2               3000            504971 ns/op
BenchmarkXMSS20-2                      1        820250400243 ns/op
```

On DIGNO M KYL22(Android Smartphone):

```
* Compiler: go version go1.10 linux/arm
* OS: 	Android 4.2.2
* CPU:	Qualcomm Snapdragon 800 MSM8974 2.2GHz (quad core)
* Memory: 2 GB
```


For XMSS-SHA2_10_256, it takes 

* about 2.9 seconds to generating a keypair,
* about 34 mS to sign a message,
* about 4.5 mS to verify a signature.

```
BenchmarkXMSS10                1        2906321328 ns/op
BenchmarkXMSS10Sign          100          34440405 ns/op
BenchmarkXMSS10Veri          300           4496049 ns/op
```

On a cloud server:

```
* Compiler: go version go1.8.1 linux/amd64
* Kernel: Linux 4.8.0-58-generic #63~16.04.1-Ubuntu SMP Mon Jun 26 18:08:51 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
* CPU:  CAMD Ryzen 7 1700X Eight-Core Processor @ 2.20GHz (16 cores)
* Memory: 64 GB
```

For XMSS-SHA2_10_256, it takes 

* about 190 mS to generating a keypair,
* about 4.9 mS to sign a message,
* about 410 uS to verify a signature.

For XMSS-SHA2_16_256, it takes 

* about  9.0 seconds to generating a keypair,
* about  5.3 mS to sign a message,
* about  420 uS to verify a signature.


For XMSS-SHA2_20_256, it takes 
about  3.1 minutes to generating a keypair,


```
BenchmarkXMSS10-16        	      10	 180479693 ns/op
BenchmarkXMSS10Sign-16    	     300	   4939994 ns/op
BenchmarkXMSS10Veri-16    	    5000	    411160 ns/op
BenchmarkXMSS16-16        	       1	9032432802 ns/op
BenchmarkXMSS16Sign-16    	     300	   5364563 ns/op
BenchmarkXMSS16Veri-16    	    3000	    419544 ns/op
BenchmarkXMSS20-16        	       1  187203367087 ns/op
```

## Dependencies and Licenses

This software includes the work that is distributed in the Apache License 2.0.

```
github.com/AidosKuneen/xmss           MIT License 
github.com/AidosKuneen/sha256-simd    Apache License 2.0
github.com/vmihailenco/msgpack/codes  BSD 2-clause "Simplified" License
Golang Standard Library               BSD 3-clause License
```