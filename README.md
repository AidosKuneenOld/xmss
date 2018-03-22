[![Build Status](https://travis-ci.org/AidosKuneen/xmss.svg?branch=master)](https://travis-ci.org/AidosKuneen/xmss)
[![GoDoc](https://godoc.org/github.com/AidosKuneen/xmss?status.svg)](https://godoc.org/github.com/AidosKuneen/xmss)
[![GitHub license](https://img.shields.io/badge/license-MIT-blue.svg)](https://raw.githubusercontent.com/AidosKuneen/xmss/master/LICENSE)


XMSS (eXtended Merkle Signature Scheme)
=====

## Overview

This library is for creating keys, signing messages and verifing the signature by XMSS in golang.

This code implements XMSS-SHA2_10_256, 
XMSS-SHA2_16_256, XMSS-SHA2_20_256 described on IRTF draft [XMSS: Extended Hash-Based Signatures](https://datatracker.ietf.org/doc/draft-irtf-cfrg-xmss-hash-based-signatures/) and 
compatible with [XMSS reference code](https://github.com/joostrijneveld/xmss-reference).
But this code is much faster than the reference code by using [SSE extention](https://github.com/minio/sha256-simd) and block level optimizations in sha256,
with multi threadings.


## Requirements

* git
* go 1.9+

are required to compile.


## Install
    $ go get -u github.com/AidosKuneen/xmss


## Usage

```go
	import "github.com/AidosKuneen/xmss"
	seed := []byte{0x01,0x02...}
	mer := xmss.NewMerkle(10, seed)
	msg := []byte("This is a test for XMSS.")
	sig := mer.Sign(msg)
	pub := mer.PublicKey()
	if !xmss.Verify(sig, msg, pub) {
		log.Println("signature is invalid")
	}
	//output Merkle contents to json
	dat, err := mer.MarshalJSON()
	//convert json to Merkle
	mer2 := xmss.Merkle{}
    err := mer2.UnmarshalJSON(dat)
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

* about 760 seconds to generating a keypair,
* about 6.3 mS to sign a message,
* about 490 uS to verify a signature.

For XMSS-SHA2_16_256, it takes 

* about 50 seconds to generating a keypair,
* about 8.3 mS to sign a message,
* about 520 uS to verify a signature.


For XMSS-SHA2_20_256, it takes 
about  14 minutes to generating a keypair,

```
BenchmarkXMSS10-2                      2         759714114 ns/op
BenchmarkXMSS10Sign-2                300           6281026 ns/op
BenchmarkXMSS10Veri-2               3000            487012 ns/op
BenchmarkXMSS16-2                      1        49811815344 ns/op
BenchmarkXMSS16Sign-2                200           8270566 ns/op
BenchmarkXMSS16Veri-2               2000            518886 ns/op
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
