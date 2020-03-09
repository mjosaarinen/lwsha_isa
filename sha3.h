//	sha3.h
//	2020-03-02	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2020, PQShield Ltd. All rights reserved.

//	FIPS 202: SHA-3 hash and SHAKE eXtensible Output Functions (XOF)

#ifndef _SHA3_H_
#define _SHA3_H_

#include <stddef.h>
#include <stdint.h>

//	state context

typedef struct {
	union {									//	aligned:
		uint8_t b[200];						//	8-bit bytes
		uint64_t q[25];						//	64-bit words
	} st;
	int pt, rsiz, mdlen;					//	(don't overflow)
} sha3_ctx_t;

//	function pointer to the permutation
extern void (*sha3_keccakp)(void *);

//	which can be set to point to an external function. default is
void ref_keccakp(void *);					//	sha3.c ("reference")

//	compute a SHA-3 hash "md" of "mdlen" bytes from data in "in"
void *sha3(void *md, int mdlen, const void *in, size_t inlen);

//	OpenSSL - like interfece
int sha3_init(sha3_ctx_t *c, int mdlen);	//	mdlen = hash output in bytes
int sha3_update(sha3_ctx_t *c, const void *data, size_t len);
int sha3_final(void *md, sha3_ctx_t *c);	//	digest goes to md

//	SHAKE128 and SHAKE256 extensible-output functions
#define shake128_init(c) sha3_init(c, 16)
#define shake256_init(c) sha3_init(c, 32)
#define shake_update sha3_update

//	add padding (call once after calls to shake_update() are done
void shake_xof(sha3_ctx_t *c);

//	squeeze output
void shake_out(sha3_ctx_t *c, void *out, size_t len);

#endif

