//	sha2.h
//	2020-03-09	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2020, PQShield Ltd. All rights reserved.

//	FIPS 180-4 SHA-2 testing interface

#ifndef _SHA2_H_
#define _SHA2_H_

#include <stddef.h>
#include <stdint.h>

//	SHA-224: Compute 28-byte hash to "md" from "in" which has "inlen" bytes.
void sha2_224(uint8_t *md, const void *in, size_t inlen);

//	SHA-256: Compute 32-byte hash to "md" from "in" which has "inlen" bytes.
void sha2_256(uint8_t *md, const void *in, size_t inlen);

//	function pointer to the compression function
extern void (*sha256_compress)(uint32_t *, uint32_t *);

//	compression function implementation (rv32_sha256.c)
void rv32_sha256_compress(uint32_t *s, uint32_t *m);

#endif
