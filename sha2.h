//  sha2.h
//  2020-03-09  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  FIPS 180-4 SHA-2 testing interface

#ifndef _SHA2_H_
#define _SHA2_H_

#include <stddef.h>
#include <stdint.h>

//  SHA2-224: Compute 28-byte hash to "md" from "in" which has "inlen" bytes.
void sha2_224(uint8_t * md, const void *in, size_t inlen);

//  SHA2-256: Compute 32-byte hash to "md" from "in" which has "inlen" bytes.
void sha2_256(uint8_t * md, const void *in, size_t inlen);

//  SHA2-384: Compute 48-byte hash to "md" from "in" which has "inlen" bytes.
void sha2_384(uint8_t * md, const void *in, size_t inlen);

//  SHA2-512: Compute 64-byte hash to "md" from "in" which has "inlen" bytes.
void sha2_512(uint8_t * md, const void *in, size_t inlen);


//  function pointer to the compression function used by the test wrappers
extern void (*sha256_compress)(void *);
extern void (*sha512_compress)(void *);

//  SHA-256 compression function for RV32 (rv32_sha256.c)
void rv32_sha256_compress(void *s);

//  SHA-512 compression function for RV64 (rv64_sha512.c)
void rv64_sha512_compress(void *s);

//  SHA-512 compression function for RV32 (rv32_sha512.c)
void rv32_sha512_compress(void *s);

#endif
