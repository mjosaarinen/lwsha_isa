//  sha2.c
//  2020-03-10  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  FIPS 180-4 SHA-2 hash padding mode code for testing compression function
//  implementations. This generic wrap part is not optimized for performance.

#include <string.h>
#include "sha2.h"

//  pointers to the compression functions

void (*sha256_compress)(void *s, void *) = &rv32_sha256_compress;
void (*sha512_compress)(void *s, void *) = &rv64_sha512_compress;


//  shared part between SHA-224 and SHA-256

static void sha256pad(uint32_t s[8], const void *in, size_t inlen)
{
	union {									//  aligned:
		uint8_t b[64];						//  8-bit bytes
		uint32_t w[16];						//  32-bit words
	} m;
	size_t i;
	uint64_t x;

	const uint8_t *p = in;

	//  "md padding"
	x = inlen << 3;							//  length in bits

	while (inlen >= 64) {					//  full blocks
		memcpy(m.b, p, 64);
		sha256_compress(s, m.w);
		inlen -= 64;
		p += 64;
	}
	memcpy(m.b, p, inlen);					//  last data block
	m.b[inlen++] = 0x80;
	if (inlen > 56) {
		memset(&m.b[inlen], 0x00, 64 - inlen);
		sha256_compress(s, m.w);
		inlen = 0;
	}
	i = 64;									//  process length
	while (x > 0) {
		m.b[--i] = x & 0xFF;
		x >>= 8;
	}
	memset(&m.b[inlen], 0x00, i - inlen);
	sha256_compress(s, m.w);
}

//  Compute 28-byte message digest to "md" from "in" which has "inlen" bytes

void sha2_224(uint8_t * md, const void *in, size_t inlen)
{
	size_t i;
	uint32_t t, s[8];

	//  SHA-224 initial values H0, Sect 5.3.2.
	s[0] = 0xC1059ED8;
	s[1] = 0x367CD507;
	s[2] = 0x3070DD17;
	s[3] = 0xF70E5939;
	s[4] = 0xFFC00B31;
	s[5] = 0x68581511;
	s[6] = 0x64F98FA7;
	s[7] = 0xBEFA4FA4;

	sha256pad(s, in, inlen);

	//  store big endian output
	for (i = 0; i < 28; i += 4) {
		t = s[i >> 2];
		md[i] = t >> 24;
		md[i + 1] = (t >> 16) & 0xFF;
		md[i + 2] = (t >> 8) & 0xFF;
		md[i + 3] = t & 0xFF;
	}
}

//  Compute 32-byte message digest to "md" from "in" which has "inlen" bytes

void sha2_256(uint8_t * md, const void *in, size_t inlen)
{
	size_t i;
	uint32_t t, s[8];

	//  SHA-256 initial values H0, Sect 5.3.3.
	s[0] = 0x6A09E667;
	s[1] = 0xBB67AE85;
	s[2] = 0x3C6EF372;
	s[3] = 0xA54FF53A, s[4] = 0x510E527F;
	s[5] = 0x9B05688C;
	s[6] = 0x1F83D9AB;
	s[7] = 0x5BE0CD19;

	sha256pad(s, in, inlen);

	//  store big endian output
	for (i = 0; i < 32; i += 4) {
		t = s[i >> 2];
		md[i] = t >> 24;
		md[i + 1] = (t >> 16) & 0xFF;
		md[i + 2] = (t >> 8) & 0xFF;
		md[i + 3] = t & 0xFF;
	}
}

//  shared part between SHA-384 and SHA-512

static void sha512pad(uint64_t s[8], const void *in, size_t inlen)
{
	union {									//  aligned:
		uint8_t b[128];						//  8-bit bytes
		uint64_t d[16];						//  64-bit words
	} m;

	size_t i;
	uint64_t x;

	const uint8_t *p = in;

	//  "md padding"
	x = inlen << 3;							//  length in bits

	while (inlen >= 128) {					//  full blocks
		memcpy(m.b, p, 128);
		sha512_compress(s, m.d);
		inlen -= 128;
		p += 128;
	}
	memcpy(m.b, p, inlen);					//  last data block
	m.b[inlen++] = 0x80;
	if (inlen > 112) {
		memset(&m.b[inlen], 0x00, 128 - inlen);
		sha512_compress(s, m.d);
		inlen = 0;
	}
	i = 128;								//  process length
	while (x > 0) {
		m.b[--i] = x & 0xFF;
		x >>= 8;
	}
	memset(&m.b[inlen], 0x00, i - inlen);
	sha512_compress(s, m.d);
}

//  Compute 48-byte message digest to "md" from "in" which has "inlen" bytes

void sha2_384(uint8_t * md, const void *in, size_t inlen)
{
	size_t i;
	uint64_t t, s[8];

	//  SHA-384 initial values H0, Sect 5.3.4.

	s[0] = 0xCBBB9D5DC1059ED8LL;
	s[1] = 0x629A292A367CD507LL;
	s[2] = 0x9159015A3070DD17LL;
	s[3] = 0x152FECD8F70E5939LL;
	s[4] = 0x67332667FFC00B31LL;
	s[5] = 0x8EB44A8768581511LL;
	s[6] = 0xDB0C2E0D64F98FA7LL;
	s[7] = 0x47B5481DBEFA4FA4LL;

	sha512pad(s, in, inlen);

	//  store big endian output
	for (i = 0; i < 48; i += 8) {
		t = s[i >> 3];
		md[i] = t >> 56;
		md[i + 1] = (t >> 48) & 0xFF;
		md[i + 2] = (t >> 40) & 0xFF;
		md[i + 3] = (t >> 32) & 0xFF;
		md[i + 4] = (t >> 24) & 0xFF;
		md[i + 5] = (t >> 16) & 0xFF;
		md[i + 6] = (t >> 8) & 0xFF;
		md[i + 7] = t & 0xFF;
	}
}

//  Compute 64-byte message digest to "md" from "in" which has "inlen" bytes

void sha2_512(uint8_t * md, const void *in, size_t inlen)
{
	size_t i;
	uint64_t t, s[8];

	//  SHA-512 initial values H0, Sect 5.3.5.

	s[0] = 0x6A09E667F3BCC908LL;
	s[1] = 0xBB67AE8584CAA73BLL;
	s[2] = 0x3C6EF372FE94F82BLL;
	s[3] = 0xA54FF53A5F1D36F1LL;
	s[4] = 0x510E527FADE682D1LL;
	s[5] = 0x9B05688C2B3E6C1FLL;
	s[6] = 0x1F83D9ABFB41BD6BLL;
	s[7] = 0x5BE0CD19137E2179LL;

	sha512pad(s, in, inlen);

	//  store big endian output
	for (i = 0; i < 64; i += 8) {
		t = s[i >> 3];
		md[i] = t >> 56;
		md[i + 1] = (t >> 48) & 0xFF;
		md[i + 2] = (t >> 40) & 0xFF;
		md[i + 3] = (t >> 32) & 0xFF;
		md[i + 4] = (t >> 24) & 0xFF;
		md[i + 5] = (t >> 16) & 0xFF;
		md[i + 6] = (t >> 8) & 0xFF;
		md[i + 7] = t & 0xFF;
	}
}
