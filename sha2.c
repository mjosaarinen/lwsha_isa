//	sha2.c
//	2020-03-10	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2020, PQShield Ltd. All rights reserved.

//	FIPS 180-4 SHA-2
//	Hash padding mode code for testing compression function implementations.

#include <string.h>
#include "sha2.h"

//	pointer to the compression function

void (*sha256_compress)(uint32_t *s, uint32_t *) = &rv32_sha256_compress;

//	Compute 32-byte message digest to "md" from "in" which has "inlen" bytes

void sha256(uint8_t *md, const void *in, size_t inlen)
{
	size_t i;
	uint64_t x;
	uint32_t t, s[8];
	const uint8_t *p = in;

	union {									//	aligned:
		uint8_t b[64];						//	8-bit bytes
		uint32_t w[16];						//	32-bit words
	} m;

	//	SHA-256 initial value, Sect 5.3.3.
	s[0] = 0x6A09E667;	s[1] = 0xBB67AE85;
	s[2] = 0x3C6EF372;	s[3] = 0xA54FF53A,
	s[4] = 0x510E527F;	s[5] = 0x9B05688C;
	s[6] = 0x1F83D9AB;	s[7] = 0x5BE0CD19;

	//	"md padding"
	x = inlen << 3;							//	length in bits

	while (inlen >= 64) {					//	full blocks
		memcpy(m.b, p, 64);
		sha256_compress(s, m.w);
		inlen -= 64;
		p += 64;
	}
	memcpy(m.b, p, inlen);					//	last data block
	m.b[inlen++] = 0x80;
	if (inlen > 56) {
		memset(&m.b[inlen], 0x00, 64 - inlen);
		sha256_compress(s, m.w);
		inlen = 0;
	}
	i = 64;									//	process length
	while (x > 0) {
		m.b[--i] = x & 0xFF;
		x >>= 8;
	}
	memset(&m.b[inlen], 0x00, i - inlen);
	sha256_compress(s, m.w);

	//	store big endian output
	for (i = 0; i < 32; i += 4) {
		t = s[i >> 2];
		md[i] = t >> 24;
		md[i + 1] = (t >> 16) & 0xFF;
		md[i + 2] = (t >> 8) & 0xFF;
		md[i + 3] = t & 0xFF;
	}
}



