//  sha2_wrap.c
//  2020-03-10  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  FIPS 180-4 SHA-2 hash padding mode code for testing compression function
//  implementations. This generic wrap part is not optimized for performance.

#include <string.h>
#include "sha2_wrap.h"
#include "rv_endian.h"

//  pointers to the compression functions

void (*sha256_compress)(void *s) = &rv32_sha256_compress;
void (*sha512_compress)(void *s) = &rv64_sha512_compress;

//  shared part between SHA-224 and SHA-256

static void sha256pad(uint32_t * s,
					  const uint8_t * k, size_t klen, uint8_t pad,
					  const void *in, size_t inlen)
{
	size_t i;
	uint64_t x;
	uint8_t *mp = (uint8_t *) & s[8];
	const uint8_t *ip = in;

	x = inlen << 3;							//  length in bits

	if (k != NULL) {						//  key block for HMAC
		x += 512;
		for (i = 0; i < klen; i++)
			mp[i] = k[i] ^ pad;
		memset(mp + klen, pad, 64 - klen);
		sha256_compress(s);
	}

	while (inlen >= 64) {					//  full blocks
		memcpy(mp, ip, 64);
		sha256_compress(s);
		inlen -= 64;
		ip += 64;
	}
	memcpy(mp, ip, inlen);					//  last data block
	mp[inlen++] = 0x80;
	if (inlen > 56) {
		memset(mp + inlen, 0x00, 64 - inlen);
		sha256_compress(s);
		inlen = 0;
	}

	i = 64;									//  process length
	while (x > 0) {
		mp[--i] = x & 0xFF;
		x >>= 8;
	}
	memset(mp + inlen, 0x00, i - inlen);
	sha256_compress(s);
}

//  SHA-224 initial values H0, Sect 5.3.2.

static const uint32_t sha2_224_h0[8] = {
	0xC1059ED8, 0x367CD507, 0x3070DD17, 0xF70E5939,
	0xFFC00B31, 0x68581511, 0x64F98FA7, 0xBEFA4FA4
};

//  Compute 28-byte message digest to "md" from "in" which has "inlen" bytes

void sha2_224(uint8_t * md, const void *in, size_t inlen)
{
	int i;
	uint32_t s[8 + 24];

	for (i = 0; i < 8; i++)					//  set H0 (IV)
		s[i] = sha2_224_h0[i];

	sha256pad(s, NULL, 0, 0x00, in, inlen);

	for (i = 0; i < 7; i++)					//  store big endian output
		be_put32(&md[i << 2], s[i]);

}

void hmac_sha2_224(uint8_t * mac, const void *k, size_t klen,
				   const void *in, size_t inlen)
{
	int i;
	uint32_t s[8 + 16];
	uint8_t t[28], k0[28];

	if (klen > 64) {						//  hash the key if needed
		sha2_224(k0, k, klen);
		k = k0;
		klen = 28;
	}

	for (i = 0; i < 8; i++)					//  set H0 (IV)
		s[i] = sha2_224_h0[i];

	sha256pad(s, k, klen, 0x36, in, inlen);

	for (i = 0; i < 7; i++)					//  get temporary, reinit
		be_put32(&t[i << 2], s[i]);
	for (i = 0; i < 8; i++)
		s[i] = sha2_224_h0[i];				//  set H0 (IV)

	sha256pad(s, k, klen, 0x5c, t, 28);

	for (i = 0; i < 7; i++)					//  store big endian output
		be_put32(&mac[i << 2], s[i]);
}

//  SHA-256 initial values H0, Sect 5.3.3.

static const uint32_t sha2_256_h0[8] = {
	0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
	0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

//  Compute 32-byte message digest to "md" from "in" which has "inlen" bytes

void sha2_256(uint8_t * md, const void *in, size_t inlen)
{
	int i;
	uint32_t s[8 + 16];

	for (i = 0; i < 8; i++)					//  set H0 (IV)
		s[i] = sha2_256_h0[i];

	sha256pad(s, NULL, 0, 0x00, in, inlen);

	for (i = 0; i < 8; i++)					//  store big endian output
		be_put32(&md[i << 2], s[i]);
}

void hmac_sha2_256(uint8_t * mac, const void *k, size_t klen,
				   const void *in, size_t inlen)
{
	int i;
	uint32_t s[8 + 16];
	uint8_t t[32], k0[32];

	if (klen > 64) {						//  hash the key if needed
		sha2_256(k0, k, klen);
		k = k0;
		klen = 32;
	}

	for (i = 0; i < 8; i++)					//  set H0 (IV)
		s[i] = sha2_256_h0[i];

	sha256pad(s, k, klen, 0x36, in, inlen);

	for (i = 0; i < 8; i++) {				//  get temporary, reinit
		be_put32(&t[i << 2], s[i]);
		s[i] = sha2_256_h0[i];				//  set H0 (IV)
	}

	sha256pad(s, k, klen, 0x5c, t, 32);

	for (i = 0; i < 8; i++)					//  store big endian output
		be_put32(&mac[i << 2], s[i]);
}


//  shared part between SHA-384 and SHA-512

static void sha512pad(uint64_t s[8],
					  const uint8_t * k, size_t klen, uint8_t pad,
					  const void *in, size_t inlen)
{
	size_t i;
	uint64_t x;

	uint8_t *mp = (uint8_t *) & s[8];
	const uint8_t *ip = in;

	x = inlen << 3;							//  length in bits

	if (k != NULL) {						//  key block for HMAC
		x += 1024;
		for (i = 0; i < klen; i++)
			mp[i] = k[i] ^ pad;
		memset(mp + klen, pad, 128 - klen);
		sha512_compress(s);
	}

	while (inlen >= 128) {					//  full blocks
		memcpy(mp, ip, 128);
		sha512_compress(s);
		inlen -= 128;
		ip += 128;
	}

	memcpy(mp, ip, inlen);					//  last data block
	mp[inlen++] = 0x80;
	if (inlen > 112) {
		memset(mp + inlen, 0x00, 128 - inlen);
		sha512_compress(s);
		inlen = 0;
	}

	i = 128;								//  process length
	while (x > 0) {
		mp[--i] = x & 0xFF;
		x >>= 8;
	}
	memset(mp + inlen, 0x00, i - inlen);
	sha512_compress(s);
}

//  SHA-384 initial values H0, Sect 5.3.4.

static const uint64_t sha2_384_h0[8] = {
	0xCBBB9D5DC1059ED8LL, 0x629A292A367CD507LL,
	0x9159015A3070DD17LL, 0x152FECD8F70E5939LL,
	0x67332667FFC00B31LL, 0x8EB44A8768581511LL,
	0xDB0C2E0D64F98FA7LL, 0x47B5481DBEFA4FA4LL
};

//  Compute 48-byte message digest to "md" from "in" which has "inlen" bytes

void sha2_384(uint8_t * md, const void *in, size_t inlen)
{
	int i;
	uint64_t s[8 + 16];

	for (i = 0; i < 8; i++)					//  set H0 (IV)
		s[i] = sha2_384_h0[i];

	sha512pad(s, NULL, 0, 0x00, in, inlen);

	for (i = 0; i < 6; i++)					//  store big endian output
		be_put64(&md[i << 3], s[i]);
}

void hmac_sha2_384(uint8_t * mac, const void *k, size_t klen,
				   const void *in, size_t inlen)
{
	int i;
	uint64_t s[8 + 16];
	uint8_t t[48], k0[48];

	if (klen > 128) {						//  hash the key if needed
		sha2_384(k0, k, klen);
		k = k0;
		klen = 48;
	}

	for (i = 0; i < 8; i++)					//  set H0 (IV)
		s[i] = sha2_384_h0[i];

	sha512pad(s, k, klen, 0x36, in, inlen);

	for (i = 0; i < 6; i++) {				//  get temporary, reinit
		be_put64(&t[i << 3], s[i]);
	}
	for (i = 0; i < 8; i++)					//  set H0 (IV)
		s[i] = sha2_384_h0[i];

	sha512pad(s, k, klen, 0x5c, t, 48);

	for (i = 0; i < 6; i++)					//  store big endian output
		be_put64(&mac[i << 3], s[i]);
}

//  SHA-512 initial values H0, Sect 5.3.5.

static const uint64_t sha2_512_h0[8] = {
	0x6A09E667F3BCC908LL, 0xBB67AE8584CAA73BLL,
	0x3C6EF372FE94F82BLL, 0xA54FF53A5F1D36F1LL,
	0x510E527FADE682D1LL, 0x9B05688C2B3E6C1FLL,
	0x1F83D9ABFB41BD6BLL, 0x5BE0CD19137E2179LL
};

//  Compute 64-byte message digest to "md" from "in" which has "inlen" bytes

void sha2_512(uint8_t * md, const void *in, size_t inlen)
{
	int i;
	uint64_t s[8 + 16];

	for (i = 0; i < 8; i++)					//  set H0 (IV)
		s[i] = sha2_512_h0[i];

	sha512pad(s, NULL, 0, 0x00, in, inlen);

	for (i = 0; i < 8; i++)					//  store big endian output
		be_put64(&md[i << 3], s[i]);
}

void hmac_sha2_512(uint8_t * mac, const void *k, size_t klen,
				   const void *in, size_t inlen)
{
	int i;
	uint64_t s[8 + 16];
	uint8_t t[64], k0[64];

	if (klen > 128) {						//  hash the key if needed
		sha2_512(k0, k, klen);
		k = k0;
		klen = 64;
	}

	for (i = 0; i < 8; i++)					//  set H0 (IV)
		s[i] = sha2_512_h0[i];

	sha512pad(s, k, klen, 0x36, in, inlen);

	for (i = 0; i < 8; i++) {				//  get temporary, reinit
		be_put64(&t[i << 3], s[i]);
		s[i] = sha2_512_h0[i];				//  set H0 (IV)
	}

	sha512pad(s, k, klen, 0x5c, t, 64);

	for (i = 0; i < 8; i++)					//  store big endian output
		be_put64(&mac[i << 3], s[i]);
}
