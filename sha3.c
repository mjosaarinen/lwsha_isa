//	sha3.c
//	2020-03-02	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2020, PQShield Ltd. All rights reserved.

//	FIPS 202: SHA-3 hash and SHAKE eXtensible Output Functions (XOF)

#include "sha3.h"

//	These functions have not been optimized for performance -- they are
//	here just to facilitate testing of the external permutation
//	implementations rv32_keccakp() and rv64_keccakp().

//	Simple and slow "reference" permutation. THIS IS NOT THE RISC-V CODE !

#ifndef ROTL64
#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))
#endif

void ref_keccakp(void *s)
{
	// constants
	const uint64_t keccakf_rndc[24] = {
		0x0000000000000001LL, 0x0000000000008082LL, 0x800000000000808ALL,
		0x8000000080008000LL, 0x000000000000808BLL, 0x0000000080000001LL,
		0x8000000080008081LL, 0x8000000000008009LL, 0x000000000000008ALL,
		0x0000000000000088LL, 0x0000000080008009LL, 0x000000008000000ALL,
		0x000000008000808BLL, 0x800000000000008BLL, 0x8000000000008089LL,
		0x8000000000008003LL, 0x8000000000008002LL, 0x8000000000000080LL,
		0x000000000000800ALL, 0x800000008000000ALL, 0x8000000080008081LL,
		0x8000000000008080LL, 0x0000000080000001LL, 0x8000000080008008LL
	};
	const int keccakf_rotc[24] = {
		1,	3,	6,	10, 15, 21, 28, 36, 45, 55, 2,	14,
		27, 41, 56, 8,	25, 43, 62, 18, 39, 61, 20, 44
	};
	const int keccakf_piln[24] = {
		10, 7,	11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
		15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
	};

	int i, j, r;
	uint64_t t, u, bc[5];
	uint8_t *v;
	uint64_t *st = s;

	// endianess conversion. this is redundant on little-endian targets

	for (i = 0; i < 25; i++) {
		v = (uint8_t *) &st[i];
		st[i] = ((uint64_t) v[0])	  | (((uint64_t) v[1]) << 8) |
			(((uint64_t) v[2]) << 16) | (((uint64_t) v[3]) << 24) |
			(((uint64_t) v[4]) << 32) | (((uint64_t) v[5]) << 40) |
			(((uint64_t) v[6]) << 48) | (((uint64_t) v[7]) << 56);
	}

	for (r = 0; r < 24; r++) {				//	24 rounds

		for (i = 0; i < 5; i++) {			//	Theta
			bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
		}

		for (i = 0; i < 5; i++) {
			t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
			for (j = 0; j < 25; j += 5)
				st[j + i] ^= t;
		}

		t = st[1];							//	Rho Pi
		for (i = 0; i < 24; i++) {
			j = keccakf_piln[i];
			u = st[j];
			st[j] = ROTL64(t, keccakf_rotc[i]);
			t = u;
		}

		for (j = 0; j < 25; j += 5) {		//	Chi
			for (i = 0; i < 5; i++)
				bc[i] = st[j + i];
			for (i = 0; i < 5; i++)
				st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
		}

		st[0] ^= keccakf_rndc[r];			//	Iota
	}

	// endianess conversion. this is redundant on little-endian targets

	for (i = 0; i < 25; i++) {
		v = (uint8_t *) &st[i];
		t = st[i];
		v[0] = t & 0xFF;
		v[1] = (t >>  8) & 0xFF;
		v[2] = (t >> 16) & 0xFF;
		v[3] = (t >> 24) & 0xFF;
		v[4] = (t >> 32) & 0xFF;
		v[5] = (t >> 40) & 0xFF;
		v[6] = (t >> 48) & 0xFF;
		v[7] = (t >> 56) & 0xFF;
	}
}

//	pointer to the function

void (*sha3_keccakp)(void *) = &ref_keccakp;

//	initialize the context for SHA3

int sha3_init(sha3_ctx_t *c, int mdlen)
{
	int i;

	for (i = 0; i < 25; i++)
		c->st.d[i] = 0;
	c->mdlen = mdlen;
	c->rsiz = 200 - 2 * mdlen;
	c->pt = 0;

	return 1;
}

//	update state with more data

int sha3_update(sha3_ctx_t *c, const void *data, size_t len)
{
	size_t i;
	int j;

	j = c->pt;
	for (i = 0; i < len; i++) {
		c->st.b[j++] ^= ((const uint8_t *) data)[i];
		if (j >= c->rsiz) {
			sha3_keccakp(c->st.d);
			j = 0;
		}
	}
	c->pt = j;

	return 1;
}

//	finalize and output a hash

int sha3_final(void *md, sha3_ctx_t *c)
{
	int i;

	c->st.b[c->pt] ^= 0x06;
	c->st.b[c->rsiz - 1] ^= 0x80;
	sha3_keccakp(c->st.d);

	for (i = 0; i < c->mdlen; i++) {
		((uint8_t *) md)[i] = c->st.b[i];
	}

	return 1;
}

//	compute a SHA-3 hash "md" of "mdlen" bytes from data in "in"

void *sha3(void *md, int mdlen, const void *in, size_t inlen)
{
	sha3_ctx_t sha3;

	sha3_init(&sha3, mdlen);
	sha3_update(&sha3, in, inlen);
	sha3_final(md, &sha3);

	return md;
}

//	SHAKE128 and SHAKE256 extensible-output functionality

//	add padding (call once after calls to shake_update() are done

void shake_xof(sha3_ctx_t *c)
{
	c->st.b[c->pt] ^= 0x1F;
	c->st.b[c->rsiz - 1] ^= 0x80;
	sha3_keccakp(c->st.d);
	c->pt = 0;
}

//	squeeze output

void shake_out(sha3_ctx_t *c, void *out, size_t len)
{
	size_t i;
	int j;

	j = c->pt;
	for (i = 0; i < len; i++) {
		if (j >= c->rsiz) {
			sha3_keccakp(c->st.d);
			j = 0;
		}
		((uint8_t *) out)[i] = c->st.b[j++];
	}
	c->pt = j;
}

