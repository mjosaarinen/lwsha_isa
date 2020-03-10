//	ref_keccakp.c
//	2020-03-02	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2020, PQShield Ltd. All rights reserved.

#include "sha3.h"

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

