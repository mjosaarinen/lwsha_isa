//	rv32_keccakp.c
//	2020-03-02	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2020, PQShield Ltd. All rights reserved.

//	Bit-interleaved Keccak permutation

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "sha3.h"
#include "xrand.h"

//	ROR / RORI

uint32_t rv_ror(uint32_t rs1, uint32_t rs2)
{
	int shamt = rs2 & (32 - 1);
	return (rs1 >> shamt) | (rs1 << ((32 - shamt) & (32 - 1)));
}

//	RORW / RORIW

uint64_t rv_rorw(uint64_t rs1, uint64_t rs2)
{
	int shamt = rs2 & (64 - 1);
	return (rs1 >> shamt) | (rs1 << ((64 - shamt) & (64 - 1)));
}

//	interleave

void intrlv(uint32_t *a, uint32_t *b, uint64_t x)
{
	int i;

	*a = 0;
	*b = 0;

	for (i = 0; i < 32; i++) {
		*a |= (x & 1) << i;
		x >>= 1;
		*b |= (x & 1) << i;
		x >>= 1;
	}
}

//	un-interlave

uint64_t untrlv(uint32_t a, uint32_t b)
{
	int i;
	uint64_t x;

	x = 0;

	for (i = 31; i >= 0; i--) {

		x <<= 1;
		x |= (b >> i) & 1;
		x <<= 1;
		x |= (a >> i) & 1;
	}

	return x;
}

void prtst(const void *p)
{
	int i;
	const uint64_t *v = ((const uint64_t *) p);

	for (i = 0; i < 25; i += 5) {
		printf("%2d : %016lX %016lX %016lX %016lX %016lX\n", 
			i, v[i], v[i + 1], v[i + 2], v[i + 3], v[i + 4]);
	}
}

// update the state with given number of rounds

void split_keccakf(uint64_t st[25], int rounds)
{
	// constants
	const uint64_t keccakf_rndc[24] = {
		0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
		0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
		0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
		0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
		0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
		0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
		0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
		0x8000000000008080, 0x0000000080000001, 0x8000000080008008
	};

	const int keccakf_rotc[24] = {
		1,	3,	6,	10, 15, 21, 28, 36, 45, 55, 2,	14,
		27, 41, 56, 8,	25, 43, 62, 18, 39, 61, 20, 44
	};
	const int keccakf_piln[24] = {
		10, 7,	11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
		15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
	};

	// variables
	int i, j, r;
	uint64_t t, bc[5];


/*
	const int rorc[25] = {   0, 63,  2, 36, 37, 28, 20, 58,  9, 44, 
		61, 54, 21, 39, 25, 23, 19, 49, 43, 56, 46, 62,  3,  8, 50 };

	for (i = 1; i < 25; i++)
			st[i] = rv_rorw(st[i], rorc[i]);	
*/	

	uint32_t v[25][2];

	uint32_t t0, t1, u0, u1;

	//	iteration
	for (r = 0; r < rounds; r++) {

		// Theta
		for (i = 0; i < 5; i++)
			bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];

		for (i = 0; i < 5; i++) {
			t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
			for (j = 0; j < 25; j += 5)
				st[j + i] ^= t;
		}

		// Pi

/*
		t = st[1];
		for (i = 0; i < 24; i++) {
			j = keccakf_piln[i];
			bc[0] = st[j];
			st[j] = rv_rorw(t, 64-keccakf_rotc[i]);
			t = bc[0];
		}
*/

		for (i = 0; i < 25; i++) {
			intrlv(&v[i][0], &v[i][1], st[i]);
		}

		t0 = v[1][0];
		t1 = v[1][1];

		for (i = 0; i < 24; i++) {

			int rr;
			int r0, r1;

			j = keccakf_piln[i];

			u0 = v[j][0];
			u1 = v[j][1];

			rr = 64 - keccakf_rotc[i];

			r0 = (rr >> 1) & 0x1F;
			r1 = ((rr + 1) >> 1) & 0x1F;
	
			if ((rr & 1) == 0) {
				v[j][0] = rv_ror(t0, r1);
				v[j][1] = rv_ror(t1, r1);
			} else {
				v[j][0] = rv_ror(t1, r0);
				v[j][1] = rv_ror(t0, r1);
			}

			t0 = u0;
			t1 = u1;
		}

		for (i = 0; i < 25; i++) {
			st[i] = untrlv(v[i][0], v[i][1]);
		}


		//	Chi
		for (j = 0; j < 25; j += 5) {
			for (i = 0; i < 5; i++)
				bc[i] = st[j + i];
			for (i = 0; i < 5; i++)
				st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
		}

		//	Iota
		st[0] ^= keccakf_rndc[r];
	}
}


int gek()
{
	int i, d;
	uint64_t sa[25], sb[25];

	for (i = 0; i < 25; i++)
		sa[i] = i;
	memcpy(sb, sa, sizeof(sb));

	sha3_keccakf(sb, 24);
	prtst(sb);
	printf("\n");

	split_keccakf(sa, 24);
	prtst(sa);

	d = 0;
	for (i = 0; i < 25; i++) {
		d += __builtin_popcountll(sa[i] ^ sb[i]);
	}
	printf("d = %d\n", d);

	return 0;
}

int vgek()
{
	int i;
	int r0, r1;

	uint32_t a0, b0, a1, b1, a2, b2;
	uint64_t x, y, z;

	xsrand(time(NULL));

	x = 0xDEADBEEF01234567;
	
	for (i = 0; i < 64; i++) {

		y = rv_rorw(x, i);
		intrlv(&a0, &b0, y);

		intrlv(&a1, &b1, x);
		
		r0 = (i >> 1) & 0x1F;
		r1 = ((i + 1) >> 1) & 0x1F;

		if ((i & 1) == 0) {
			a2 = rv_ror(a1, r1);
			b2 = rv_ror(b1, r1);
		} else {
			a2 = rv_ror(b1, r0);
			b2 = rv_ror(a1, r1);
		}

		z = untrlv(a2, b2);

		printf("%2d : %016lX %016lX %016lX  %08X %08X  %08X %08X\n",
			i, x, y, z, a0, b0, a2, b2);

		if (y != z) {
			printf("FAIL!\n");
		}
	}

	return 0;
}

