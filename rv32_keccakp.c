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


#ifndef ROTL64
#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))
#endif

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

//	ANDN

uint64_t rv_andn(uint64_t rs1, uint64_t rs2)
{
	return rs1 & ~rs2;
}

//	interleave even

uint32_t intrlv0(uint32_t xl, uint32_t xh)
{
	int i, j;
	uint32_t y = 0;

	for (i = 0; i < 16; i++) {
		j = 2 * i;
		y |= (((xl >> j) & 1) << i);
		y |= (((xh >> j) & 1) << (i + 16));
	}

	return y;
}

//	interleave odd

uint32_t intrlv1(uint32_t xl, uint32_t xh)
{
	int i, j;
	uint32_t y = 0;

	for (i = 0; i < 16; i++) {
		j = 2 * i + 1;
		y |= (((xl >> j) & 1) << i);
		y |= (((xh >> j) & 1) << (i + 16));
	}

	return y;
}

//	un-interlave low

uint32_t untrlvl(uint32_t x0, uint32_t x1)
{
	int i;
	uint32_t y = 0;

	for (i = 15; i >= 0; i--) {

		y <<= 1;
		y |= (x1 >> i) & 1;
		y <<= 1;
		y |= (x0 >> i) & 1;
	}

	return y;
}

//	un-interlave high

uint32_t untrlvh(uint32_t x0, uint32_t x1)
{
	int i;
	uint32_t y = 0;

	for (i = 31; i >= 16; i--) {

		y <<= 1;
		y |= (x1 >> i) & 1;
		y <<= 1;
		y |= (x0 >> i) & 1;
	}

	return y;
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

int gek()
{
	int i;
	int r0, r1;

	uint32_t x0, x1, y0, y1;
	uint64_t x, y, z;

	xsrand(time(NULL));

	x = 0xDEADBEEF01234567;

	for (i = 0; i < 64; i++) {

		y = rv_rorw(x, i);

		x0 = intrlv0(x, x >> 32);
		x1 = intrlv1(x, x >> 32);

		r0 = (i >> 1) & 0x1F;
		r1 = ((i + 1) >> 1) & 0x1F;

		if ((i & 1) == 0) {
			y0 = rv_ror(x0, r1);
			y1 = rv_ror(x1, r1);

			printf("%2d: y0 = rv_ror(x0, %2d); y1 = rv_ror(x1, %2d);\n",
				i, r1, r1);
		} else {
			y0 = rv_ror(x1, r0);
			y1 = rv_ror(x0, r1);

			printf("%2d: y0 = rv_ror(x1, %2d); y1 = rv_ror(x0, %2d);\n",
				i, r0, r1);
		}

		z = ((uint64_t) untrlvl(y0, y1)) | 
			(((uint64_t) untrlvh(y0, y1)) << 32);

		if (y != z) {
			printf("%2d : %016lX %016lX %016lX	%08X %08X  %08X %08X\n",
				i, x, y, z, x0, x1, y0, y1);

			printf("FAIL!\n");
		}
	}

	return 0;
}




