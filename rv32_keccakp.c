//	rv32_keccakp.c
//	2020-03-02	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2020, PQShield Ltd. All rights reserved.

//	Bit-interleaved Keccak permutation

#include <stdio.h>
#include "sha3.h"

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

int gek()
{
	int i;

	uint32_t a, b;
	uint64_t x, y;
	

	x = 0;
	
	for (i = 0; i < 64; i++) {

		x += 0xDEADBEEF01234567;
//1llu << i;

		intrlv(&a, &b, x);

		y = untrlv(a, b);


//		if (x != y)
			printf("%016lX %08X %08X %016lX\n", x, a, b, y);
	}

	return 0;
}
