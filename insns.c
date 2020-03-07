//	insns.c
//	2020-03-07	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2020, PQShield Ltd. All rights reserved.

//	instruction emulation code

#include "insns.h"

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


