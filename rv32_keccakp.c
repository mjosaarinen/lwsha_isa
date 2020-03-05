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

static uint32_t rv_ror(uint32_t rs1, uint32_t rs2)
{
	int shamt = rs2 & (32 - 1);
	return (rs1 >> shamt) | (rs1 << ((32 - shamt) & (32 - 1)));
}

//	RORW / RORIW

static int64_t rv_rorw(uint64_t rs1, uint64_t rs2)
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

void split_keccakf(uint64_t s[25], int rounds)
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
			s[i] = rv_rorw(s[i], rorc[i]);	
*/	

//	uint32_t v[25][2];
//	uint32_t t0, t1, u0, u1;

	//	iteration
	for (r = 0; r < rounds; r++) {

		// Theta
		for (i = 0; i < 5; i++)
			bc[i] = s[i] ^ s[i + 5] ^ s[i + 10] ^ s[i + 15] ^ s[i + 20];

		for (i = 0; i < 5; i++) {
			t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
			for (j = 0; j < 25; j += 5)
				s[j + i] ^= t;
		}

		// Pi

#if 1

		t = s[ 1];
		s[ 1] = rv_rorw(s[ 6], 20);
		s[ 6] = rv_rorw(s[ 9], 44);
		s[ 9] = rv_rorw(s[22],  3);
		s[22] = rv_rorw(s[14], 25);
		s[14] = rv_rorw(s[20], 46);
		s[20] = rv_rorw(s[ 2],  2);
		s[ 2] = rv_rorw(s[12], 21);
		s[12] = rv_rorw(s[13], 39);
		s[13] = rv_rorw(s[19], 56);
		s[19] = rv_rorw(s[23],  8);
		s[23] = rv_rorw(s[15], 23);
		s[15] = rv_rorw(s[ 4], 37);
		s[ 4] = rv_rorw(s[24], 50);
		s[24] = rv_rorw(s[21], 62);
		s[21] = rv_rorw(s[ 8],  9);
		s[ 8] = rv_rorw(s[16], 19);
		s[16] = rv_rorw(s[ 5], 28);
		s[ 5] = rv_rorw(s[ 3], 36);
		s[ 3] = rv_rorw(s[18], 43);
		s[18] = rv_rorw(s[17], 49);
		s[17] = rv_rorw(s[11], 54);
		s[11] = rv_rorw(s[ 7], 58);
		s[ 7] = rv_rorw(s[10], 61);
		s[10] = rv_rorw(s[ 1], 63);


		for (i = 23; i >= 0; i--) {
			j = 64 - keccakf_rotc[i];
			printf("\t\ts%c = rv_rorw(s%c, %2d);\n",
				'a' + keccakf_piln[i], 'a' + keccakf_piln[(i + 23) % 24], j);
		}

		exit(0);

/*
		t = s[1];
		for (i = 0; i < 24; i += 2) {

			j = keccakf_piln[i];
			u = s[j];
			s[j] = rv_rorw(t, 64-keccakf_rotc[i]);

			printf("u = s[%2d]; s[%2d] = rv_rorw(t, %2d);\n",
				j, j, 64-keccakf_rotc[i]);

			j = keccakf_piln[i + 1];
			t = s[j];
			s[j] = rv_rorw(u, 64-keccakf_rotc[i + 1]);


			printf("t = s[%2d]; s[%2d] = rv_rorw(u, %2d);\n",
				j, j, 64-keccakf_rotc[i + 1]);
		}

	exit(0);
*/
#else


	//	state; 50 words

	uint32_t	sa0, sa1, sb0, sb1, sc0, sc1, sd0, sd1, se0, se1,
				sf0, sf1, sg0, sg1, sh0, sh1, si0, si1, sj0, sj1,
				sk0, sk1, sl0, sl1, sm0, sm1, sn0, sn1, so0, so1,
				sp0, sp1, sq0, sq1, sr0, sr1, ss0, ss1, st0, st1,
				su0, su1, sv0, sv1, sw0, sw1, sx0, sx1, sy0, sy1;

		intrlv(&sa0, &sa1, s[ 0]);
		intrlv(&sb0, &sb1, s[ 1]);
		intrlv(&sc0, &sc1, s[ 2]);
		intrlv(&sd0, &sd1, s[ 3]);
		intrlv(&se0, &se1, s[ 4]);
		intrlv(&sf0, &sf1, s[ 5]);
		intrlv(&sg0, &sg1, s[ 6]);
		intrlv(&sh0, &sh1, s[ 7]);
		intrlv(&si0, &si1, s[ 8]);
		intrlv(&sj0, &sj1, s[ 9]);
		intrlv(&sk0, &sk1, s[10]);
		intrlv(&sl0, &sl1, s[11]);
		intrlv(&sm0, &sm1, s[12]);
		intrlv(&sn0, &sn1, s[13]);
		intrlv(&so0, &so1, s[14]);
		intrlv(&sp0, &sp1, s[15]);
		intrlv(&sq0, &sq1, s[16]);
		intrlv(&sr0, &sr1, s[17]);
		intrlv(&ss0, &ss1, s[18]);
		intrlv(&st0, &st1, s[19]);
		intrlv(&su0, &su1, s[20]);
		intrlv(&sv0, &sv1, s[21]);
		intrlv(&sw0, &sw1, s[22]);
		intrlv(&sx0, &sx1, s[23]);
		intrlv(&sy0, &sy1, s[24]);

		t0 = sb0;
		t1 = sb1;

		j = 1;

		t0 = v[j][0];
		t1 = v[j][1];

		for (i = 0; i < 24; i += 2) {

			int rr;
			int r0, r1;

			j = keccakf_piln[i];

			u0 = v[j][0];
			u1 = v[j][1];

			printf("\t\ts%c0 = rv_ror(t0, %d);\n", j, r1);
			printf("\t\ts%c1 = rv_ror(t1, %d);\n", j, r1);

			rr = 64 - keccakf_rotc[i];

			r0 = (rr >> 1) & 0x1F;
			r1 = ((rr + 1) >> 1) & 0x1F;
	
			if ((rr & 1) == 0) {
				v[j][0] = rv_ror(t0, r1);
				v[j][1] = rv_ror(t1, r1);

				printf("\t\ts%c0 = rv_ror(t0, %d);\n", j, r1);
				printf("\t\ts%c1 = rv_ror(t1, %d);\n", j, r1);
			} else {
				v[j][0] = rv_ror(t1, r0);
				v[j][1] = rv_ror(t0, r1);

				printf("\t\ts%c0 = rv_ror(t1, %d);\n", j, r0);
				printf("\t\ts%c1 = rv_ror(t0, %d);\n", j, r1);
			}


			j = keccakf_piln[i + 1];

			t0 = v[j][0];
			t1 = v[j][1];

			rr = 64 - keccakf_rotc[i + 1];

			r0 = (rr >> 1) & 0x1F;
			r1 = ((rr + 1) >> 1) & 0x1F;
	
			if ((rr & 1) == 0) {
				v[j][0] = rv_ror(u0, r1);
				v[j][1] = rv_ror(u1, r1);
			} else {
				v[j][0] = rv_ror(u1, r0);
				v[j][1] = rv_ror(u0, r1);
			}
		}



		s[ 0] = untrlv(sa0, sa1);
		s[ 1] = untrlv(sb0, sb1);
		s[ 2] = untrlv(sc0, sc1);
		s[ 3] = untrlv(sd0, sd1);
		s[ 4] = untrlv(se0, se1);
		s[ 5] = untrlv(sf0, sf1);
		s[ 6] = untrlv(sg0, sg1);
		s[ 7] = untrlv(sh0, sh1);
		s[ 8] = untrlv(si0, si1);
		s[ 9] = untrlv(sj0, sj1);
		s[10] = untrlv(sk0, sk1);
		s[11] = untrlv(sl0, sl1);
		s[12] = untrlv(sm0, sm1);
		s[13] = untrlv(sn0, sn1);
		s[14] = untrlv(so0, so1);
		s[15] = untrlv(sp0, sp1);
		s[16] = untrlv(sq0, sq1);
		s[17] = untrlv(sr0, sr1);
		s[18] = untrlv(ss0, ss1);
		s[19] = untrlv(st0, st1);
		s[20] = untrlv(su0, su1);
		s[21] = untrlv(sv0, sv1);
		s[22] = untrlv(sw0, sw1);
		s[23] = untrlv(sx0, sx1);
		s[24] = untrlv(sy0, sy1);

		for (i = 0; i < 25; i++) {
			s[i] = untrlv(v[i][0], v[i][1]);
		}

#endif

		//	Chi
		for (j = 0; j < 25; j += 5) {
			for (i = 0; i < 5; i++)
				bc[i] = s[j + i];
			for (i = 0; i < 5; i++)
				s[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
		}

		//	Iota
		s[0] ^= keccakf_rndc[r];
	}
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

