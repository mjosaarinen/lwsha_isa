//	rv32_keccakp.c
//	2020-03-02	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2020, PQShield Ltd. All rights reserved.

//	Bit-interleaved FIPS 202 Keccak permutation for a 32-bit target.

#include "insns.h"

//	interleave the state (for input)

void kp_intrlv50(uint32_t v[50])
{
	uint32_t t0, t1, *p;

	for (p = v; p != &v[50]; p += 2) {
		//	uses bitmanip UNSHFL with immediate 15, which is pseudo-op "unzip"
		t0 	 = rv_unshfl(p[0], 15);
		t1	 = rv_unshfl(p[1], 15);
		p[0] = (t0 & 0x0000FFFF) | (t1 << 16);
		p[1] = (t1 & 0xFFFF0000) | (t0 >> 16);
	}
}

//	un-interleave the state (for output)

void kp_untrlv50(uint32_t v[50])
{
	uint32_t t0, t1, *p;

	for (p = v; p != &v[50]; p += 2) {
		//	uses bitmanip SHFL with immediate 15, which is pseudo-op "zip"
		t0 	 = rv_shfl(p[0], 15);
		t1	 = rv_shfl(p[1], 15);
		p[0] = ((t1 & 0x55555555) << 1) | (t0 & 0x55555555);
		p[1] = ((t0 & 0xAAAAAAAA) >> 1) | (t1 & 0xAAAAAAAA);
	}
}

//	Keccak-p[1600,24](S)

void rv32_keccakp(void *s)
{
	//	round constants (interleaved)

	const uint32_t rc[48] = {
		0x00000001, 0x00000000, 0x00000000, 0x00000089, 0x00000000,
		0x8000008B, 0x00000000, 0x80008080, 0x00000001, 0x0000008B,
		0x00000001, 0x00008000, 0x00000001, 0x80008088, 0x00000001,
		0x80000082, 0x00000000, 0x0000000B, 0x00000000, 0x0000000A,
		0x00000001, 0x00008082, 0x00000000, 0x00008003, 0x00000001,
		0x0000808B, 0x00000001, 0x8000000B, 0x00000001, 0x8000008A,
		0x00000001, 0x80000081, 0x00000000, 0x80000081, 0x00000000,
		0x80000008, 0x00000000, 0x00000083, 0x00000000, 0x80008003,
		0x00000001, 0x80008088, 0x00000000, 0x80000088, 0x00000001,
		0x00008000, 0x00000000, 0x80008082
	};

	uint32_t	t0, t1, t2, t3, t4, t5, t6, t7, t8, t9;
	uint32_t	u0, u1, u2, u3;
	const uint32_t *q;
	uint32_t	*p;
	uint32_t	*v = (uint32_t *) s;

	//	interleave the state (this can be outside the function)
	kp_intrlv50(v);

	//	(passed between rounds, initial load)

	u0 = v[40]; u1 = v[41]; t2 = v[42]; t3 = v[43]; t4 = v[44];
	t5 = v[45]; t6 = v[46]; t7 = v[47]; t8 = v[48]; t9 = v[49];

	//	24 rounds

	for (q = rc; q != &rc[48]; q += 2) {

		//	Theta
		for (p = v; p != &v[40]; p += 10) {
			u0 = u0 ^ p[0];			u1 = u1 ^ p[1];
			t2 = t2 ^ p[2];			t3 = t3 ^ p[3];
			t4 = t4 ^ p[4];			t5 = t5 ^ p[5];
			t6 = t6 ^ p[6];			t7 = t7 ^ p[7];
			t8 = t8 ^ p[8];			t9 = t9 ^ p[9];
		}

		t0 = u0 ^ rv_ror(t5, 31);	t1 = u1 ^ t4;
		t4 = t4 ^ rv_ror(t9, 31);	t5 = t5 ^ t8;
		t8 = t8 ^ rv_ror(t3, 31);	t9 = t9 ^ t2;
		t2 = t2 ^ rv_ror(t7, 31);	t3 = t3 ^ t6;
		t6 = t6 ^ rv_ror(u1, 31);	t7 = t7 ^ u0;

		//	(Theta) Rho Pi

		u0 = v[ 0] ^ t8;			u1 = v[1] ^ t9;
		v[ 0] = u0;					v[1] = u1;
		u2 = v[ 2] ^ t0;			u3 = v[ 3] ^ t1;
		u0 = v[12] ^ t0;			u1 = v[13] ^ t1;
		v[ 2] = rv_ror(u0, 10);		v[ 3] = rv_ror(u1, 10);
		u0 = v[18] ^ t6;			u1 = v[19] ^ t7;
		v[12] = rv_ror(u0, 22);		v[13] = rv_ror(u1, 22);
		u0 = v[44] ^ t2;			u1 = v[45] ^ t3;
		v[18] = rv_ror(u1,	1);		v[19] = rv_ror(u0,	2);
		u0 = v[28] ^ t6;			u1 = v[29] ^ t7;
		v[44] = rv_ror(u1, 12);		v[45] = rv_ror(u0, 13);
		u0 = v[40] ^ t8;			u1 = v[41] ^ t9;
		v[28] = rv_ror(u0, 23);		v[29] = rv_ror(u1, 23);
		u0 = v[ 4] ^ t2;			u1 = v[ 5] ^ t3;
		v[40] = rv_ror(u0,	1);		v[41] = rv_ror(u1,	1);
		u0 = v[24] ^ t2;			u1 = v[25] ^ t3;
		v[ 4] = rv_ror(u1, 10);		v[ 5] = rv_ror(u0, 11);
		u0 = v[26] ^ t4;			u1 = v[27] ^ t5;
		v[24] = rv_ror(u1, 19);		v[25] = rv_ror(u0, 20);
		u0 = v[38] ^ t6;			u1 = v[39] ^ t7;
		v[26] = rv_ror(u0, 28);		v[27] = rv_ror(u1, 28);
		u0 = v[46] ^ t4;			u1 = v[47] ^ t5;
		v[38] = rv_ror(u0,	4);		v[39] = rv_ror(u1,	4);
		u0 = v[30] ^ t8;			u1 = v[31] ^ t9;
		v[46] = rv_ror(u1, 11);		v[47] = rv_ror(u0, 12);
		u0 = v[ 8] ^ t6;			u1 = v[ 9] ^ t7;
		v[30] = rv_ror(u1, 18);		v[31] = rv_ror(u0, 19);
		u0 = v[48] ^ t6;			u1 = v[49] ^ t7;
		v[ 8] = rv_ror(u0, 25);		v[ 9] = rv_ror(u1, 25);
		u0 = v[42] ^ t0;			u1 = v[43] ^ t1;
		v[48] = rv_ror(u0, 31);		v[49] = rv_ror(u1, 31);
		u0 = v[16] ^ t4;			u1 = v[17] ^ t5;
		v[42] = rv_ror(u1,	4);		v[43] = rv_ror(u0,	5);
		u0 = v[32] ^ t0;			u1 = v[33] ^ t1;
		v[16] = rv_ror(u1,	9);		v[17] = rv_ror(u0, 10);
		u0 = v[10] ^ t8;			u1 = v[11] ^ t9;
		v[32] = rv_ror(u0, 14);		v[33] = rv_ror(u1, 14);
		u0 = v[ 6] ^ t4;			u1 = v[ 7] ^ t5;
		v[10] = rv_ror(u0, 18);		v[11] = rv_ror(u1, 18);
		u0 = v[36] ^ t4;			u1 = v[37] ^ t5;
		v[ 6] = rv_ror(u1, 21);		v[ 7] = rv_ror(u0, 22);
		u0 = v[34] ^ t2;			u1 = v[35] ^ t3;
		v[36] = rv_ror(u1, 24);		v[37] = rv_ror(u0, 25);
		u0 = v[22] ^ t0;			u1 = v[23] ^ t1;
		v[34] = rv_ror(u0, 27);		v[35] = rv_ror(u1, 27);
		u0 = v[14] ^ t2;			u1 = v[15] ^ t3;
		v[22] = rv_ror(u0, 29);		v[23] = rv_ror(u1, 29);
		u0 = v[20] ^ t8;			u1 = v[21] ^ t9;
		v[14] = rv_ror(u1, 30);		v[15] = rv_ror(u0, 31);
		v[20] = rv_ror(u3, 31);		v[21] = u2;

		//	Chi

		for (p = v; p <= &v[40]; p += 10) {
			u0 = p[0];	t2 = p[2];	t4 = p[4];	t6 = p[6];	t8 = p[8];
			u1 = p[1];	t3 = p[3];	t5 = p[5];	t7 = p[7];	t9 = p[9];
			t0 = rv_andn(t8, t6);		t1 = rv_andn(t9, t7);
			t8 = t8 ^ rv_andn(t2, u0);	t9 = t9 ^ rv_andn(t3, u1);
			t2 = t2 ^ rv_andn(t6, t4);	t3 = t3 ^ rv_andn(t7, t5);
			t6 = t6 ^ rv_andn(u0, t8);	t7 = t7 ^ rv_andn(u1, t9);
			u0 = u0 ^ rv_andn(t4, t2);	u1 = u1 ^ rv_andn(t5, t3);
			t4 = t4 ^ t0;				t5 = t5 ^ t1;
			p[0] = u0;	p[2] = t2;	p[4] = t4;	p[6] = t6;	p[8] = t8;
			p[1] = u1;	p[3] = t3;	p[5] = t5;	p[7] = t7;	p[9] = t9;
		}

		//	Iota

		t0 = v[ 0]; t1 = v[ 1];
		v[ 0] = t0 ^ q[0];	v[ 1] = t1 ^ q[1];
	}

	//	un-interleave (this can be outside the function)

	kp_untrlv50(v);
}

