//	rv32_keccakp.c
//	2020-03-02	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2020, PQShield Ltd. All rights reserved.

//	Bit-interleaved Keccak permutation

#include "insns.h"
#include "sha3.h"


//	parity on a column

uint32_t kp_par5(uint32_t *v)
{
	return	v[ 0] ^ v[10] ^ v[20] ^ v[30] ^ v[40];
}

//	xor on a column

void kp_xor10(uint32_t *v, uint32_t x0, uint32_t x1)
{
	v[ 0] = v[ 0] ^ x0;
	v[ 1] = v[ 1] ^ x1;
	v[10] = v[10] ^ x0;
	v[11] = v[11] ^ x1;
	v[20] = v[20] ^ x0;
	v[21] = v[21] ^ x1;
	v[30] = v[30] ^ x0;
	v[31] = v[31] ^ x1;
	v[40] = v[40] ^ x0;
	v[41] = v[41] ^ x1;
}

//	chi function on a 32-bit slice

void kp_chi5(uint32_t *v)
{
	uint32_t t, a, b, c, d, e;

	a = v[ 0];	b = v[ 2];	c = v[ 4];	d = v[ 6];	e = v[ 8];

	t  = rv_andn(e, d);
	e = e ^ rv_andn(b, a);
	b = b ^ rv_andn(d, c);
	d = d ^ rv_andn(a, e);
	a = a ^ rv_andn(c, b);
	c = c ^ t;

	v[ 0] = a;	v[ 2] = b;	v[ 4] = c;	v[ 6] = d;	v[ 8] = e;
}

//	interleave the state (for input)

void kp_intrlv50(uint32_t v[50])
{
	int i;
	uint32_t t0, t1;

	for (i = 0; i < 50; i += 2) {
		t0 		 = 	v[i];
		t1 		 = 	v[i + 1];
		v[i] 	 = 	intrlv0(t0, t1);
		v[i + 1] = 	intrlv1(t0, t1);
	}
}

//	un-interleave the state (for output)

void kp_untrlv50(uint32_t v[50])
{
	int i;
	uint32_t t0, t1;

	for (i = 0; i < 50; i += 2) {
		t0 		 = 	v[i];
		t1 		 = 	v[i + 1];
		v[i] 	 = 	untrlvl(t0, t1);
		v[i + 1] = 	untrlvh(t0, t1);
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

	int 		i;
	uint32_t	t0, t1, t2, t3, t4, t5, t6, t7, t8, t9;
	uint32_t	*vs = (uint32_t *) s;

	//	interleave the state (this can be outside the function)
	kp_intrlv50(vs);

	//	24 rounds
	for (i = 0; i < 48; i += 2) {

		//	Theta

		t0 = kp_par5(&vs[ 0]);
		t1 = kp_par5(&vs[ 1]);
		t2 = kp_par5(&vs[ 2]);
		t3 = kp_par5(&vs[ 3]);
		t4 = kp_par5(&vs[ 4]);
		t5 = kp_par5(&vs[ 5]);
		t6 = kp_par5(&vs[ 6]);
		t7 = kp_par5(&vs[ 7]);
		t8 = kp_par5(&vs[ 8]);
		t9 = kp_par5(&vs[ 9]);

		kp_xor10(&vs[ 0], t8 ^ rv_ror(t3, 31), t9 ^ t2);
		kp_xor10(&vs[ 2], t0 ^ rv_ror(t5, 31), t1 ^ t4);
		kp_xor10(&vs[ 4], t2 ^ rv_ror(t7, 31), t3 ^ t6);
		kp_xor10(&vs[ 6], t4 ^ rv_ror(t9, 31), t5 ^ t8);
		kp_xor10(&vs[ 8], t6 ^ rv_ror(t1, 31), t7 ^ t0);

		//	Rho Pi

		t2 = vs[ 2]; t3 = vs[ 3];
		t0 = vs[12]; t1 = vs[13];
		vs[ 2] = rv_ror(t0, 10); vs[ 3] = rv_ror(t1, 10);
		t0 = vs[18]; t1 = vs[19];
		vs[12] = rv_ror(t0, 22); vs[13] = rv_ror(t1, 22);
		t0 = vs[44]; t1 = vs[45];
		vs[18] = rv_ror(t1,  1); vs[19] = rv_ror(t0,  2);
		t0 = vs[28]; t1 = vs[29];
		vs[44] = rv_ror(t1, 12); vs[45] = rv_ror(t0, 13);
		t0 = vs[40]; t1 = vs[41];
		vs[28] = rv_ror(t0, 23); vs[29] = rv_ror(t1, 23);
		t0 = vs[ 4]; t1 = vs[ 5];
		vs[40] = rv_ror(t0,  1); vs[41] = rv_ror(t1,  1);
		t0 = vs[24]; t1 = vs[25];
		vs[ 4] = rv_ror(t1, 10); vs[ 5] = rv_ror(t0, 11);
		t0 = vs[26]; t1 = vs[27];
		vs[24] = rv_ror(t1, 19); vs[25] = rv_ror(t0, 20);
		t0 = vs[38]; t1 = vs[39];
		vs[26] = rv_ror(t0, 28); vs[27] = rv_ror(t1, 28);
		t0 = vs[46]; t1 = vs[47];
		vs[38] = rv_ror(t0,  4); vs[39] = rv_ror(t1,  4);
		t0 = vs[30]; t1 = vs[31]; 
		vs[46] = rv_ror(t1, 11); vs[47] = rv_ror(t0, 12);
		t0 = vs[ 8]; t1 = vs[ 9];
		vs[30] = rv_ror(t1, 18); vs[31] = rv_ror(t0, 19);
		t0 = vs[48]; t1 = vs[49];
		vs[ 8] = rv_ror(t0, 25); vs[ 9] = rv_ror(t1, 25);
		t0 = vs[42]; t1 = vs[43];
		vs[48] = rv_ror(t0, 31); vs[49] = rv_ror(t1, 31);
		t0 = vs[16]; t1 = vs[17];
		vs[42] = rv_ror(t1,  4); vs[43] = rv_ror(t0,  5);
		t0 = vs[32]; t1 = vs[33];
		vs[16] = rv_ror(t1,  9); vs[17] = rv_ror(t0, 10);
		t0 = vs[10]; t1 = vs[11];
		vs[32] = rv_ror(t0, 14); vs[33] = rv_ror(t1, 14);
		t0 = vs[ 6]; t1 = vs[ 7];
		vs[10] = rv_ror(t0, 18); vs[11] = rv_ror(t1, 18);
		t0 = vs[36]; t1 = vs[37];
		vs[ 6] = rv_ror(t1, 21); vs[ 7] = rv_ror(t0, 22);
		t0 = vs[34]; t1 = vs[35];
		vs[36] = rv_ror(t1, 24); vs[37] = rv_ror(t0, 25);
		t0 = vs[22]; t1 = vs[23];
		vs[34] = rv_ror(t0, 27); vs[35] = rv_ror(t1, 27);
		t0 = vs[14]; t1 = vs[15];
		vs[22] = rv_ror(t0, 29); vs[23] = rv_ror(t1, 29);
		t0 = vs[20]; t1 = vs[21];
		vs[14] = rv_ror(t1, 30); vs[15] = rv_ror(t0, 31);
		vs[20] = rv_ror(t3, 31); vs[21] = t2;

		//	Chi

		kp_chi5(&vs[ 0]);
		kp_chi5(&vs[ 1]);
		kp_chi5(&vs[10]);
		kp_chi5(&vs[11]);
		kp_chi5(&vs[20]);
		kp_chi5(&vs[21]);
		kp_chi5(&vs[30]);
		kp_chi5(&vs[31]);
		kp_chi5(&vs[40]);
		kp_chi5(&vs[41]);

		//	Iota

		t0 = vs[ 0]; t1 = vs[ 1];
		vs[ 0] = t0 ^ rc[i]; vs[ 1] = t1 ^ rc[i + 1]; 
	}	

	//	un-interleave (this can be outside the function)

	kp_untrlv50(vs);
}

