//	rv32_keccakp.c
//	2020-03-02	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2020, PQShield Ltd. All rights reserved.

//	Bit-interleaved Keccak permutation

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "insns.h"
#include "test_hex.h"
#include "sha3.h"

#ifndef ROTL64
#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))
#endif

//	Keccak-p[1600,24](S)

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

//	interleave the state

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

//	un-interleave the state

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

void rv32_keccakp(void *s)
{
	//	round constants
	const uint64_t rc[24] = {
		0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
		0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
		0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
		0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
		0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
		0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
		0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
		0x8000000000008080, 0x0000000080000001, 0x8000000080008008
	};

	int 		i, j;
	uint64_t	t;
	uint64_t	sa, sb, sc, sd, se, sf, sg, sh, si, sj, sk, sl, sm,
				sn, so, sp, sq, sr, ss, st, su, sv, sw, sx, sy;

	//	load state, little endian, aligned

	uint32_t	*vs = (uint32_t *) s;
	uint64_t	*ts = (uint64_t *) s;

	uint32_t	xa0, xa1, xb0, xb1, xc0, xc1, xd0, xd1, xe0, xe1;

	//	iteration

	for (i = 0; i < 24; i++) {

		kp_intrlv50(vs);

		//	Theta
		xa0 = kp_par5(&vs[ 0]);
		xa1 = kp_par5(&vs[ 1]);
		xb0 = kp_par5(&vs[ 2]);
		xb1 = kp_par5(&vs[ 3]);
		xc0 = kp_par5(&vs[ 4]);
		xc1 = kp_par5(&vs[ 5]);
		xd0 = kp_par5(&vs[ 6]);
		xd1 = kp_par5(&vs[ 7]);
		xe0 = kp_par5(&vs[ 8]);
		xe1 = kp_par5(&vs[ 9]);

		kp_xor10(&vs[ 0], xe0 ^ rv_ror(xb1, 31), xe1 ^ xb0);
		kp_xor10(&vs[ 2], xa0 ^ rv_ror(xc1, 31), xa1 ^ xc0);
		kp_xor10(&vs[ 4], xb0 ^ rv_ror(xd1, 31), xb1 ^ xd0);
		kp_xor10(&vs[ 6], xc0 ^ rv_ror(xe1, 31), xc1 ^ xe0);
		kp_xor10(&vs[ 8], xd0 ^ rv_ror(xa1, 31), xd1 ^ xa0);

		kp_untrlv50(vs);

	sa = ts[ 0]; sb = ts[ 1]; sc = ts[ 2]; sd = ts[ 3]; se = ts[ 4];
	sf = ts[ 5]; sg = ts[ 6]; sh = ts[ 7]; si = ts[ 8]; sj = ts[ 9];
	sk = ts[10]; sl = ts[11]; sm = ts[12]; sn = ts[13]; so = ts[14];
	sp = ts[15]; sq = ts[16]; sr = ts[17]; ss = ts[18]; st = ts[19];
	su = ts[20]; sv = ts[21]; sw = ts[22]; sx = ts[23]; sy = ts[24];

		//	Rho Pi

		t  = rv_rorw(sb, 63);
		sb = rv_rorw(sg, 20);
		sg = rv_rorw(sj, 44);
		sj = rv_rorw(sw,  3);
		sw = rv_rorw(so, 25);
		so = rv_rorw(su, 46);
		su = rv_rorw(sc,  2);
		sc = rv_rorw(sm, 21);
		sm = rv_rorw(sn, 39);
		sn = rv_rorw(st, 56);
		st = rv_rorw(sx,  8);
		sx = rv_rorw(sp, 23);
		sp = rv_rorw(se, 37);
		se = rv_rorw(sy, 50);
		sy = rv_rorw(sv, 62);
		sv = rv_rorw(si,  9);
		si = rv_rorw(sq, 19);
		sq = rv_rorw(sf, 28);
		sf = rv_rorw(sd, 36);
		sd = rv_rorw(ss, 43);
		ss = rv_rorw(sr, 49);
		sr = rv_rorw(sl, 54);
		sl = rv_rorw(sh, 58);
		sh = rv_rorw(sk, 61);
		sk = t;

	//	store state
	ts[ 0] = sa; ts[ 1] = sb; ts[ 2] = sc; ts[ 3] = sd; ts[ 4] = se;
	ts[ 5] = sf; ts[ 6] = sg; ts[ 7] = sh; ts[ 8] = si; ts[ 9] = sj;
	ts[10] = sk; ts[11] = sl; ts[12] = sm; ts[13] = sn; ts[14] = so;
	ts[15] = sp; ts[16] = sq; ts[17] = sr; ts[18] = ss; ts[19] = st;
	ts[20] = su; ts[21] = sv; ts[22] = sw; ts[23] = sx; ts[24] = sy;

		//	Chi

		kp_intrlv50(vs);

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

		kp_untrlv50(vs);

		ts[ 0] ^= rc[i];
	
	}	
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

int gek()
{
	int i;
	uint64_t st[25];
	int fail = 0;

	for (i = 0; i < 25; i++) {
		st[i] = i;
	}

	rv32_keccakp(st);

	fail += chkhex("st", st, sizeof(st),
		"1581ED5252B07483009456B676A6F71D7D79518A4B1965F745"
		"0576D1437B47206A60F6F3A48B5FD193D48D7C4F14D7A13FFD"
		"38519693D130BEE31B9572947E485A7ADACB58A8F30C887FB1"
		"9B384EE52F8F269F0DDE38730B7F6D258BF5DFEF556A3E2CEB"
		"943E35C8111F908C94F62A2EA69D30CA0CDE73E8E2314D946C"
		"C2AFF7D715C48C80EAF5A0CFD83E7E4331F55321D2A4433B1F"
		"7F7785E999B43CA60CFD3023D1C5C055C0D4DFA7E0A68AE52F"
		"A7A348997C93F51A42880834713010165E334A7E293AF453D1");

	return fail;
}


int gvk()
{
	int i;
	int r0, r1;

	uint32_t x0, x1, y0, y1;
	uint64_t x, y, z;

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

