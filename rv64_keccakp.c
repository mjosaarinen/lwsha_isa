//	rv64_keccakp.c
//	2020-03-05	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2020, PQShield Ltd. All rights reserved.

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "sha3.h"
#include "xrand.h"


//	RORW / RORIW

static uint64_t rv_rorw(uint64_t rs1, uint64_t rs2)
{
	int shamt = rs2 & (64 - 1);
	return (rs1 >> shamt) | (rs1 << ((64 - shamt) & (64 - 1)));
}

//	ANDN

static uint64_t rv_andn(uint64_t rs1, uint64_t rs2)
{
	return ~rs1 & rs2;
}


static void prtst(const void *p)
{
	int i;
	const uint64_t *v = ((const uint64_t *) p);

	for (i = 0; i < 25; i += 5) {
		printf("%2d : %016lX %016lX %016lX %016lX %016lX\n",
			i, v[i], v[i + 1], v[i + 2], v[i + 3], v[i + 4]);
	}
}

// update the state with given number of rounds

void rv64_keccakf(uint64_t s[25], int rounds)
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

	// variables
	int i;
	uint64_t	t, x, y, z;

	uint64_t	sa, sb, sc, sd, se,
				sf, sg, sh, si, sj,
				sk, sl, sm, sn, so,
				sp, sq, sr, ss, st,
				su, sv, sw, sx, sy;

	sa = s[ 0];
	sb = s[ 1];
	sc = s[ 2];
	sd = s[ 3];
	se = s[ 4];
	sf = s[ 5];
	sg = s[ 6];
	sh = s[ 7];
	si = s[ 8];
	sj = s[ 9];
	sk = s[10];
	sl = s[11];
	sm = s[12];
	sn = s[13];
	so = s[14];
	sp = s[15];
	sq = s[16];
	sr = s[17];
	ss = s[18];
	st = s[19];
	su = s[20];
	sv = s[21];
	sw = s[22];
	sx = s[23];
	sy = s[24];

	//	iteration

	for (i = 0; i < rounds; i++) {

		//	Theta Rho Pi

		x = sa ^ sf ^ sk ^ sp ^ su;
		y = sb ^ sg ^ sl ^ sq ^ sv;
		z = se ^ sj ^ so ^ st ^ sy;
		t = z ^ rv_rorw(y, 63);
		sa = sa ^ t;
		sf = sf ^ t;
		sk = sk ^ t;
		sp = sp ^ t;
		su = su ^ t;

		t = sd ^ si ^ sn ^ ss ^ sx;
		y = y ^ rv_rorw(t, 63);
		t = t ^ rv_rorw(x, 63);
		se = se ^ t;
		sj = sj ^ t;
		so = so ^ t;
		st = st ^ t;
		sy = sy ^ t;

		t = sc ^ sh ^ sm ^ sr ^ sw;
		x = x ^ rv_rorw(t, 63);
		z = t ^ rv_rorw(z, 63);

		sc = sc ^ y;
		sh = sh ^ y;
		sm = sm ^ y;
		sr = sr ^ y;
		sw = sw ^ y;

		sb = sb ^ x;
		sg = sg ^ x;
		sl = sl ^ x;
		sq = sq ^ x;
		sv = sv ^ x;

		sd = sd ^ z;
		si = si ^ z;
		sn = sn ^ z;
		ss = ss ^ z;
		sx = sx ^ z;

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

		//	Chi

		t  = rv_andn(sd, se);
		se = se ^ rv_andn(sa, sb);
		sb = sb ^ rv_andn(sc, sd);
		sd = sd ^ rv_andn(se, sa);
		sa = sa ^ rv_andn(sb, sc);
		sc = sc ^ t;

		t  = rv_andn(si, sj);
		sj = sj ^ rv_andn(sf, sg);
		sg = sg ^ rv_andn(sh, si);
		si = si ^ rv_andn(sj, sf);
		sf = sf ^ rv_andn(sg, sh);
		sh = sh ^ t;

		t  = rv_andn(sn, so);
		so = so ^ rv_andn(sk, sl);
		sl = sl ^ rv_andn(sm, sn);
		sn = sn ^ rv_andn(so, sk);
		sk = sk ^ rv_andn(sl, sm);
		sm = sm ^ t;

		t  = rv_andn(ss, st);
		st = st ^ rv_andn(sp, sq);
		sq = sq ^ rv_andn(sr, ss);
		ss = ss ^ rv_andn(st, sp);
		sp = sp ^ rv_andn(sq, sr);
		sr = sr ^ t;

		t  = rv_andn(sx, sy);
		sy = sy ^ rv_andn(su, sv);
		sv = sv ^ rv_andn(sw, sx);
		sx = sx ^ rv_andn(sy, su);
		su = su ^ rv_andn(sv, sw);
		sw = sw ^ t;

		//	Iota

		sa ^= keccakf_rndc[i];			//	1 load, 1 XOR
	}

	s[ 0] = sa;
	s[ 1] = sb;
	s[ 2] = sc;
	s[ 3] = sd;
	s[ 4] = se;
	s[ 5] = sf;
	s[ 6] = sg;
	s[ 7] = sh;
	s[ 8] = si;
	s[ 9] = sj;
	s[10] = sk;
	s[11] = sl;
	s[12] = sm;
	s[13] = sn;
	s[14] = so;
	s[15] = sp;
	s[16] = sq;
	s[17] = sr;
	s[18] = ss;
	s[19] = st;
	s[20] = su;
	s[21] = sv;
	s[22] = sw;
	s[23] = sx;
	s[24] = sy;
}


int gek()
{
	int i, d;
	uint64_t sa[25], sb[25];

	for (i = 0; i < 25; i++) {
		sa[i] = i;
	}

	memcpy(sb, sa, sizeof(sb));

	sha3_keccakf(sb, 24);
	prtst(sb);
	printf("\n");

	rv64_keccakf(sa, 24);
	prtst(sa);

	d = 0;
	for (i = 0; i < 25; i++) {
		d += __builtin_popcountll(sa[i] ^ sb[i]);
	}
	printf("d = %d\n", d);

	return 0;
}

