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
	uint64_t u;

	uint64_t	ta, tb, tc, td, te;

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

		ta = sa ^ sf ^ sk ^ sp ^ su;	//	20 XOR
		tb = sb ^ sg ^ sl ^ sq ^ sv;
		tc = sc ^ sh ^ sm ^ sr ^ sw;
		td = sd ^ si ^ sn ^ ss ^ sx;
		u  = se ^ sj ^ so ^ st ^ sy;

		te = u	^ rv_rorw(tb, 63);		//	5 RORW, 5 XOR
		tb = tb ^ rv_rorw(td, 63);
		td = td ^ rv_rorw(ta, 63);
		ta = ta ^ rv_rorw(tc, 63);
		tc = tc ^ rv_rorw( u, 63);

		sa = sa ^ te;					//	1 xor
		u  = rv_rorw(sb ^ ta, 63);		//	24 XOR, 24 RORW
		sb = rv_rorw(sg ^ ta, 20);
		sg = rv_rorw(sj ^ td, 44);
		sj = rv_rorw(sw ^ tb,  3);
		sw = rv_rorw(so ^ td, 25);
		so = rv_rorw(su ^ te, 46);
		su = rv_rorw(sc ^ tb,  2);
		sc = rv_rorw(sm ^ tb, 21);
		sm = rv_rorw(sn ^ tc, 39);
		sn = rv_rorw(st ^ td, 56);
		st = rv_rorw(sx ^ tc,  8);
		sx = rv_rorw(sp ^ te, 23);
		sp = rv_rorw(se ^ td, 37);
		se = rv_rorw(sy ^ td, 50);
		sy = rv_rorw(sv ^ ta, 62);
		sv = rv_rorw(si ^ tc,  9);
		si = rv_rorw(sq ^ ta, 19);
		sq = rv_rorw(sf ^ te, 28);
		sf = rv_rorw(sd ^ tc, 36);
		sd = rv_rorw(ss ^ tc, 43);
		ss = rv_rorw(sr ^ tb, 49);
		sr = rv_rorw(sl ^ ta, 54);
		sl = rv_rorw(sh ^ tb, 58);
		sh = rv_rorw(sk ^ te, 61);
		sk = u;

		//	Chi

		ta = rv_andn(sb, sc);			//	25 ANDN, 25 XOR
		tb = rv_andn(sc, sd);
		tc = rv_andn(sd, se);
		td = rv_andn(se, sa);
		te = rv_andn(sa, sb);
		sa = sa ^ ta;
		sb = sb ^ tb;
		sc = sc ^ tc;
		sd = sd ^ td;
		se = se ^ te;
		ta = rv_andn(sg, sh);
		tb = rv_andn(sh, si);
		tc = rv_andn(si, sj);
		td = rv_andn(sj, sf);
		te = rv_andn(sf, sg);
		sf = sf ^ ta;
		sg = sg ^ tb;
		sh = sh ^ tc;
		si = si ^ td;
		sj = sj ^ te;
		ta = rv_andn(sl, sm);
		tb = rv_andn(sm, sn);
		tc = rv_andn(sn, so);
		td = rv_andn(so, sk);
		te = rv_andn(sk, sl);
		sk = sk ^ ta;
		sl = sl ^ tb;
		sm = sm ^ tc;
		sn = sn ^ td;
		so = so ^ te;
		ta = rv_andn(sq, sr);
		tb = rv_andn(sr, ss);
		tc = rv_andn(ss, st);
		td = rv_andn(st, sp);
		te = rv_andn(sp, sq);
		sp = sp ^ ta;
		sq = sq ^ tb;
		sr = sr ^ tc;
		ss = ss ^ td;
		st = st ^ te;
		ta = rv_andn(sv, sw);
		tb = rv_andn(sw, sx);
		tc = rv_andn(sx, sy);
		td = rv_andn(sy, su);
		te = rv_andn(su, sv);
		su = su ^ ta;
		sv = sv ^ tb;
		sw = sw ^ tc;
		sx = sx ^ td;
		sy = sy ^ te;

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

