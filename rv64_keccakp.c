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

	//	iteration
	for (i = 0; i < rounds; i++) {

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

		//	Theta

		ta = sa ^ sf ^ sk ^ sp ^ su;
		tb = sb ^ sg ^ sl ^ sq ^ sv;
		tc = sc ^ sh ^ sm ^ sr ^ sw;
		td = sd ^ si ^ sn ^ ss ^ sx;
		te = se ^ sj ^ so ^ st ^ sy;

		u = te;	
		te ^= rv_rorw(tb, 63);
		tb ^= rv_rorw(td, 63);
		td ^= rv_rorw(ta, 63);
		ta ^= rv_rorw(tc, 63);
		tc ^= rv_rorw( u, 63);

		sa ^= te;
		sf ^= te;
		sk ^= te;
		sp ^= te;
		su ^= te;
		sb ^= ta;
		sg ^= ta;
		sl ^= ta;
		sq ^= ta;
		sv ^= ta;
		sc ^= tb;
		sh ^= tb;
		sm ^= tb;
		sr ^= tb;
		sw ^= tb;
		sd ^= tc;
		si ^= tc;
		sn ^= tc;
		ss ^= tc;
		sx ^= tc;
		se ^= td;
		sj ^= td;
		so ^= td;
		st ^= td;
		sy ^= td;

		//	Rho Pi

		u  = rv_rorw(sb, 63);
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
		sk = u;

		//	Chi

		ta = ~sb & sc;
		tb = ~sc & sd;
		tc = ~sd & se;
		td = ~se & sa;
		te = ~sa & sb;
		sa ^= ta;
		sb ^= tb;
		sc ^= tc;
		sd ^= td;
		se ^= te;
		ta = ~sg & sh;
		tb = ~sh & si;
		tc = ~si & sj;
		td = ~sj & sf;
		te = ~sf & sg;
		sf ^= ta;
		sg ^= tb;
		sh ^= tc;
		si ^= td;
		sj ^= te;
		ta = ~sl & sm;
		tb = ~sm & sn;
		tc = ~sn & so;
		td = ~so & sk;
		te = ~sk & sl;
		sk ^= ta;
		sl ^= tb;
		sm ^= tc;
		sn ^= td;
		so ^= te;
		ta = ~sq & sr;
		tb = ~sr & ss;
		tc = ~ss & st;
		td = ~st & sp;
		te = ~sp & sq;
		sp ^= ta;
		sq ^= tb;
		sr ^= tc;
		ss ^= td;
		st ^= te;
		ta = ~sv & sw;
		tb = ~sw & sx;
		tc = ~sx & sy;
		td = ~sy & su;
		te = ~su & sv;
		su ^= ta;
		sv ^= tb;
		sw ^= tc;
		sx ^= td;
		sy ^= te;

		//	Iota
		sa ^= keccakf_rndc[i];

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

