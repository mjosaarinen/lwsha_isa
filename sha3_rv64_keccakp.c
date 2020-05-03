//  sha3_rv64_keccakp.c
//  2020-03-05  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  FIPS 202 Keccak permutation implementation for a 64-bit target.

#include "bitmanip.h"

//  Keccak-p[1600,24](S)

void rv64_keccakp(void *s)
{
	//  round constants
	const uint64_t rc[24] = {
		0x0000000000000001LL, 0x0000000000008082LL, 0x800000000000808ALL,
		0x8000000080008000LL, 0x000000000000808BLL, 0x0000000080000001LL,
		0x8000000080008081LL, 0x8000000000008009LL, 0x000000000000008ALL,
		0x0000000000000088LL, 0x0000000080008009LL, 0x000000008000000ALL,
		0x000000008000808BLL, 0x800000000000008BLL, 0x8000000000008089LL,
		0x8000000000008003LL, 0x8000000000008002LL, 0x8000000000000080LL,
		0x000000000000800ALL, 0x800000008000000ALL, 0x8000000080008081LL,
		0x8000000000008080LL, 0x0000000080000001LL, 0x8000000080008008LL
	};

	int i;
	uint64_t t, u, v, w;
	uint64_t sa, sb, sc, sd, se, sf, sg, sh, si, sj, sk, sl, sm,
		sn, so, sp, sq, sr, ss, st, su, sv, sw, sx, sy;

	//  load state, little endian, aligned

	uint64_t *vs = (uint64_t *) s;

	sa = vs[0];
	sb = vs[1];
	sc = vs[2];
	sd = vs[3];
	se = vs[4];
	sf = vs[5];
	sg = vs[6];
	sh = vs[7];
	si = vs[8];
	sj = vs[9];
	sk = vs[10];
	sl = vs[11];
	sm = vs[12];
	sn = vs[13];
	so = vs[14];
	sp = vs[15];
	sq = vs[16];
	sr = vs[17];
	ss = vs[18];
	st = vs[19];
	su = vs[20];
	sv = vs[21];
	sw = vs[22];
	sx = vs[23];
	sy = vs[24];

	//  iteration

	for (i = 0; i < 24; i++) {

		//  Theta

		u = sa ^ sf ^ sk ^ sp ^ su;
		v = sb ^ sg ^ sl ^ sq ^ sv;
		w = se ^ sj ^ so ^ st ^ sy;
		t = w ^ rv64b_ror(v, 63);
		sa = sa ^ t;
		sf = sf ^ t;
		sk = sk ^ t;
		sp = sp ^ t;
		su = su ^ t;

		t = sd ^ si ^ sn ^ ss ^ sx;
		v = v ^ rv64b_ror(t, 63);
		t = t ^ rv64b_ror(u, 63);
		se = se ^ t;
		sj = sj ^ t;
		so = so ^ t;
		st = st ^ t;
		sy = sy ^ t;

		t = sc ^ sh ^ sm ^ sr ^ sw;
		u = u ^ rv64b_ror(t, 63);
		t = t ^ rv64b_ror(w, 63);
		sc = sc ^ v;
		sh = sh ^ v;
		sm = sm ^ v;
		sr = sr ^ v;
		sw = sw ^ v;

		sb = sb ^ u;
		sg = sg ^ u;
		sl = sl ^ u;
		sq = sq ^ u;
		sv = sv ^ u;

		sd = sd ^ t;
		si = si ^ t;
		sn = sn ^ t;
		ss = ss ^ t;
		sx = sx ^ t;

		//  Rho Pi

		t = rv64b_ror(sb, 63);
		sb = rv64b_ror(sg, 20);
		sg = rv64b_ror(sj, 44);
		sj = rv64b_ror(sw, 3);
		sw = rv64b_ror(so, 25);
		so = rv64b_ror(su, 46);
		su = rv64b_ror(sc, 2);
		sc = rv64b_ror(sm, 21);
		sm = rv64b_ror(sn, 39);
		sn = rv64b_ror(st, 56);
		st = rv64b_ror(sx, 8);
		sx = rv64b_ror(sp, 23);
		sp = rv64b_ror(se, 37);
		se = rv64b_ror(sy, 50);
		sy = rv64b_ror(sv, 62);
		sv = rv64b_ror(si, 9);
		si = rv64b_ror(sq, 19);
		sq = rv64b_ror(sf, 28);
		sf = rv64b_ror(sd, 36);
		sd = rv64b_ror(ss, 43);
		ss = rv64b_ror(sr, 49);
		sr = rv64b_ror(sl, 54);
		sl = rv64b_ror(sh, 58);
		sh = rv64b_ror(sk, 61);
		sk = t;

		//  Chi

		t = rv64b_andn(se, sd);
		se = se ^ rv64b_andn(sb, sa);
		sb = sb ^ rv64b_andn(sd, sc);
		sd = sd ^ rv64b_andn(sa, se);
		sa = sa ^ rv64b_andn(sc, sb);
		sc = sc ^ t;

		t = rv64b_andn(sj, si);
		sj = sj ^ rv64b_andn(sg, sf);
		sg = sg ^ rv64b_andn(si, sh);
		si = si ^ rv64b_andn(sf, sj);
		sf = sf ^ rv64b_andn(sh, sg);
		sh = sh ^ t;

		t = rv64b_andn(so, sn);
		so = so ^ rv64b_andn(sl, sk);
		sl = sl ^ rv64b_andn(sn, sm);
		sn = sn ^ rv64b_andn(sk, so);
		sk = sk ^ rv64b_andn(sm, sl);
		sm = sm ^ t;

		t = rv64b_andn(st, ss);
		st = st ^ rv64b_andn(sq, sp);
		sq = sq ^ rv64b_andn(ss, sr);
		ss = ss ^ rv64b_andn(sp, st);
		sp = sp ^ rv64b_andn(sr, sq);
		sr = sr ^ t;

		t = rv64b_andn(sy, sx);
		sy = sy ^ rv64b_andn(sv, su);
		sv = sv ^ rv64b_andn(sx, sw);
		sx = sx ^ rv64b_andn(su, sy);
		su = su ^ rv64b_andn(sw, sv);
		sw = sw ^ t;

		//  Iota

		sa = sa ^ rc[i];
	}

	//  store state

	vs[0] = sa;
	vs[1] = sb;
	vs[2] = sc;
	vs[3] = sd;
	vs[4] = se;
	vs[5] = sf;
	vs[6] = sg;
	vs[7] = sh;
	vs[8] = si;
	vs[9] = sj;
	vs[10] = sk;
	vs[11] = sl;
	vs[12] = sm;
	vs[13] = sn;
	vs[14] = so;
	vs[15] = sp;
	vs[16] = sq;
	vs[17] = sr;
	vs[18] = ss;
	vs[19] = st;
	vs[20] = su;
	vs[21] = sv;
	vs[22] = sw;
	vs[23] = sx;
	vs[24] = sy;
}
