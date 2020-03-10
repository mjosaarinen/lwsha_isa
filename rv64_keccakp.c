//	rv64_keccakp.c
//	2020-03-05	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2020, PQShield Ltd. All rights reserved.

//	FIPS 202 Keccak permutation implementation for a 64-bit target.

#include "bitmanip.h"

//	Keccak-p[1600,24](S)

void rv64_keccakp(void *s)
{
	//	round constants
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
	uint64_t	t, u, v, w;
	uint64_t	sa, sb, sc, sd, se, sf, sg, sh, si, sj, sk, sl, sm,
				sn, so, sp, sq, sr, ss, st, su, sv, sw, sx, sy;

	//	load state, little endian, aligned

	uint64_t	*vs = (uint64_t *) s;

	sa = vs[ 0]; sb = vs[ 1]; sc = vs[ 2]; sd = vs[ 3]; se = vs[ 4];
	sf = vs[ 5]; sg = vs[ 6]; sh = vs[ 7]; si = vs[ 8]; sj = vs[ 9];
	sk = vs[10]; sl = vs[11]; sm = vs[12]; sn = vs[13]; so = vs[14];
	sp = vs[15]; sq = vs[16]; sr = vs[17]; ss = vs[18]; st = vs[19];
	su = vs[20]; sv = vs[21]; sw = vs[22]; sx = vs[23]; sy = vs[24];

	//	iteration

	for (i = 0; i < 24; i++) {

		//	Theta

		u = sa ^ sf ^ sk ^ sp ^ su;
		v = sb ^ sg ^ sl ^ sq ^ sv;
		w = se ^ sj ^ so ^ st ^ sy;
		t = w ^ rv_rorw(v, 63);
		sa = sa ^ t;
		sf = sf ^ t;
		sk = sk ^ t;
		sp = sp ^ t;
		su = su ^ t;

		t = sd ^ si ^ sn ^ ss ^ sx;
		v = v ^ rv_rorw(t, 63);
		t = t ^ rv_rorw(u, 63);
		se = se ^ t;
		sj = sj ^ t;
		so = so ^ t;
		st = st ^ t;
		sy = sy ^ t;

		t = sc ^ sh ^ sm ^ sr ^ sw;
		u = u ^ rv_rorw(t, 63);
		t = t ^ rv_rorw(w, 63);
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

		//	Chi

		t  = rv_andn(se, sd);
		se = se ^ rv_andn(sb, sa);
		sb = sb ^ rv_andn(sd, sc);
		sd = sd ^ rv_andn(sa, se);
		sa = sa ^ rv_andn(sc, sb);
		sc = sc ^ t;

		t  = rv_andn(sj, si);
		sj = sj ^ rv_andn(sg, sf);
		sg = sg ^ rv_andn(si, sh);
		si = si ^ rv_andn(sf, sj);
		sf = sf ^ rv_andn(sh, sg);
		sh = sh ^ t;

		t  = rv_andn(so, sn);
		so = so ^ rv_andn(sl, sk);
		sl = sl ^ rv_andn(sn, sm);
		sn = sn ^ rv_andn(sk, so);
		sk = sk ^ rv_andn(sm, sl);
		sm = sm ^ t;

		t  = rv_andn(st, ss);
		st = st ^ rv_andn(sq, sp);
		sq = sq ^ rv_andn(ss, sr);
		ss = ss ^ rv_andn(sp, st);
		sp = sp ^ rv_andn(sr, sq);
		sr = sr ^ t;

		t  = rv_andn(sy, sx);
		sy = sy ^ rv_andn(sv, su);
		sv = sv ^ rv_andn(sx, sw);
		sx = sx ^ rv_andn(su, sy);
		su = su ^ rv_andn(sw, sv);
		sw = sw ^ t;

		//	Iota

		sa = sa ^ rc[i];
	}

	//	store state

	vs[ 0] = sa; vs[ 1] = sb; vs[ 2] = sc; vs[ 3] = sd; vs[ 4] = se;
	vs[ 5] = sf; vs[ 6] = sg; vs[ 7] = sh; vs[ 8] = si; vs[ 9] = sj;
	vs[10] = sk; vs[11] = sl; vs[12] = sm; vs[13] = sn; vs[14] = so;
	vs[15] = sp; vs[16] = sq; vs[17] = sr; vs[18] = ss; vs[19] = st;
	vs[20] = su; vs[21] = sv; vs[22] = sw; vs[23] = sx; vs[24] = sy;
}

