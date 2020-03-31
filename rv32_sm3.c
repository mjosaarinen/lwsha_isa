//  rv32_sm3.c
//  2020-03-10  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  The Chinese Standard SM3 Hash Function
//  GB/T 32905-2016, GM/T 0004-2012, ISO/IEC 10118-3:2018
#include "sm3.h"

//  bitmanip (emulation) prototypes here
#include "bitmanip.h"

//  4.4 Permutations (defined with left shifts)

uint32_t sm3_p0(uint32_t rs1)
{
	return rs1 ^ rvb_ror(rs1, 15) ^ rvb_ror(rs1, 23);
}

uint32_t sm3_p1(uint32_t rs1)
{
	return rs1 ^ rvb_ror(rs1, 9) ^ rvb_ror(rs1, 17);
}


//  key schedule

#define SM3KEY(w0, w3, w7, wa, wd) {				\
	t = w0 ^ w7 ^ rvb_ror(wd, 17);					\
	t = sm3_p1(t);									\
	w0 = wa ^ rvb_ror(w3, 25) ^ t;					}

//  rounds 0..15

#define SM3RF0(a, b, c, d, e, f, g, h, w0, w4) {	\
	h = h + w0;										\
	t = rvb_ror(a, 20);								\
	u = t + e + tj;									\
	u = rvb_ror(u, 25);								\
	d = d + (t ^ u) + (a ^ b ^ c);					\
	b = rvb_ror(b, 23);								\
	h = h + u + (e ^ f ^ g);						\
	h = sm3_p0(h);									\
	f = rvb_ror(f, 13);								\
	d = d + (w0 ^ w4);								\
	tj = rvb_ror(tj, 31);							}

//  rounds 16..63

#define SM3RF1(a, b, c, d, e, f, g, h, w0, w4) {	\
	h = h + w0;										\
	t = rvb_ror(a, 20);								\
	u = t + e + tj;									\
	u = rvb_ror(u, 25);								\
	d = d + (t ^ u) + (((a | c) & b) | (a & c));	\
	b = rvb_ror(b, 23);								\
	h = h + u + ((e & f) ^ rvb_andn(g, e));			\
	h = sm3_p0(h);									\
	f = rvb_ror(f, 13);								\
	d = d + (w0 ^ w4);								\
	tj = rvb_ror(tj, 31);							}


//  compression function (this one does *not* modify m[8..23])

void rv32_sm3_compress(void *s)
{
	int i;
	uint32_t a, b, c, d, e, f, g, h;
	uint32_t m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, ma, mb, mc, md, me, mf;
	uint32_t tj, t, u;

	uint32_t *sp = s;
	const uint32_t *mp = sp + 8;

	a = sp[0];
	b = sp[1];
	c = sp[2];
	d = sp[3];
	e = sp[4];
	f = sp[5];
	g = sp[6];
	h = sp[7];

	//  load with rev8.w

	m0 = rvb_grev(mp[0], 0x18);
	m1 = rvb_grev(mp[1], 0x18);
	m2 = rvb_grev(mp[2], 0x18);
	m3 = rvb_grev(mp[3], 0x18);
	m4 = rvb_grev(mp[4], 0x18);
	m5 = rvb_grev(mp[5], 0x18);
	m6 = rvb_grev(mp[6], 0x18);
	m7 = rvb_grev(mp[7], 0x18);
	m8 = rvb_grev(mp[8], 0x18);
	m9 = rvb_grev(mp[9], 0x18);
	ma = rvb_grev(mp[10], 0x18);
	mb = rvb_grev(mp[11], 0x18);
	mc = rvb_grev(mp[12], 0x18);
	md = rvb_grev(mp[13], 0x18);
	me = rvb_grev(mp[14], 0x18);
	mf = rvb_grev(mp[15], 0x18);

	tj = 0x79CC4519;

	SM3RF0(a, b, c, d, e, f, g, h, m0, m4);
	SM3RF0(d, a, b, c, h, e, f, g, m1, m5);
	SM3RF0(c, d, a, b, g, h, e, f, m2, m6);
	SM3RF0(b, c, d, a, f, g, h, e, m3, m7);

	SM3RF0(a, b, c, d, e, f, g, h, m4, m8);
	SM3RF0(d, a, b, c, h, e, f, g, m5, m9);
	SM3RF0(c, d, a, b, g, h, e, f, m6, ma);
	SM3RF0(b, c, d, a, f, g, h, e, m7, mb);

	SM3RF0(a, b, c, d, e, f, g, h, m8, mc);
	SM3RF0(d, a, b, c, h, e, f, g, m9, md);
	SM3RF0(c, d, a, b, g, h, e, f, ma, me);
	SM3RF0(b, c, d, a, f, g, h, e, mb, mf);

	SM3KEY(m0, m3, m7, ma, md);
	SM3KEY(m1, m4, m8, mb, me);
	SM3KEY(m2, m5, m9, mc, mf);
	SM3KEY(m3, m6, ma, md, m0);

	SM3RF0(a, b, c, d, e, f, g, h, mc, m0);
	SM3RF0(d, a, b, c, h, e, f, g, md, m1);
	SM3RF0(c, d, a, b, g, h, e, f, me, m2);
	SM3RF0(b, c, d, a, f, g, h, e, mf, m3);

	tj = 0x9D8A7A87;

	for (i = 0; i < 3; i++) {

		SM3KEY(m4, m7, mb, me, m1);
		SM3KEY(m5, m8, mc, mf, m2);
		SM3KEY(m6, m9, md, m0, m3);
		SM3KEY(m7, ma, me, m1, m4);
		SM3KEY(m8, mb, mf, m2, m5);
		SM3KEY(m9, mc, m0, m3, m6);
		SM3KEY(ma, md, m1, m4, m7);
		SM3KEY(mb, me, m2, m5, m8);
		SM3KEY(mc, mf, m3, m6, m9);
		SM3KEY(md, m0, m4, m7, ma);
		SM3KEY(me, m1, m5, m8, mb);
		SM3KEY(mf, m2, m6, m9, mc);

		SM3RF1(a, b, c, d, e, f, g, h, m0, m4);
		SM3RF1(d, a, b, c, h, e, f, g, m1, m5);
		SM3RF1(c, d, a, b, g, h, e, f, m2, m6);
		SM3RF1(b, c, d, a, f, g, h, e, m3, m7);

		SM3RF1(a, b, c, d, e, f, g, h, m4, m8);
		SM3RF1(d, a, b, c, h, e, f, g, m5, m9);
		SM3RF1(c, d, a, b, g, h, e, f, m6, ma);
		SM3RF1(b, c, d, a, f, g, h, e, m7, mb);

		SM3RF1(a, b, c, d, e, f, g, h, m8, mc);
		SM3RF1(d, a, b, c, h, e, f, g, m9, md);
		SM3RF1(c, d, a, b, g, h, e, f, ma, me);
		SM3RF1(b, c, d, a, f, g, h, e, mb, mf);

		SM3KEY(m0, m3, m7, ma, md);
		SM3KEY(m1, m4, m8, mb, me);
		SM3KEY(m2, m5, m9, mc, mf);
		SM3KEY(m3, m6, ma, md, m0);

		SM3RF1(a, b, c, d, e, f, g, h, mc, m0);
		SM3RF1(d, a, b, c, h, e, f, g, md, m1);
		SM3RF1(c, d, a, b, g, h, e, f, me, m2);
		SM3RF1(b, c, d, a, f, g, h, e, mf, m3);

	}

	sp[0] = sp[0] ^ a;
	sp[1] = sp[1] ^ b;
	sp[2] = sp[2] ^ c;
	sp[3] = sp[3] ^ d;
	sp[4] = sp[4] ^ e;
	sp[5] = sp[5] ^ f;
	sp[6] = sp[6] ^ g;
	sp[7] = sp[7] ^ h;
}
