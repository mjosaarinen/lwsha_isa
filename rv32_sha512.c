//  rv64_sha512.c
//  2020-03-08  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  FIPS 180-4 SHA2-384/512 compression function for RV64

#include "sha2.h"

//  bitmanip (emulation) prototypes here
#include "bitmanip.h"

//  4.1.3 SHA-384, SHA-512, SHA-512/224 and SHA-512/256 Functions
//  these four are intended as ISA extensions

//  upper case sigma0, sigma1 is "sum"

uint32_t sha512_sum0l(uint32_t rs1, uint32_t rs2)
{
	uint64_t t = ((uint64_t) rs1) | (((uint64_t) rs2) << 32);
	t = (rvb_rorw(t, 28) ^ rvb_rorw(t, 34) ^ rvb_rorw(t, 39));
	return (uint32_t) t;
}

uint32_t sha512_sum0h(uint32_t rs1, uint32_t rs2)
{
	uint64_t t = ((uint64_t) rs1) | (((uint64_t) rs2) << 32);
	t = (rvb_rorw(t, 28) ^ rvb_rorw(t, 34) ^ rvb_rorw(t, 39));
	return (uint32_t) (t >> 32);
}

uint32_t sha512_sum1l(uint32_t rs1, uint32_t rs2)
{
	uint64_t t = ((uint64_t) rs1) | (((uint64_t) rs2) << 32);
	t = rvb_rorw(t, 14) ^ rvb_rorw(t, 18) ^ rvb_rorw(t, 41);
	return (uint32_t) t;
}

uint32_t sha512_sum1h(uint32_t rs1, uint32_t rs2)
{
	uint64_t t = ((uint64_t) rs1) | (((uint64_t) rs2) << 32);
	t = rvb_rorw(t, 14) ^ rvb_rorw(t, 18) ^ rvb_rorw(t, 41);
	return (uint32_t) (t >> 32);
}

//  lower case sigma0, sigma1 is "sig"

uint32_t sha512_sig0l(uint32_t rs1, uint32_t rs2)
{
	uint64_t t = ((uint64_t) rs1) | (((uint64_t) rs2) << 32);
	t = rvb_rorw(t, 1) ^ rvb_rorw(t, 8) ^ (t >> 7);
	return (uint32_t) t;
}

uint32_t sha512_sig0h(uint32_t rs1, uint32_t rs2)
{
	uint64_t t = ((uint64_t) rs1) | (((uint64_t) rs2) << 32);
	t = rvb_rorw(t, 1) ^ rvb_rorw(t, 8) ^ (t >> 7);
	return (uint32_t) (t >> 32);
}

uint32_t sha512_sig1l(uint32_t rs1, uint32_t rs2)
{
	uint64_t t = ((uint64_t) rs1) | (((uint64_t) rs2) << 32);
	t = rvb_rorw(t, 19) ^ rvb_rorw(t, 61) ^ (t >> 6);
	return (uint32_t) t;
}

uint32_t sha512_sig1h(uint32_t rs1, uint32_t rs2)
{
	uint64_t t = ((uint64_t) rs1) | (((uint64_t) rs2) << 32);
	t = rvb_rorw(t, 19) ^ rvb_rorw(t, 61) ^ (t >> 6);
	return (uint32_t) (t >> 32);
}

uint32_t rv32_sltu(uint32_t rs1, uint32_t rs2)
{
	return rs1 < rs2 ? 1 : 0;
}


//  (((a | c) & b) | (c & a)) = Maj(a, b, c)
//  ((e & f) ^ rvb_andn(g, e)) = Ch(e, f, g)

//  64-bit addition; 3 * ADD, 1 * SLTU

#define ADD64(dl, dh, s1l, s1h, s2l, s2h) {	\
	dl = s1l + s2l;							\
	dh = s1h + s2h + rv32_sltu(dl, s2l);	}

#define LSADD64(p0, p1, xl, xh) 	{	\
	tl = p0 + xl;						\
	th = p1 + xh + rv32_sltu(tl, xl);	\
	p0 = tl;							\
	p1 = th;							}

//  compression function (this one does *not* modify m[16])


const uint32_t ck[160] = {
	0xD728AE22, 0x428A2F98, 0x23EF65CD, 0x71374491, 0xEC4D3B2F, 0xB5C0FBCF,
	0x8189DBBC, 0xE9B5DBA5, 0xF348B538, 0x3956C25B, 0xB605D019, 0x59F111F1,
	0xAF194F9B, 0x923F82A4, 0xDA6D8118, 0xAB1C5ED5, 0xA3030242, 0xD807AA98,
	0x45706FBE, 0x12835B01, 0x4EE4B28C, 0x243185BE, 0xD5FFB4E2, 0x550C7DC3,
	0xF27B896F, 0x72BE5D74, 0x3B1696B1, 0x80DEB1FE, 0x25C71235, 0x9BDC06A7,
	0xCF692694, 0xC19BF174, 0x9EF14AD2, 0xE49B69C1, 0x384F25E3, 0xEFBE4786,
	0x8B8CD5B5, 0x0FC19DC6, 0x77AC9C65, 0x240CA1CC, 0x592B0275, 0x2DE92C6F,
	0x6EA6E483, 0x4A7484AA, 0xBD41FBD4, 0x5CB0A9DC, 0x831153B5, 0x76F988DA,
	0xEE66DFAB, 0x983E5152, 0x2DB43210, 0xA831C66D, 0x98FB213F, 0xB00327C8,
	0xBEEF0EE4, 0xBF597FC7, 0x3DA88FC2, 0xC6E00BF3, 0x930AA725, 0xD5A79147,
	0xE003826F, 0x06CA6351, 0x0A0E6E70, 0x14292967, 0x46D22FFC, 0x27B70A85,
	0x5C26C926, 0x2E1B2138, 0x5AC42AED, 0x4D2C6DFC, 0x9D95B3DF, 0x53380D13,
	0x8BAF63DE, 0x650A7354, 0x3C77B2A8, 0x766A0ABB, 0x47EDAEE6, 0x81C2C92E,
	0x1482353B, 0x92722C85, 0x4CF10364, 0xA2BFE8A1, 0xBC423001, 0xA81A664B,
	0xD0F89791, 0xC24B8B70, 0x0654BE30, 0xC76C51A3, 0xD6EF5218, 0xD192E819,
	0x5565A910, 0xD6990624, 0x5771202A, 0xF40E3585, 0x32BBD1B8, 0x106AA070,
	0xB8D2D0C8, 0x19A4C116, 0x5141AB53, 0x1E376C08, 0xDF8EEB99, 0x2748774C,
	0xE19B48A8, 0x34B0BCB5, 0xC5C95A63, 0x391C0CB3, 0xE3418ACB, 0x4ED8AA4A,
	0x7763E373, 0x5B9CCA4F, 0xD6B2B8A3, 0x682E6FF3, 0x5DEFB2FC, 0x748F82EE,
	0x43172F60, 0x78A5636F, 0xA1F0AB72, 0x84C87814, 0x1A6439EC, 0x8CC70208,
	0x23631E28, 0x90BEFFFA, 0xDE82BDE9, 0xA4506CEB, 0xB2C67915, 0xBEF9A3F7,
	0xE372532B, 0xC67178F2, 0xEA26619C, 0xCA273ECE, 0x21C0C207, 0xD186B8C7,
	0xCDE0EB1E, 0xEADA7DD6, 0xEE6ED178, 0xF57D4F7F, 0x72176FBA, 0x06F067AA,
	0xA2C898A6, 0x0A637DC5, 0xBEF90DAE, 0x113F9804, 0x131C471B, 0x1B710B35,
	0x23047D84, 0x28DB77F5, 0x40C72493, 0x32CAAB7B, 0x15C9BEBC, 0x3C9EBE0A,
	0x9C100D4C, 0x431D67C4, 0xCB3E42B6, 0x4CC5D4BE, 0xFC657E2A, 0x597F299C,
	0x3AD6FAEC, 0x5FCB6FAB, 0x4A475817, 0x6C44198C
};


void rv32_sha512_compress(void *s, void *m)
{
	//  4.2.3 SHA-384, SHA-512, SHA-512/224 and SHA-512/256 Constants


	uint32_t mm[16][2];
	const uint32_t *mp = m;
	uint32_t *spp = s;

	const uint32_t *k;

	uint32_t tl, th, ul, uh;
	uint32_t al, ah, bl, bh, cl, ch, dl, dh, el, eh, fl, fh, gl, gh, hl, hh;

	int i;

	al = spp[0];
	ah = spp[1];
	bl = spp[2];
	bh = spp[3];
	cl = spp[4];
	ch = spp[5];
	dl = spp[6];
	dh = spp[7];
	el = spp[8];
	eh = spp[9];
	fl = spp[10];
	fh = spp[11];
	gl = spp[12];
	gh = spp[13];
	hl = spp[14];
	hh = spp[15];

	mp = m;
	for (i = 0; i < 16; i++) {
		mm[i][0] = rvb_grev(mp[1], 0x18);
		mm[i][1] = rvb_grev(mp[0], 0x18);
		mp += 2;
	}


	k = ck;

	goto skipks;							//  skip first key schedule

	do {

		for (i = 0; i < 16; i++) {
			tl = mm[i][0];
			th = mm[i][1];
			mp = mm[(i + 9) & 0xF];
			ul = mp[0];
			uh = mp[1];
			ADD64(tl, th, tl, th, ul, uh);
			mp = mm[(i + 1) & 0xF];
			ul = sha512_sig0l(mp[0], mp[1]);
			uh = sha512_sig0h(mp[0], mp[1]);
			ADD64(tl, th, tl, th, ul, uh);
			mp = mm[(i + 14) & 0xF];
			ul = sha512_sig1l(mp[0], mp[1]);
			uh = sha512_sig1h(mp[0], mp[1]);
			ADD64(tl, th, tl, th, ul, uh);
			mm[i][0] = tl;
			mm[i][1] = th;
		}

	  skipks:


		for (i = 0; i < 16; i++) {
			tl = mm[i][0];
			th = mm[i][1];
			ADD64(hl, hh, hl, hh, tl, th);
			tl = k[0];
			th = k[1];
			ADD64(hl, hh, hl, hh, tl, th);
			tl = (el & fl) ^ rvb_andn(gl, el);
			th = (eh & fh) ^ rvb_andn(gh, eh);
			ADD64(hl, hh, hl, hh, tl, th);
			tl = sha512_sum1l(el, eh);
			th = sha512_sum1h(el, eh);
			ADD64(hl, hh, hl, hh, tl, th);
			ADD64(dl, dh, dl, dh, hl, hh);
			tl = sha512_sum0l(al, ah);
			th = sha512_sum0h(al, ah);
			ADD64(hl, hh, hl, hh, tl, th);
			tl = (((al | cl) & bl) | (cl & al));
			th = (((ah | ch) & bh) | (ch & ah));
			ADD64(hl, hh, hl, hh, tl, th);

			tl = hl;
			th = hh;
			hl = gl;
			hh = gh;
			gl = fl;
			gh = fh;
			fl = el;
			fh = eh;
			el = dl;
			eh = dh;
			dl = cl;
			dh = ch;
			cl = bl;
			ch = bh;
			bl = al;
			bh = ah;
			al = tl;
			ah = th;

			k += 2;
		}

	} while (k != &ck[160]);

	LSADD64(spp[0], spp[1], al, ah);
	LSADD64(spp[2], spp[3], bl, bh);
	LSADD64(spp[4], spp[5], cl, ch);
	LSADD64(spp[6], spp[7], dl, dh);
	LSADD64(spp[8], spp[9], el, eh);
	LSADD64(spp[10], spp[11], fl, fh);
	LSADD64(spp[12], spp[13], gl, gh);
	LSADD64(spp[14], spp[15], hl, hh);

}
