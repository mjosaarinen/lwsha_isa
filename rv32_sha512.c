//  rv64_sha512.c
//  2020-03-08  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  FIPS 180-4 SHA2-384/512 compression function for RV64

#include <string.h>

#include "sha2.h"

//  bitmanip (emulation) prototypes here
#include "bitmanip.h"

//  RV32I base SLTU emulation

uint32_t rv32_sltu(uint32_t rs1, uint32_t rs2)
{
	return rs1 < rs2 ? 1 : 0;
}

//  4.1.3 SHA-384, SHA-512, SHA-512/224 and SHA-512/256 Functions
//	These six instructions are the ISA Extension proposal.

//  low word of Sigma0 ("sum0") x=rs2_rs1: (x >>> 28) ^ (x >>> 34) ^ (x >>> 39)
//  ( high word can be obtained by flipping the input words x=rs1_rs2 )

uint32_t sha512_sum0l(uint32_t rs1, uint32_t rs2)
{
	return  (rs1 << 25) ^ (rs1 << 30) ^ (rs1 >> 28) ^
			(rs2 >>  7) ^ (rs2 >>  2) ^	(rs2 <<  4);
}

//  low word of Sigma1 ("sum1") x=rs2_rs1: (x >>> 14) ^ (x >>> 18) ^ (x >>> 41)
//  ( high word can be obtained by flipping the input words x=rs1_rs2 )

uint32_t sha512_sum1l(uint32_t rs1, uint32_t rs2)
{
	return 	(rs1 << 23) ^ (rs1 >> 14) ^ (rs1 >> 18) ^
			(rs2 >>  9) ^ (rs2 << 18) ^ (rs2 << 14);
}

//  low word of sigma0 ("sig0") x=rs2_rs1 : (x >>> 1) ^ (x >>> 8) ^ (x >> 7)

uint32_t sha512_sig0l(uint32_t rs1, uint32_t rs2)
{
	return 	(rs1 >>  1) ^ (rs1 >>  7) ^ (rs1 >>  8) ^
			(rs2 << 31) ^ (rs2 << 25) ^ (rs2 << 24);
}

//  high word of sigma0 x=rs1_rs2 ( same but left shift 25 is missing )

uint32_t sha512_sig0h(uint32_t rs1, uint32_t rs2)
{
	return 	(rs1 >>  1) ^ (rs1 >>  7) ^ (rs1 >>  8) ^
			(rs2 << 31) ^ 				(rs2 << 24);
}

//  low word of sigma1 ("sig") x=rs2_rs1: (x >>> 19) ^ (x >>> 61) ^ (x >> 6)

uint32_t sha512_sig1l(uint32_t rs1, uint32_t rs2)
{
	return 	(rs1 <<  3) ^ (rs1 >>  6) ^ (rs1 >> 19) ^
			(rs2 >> 29) ^ (rs2 << 26) ^ (rs2 << 13);
}

//  high word of sigma1 x=rs1_rs2 ( same but left shift 26 is missing )

uint32_t sha512_sig1h(uint32_t rs1, uint32_t rs2)
{
	return	(rs1 <<  3)	^ (rs1 >>  6) ^	(rs1 >> 19) ^
			(rs2 >> 29)	^ 				(rs2 << 13);
}


//  (((a | c) & b) | (c & a)) = Maj(a, b, c)
//  ((e & f) ^ rvb_andn(g, e)) = Ch(e, f, g)

//  64-bit addition; 3 * ADD, 1 * SLTU

#define ADD64(dl, dh, s1l, s1h, s2l, s2h) {	\
	dl = s1l + s2l;							\
	dh = s1h + s2h + rv32_sltu(dl, s2l);	}

//  final Merkle-Damgard addition

#define LSADD64(p0, p1, xl, xh) 	{	\
	tl = p0 + xl;						\
	th = p1 + xh + rv32_sltu(tl, xl);	\
	p0 = tl;							\
	p1 = th;							}

#define SHA512K(i) {												\
	tl = mp[i];														\
	th = mp[i + 1];													\
	ul = mp[(i + 18) & 0x1F];										\
	uh = mp[(i + 19) & 0x1F];										\
	ADD64(tl, th, tl, th, ul, uh);									\
	ul = sha512_sig0l(mp[(i + 2) & 0x1F], mp[(i + 3) & 0x1F]);		\
	uh = sha512_sig0h(mp[(i + 3) & 0x1F], mp[(i + 2) & 0x1F]);		\
	ADD64(tl, th, tl, th, ul, uh);									\
	ul = sha512_sig1l(mp[(i + 28) & 0x1F], mp[(i + 29) & 0x1F]);	\
	uh = sha512_sig1h(mp[(i + 29) & 0x1F], mp[(i + 28) & 0x1F]);	\
	ADD64(tl, th, tl, th, ul, uh);									\
	mp[i] = tl;														\
	mp[i + 1] = th;													}

#define SHA512R(x0, x1, x2, x3, x4, x5, x6, x7, 		\
				x8, x9, xa, xb, xc, xd, xe, xf, i) {	\
	tl = mp[i];											\
	th = mp[i + 1];										\
	ADD64(xe, xf, xe, xf, tl, th);						\
	tl = kp[i];											\
	th = kp[i + 1];										\
	ADD64(xe, xf, xe, xf, tl, th);						\
	tl = (x8 & xa) ^ rvb_andn(xc, x8);					\
	th = (x9 & xb) ^ rvb_andn(xd, x9);					\
	ADD64(xe, xf, xe, xf, tl, th);						\
	tl = sha512_sum1l(x8, x9);							\
	th = sha512_sum1l(x9, x8);							\
	ADD64(xe, xf, xe, xf, tl, th);						\
	ADD64(x6, x7, x6, x7, xe, xf);						\
	tl = sha512_sum0l(x0, x1);							\
	th = sha512_sum0l(x1, x0);							\
	ADD64(xe, xf, xe, xf, tl, th);						\
	tl = (((x0 | x4) & x2) | (x4 & x0));				\
	th = (((x1 | x5) & x3) | (x5 & x1));				\
	ADD64(xe, xf, xe, xf, tl, th);						}

//  compression function (this one does *not* modify m[16])


void rv32_sha512_compress(void *s)
{
	//  4.2.3 SHA-384, SHA-512, SHA-512/224 and SHA-512/256 Constants

	const uint32_t ck[160] = {
		0xD728AE22, 0x428A2F98, 0x23EF65CD, 0x71374491, 0xEC4D3B2F,
		0xB5C0FBCF, 0x8189DBBC, 0xE9B5DBA5, 0xF348B538, 0x3956C25B,
		0xB605D019, 0x59F111F1, 0xAF194F9B, 0x923F82A4, 0xDA6D8118,
		0xAB1C5ED5, 0xA3030242, 0xD807AA98, 0x45706FBE, 0x12835B01,
		0x4EE4B28C, 0x243185BE, 0xD5FFB4E2, 0x550C7DC3, 0xF27B896F,
		0x72BE5D74, 0x3B1696B1, 0x80DEB1FE, 0x25C71235, 0x9BDC06A7,
		0xCF692694, 0xC19BF174, 0x9EF14AD2, 0xE49B69C1, 0x384F25E3,
		0xEFBE4786, 0x8B8CD5B5, 0x0FC19DC6, 0x77AC9C65, 0x240CA1CC,
		0x592B0275, 0x2DE92C6F, 0x6EA6E483, 0x4A7484AA, 0xBD41FBD4,
		0x5CB0A9DC, 0x831153B5, 0x76F988DA, 0xEE66DFAB, 0x983E5152,
		0x2DB43210, 0xA831C66D, 0x98FB213F, 0xB00327C8, 0xBEEF0EE4,
		0xBF597FC7, 0x3DA88FC2, 0xC6E00BF3, 0x930AA725, 0xD5A79147,
		0xE003826F, 0x06CA6351, 0x0A0E6E70, 0x14292967, 0x46D22FFC,
		0x27B70A85, 0x5C26C926, 0x2E1B2138, 0x5AC42AED, 0x4D2C6DFC,
		0x9D95B3DF, 0x53380D13, 0x8BAF63DE, 0x650A7354, 0x3C77B2A8,
		0x766A0ABB, 0x47EDAEE6, 0x81C2C92E, 0x1482353B, 0x92722C85,
		0x4CF10364, 0xA2BFE8A1, 0xBC423001, 0xA81A664B, 0xD0F89791,
		0xC24B8B70, 0x0654BE30, 0xC76C51A3, 0xD6EF5218, 0xD192E819,
		0x5565A910, 0xD6990624, 0x5771202A, 0xF40E3585, 0x32BBD1B8,
		0x106AA070, 0xB8D2D0C8, 0x19A4C116, 0x5141AB53, 0x1E376C08,
		0xDF8EEB99, 0x2748774C, 0xE19B48A8, 0x34B0BCB5, 0xC5C95A63,
		0x391C0CB3, 0xE3418ACB, 0x4ED8AA4A, 0x7763E373, 0x5B9CCA4F,
		0xD6B2B8A3, 0x682E6FF3, 0x5DEFB2FC, 0x748F82EE, 0x43172F60,
		0x78A5636F, 0xA1F0AB72, 0x84C87814, 0x1A6439EC, 0x8CC70208,
		0x23631E28, 0x90BEFFFA, 0xDE82BDE9, 0xA4506CEB, 0xB2C67915,
		0xBEF9A3F7, 0xE372532B, 0xC67178F2, 0xEA26619C, 0xCA273ECE,
		0x21C0C207, 0xD186B8C7, 0xCDE0EB1E, 0xEADA7DD6, 0xEE6ED178,
		0xF57D4F7F, 0x72176FBA, 0x06F067AA, 0xA2C898A6, 0x0A637DC5,
		0xBEF90DAE, 0x113F9804, 0x131C471B, 0x1B710B35, 0x23047D84,
		0x28DB77F5, 0x40C72493, 0x32CAAB7B, 0x15C9BEBC, 0x3C9EBE0A,
		0x9C100D4C, 0x431D67C4, 0xCB3E42B6, 0x4CC5D4BE, 0xFC657E2A,
		0x597F299C, 0x3AD6FAEC, 0x5FCB6FAB, 0x4A475817, 0x6C44198C
	};

	uint32_t *sp = s;
	uint32_t *mp = sp + 16;
	const uint32_t *kp = ck;

	uint32_t tl, th, ul, uh;
	uint32_t al, ah, bl, bh, cl, ch, dl, dh, el, eh, fl, fh, gl, gh, hl, hh;

	al = sp[0];
	ah = sp[1];
	bl = sp[2];
	bh = sp[3];
	cl = sp[4];
	ch = sp[5];
	dl = sp[6];
	dh = sp[7];
	el = sp[8];
	eh = sp[9];
	fl = sp[10];
	fh = sp[11];
	gl = sp[12];
	gh = sp[13];
	hl = sp[14];
	hh = sp[15];

	mp = sp + 16;
	do {
		tl = mp[1];							//  revert tje block
		th = mp[0];
		mp[0] = rvb_grev(tl, 0x18);
		mp[1] = rvb_grev(th, 0x18);
		mp += 2;
	} while (mp != sp + 48);

	mp = sp + 16;

	while (1) {

		do {

			SHA512R(al, ah, bl, bh, cl, ch, dl, dh,
					el, eh, fl, fh, gl, gh, hl, hh, 0);
			SHA512R(hl, hh, al, ah, bl, bh, cl, ch,
					dl, dh, el, eh, fl, fh, gl, gh, 2);
			SHA512R(gl, gh, hl, hh, al, ah, bl, bh,
					cl, ch, dl, dh, el, eh, fl, fh, 4);
			SHA512R(fl, fh, gl, gh, hl, hh, al, ah,
					bl, bh, cl, ch, dl, dh, el, eh, 6);
			SHA512R(el, eh, fl, fh, gl, gh, hl, hh,
					al, ah, bl, bh, cl, ch, dl, dh, 8);
			SHA512R(dl, dh, el, eh, fl, fh, gl, gh,
					hl, hh, al, ah, bl, bh, cl, ch, 10);
			SHA512R(cl, ch, dl, dh, el, eh, fl, fh,
					gl, gh, hl, hh, al, ah, bl, bh, 12);
			SHA512R(bl, bh, cl, ch, dl, dh, el, eh,
					fl, fh, gl, gh, hl, hh, al, ah, 14);

			kp += 16;
			mp += 16;

		} while (mp != sp + 48);

		if (kp == &ck[160])
			break;

		mp = sp + 16;

		SHA512K(0);
		SHA512K(2);
		SHA512K(4);
		SHA512K(6);
		SHA512K(8);
		SHA512K(10);
		SHA512K(12);
		SHA512K(14);
		SHA512K(16);
		SHA512K(18);
		SHA512K(20);
		SHA512K(22);
		SHA512K(24);
		SHA512K(26);
		SHA512K(28);
		SHA512K(30);
	}

	LSADD64(sp[0], sp[1], al, ah);
	LSADD64(sp[2], sp[3], bl, bh);
	LSADD64(sp[4], sp[5], cl, ch);
	LSADD64(sp[6], sp[7], dl, dh);
	LSADD64(sp[8], sp[9], el, eh);
	LSADD64(sp[10], sp[11], fl, fh);
	LSADD64(sp[12], sp[13], gl, gh);
	LSADD64(sp[14], sp[15], hl, hh);

}
