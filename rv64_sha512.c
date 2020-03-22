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

uint64_t sha512_sum0(uint64_t rs1, uint64_t rs2)
{
	return rs1 + (rvb_rorw(rs2, 28) ^ rvb_rorw(rs2, 34) ^ rvb_rorw(rs2, 39));
}

uint64_t sha512_sum1(uint64_t rs1, uint64_t rs2)
{
	return rs1 + (rvb_rorw(rs2, 14) ^ rvb_rorw(rs2, 18) ^ rvb_rorw(rs2, 41));
}

//  lower case sigma0, sigma1 is "sig"

uint64_t sha512_sig0(uint64_t rs1, uint64_t rs2)
{
	return rs1 + (rvb_rorw(rs2, 1) ^ rvb_rorw(rs2, 8) ^ (rs2 >> 7));
}

uint64_t sha512_sig1(uint64_t rs1, uint64_t rs2)
{
	return rs1 + (rvb_rorw(rs2, 19) ^ rvb_rorw(rs2, 61) ^ (rs2 >> 6));
}

//  (((a | c) & b) | (c & a)) = Maj(a, b, c)
//  ((e & f) ^ rvb_andn(g, e)) = Ch(e, f, g)

//  processing step, sets "d" and "h" as a function of all 8 inputs
//  and message schedule "mi", round constant "ki"
#define SHA512R(a, b, c, d, e, f, g, h, mi, ki) {	\
	h = h + ((e & f) ^ rvb_andn(g, e)) + mi + ki;	\
	h = sha512_sum1(h, e);							\
	d = d + h;										\
	h = sha512_sum0(h, a);							\
	h = h + (((a | c) & b) | (c & a));				}

//  keying step, sets x0 as a function of 4 inputs
#define SHA512K(x0, x1, x9, xe) {	\
	x0 = x0 + x9;					\
	x0 = sha512_sig0(x0, x1);		\
	x0 = sha512_sig1(x0, xe); }

//  compression function (this one does *not* modify m[16])

void rv64_sha512_compress(void *s, void *m)
{
	//  4.2.3 SHA-384, SHA-512, SHA-512/224 and SHA-512/256 Constants

	const uint64_t ck[80] = {
		0x428A2F98D728AE22LL, 0x7137449123EF65CDLL, 0xB5C0FBCFEC4D3B2FLL,
		0xE9B5DBA58189DBBCLL, 0x3956C25BF348B538LL, 0x59F111F1B605D019LL,
		0x923F82A4AF194F9BLL, 0xAB1C5ED5DA6D8118LL, 0xD807AA98A3030242LL,
		0x12835B0145706FBELL, 0x243185BE4EE4B28CLL, 0x550C7DC3D5FFB4E2LL,
		0x72BE5D74F27B896FLL, 0x80DEB1FE3B1696B1LL, 0x9BDC06A725C71235LL,
		0xC19BF174CF692694LL, 0xE49B69C19EF14AD2LL, 0xEFBE4786384F25E3LL,
		0x0FC19DC68B8CD5B5LL, 0x240CA1CC77AC9C65LL, 0x2DE92C6F592B0275LL,
		0x4A7484AA6EA6E483LL, 0x5CB0A9DCBD41FBD4LL, 0x76F988DA831153B5LL,
		0x983E5152EE66DFABLL, 0xA831C66D2DB43210LL, 0xB00327C898FB213FLL,
		0xBF597FC7BEEF0EE4LL, 0xC6E00BF33DA88FC2LL, 0xD5A79147930AA725LL,
		0x06CA6351E003826FLL, 0x142929670A0E6E70LL, 0x27B70A8546D22FFCLL,
		0x2E1B21385C26C926LL, 0x4D2C6DFC5AC42AEDLL, 0x53380D139D95B3DFLL,
		0x650A73548BAF63DELL, 0x766A0ABB3C77B2A8LL, 0x81C2C92E47EDAEE6LL,
		0x92722C851482353BLL, 0xA2BFE8A14CF10364LL, 0xA81A664BBC423001LL,
		0xC24B8B70D0F89791LL, 0xC76C51A30654BE30LL, 0xD192E819D6EF5218LL,
		0xD69906245565A910LL, 0xF40E35855771202ALL, 0x106AA07032BBD1B8LL,
		0x19A4C116B8D2D0C8LL, 0x1E376C085141AB53LL, 0x2748774CDF8EEB99LL,
		0x34B0BCB5E19B48A8LL, 0x391C0CB3C5C95A63LL, 0x4ED8AA4AE3418ACBLL,
		0x5B9CCA4F7763E373LL, 0x682E6FF3D6B2B8A3LL, 0x748F82EE5DEFB2FCLL,
		0x78A5636F43172F60LL, 0x84C87814A1F0AB72LL, 0x8CC702081A6439ECLL,
		0x90BEFFFA23631E28LL, 0xA4506CEBDE82BDE9LL, 0xBEF9A3F7B2C67915LL,
		0xC67178F2E372532BLL, 0xCA273ECEEA26619CLL, 0xD186B8C721C0C207LL,
		0xEADA7DD6CDE0EB1ELL, 0xF57D4F7FEE6ED178LL, 0x06F067AA72176FBALL,
		0x0A637DC5A2C898A6LL, 0x113F9804BEF90DAELL, 0x1B710B35131C471BLL,
		0x28DB77F523047D84LL, 0x32CAAB7B40C72493LL, 0x3C9EBE0A15C9BEBCLL,
		0x431D67C49C100D4CLL, 0x4CC5D4BECB3E42B6LL, 0x597F299CFC657E2ALL,
		0x5FCB6FAB3AD6FAECLL, 0x6C44198C4A475817LL
	};

	uint64_t a, b, c, d, e, f, g, h;
	uint64_t m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, ma, mb, mc, md, me, mf;

	const uint64_t *k, *mp = m;
	uint64_t *sp = s;

	a = sp[0];
	b = sp[1];
	c = sp[2];
	d = sp[3];
	e = sp[4];
	f = sp[5];
	g = sp[6];
	h = sp[7];

	//  load with rev8

	m0 = rvb_grevw(mp[0], 0x38);
	m1 = rvb_grevw(mp[1], 0x38);
	m2 = rvb_grevw(mp[2], 0x38);
	m3 = rvb_grevw(mp[3], 0x38);
	m4 = rvb_grevw(mp[4], 0x38);
	m5 = rvb_grevw(mp[5], 0x38);
	m6 = rvb_grevw(mp[6], 0x38);
	m7 = rvb_grevw(mp[7], 0x38);
	m8 = rvb_grevw(mp[8], 0x38);
	m9 = rvb_grevw(mp[9], 0x38);
	ma = rvb_grevw(mp[10], 0x38);
	mb = rvb_grevw(mp[11], 0x38);
	mc = rvb_grevw(mp[12], 0x38);
	md = rvb_grevw(mp[13], 0x38);
	me = rvb_grevw(mp[14], 0x38);
	mf = rvb_grevw(mp[15], 0x38);

	k = ck;

	goto skipks;							//  skip first key schedule

	do {

		SHA512K(m0, m1, m9, me);
		SHA512K(m1, m2, ma, mf);
		SHA512K(m2, m3, mb, m0);
		SHA512K(m3, m4, mc, m1);
		SHA512K(m4, m5, md, m2);
		SHA512K(m5, m6, me, m3);
		SHA512K(m6, m7, mf, m4);
		SHA512K(m7, m8, m0, m5);
		SHA512K(m8, m9, m1, m6);
		SHA512K(m9, ma, m2, m7);
		SHA512K(ma, mb, m3, m8);
		SHA512K(mb, mc, m4, m9);
		SHA512K(mc, md, m5, ma);
		SHA512K(md, me, m6, mb);
		SHA512K(me, mf, m7, mc);
		SHA512K(mf, m0, m8, md);

	  skipks:

		SHA512R(a, b, c, d, e, f, g, h, m0, k[0]);
		SHA512R(h, a, b, c, d, e, f, g, m1, k[1]);
		SHA512R(g, h, a, b, c, d, e, f, m2, k[2]);
		SHA512R(f, g, h, a, b, c, d, e, m3, k[3]);
		SHA512R(e, f, g, h, a, b, c, d, m4, k[4]);
		SHA512R(d, e, f, g, h, a, b, c, m5, k[5]);
		SHA512R(c, d, e, f, g, h, a, b, m6, k[6]);
		SHA512R(b, c, d, e, f, g, h, a, m7, k[7]);
		SHA512R(a, b, c, d, e, f, g, h, m8, k[8]);
		SHA512R(h, a, b, c, d, e, f, g, m9, k[9]);
		SHA512R(g, h, a, b, c, d, e, f, ma, k[10]);
		SHA512R(f, g, h, a, b, c, d, e, mb, k[11]);
		SHA512R(e, f, g, h, a, b, c, d, mc, k[12]);
		SHA512R(d, e, f, g, h, a, b, c, md, k[13]);
		SHA512R(c, d, e, f, g, h, a, b, me, k[14]);
		SHA512R(b, c, d, e, f, g, h, a, mf, k[15]);

		k += 16;

	} while (k != &ck[80]);

	sp[0] = sp[0] + a;
	sp[1] = sp[1] + b;
	sp[2] = sp[2] + c;
	sp[3] = sp[3] + d;
	sp[4] = sp[4] + e;
	sp[5] = sp[5] + f;
	sp[6] = sp[6] + g;
	sp[7] = sp[7] + h;
}
