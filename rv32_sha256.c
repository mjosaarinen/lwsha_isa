//	rv32_sha256.c
//	2020-03-08	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2020, PQShield Ltd. All rights reserved.

//	FIPS 180-4 SHA2-224/256 compression function for RV32

#include "sha2.h"

//	bitmanip (emulation) prototypes here
#include "bitmanip.h"

//	4.1.2 SHA-224 and SHA-256 Functions
//	upper case sigma0, sigma1 is "sum" here; sha256_sum0, sha256_sum1

uint32_t sha256_sum0(uint32_t rs1, uint32_t rs2)
{
	return rs1 + (rv_ror(rs2,  2) ^ rv_ror(rs2, 13) ^ rv_ror(rs2, 22));
}

uint32_t sha256_sum1(uint32_t rs1, uint32_t rs2)
{
	return rs1 + (rv_ror(rs2,  6) ^ rv_ror(rs2, 11) ^ rv_ror(rs2, 25));
}

//	lower case sigma0, sigma1

uint32_t sha256_sig0(uint32_t rs1, uint32_t rs2)
{
	return rs1 + (rv_ror(rs2,  7) ^ rv_ror(rs2, 18) ^ (rs2 >>  3));
}

uint32_t sha256_sig1(uint32_t rs1, uint32_t rs2)
{
	return rs1 + (rv_ror(rs2, 17) ^ rv_ror(rs2, 19) ^ (rs2 >> 10));
}

//	nonlinear functions

uint32_t ch(uint32_t x, uint32_t y, uint32_t z)
{
	return (x & y) ^ rv_andn(z, x);
}

uint32_t maj(uint32_t x, uint32_t y, uint32_t z)
{
	return (x & y) ^ (x & z) ^ (y & z);
}

#define SHA256R(a, b, c, d, e, f, g, h, mi, ki) {		\
	h = sha256_sum1(h, e) + mi + ch(e, f, g) + ki;				\
	d = d + h;											\
	h = sha256_sum0(h, a) + maj(a, b, c);						}

#define SHA256K(x0, x1, x9, xe)		\
	x0 = sha256_sig0(x0, x1) + sha256_sig1(x9, xe);

//	compression function (this one does *not* modify m[16])

void rv32_sha256_compress(uint32_t *s, uint32_t *m)
{
	//	SHA-256 Round Constants, Sect 4.2.2.

	const uint32_t ck[64] = {
		0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
		0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
		0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
		0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
		0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
		0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
		0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
		0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
		0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
		0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
		0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
		0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
		0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
		0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
		0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
		0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
	};

	uint32_t	a, b, c, d, e, f, g, h;
	uint32_t	m0, m1, m2, m3, m4, m5, m6, m7,
				m8, m9, ma, mb, mc, md, me, mf;

	const uint32_t *k;

	a = s[0];	b = s[1];	c = s[2];	d = s[3];
	e = s[4];	f = s[5];	g = s[6];	h = s[7];

	//	load with rev8.w

	m0 = rv_grev(m[ 0], 0x18);	m1 = rv_grev(m[ 1], 0x18);
	m2 = rv_grev(m[ 2], 0x18);	m3 = rv_grev(m[ 3], 0x18);
	m4 = rv_grev(m[ 4], 0x18);	m5 = rv_grev(m[ 5], 0x18);
	m6 = rv_grev(m[ 6], 0x18);	m7 = rv_grev(m[ 7], 0x18);
	m8 = rv_grev(m[ 8], 0x18);	m9 = rv_grev(m[ 9], 0x18);
	ma = rv_grev(m[10], 0x18);	mb = rv_grev(m[11], 0x18);
	mc = rv_grev(m[12], 0x18);	md = rv_grev(m[13], 0x18);
	me = rv_grev(m[14], 0x18);	mf = rv_grev(m[15], 0x18);

	k = ck;

	goto noexp;

	do {

		SHA256K(m0, m1, m9, me);	SHA256K(m1, m2, ma, mf);
		SHA256K(m2, m3, mb, m0);	SHA256K(m3, m4, mc, m1);
		SHA256K(m4, m5, md, m2);	SHA256K(m5, m6, me, m3);
		SHA256K(m6, m7, mf, m4);	SHA256K(m7, m8, m0, m5);
		SHA256K(m8, m9, m1, m6);	SHA256K(m9, ma, m2, m7);
		SHA256K(ma, mb, m3, m8);	SHA256K(mb, mc, m4, m9);
		SHA256K(mc, md, m5, ma);	SHA256K(md, me, m6, mb);
		SHA256K(me, mf, m7, mc);	SHA256K(mf, m0, m8, md);

	noexp:

		SHA256R( a, b, c, d, e, f, g, h, m0, k[ 0] );
		SHA256R( h, a, b, c, d, e, f, g, m1, k[ 1] );
		SHA256R( g, h, a, b, c, d, e, f, m2, k[ 2] );
		SHA256R( f, g, h, a, b, c, d, e, m3, k[ 3] );
		SHA256R( e, f, g, h, a, b, c, d, m4, k[ 4] );
		SHA256R( d, e, f, g, h, a, b, c, m5, k[ 5] );
		SHA256R( c, d, e, f, g, h, a, b, m6, k[ 6] );
		SHA256R( b, c, d, e, f, g, h, a, m7, k[ 7] );
		SHA256R( a, b, c, d, e, f, g, h, m8, k[ 8] );
		SHA256R( h, a, b, c, d, e, f, g, m9, k[ 9] );
		SHA256R( g, h, a, b, c, d, e, f, ma, k[10] );
		SHA256R( f, g, h, a, b, c, d, e, mb, k[11] );
		SHA256R( e, f, g, h, a, b, c, d, mc, k[12] );
		SHA256R( d, e, f, g, h, a, b, c, md, k[13] );
		SHA256R( c, d, e, f, g, h, a, b, me, k[14] );
		SHA256R( b, c, d, e, f, g, h, a, mf, k[15] );

		k += 16;

	} while (k != &ck[64]);

	s[0] = s[0] + a;	s[1] = s[1] + b;
	s[2] = s[2] + c;	s[3] = s[3] + d;
	s[4] = s[4] + e;	s[5] = s[5] + f;
	s[6] = s[6] + g;	s[7] = s[7] + h;
}


