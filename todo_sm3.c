//	todo_sm3.c
//	2020-03-10	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2020, PQShield Ltd. All rights reserved.

//	The Chinese Standard SM3 Hash Function
//	GB/T 32905-2016, GM/T 0004-2012, ISO/IEC 10118-3:2018

//	XXX this is work in progress;
//	currently compression function, padding, and test are in the same file.

#include "test_hex.h"

//	bitmanip (emulation) prototypes here
#include "bitmanip.h"

//	key schedule

#define SM3KEY(w0, w3, w7, wa, wd) {				\
	t = w0 ^ w7 ^ rv_ror(wd, 17);					\
	t = t ^ rv_ror(t,  9) ^ rv_ror(t, 17) ;			\
	w0 = wa ^ rv_ror(w3, 25) ^ t;					}

//	rounds 0..15

#define SM3RF0(a, b, c, d, e, f, g, h, w0, w4) {	\
	h = h + w0;										\
	t = rv_ror(a, 20);								\
	u = t + e + tj;									\
	u = rv_ror(u, 25);								\
	d = d + (t ^ u) + (a ^ b ^ c);					\
	b = rv_ror(b, 23);								\
	h = h + u + (e ^ f ^ g);						\
	h = h ^ rv_ror(h, 23) ^ rv_ror(h, 15);			\
	f = rv_ror(f, 13);								\
	d = d + (w0 ^ w4);								\
	tj = rv_ror(tj, 31);							}

//	rounds 16..63

#define SM3RF1(a, b, c, d, e, f, g, h, w0, w4) {	\
	h = h + w0;										\
	t = rv_ror(a, 20);								\
	u = t + e + tj;									\
	u = rv_ror(u, 25);								\
	d = d + (t ^ u) + (((a | c) & b) | (a & c));	\
	b = rv_ror(b, 23);								\
	h = h + u + ((e & f) ^ rv_andn(g, e));			\
	h = h ^ rv_ror(h, 23) ^ rv_ror(h, 15);			\
	f = rv_ror(f, 13);								\
	d = d + (w0 ^ w4);								\
	tj = rv_ror(tj, 31);							}


//	compression function (this one does *not* modify m[16])

void sm3_compress(uint32_t *s, uint32_t *m)
{
	int i;
	uint32_t	a, b, c, d, e, f, g, h;
	uint32_t	m0, m1, m2, m3, m4, m5, m6, m7,
				m8, m9, ma, mb, mc, md, me, mf;
	uint32_t	tj, t, u;

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

	tj = 0x79CC4519;

	SM3RF0( a, b, c, d, e, f, g, h, m0, m4 );
	SM3RF0( d, a, b, c, h, e, f, g, m1, m5 );
	SM3RF0( c, d, a, b, g, h, e, f, m2, m6 );
	SM3RF0( b, c, d, a, f, g, h, e, m3, m7 );

	SM3RF0( a, b, c, d, e, f, g, h, m4, m8 );
	SM3RF0( d, a, b, c, h, e, f, g, m5, m9 );
	SM3RF0( c, d, a, b, g, h, e, f, m6, ma );
	SM3RF0( b, c, d, a, f, g, h, e, m7, mb );

	SM3RF0( a, b, c, d, e, f, g, h, m8, mc );
	SM3RF0( d, a, b, c, h, e, f, g, m9, md );
	SM3RF0( c, d, a, b, g, h, e, f, ma, me );
	SM3RF0( b, c, d, a, f, g, h, e, mb, mf );

	SM3KEY( m0, m3, m7, ma, md );
	SM3KEY( m1, m4, m8, mb, me );
	SM3KEY( m2, m5, m9, mc, mf );
	SM3KEY( m3, m6, ma, md, m0 );

	SM3RF0( a, b, c, d, e, f, g, h, mc, m0 );
	SM3RF0( d, a, b, c, h, e, f, g, md, m1 );
	SM3RF0( c, d, a, b, g, h, e, f, me, m2 );
	SM3RF0( b, c, d, a, f, g, h, e, mf, m3 );

	tj = 0x9D8A7A87;

	for (i = 0; i < 3; i++) {

		SM3KEY( m4, m7, mb, me, m1 );
		SM3KEY( m5, m8, mc, mf, m2 );
		SM3KEY( m6, m9, md, m0, m3 );
		SM3KEY( m7, ma, me, m1, m4 );
		SM3KEY( m8, mb, mf, m2, m5 );
		SM3KEY( m9, mc, m0, m3, m6 );
		SM3KEY( ma, md, m1, m4, m7 );
		SM3KEY( mb, me, m2, m5, m8 );
		SM3KEY( mc, mf, m3, m6, m9 );
		SM3KEY( md, m0, m4, m7, ma );
		SM3KEY( me, m1, m5, m8, mb );
		SM3KEY( mf, m2, m6, m9, mc );

		SM3RF1( a, b, c, d, e, f, g, h, m0, m4 );
		SM3RF1( d, a, b, c, h, e, f, g, m1, m5 );
		SM3RF1( c, d, a, b, g, h, e, f, m2, m6 );
		SM3RF1( b, c, d, a, f, g, h, e, m3, m7 );

		SM3RF1( a, b, c, d, e, f, g, h, m4, m8 );
		SM3RF1( d, a, b, c, h, e, f, g, m5, m9 );
		SM3RF1( c, d, a, b, g, h, e, f, m6, ma );
		SM3RF1( b, c, d, a, f, g, h, e, m7, mb );

		SM3RF1( a, b, c, d, e, f, g, h, m8, mc );
		SM3RF1( d, a, b, c, h, e, f, g, m9, md );
		SM3RF1( c, d, a, b, g, h, e, f, ma, me );
		SM3RF1( b, c, d, a, f, g, h, e, mb, mf );

		SM3KEY( m0, m3, m7, ma, md );
		SM3KEY( m1, m4, m8, mb, me );
		SM3KEY( m2, m5, m9, mc, mf );
		SM3KEY( m3, m6, ma, md, m0 );

		SM3RF1( a, b, c, d, e, f, g, h, mc, m0 );
		SM3RF1( d, a, b, c, h, e, f, g, md, m1 );
		SM3RF1( c, d, a, b, g, h, e, f, me, m2 );
		SM3RF1( b, c, d, a, f, g, h, e, mf, m3 );

	}

	s[0] = s[0] ^ a;	s[1] = s[1] ^ b;
	s[2] = s[2] ^ c;	s[3] = s[3] ^ d;
	s[4] = s[4] ^ e;	s[5] = s[5] ^ f;
	s[6] = s[6] ^ g;	s[7] = s[7] ^ h;
}


//	Compute 32-byte message digest to "md" from "in" which has "inlen" bytes

void sm3_256(uint8_t *md, const void *in, size_t inlen)
{
	union {									//	aligned:
		uint8_t b[64];						//	8-bit bytes
		uint32_t w[16];						//	32-bit words
	} m;
	size_t i;
	uint64_t x;
	uint32_t t, s[8];

	const uint8_t *p = in;

	//	initial values
	s[0] = 0x7380166F;	s[1] = 0x4914B2B9;
	s[2] = 0x172442D7;	s[3] = 0xDA8A0600;
	s[4] = 0xA96F30BC;	s[5] = 0x163138AA;
	s[6] = 0xE38DEE4D;	s[7] = 0xB0FB0E4E;

	//	"md padding"
	x = inlen << 3;							//	length in bits

	while (inlen >= 64) {					//	full blocks
		memcpy(m.b, p, 64);
		sm3_compress(s, m.w);
		inlen -= 64;
		p += 64;
	}
	memcpy(m.b, p, inlen);					//	last data block
	m.b[inlen++] = 0x80;
	if (inlen > 56) {
		memset(&m.b[inlen], 0x00, 64 - inlen);
		sm3_compress(s, m.w);
		inlen = 0;
	}
	i = 64;									//	process length
	while (x > 0) {
		m.b[--i] = x & 0xFF;
		x >>= 8;
	}
	memset(&m.b[inlen], 0x00, i - inlen);
	sm3_compress(s, m.w);

	//	store big endian output
	for (i = 0; i < 32; i += 4) {
		t = s[i >> 2];
		md[i] = t >> 24;
		md[i + 1] = (t >> 16) & 0xFF;
		md[i + 2] = (t >> 8) & 0xFF;
		md[i + 3] = t & 0xFF;
	}
}

//	=== TESTS ===

//	simplified test with "abc" test vector from the standard

int test_sm3()
{
	uint8_t md[32], in[256];
	int fail = 0;

	sm3_256(md, "abc", 3);
	fail += chkhex("SM3-256", md, 32,
		"66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0");

	sm3_256(md, in, readhex(in, sizeof(in),
		"6162636461626364616263646162636461626364616263646162636461626364"
		"6162636461626364616263646162636461626364616263646162636461626364"));
	fail += chkhex("SM3-256", md, 32,
		"DEBE9FF92275B8A138604889C18E5A4D6FDB70E5387E5765293DCBA39C0C5732");

	return fail;
}

