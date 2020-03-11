//	misc_sm3.c
//	2020-03-10	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2020, PQShield Ltd. All rights reserved.

//	SM3 compression function

//	XXX	this is just a placeholder XXX

#include <stdio.h>
#include <string.h>

//	bitmanip (emulation) prototypes here
#include "bitmanip.h"

//	nonlinear functions
#define CH(x, y, z) ((x & y) ^ rv_andn(z, x))
#define MAJ(x, y, z) (((z | x) & y) | (z & x))

//	round constants 
//	tj[i] = rv_ror(0x79CC4519, (-i) & 0x1F);	//	for i =  0..15
//	tj[i] = rv_ror(0x7A879D8A, (-i) & 0x1F);	//	for i = 16..63

const uint32_t sm3_tj[64] = {
	0x79CC4519, 0xF3988A32, 0xE7311465, 0xCE6228CB, 
	0x9CC45197, 0x3988A32F,	0x7311465E, 0xE6228CBC, 
	0xCC451979, 0x988A32F3, 0x311465E7, 0x6228CBCE,
	0xC451979C, 0x88A32F39, 0x11465E73, 0x228CBCE6, 
	0x9D8A7A87, 0x3B14F50F, 0x7629EA1E, 0xEC53D43C,
	0xD8A7A879, 0xB14F50F3, 0x629EA1E7, 0xC53D43CE,
	0x8A7A879D, 0x14F50F3B, 0x29EA1E76, 0x53D43CEC,
	0xA7A879D8, 0x4F50F3B1, 0x9EA1E762, 0x3D43CEC5,
	0x7A879D8A, 0xF50F3B14, 0xEA1E7629, 0xD43CEC53,
	0xA879D8A7, 0x50F3B14F, 0xA1E7629E, 0x43CEC53D, 
	0x879D8A7A, 0x0F3B14F5,	0x1E7629EA, 0x3CEC53D4,
	0x79D8A7A8, 0xF3B14F50, 0xE7629EA1, 0xCEC53D43,
	0x9D8A7A87, 0x3B14F50F, 0x7629EA1E, 0xEC53D43C,
	0xD8A7A879, 0xB14F50F3, 0x629EA1E7, 0xC53D43CE,
	0x8A7A879D, 0x14F50F3B, 0x29EA1E76, 0x53D43CEC,
	0xA7A879D8, 0x4F50F3B1, 0x9EA1E762, 0x3D43CEC5
};

//	compression function (this one does *not* modify m[16])

void rv32_sm3_compress(uint32_t *s, uint32_t *m)
{
	int i;
	uint32_t	a, b, c, d, e, f, g, h;

	uint32_t 	w[68];
	uint32_t	t, u;

	a = s[0];	b = s[1];	c = s[2];	d = s[3];
	e = s[4];	f = s[5];	g = s[6];	h = s[7];

	//	load with rev8.w
	for (i = 0; i < 16; i++) {
		w[i] = m[i];	//rv_grev(m[i], 0x18);
	}

	//	linear schedule

	for (i = 16; i < 68; i++) {

		t = w[i - 16] ^ w[i - 9] ^ rv_ror(w[i - 3], 17);
		w[i] = t ^ rv_ror(t, 17) ^ rv_ror(t,  9)
				^ w[i - 6] ^ rv_ror(w[i - 13], 25);
	}


	#define SM3R0(a, b, c, d, e, f, g, h, i) {	\
	 	t = rv_ror(a, 20);						\
		u = t + e + sm3_tj[i];					\
		u = rv_ror(u, 25);						\
		t = (t ^ u) + (w[i] ^ w[i + 4]);		\
		d = d + t + (a ^ b ^ c);				\
		b = rv_ror(b, 23);						\
		h = h + u + (e ^ f ^ g) + w[i];			\
		h = h ^ rv_ror(h, 23) ^ rv_ror(h, 15);	\
		f = rv_ror(f, 13); 						}

	for (i = 0; i < 16; i += 4) {
		SM3R0( a, b, c, d, e, f, g, h, i );
		SM3R0( d, a, b, c, h, e, f, g, i + 1 );
		SM3R0( c, d, a, b, g, h, e, f, i + 2 );
		SM3R0( b, c, d, a, f, g, h, e, i + 3 );
	}

	#define SM3R1(a, b, c, d, e, f, g, h, i) {	\
	 	t = rv_ror(a, 20);						\
		u = t + e + sm3_tj[i];					\
		u = rv_ror(u, 25);						\
		t = (t ^ u) + (w[i] ^ w[i + 4]);		\
		d = d + t + MAJ(a, b, c);				\
		b = rv_ror(b, 23);						\
		h = h + u + CH(e, f, g) + w[i];			\
		h = h ^ rv_ror(h, 23) ^ rv_ror(h, 15);	\
		f = rv_ror(f, 13); 						}

	for (i = 16; i < 64; i += 4) {
		SM3R1( a, b, c, d, e, f, g, h, i );
		SM3R1( d, a, b, c, h, e, f, g, i + 1 );
		SM3R1( c, d, a, b, g, h, e, f, i + 2 );
		SM3R1( b, c, d, a, f, g, h, e, i + 3 );
	}

	s[0] = s[0] ^ a;	s[1] = s[1] ^ b;
	s[2] = s[2] ^ c;	s[3] = s[3] ^ d;
	s[4] = s[4] ^ e;	s[5] = s[5] ^ f;
	s[6] = s[6] ^ g;	s[7] = s[7] ^ h;
}

//	simplified test with "abc" test vector from the standard

int test_sm3()
{
	const uint32_t tv[16] =  {
		0x66C7F0F4, 0x62EEEDD9, 0xD1F2D46B, 0xDC10E4E2,
		0x4167C487, 0x5CF2F7A2, 0x297DA02B, 0x8F4BA8E0
	};
	uint32_t s[8], m[16];
	int i, fail = 0;

	s[0] = 0x7380166F;	s[1] = 0x4914B2B9;
	s[2] = 0x172442D7;	s[3] = 0xDA8A0600;
	s[4] = 0xA96F30BC;	s[5] = 0x163138AA;
	s[6] = 0xE38DEE4D;	s[7] = 0xB0FB0E4E;

	//	"abc" with padding, converted to little endian here
	memset(m, 0, sizeof(m));
	m[ 0] = 0x61626380;
	m[15] = 0x00000018;

	rv32_sm3_compress(s, m);

	for (i = 0; i < 8; i++) {
		printf("%08X ", s[i]);
		if (tv[i] != s[i])
			fail++;
	}
	printf("fail=%d\n", fail);

	return fail;
}

