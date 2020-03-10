//	misc_sm3.c
//	2020-03-10	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2020, PQShield Ltd. All rights reserved.

//	SM3 compression function for RV32

//	XXX	this is just a placeholder XXX

#include <stdio.h>
#include <string.h>

//	bitmanip (emulation) prototypes here
#include "bitmanip.h"

//	nonlinear functions
#define CH(x, y, z) ((x & y) ^ rv_andn(z, x))
#define MAJ(x, y, z) (((z | x) & y) | (z & x))

//	compression function (this one does *not* modify m[16])

void rv32_sm3_compress(uint32_t *s, uint32_t *m)
{
	int i;
	uint32_t	a, b, c, d, e, f, g, h;

	uint32_t 	w[68];
	uint32_t	t, u, tj;

	a = s[0];	b = s[1];	c = s[2];	d = s[3];
	e = s[4];	f = s[5];	g = s[6];	h = s[7];

	//	load with rev8.w
	for (i = 0; i < 16; i++) {
		w[i] = m[i];//rv_grev(m[i], 0x18);
	}

	//	linear schedule

	for (i = 16; i < 68; i++) {
		t = w[i - 16] ^ w[i - 9] ^ rv_ror(w[i - 3], 17);
		w[i] = t ^ rv_ror(t, 17) ^ rv_ror(t,  9)
				^ w[i - 6] ^ rv_ror(w[i - 13], 25);
	}

	for (i = 0; i < 16; i++) {


		//	round constant
		tj = rv_ror(0x79CC4519, (-i) & 0x1F);

		t = rv_ror(a, 20);
		u = rv_ror(t + e + tj, 25);
		t = t ^ u;

		//	left track

		t = t + (a ^ b ^ c) + d + (w[i] ^ w[i + 4]);
		d = c;
		c = rv_ror(b, 23);
		b = a;
		a = t;

		//	right track

		u = (e ^ f ^ g) + h + u + w[i];
		h = g;
		g = rv_ror(f, 13);
		f = e;
		e = u ^ rv_ror(u, 23) ^ rv_ror(u, 15);
	}


	for (i = 16; i < 64; i++) {

		//	round constant
		tj = rv_ror(0x7A879D8A, (-i) & 0x1F);

		t = rv_ror(a, 20);
		u = rv_ror(t + e + tj, 25);
		t = t ^ u;

		//	left track

		t = d + MAJ(a, b, c) + t + (w[i] ^ w[i + 4]);
		d = c;
		c = rv_ror(b, 23);
		b = a;
		a = t;

		//	right track

		u = h + CH(e, f, g) + u + w[i];
		h = g;
		g = rv_ror(f, 13);
		f = e;
		e = u ^ rv_ror(u, 23) ^ rv_ror(u, 15);

	}

	s[0] = s[0] ^ a;	s[1] = s[1] ^ b;
	s[2] = s[2] ^ c;	s[3] = s[3] ^ d;
	s[4] = s[4] ^ e;	s[5] = s[5] ^ f;
	s[6] = s[6] ^ g;	s[7] = s[7] ^ h;
}

int tek()
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

	return 0;
}
