//	xrand.c
//	2019-12-27	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	xoshiro with slight changes to create a useable api with seeding

#include "xrand.h"

//	== from xoshiro256starstar.c ==

/*	Written in 2018 by David Blackman and Sebastiano Vigna (vigna@acm.org)

To the extent possible under law, the author has dedicated all copyright
and related and neighboring rights to this software to the public domain
worldwide. This software is distributed without any warranty.

See <http://creativecommons.org/publicdomain/zero/1.0/>. */


/* This is xoshiro256** 1.0, one of our all-purpose, rock-solid
   generators. It has excellent (sub-ns) speed, a state (256 bits) that is
   large enough for any parallel application, and it passes all tests we
   are aware of.

   For generating just floating-point numbers, xoshiro256+ is even faster.

   The state must be seeded so that it is not everywhere zero. If you have
   a 64-bit seed, we suggest to seed a splitmix64 generator and use its
   output to fill s. */

uint64_t xrand_s[4];

static inline uint64_t roltl64(const uint64_t x, int k)
{
	return (x << k) | (x >> (64 - k));
}


uint64_t xrand(void)
{
	const uint64_t result = roltl64(xrand_s[1] * 5, 7) * 9;
	const uint64_t t = xrand_s[1] << 17;

	xrand_s[2] ^= xrand_s[0];
	xrand_s[3] ^= xrand_s[1];
	xrand_s[1] ^= xrand_s[2];
	xrand_s[0] ^= xrand_s[3];

	xrand_s[2] ^= t;

	xrand_s[3] = roltl64(xrand_s[3], 45);

	return result;
}

/* This is the jump function for the generator. It is equivalent
   to 2^128 calls to next(); it can be used to generate 2^128
   non-overlapping subsequences for parallel computations. */

void xrand_jump(void)
{
	static const uint64_t JUMP[] = {
		0x180ec6d33cfd0aba, 0xd5a61266f0c9392c,
		0xa9582618e03fc9aa, 0x39abdc4529b1661c
	};

	uint64_t s0 = 0;
	uint64_t s1 = 0;
	uint64_t s2 = 0;
	uint64_t s3 = 0;
	for(int i = 0; i < sizeof JUMP / sizeof *JUMP; i++)
		for(int b = 0; b < 64; b++) {
			if (JUMP[i] & UINT64_C(1) << b) {
				s0 ^= xrand_s[0];
				s1 ^= xrand_s[1];
				s2 ^= xrand_s[2];
				s3 ^= xrand_s[3];
			}
			xrand();
		}

	xrand_s[0] = s0;
	xrand_s[1] = s1;
	xrand_s[2] = s2;
	xrand_s[3] = s3;
}



/* This is the long-jump function for the generator. It is equivalent to
   2^192 calls to next(); it can be used to generate 2^64 starting points,
   from each of which jump() will generate 2^64 non-overlapping
   subsequences for parallel distributed computations. */

void xrand_jump192(void)
{
	static const uint64_t LONG_JUMP[] = {
		0x76e15d3efefdcbbf, 0xc5004e441c522fb3,
		0x77710069854ee241, 0x39109bb02acbe635
	};

	uint64_t s0 = 0;
	uint64_t s1 = 0;
	uint64_t s2 = 0;
	uint64_t s3 = 0;
	for(int i = 0; i < sizeof LONG_JUMP / sizeof *LONG_JUMP; i++)
		for(int b = 0; b < 64; b++) {
			if (LONG_JUMP[i] & UINT64_C(1) << b) {
				s0 ^= xrand_s[0];
				s1 ^= xrand_s[1];
				s2 ^= xrand_s[2];
				s3 ^= xrand_s[3];
			}
			xrand();
		}

	xrand_s[0] = s0;
	xrand_s[1] = s1;
	xrand_s[2] = s2;
	xrand_s[3] = s3;
}

//	from splitmix64.c

/*	Written in 2015 by Sebastiano Vigna (vigna@acm.org)

To the extent possible under law, the author has dedicated all copyright
and related and neighboring rights to this software to the public domain
worldwide. This software is distributed without any warranty.

See <http://creativecommons.org/publicdomain/zero/1.0/>. */


/* This is a fixed-increment version of Java 8's SplittableRandom generator
   See http://dx.doi.org/10.1145/2714064.2660195 and
   http://docs.oracle.com/javase/8/docs/api/java/util/SplittableRandom.html

   It is a very fast generator passing BigCrush, and it can be useful if
   for some reason you absolutely want 64 bits of state. */


void xsrand(uint64_t x)
{
	int i;
	uint64_t z;

	for (i = 0; i < 4; i++) {
		z = (x += 0x9e3779b97f4a7c15);
		z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9;
		z = (z ^ (z >> 27)) * 0x94d049bb133111eb;
		xrand_s[i] = z ^ (z >> 31);
	}
}

