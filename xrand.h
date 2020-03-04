//	xrand.h
//	2019-12-27	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	xoshiro with slight changes to create a useable api with seeding

#ifndef _XRAND_H_
#define _XRAND_H_

#include <stdint.h>

//	64-bit random number
uint64_t xrand(void);

//	jump 2^128 positions forward
void xrand_jump(void);

//	seed the random number generator
void xsrand(uint64_t x);

//	state
extern uint64_t xrand_s[4];

#endif
