//  cshake.c
//  2020-03-28  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

#include "sha3.h"


void sha3_right_enc(sha3_ctx_t * c, uint64_t x)
{
	int i;
	uint8_t be[9];							//  big endian

	i = 8;
	do {
		be[--i] = x & 0xFF;
		x >>= 8;
	}
	while (x > 0);
	be[8] = 8 - i;
	sha3_update(c, be + i, 9 - i);
}

void sha3_left_enc(sha3_ctx_t * c, uint64_t x)
{
	int i;
	uint8_t be[9];							//  big endian

	i = 8;
	do {
		be[i--] = x & 0xFF;
		x >>= 8;
	}
	while (x > 0);
	be[i] = 8 - i;
	sha3_update(c, be + i, 9 - i);
}
