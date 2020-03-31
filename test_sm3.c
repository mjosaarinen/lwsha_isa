//  test_sm3.c
//  2020-03-30  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  The Chinese Standard SM3 Hash Function
//  GB/T 32905-2016, GM/T 0004-2012, ISO/IEC 10118-3:2018

//  simplified test with "abc" test vector from the standard

#include "test_hex.h"
#include "sm3.h"

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
