//	test_main.c
//	2020-03-02	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2020, PQShield Ltd. All rights reserved.

#include <stdio.h>

//	test prototypes
int test_sha256();			//	test_sha2.c
int test_sha3s();			//	test_sha3.c

//	stub main

int main(int argc, char **argv)
{
	int fail = 0;

	fail += test_sha256();
	fail += test_sha3s();

	printf("[%s] === finished with %d unit test failures ===\n", 
		fail == 0 ? "PASS" : "FAIL", fail);

	return 0;
}

