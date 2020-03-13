//	test_main.c
//	2020-03-02	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2020, PQShield Ltd. All rights reserved.

#include <stdio.h>

//	test prototypes

int test_sha2_all();			//	test_sha2.c
int test_sha3_all();			//	test_sha3.c
int test_sm3();

//	stub main

int main(int argc, char **argv)
{
	int fail = 0;

	return test_sm3();

	fail += test_sha2_all();
	fail += test_sha3_all();
//	fail += test_sm3();

	printf("[%s] === finished with %d unit test failures ===\n",
		fail == 0 ? "PASS" : "FAIL", fail);

	return 0;
}

