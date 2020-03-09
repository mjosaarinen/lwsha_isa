//	test_main.c
//	2020-03-02	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2020, PQShield Ltd. All rights reserved.

#include "test_hex.h"
#include "sha3.h"

//	prototypes
void rv32_keccakp(void *);					//	rv32_keccakp.c
void rv64_keccakp(void *);					//	rv64_keccakp.c

int test_keccakp();							//	test_sha3.c
int test_sha3();							//	test_sha3.c
int test_shake();							//	test_sha3.c

int gek();
int tek();

//	stub main

int main(int argc, char **argv)
{
	int i;
	int fail = 0;

//	return tek();

	for (i = 0; i < 2; i++) {

		switch (i) {
			case 0:
				printf("[INFO] === SHA3 using rv32_keccakp() ===\n");
				sha3_keccakp = rv32_keccakp;
				break;

			case 1:
				printf("[INFO] === SHA3 using rv64_keccakp() ===\n");
				sha3_keccakp = rv64_keccakp;
				break;
		}
		fail += test_keccakp();
		fail += test_sha3();
		fail += test_shake();
	}


	if (fail == 0) {
		printf("[PASS] all tests passed.\n");
	} else {
		printf("[FAIL] === %d tests failed ===\n", fail);
	}

	return 0;
}

