//  test_main.c
//  2020-03-02  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//	Main self-test code.

#include <stdio.h>

#include "sha2_wrap.h"
#include "sha3_wrap.h"

int test_sha2_256();						//  test_sha2.c
int test_sha2_512();
int test_sha2_hmac();

int test_keccakp();							//  test_sha3.c
int test_sha3();
int test_shake();

int test_sm3();								//  test_sm3.c

//  stub main

int main(int argc, char **argv)
{
	int fail = 0;

	printf("[INFO] === SHA2-256 using rv32_sha256_compress() ===\n");
	sha256_compress = rv32_sha256_compress;
	fail += test_sha2_256();

	printf("[INFO] === SHA2-512 using rv64_sha512_compress() ===\n");
	sha512_compress = rv64_sha512_compress;
	fail += test_sha2_512();

	printf("[INFO] === SHA2-512 using rv32_sha512_compress() ===\n");
	sha512_compress = rv32_sha512_compress;
	fail += test_sha2_512();

	printf("[INFO] === rv32_sha256_compress() rv64_sha512_compress() ===\n");
	sha256_compress = rv32_sha256_compress;
	sha512_compress = rv64_sha512_compress;
	fail += test_sha2_hmac();

	printf("[INFO] === SHA3 using rv32_keccakp() ===\n");
	sha3_keccakp = rv32_keccakp;
	fail += test_keccakp();
	fail += test_sha3();
	fail += test_shake();

	printf("[INFO] === SHA3 using rv64_keccakp() ===\n");
	sha3_keccakp = rv64_keccakp;
	fail += test_keccakp();
	fail += test_sha3();
	fail += test_shake();

	printf("[INFO] === SM3 tests ===\n");
	fail += test_sm3();

	printf("[%s] === finished with %d unit test failures ===\n",
		   fail == 0 ? "PASS" : "FAIL", fail);

	return 0;
}
