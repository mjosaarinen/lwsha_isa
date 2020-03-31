//  sm3.h
//  2020-03-10  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  The Chinese Standard SM3 Hash Function
//  GB/T 32905-2016, GM/T 0004-2012, ISO/IEC 10118-3:2018

#ifndef _SM3_H_
#define _SM3_H_

#include <stddef.h>
#include <stdint.h>

//  Compute 32-byte hash to "md" from "in" which has "inlen" bytes (sm3.c)
void sm3_256(uint8_t * md, const void *in, size_t inlen);

//  function pointer to the compression function (sm3.c)
extern void (*sm3_compress)(void *);

//  SM3 compression function for RV32 (rv32_sm3.c)
void rv32_sm3_compress(void *s);

#endif
