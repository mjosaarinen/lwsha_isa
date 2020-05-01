//  rv_endian.h
//  2020-04-30  Markku-Juhani O. Saarinen <mjos@pqshield.com>
//  Copyright (c) 2020, PQShield Ltd. All rights reserved.

//  RISC-V specific endianess support would be here (via intrinsics)

#ifndef _RV_ENDIAN_H_
#define _RV_ENDIAN_H_

//  revert if not big endian

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define GREV_BE32(x) (x)
#else
	//  grev(x, 0x18) or rev8
#define GREV_BE32(x) (	\
	(((x) & 0xFF000000) >> 24) | (((x) & 0x00FF0000) >> 8)  | \
	(((x) & 0x0000FF00) << 8)  | (((x) & 0x000000FF) << 24))
#endif

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define GREV_BE64(x) (x)
#else
//  RISC-V: grevw(x, 0x38) or rev8(x)
#define GREV_BE64(x) (						\
	(((x) & 0xFF00000000000000LL) >> 56) | 	\
	(((x) & 0x00FF000000000000LL) >> 40) | 	\
	(((x) & 0x0000FF0000000000LL) >> 24) | 	\
	(((x) & 0x000000FF00000000LL) >> 8)  | 	\
	(((x) & 0x00000000FF000000LL) << 8)  | 	\
	(((x) & 0x0000000000FF0000LL) << 24) | 	\
	(((x) & 0x000000000000FF00LL) << 40) | 	\
	(((x) & 0x00000000000000FFLL) << 56))
#endif

//  big-endian loads and stores

static inline uint32_t be_get32(const uint8_t * x)
{
	return (((uint32_t) x[0]) << 24) | (((uint32_t) x[1]) << 16) |
		(((uint32_t) x[2]) << 8) | ((uint32_t) x[3]);
}

static inline void be_put32(uint8_t * x, uint32_t u)
{
	x[0] = u >> 24;
	x[1] = u >> 16;
	x[2] = u >> 8;
	x[3] = u;
}

static inline uint64_t be_get64(const uint8_t * x)
{
	return (((uint64_t) x[0]) << 56) | (((uint64_t) x[1]) << 48) |
		(((uint64_t) x[2]) << 40) | (((uint64_t) x[3]) << 32) |
		(((uint64_t) x[4]) << 24) | (((uint64_t) x[5]) << 16) |
		(((uint64_t) x[6]) << 8) | ((uint64_t) x[7]);
}

static inline void be_put64(uint8_t * x, uint64_t u)
{
	x[0] = u >> 56;
	x[1] = u >> 48;
	x[2] = u >> 40;
	x[3] = u >> 32;
	x[4] = u >> 24;
	x[5] = u >> 16;
	x[6] = u >> 8;
	x[7] = u;
}

#endif
