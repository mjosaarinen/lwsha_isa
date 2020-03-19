#	RISC-V ISA Extensions and Standard Hash Functions

March 11, 2020  Markku-Juhani O. Saarinen <mjos@pqshield.com>

##	Description and Goal

[RISC-V](https://riscv.org/) ISA Extension design exploration for the current
primary hash function standards:

*	**SHA-3**: 
	*"SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions"* 
	([FIPS PUB 202](https://doi.org/10.6028/NIST.FIPS.202))
	algorithms SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, and SHAKE256.
*	**SHA-2**: *"Secure Hash Standard (SHS)"* 
	([FIPS PUB 180-4](https://doi.org/10.6028/NIST.FIPS.180-4))
	algorithms SHA-224, SHA-256, SHA-384, and SHA-512.
	These older functions are denoted SHA2-xxx to avoid confusion.

Presently this repository contains "runnable pseudocode" implementations
and unit tests for all. Running `make` followed by `./xtest` should execute
those tests on most Linux type PCs without any special hardware or software
(you may have to adjust `Makefile`).

The main purpose of this work is to facilitate quantitative analysis such 
as instruction counts. We focus on the core iterations parts: the
Keccak-p permutation for SHA-3 and the two SHA-2 compression functions 
(one for SHA2-225/256 and another for SHA2-384/512). Some preliminary
investigations have also been made with the Chinese SM3 standard hash.

This work is related to the following RISC-V Extension profiles which
are also works in progress.

*	**Crypto**:
	[RISC-V Cryptographic Extension Proposals](https://github.com/scarv/riscv-crypto).
	Draft version 0.2.1, March 9, 2020.
*	**Bitmanip**:
	[RISC-V Bitmanip (Bit Manipulation) Extension](https://github.com/riscv/riscv-bitmanip). Draft version of January 29, 2020.

This work complements the analysis done in the crypto extension with somewhat
different algorithm implementation techniques.

As is being done with ["lwaes_isa"](https://github.com/mjosaarinen/lwaes_isa) 
for AES-128/192/256 and SM4 block ciphers, we hope to extend this eventually
to full freely usable assembler listings of these primitives -- an open
source "performance library" of sorts. 

Unlike with AES, these instructions are not required for resistance against 
cache-timing attacks, which is not an issue for any of them. 

##	SHA-3

The SHA-3 implementations utilize a subset of bitmanip instructions only, 
which are emulated by functions in [bitmanip.c](bitmanip.c). The file 
[sha3.c](sha3.c) provides padding testing wrappers and is used by the unit 
tests in [test_sha3.c](test_sha3.c). These are not subject to optimization.

The cryptographic permutation Keccak-p is used via a function pointer
`void (*sha3_keccakp)(void *)` which must be set to an implementation of
this 1600-bit, 24-round keyless permutation that is the foundation of all
current permutation-based NIST cryptography (even beyond FIPS 202).

* [rv64_keccakp.c](rv64_keccakp.c) is an RV64 implementation that uses
	(per round) 76 × XOR, 29 × RORIW, and 25 × ANDN, and few auxiliary
	ops for loading a round constant and looping.
	The 1600-bit state and temporary registers fit into the register file,
	although a C compiler may not be able to do that.
* [rv32_keccakp.c](rv32_keccakp.c) is an RV32 implementation that uses
	the even/odd bit interleaving technique; this is accomplished with the
	help of bitmanip SHFL and UNSHFL instructions -- however these are
	outside the main loop and not really critical.
	The benefit inside the main loop is that each 64-bit rotation can be
	implemented with one or two independent 32-bit rotations. We have 
	152 × XOR, 52 × RORI, 50 × ANDN and a large number of loads and stores --
	optimization of which is nontrivial.

**Observations:** we found it preferable to use the standard RISC-V 
offset indexing loads and stores without any need for special index
computation as proposed in "Scalar SHA3 Acceleration" instructions.
ROR and ANDN are typically expected in ISAs, although they are missing
from the RV32I/RV64I base -- here they give up to 50% performance
boost, but the main advantage is really the large register file.

##	SHA-2

The SHA-2 code explores the use of special instructions for "Scalar SHA2 
Acceleration", which offer to accelerate all SHA2 algorithms on RV64 and
SHA2-224/256 on RV32.  The file [sha2.c](sha2.c) provides padding testing
wrappers and is used by the unit tests in [test_sha2.c](test_sha2.c).

These instructions implement the "sigma functions" defined in Sections 
4.1.2 and 4.1.3 of FIPS 180-4. By convention, I'll write the upper case
sigma letter Σ as "sum" and lower case σ as "sig".
This naming convention is arbitrary and may change later.

We currently diverge from the specification somewhat as we expand them into
two-input functions that also perform an ADD operation. The operands are
selected so that we may have RS1=RD to save opcode space, as can be done with
lightweight AES. They are composed of three shifts/rotations, two XORs, 
and one addition each.

Their emulation functions are in respective compression function 
implementation files. For example for SHA-256 we have:
```C
uint32_t sha256_sum0(uint32_t rs1, uint32_t rs2)
{
    return rs1 + (rv_ror(rs2,  2) ^ rv_ror(rs2, 13) ^ rv_ror(rs2, 22));
}

uint32_t sha256_sum1(uint32_t rs1, uint32_t rs2)
{
    return rs1 + (rv_ror(rs2,  6) ^ rv_ror(rs2, 11) ^ rv_ror(rs2, 25));
}

uint32_t sha256_sig0(uint32_t rs1, uint32_t rs2)
{
    return rs1 + (rv_ror(rs2,  7) ^ rv_ror(rs2, 18) ^ (rs2 >>  3));
}

uint32_t sha256_sig1(uint32_t rs1, uint32_t rs2)
{
    return rs1 + (rv_ror(rs2, 17) ^ rv_ror(rs2, 19) ^ (rs2 >> 10));
}
```

*Note:* Based on feedback, I will probably replace these with single-input
variants soon (i.e. dropping that addition and using rs2 as the only source).


We have:

*	[rv32_sha256.c](rv32_sha256.c) is an implementation of the SHA2-224/256
	compression function on RV32 (the RV64 implementation is probably
	equivalent).
*	[rv64_sha512.c](rv64_sha512.c) is an implementation of the SHA2-384/512
	compression function on RV64.

For both of these implementations the state is 8 words and each message
block is 16 words in both cases so these fit nicely in the register file. 

There are two kinds of steps; message scheduling steps K and rounds R.
SHA2-224/256 has 48 × K steps and 64 × R steps while SHA2-384/512 has 
64 × K steps and 80 × R steps (their structure is equivalent on both,
although data path size differs 32/64-bit).

Hence we have the following core loop instruction mix:

| 			|	K 	|	R	| SHA2-224/256 	| SHA2-384/512	|
|----------:|------:|------:|--------------:|--------------:|
| ADD		|	1	|	5	|	368			|	464			|
| AND		|	0	|	3	|	192			|	240			|
| ANDN		|	0	|	1	|	64			|	80			|
| OR		|	0	|	2	|	128			|	160			|
| SHAx		|	2	|	2	|	224			|	288			|
| **Total**	|	3	|	13	|	**976**		|	**1232**	|

Each SHAx instruction would decompose into 6-12 base instructions (even with
rotate), so this is a significant speedup (2 × faster or more). The ADD 
fused here is just an opportunistic 20% performance improvement over the
current spec.

SHA2-384/512 on RV32 is not tackled yet; implementing its entirely 
64-bit data paths on RV32 is challenging. The large number of 64-bit additions
will result in a lot of SLTUs because RISC-V has no carry. Those additions 
also make the interleaving technique used for SHA-3 unusable and therefore
there may be a need for funnel shifts.

##	SM3

The file [temp_sm3.c](temp_sm3.c) contains our initial exploration of the 
Chinese Hash function [SM3](doc/sm3-ch.pdf) [english](doc/sm3-en.pdf) 
(GB/T 32905-2016, GM/T 0004-2012, ISO/IEC 10118-3:2018). Currently we
can not recommend any specific lightweight instructions that would be
particularly helpful for it.

Observations:

*	The external structure of SM3 is very similar to SHA-256; It is possible
	to perform the entire compression function iteration without stack
	loads and stores here as well.
*	Gains from RORI are very high as the algorithm is highly dependent
	on rotations.
*	The message expansion LFSR is much denser than that of SHA-256, which is
	the main factor increasing the overall instruction count.
*	A straight-forward implementation does not have timing issues.

Using a subset of bitmanip we observe from [temp_sm3.c](temp_sm3.c):
Key steps K have 4 × RORI, 6 × XOR = 10 (completely linear). 
Round 0..15 step R0 has 8 × ADD, 7 × RORI , 8 × XOR = 23 (it's entirely ARX!)
Round 16..64 step R1 has 8 × ADD, 7 × RORI, 5 × XOR, 3 × AND, 2 × OR, 1 × ANDN = 26

There are 52 K steps, 16 R0 steps, and 48 R1 steps, so 2136 total for the compression function sans looping and input/output loads.

The best single instruction I could come up with was a special instruction 
related to P1 permutation that would combine 3 RORIs and 3 XORs in K step:
```C
uint32_t sm3p1(uint32_t rs1, uint32_t rs2) 
{
	return rs1 ^ rv_ror(rs1,  9) ^ rv_ror(rs1, 17) ^ rv_ror(rs2, 25);
}
```
would save 208 instructions only (roughly 10%). Even with multiple such
things (one for P0 etc) the gains are under 50%.

####

####	Disclaimer and Status

*   [PQShield](https://pqshield.com) offers no warranty or specific claims of
    standards compliance nor does not endorse this proposal above other
    proposals. PQShield may or may not implement SHA-2, SHA-3, SM3 or other
	algorithms according to this proposal in the future.
*   Despite being proposed in a personal capacity, this proposal
    constitutes a "contribution" as defined in Section 1.4 of the
    RISC-V foundation membership agreement.
*   This distribution is offered under MIT license agreement, so you're free
    to use the pseudocode to build actual cipher implementations (that's
    what it's for).

Cheers,
- markku

