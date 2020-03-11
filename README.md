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

The main purpose of this work is to facilitate quantitative analysis and 
instruction counts for the hash function core parts which are the Keccak-p 
permutation for SHA-3 and the two SHA-2 compression functions (one for 
SHA2-225/256 and another for SHA2-384/512). Some preliminary investigations 
have also been made with the Chinese SM3 standard hash.

This work is related to the following RISC-V Extension profiles which
are also works in progress.

*	**Crypto**:
	[RISC-V Cryptographic Extension Proposals](https://github.com/scarv/riscv-crypto).
	Draft version 0.2.1, March 9, 2020.
*	**Bitmanip**:
	[RISC-V Bitmanip (Bit Manipulation) Extension](https://github.com/riscv/riscv-bitmanip). Draft version of January 29, 2020.

As is being done with ["lwaes_isa"](https://github.com/mjosaarinen/lwaes_isa) 
for AES-128/192/256 and SM4 block ciphers, we hope to extend this eventually
to full freely usable assembler listings of these primitives -- an open
source "performance library" of sorts.


##	SHA-3

The SHA-3 implementations utilize a subset of bitmanip instructions only, 
which are emulated by functions in [bitmanip.c](bitmanip.h). The file 
[sha3.c](sha3.c) provides padding testing wrappers and is used by the unit 
tests in [test_sha3.c](test_sha3.c). These are not subject to optimization.

The cryptographic permutation Keccak-p is used via a function pointer
`void (*sha3_keccakp)(void *)` which must be set to an implementation of
this 1600-bit, 24-round keyless permutation that is the foundation of all
current permutation-based NIST cryptography (even beyond FIPS 202).

* [rv64_keccakp.c](rv64_keccakp.c) is a RV64 implementation that uses
	(per round) 76 × XOR, 29 × RORIW, and 25 × ANDN, and few auxiliary
	ops for loading a round constant and looping.
	The 1600-bit state and temporary registers fit into the register file,
	although a C compiler may not be able to do that.
* [rv32_keccakp.c](rv32_keccakp.c) is a RV32 implementation that uses
	the bit interleaving technique; this is accomplished with the
	help of bitmanip SHFL and UNSHFL instructions -- however these are
	outside the main loop so an implementation could do without.
	This implementation loops some operations to show how offsets
	can be used and can split each 64-bit rotation into one or two 32-bit
	rotations, thanks to the bit-interleaving technique.
	We have 162 × XOR, 52 × RORI, 50 × ANDN and a large number of 
	loads and stores -- optimization of which is nontrivial.

**Observations:** we found it preferable to use the the standard RISC-V 
offset indexing loads and stores without any need for special index
computation as proposed in "Scalar SHA3 Accelleration" instructions.
ROR and ANDN are typically expected in ISAs, although they are missing
from the RV32I/RV64I base -- here they give up to 50% performance
boost, but the main advantage is really the large register file.

##	SHA-2

The SHA-2 code explores the use of special instructions 


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

