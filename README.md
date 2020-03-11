# Lightweight RISC-V ISA Extensions and Standard Hash Functions

March 11, 2020  Markku-Juhani O. Saarinen <mjos@pqshield.com>

##	Description and Goal

[RISC-V](https://riscv.org/) design exploration for the current primary hash
function standards:

*	**SHA-3**: 
	*"SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions"* 
	([FIPS PUB 202](https://doi.org/10.6028/NIST.FIPS.202))
	algorithms SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, and SHAKE256.
*	**SHA-2**: *"Secure Hash Standard (SHS)"* 
	([FIPS PUB 180-4](https://doi.org/10.6028/NIST.FIPS.180-4))
	algorithms SHA-224, SHA-256, SHA-384, and SHA-512.
	These older functions are denoted as SHA2-xxx to avoid confusion.

Presently this repository contains "runnable pseudocode" implementations
and unit tests for all. Running `make` followed by `./xtest` should execute
those tests on most Linux type PCs without any special hardware or software.

The main purpose is to facilitate preliminary quantitative analysis of 
instruction counts for the core functions which are the Keccak-p permutation
for FIPS 202 SHA-3 and the SHA-256 and SHA-512 compression functions for 
SHA-2 SHS. Some preliminary investigations have also gone into the 
compression function of the Chinese SM3 standard hash.

This work is related to the following RISC-V Extension profiles which
are also works in progress.

*	**Crypto**:
	[The RISC-V Crypto Extension](https://github.com/scarv/riscv-crypto).
*	**Bitmanip**:
	[The RISC-V Bitmanip Extension](https://github.com/riscv/riscv-bitmanip).

As is being done with ["lwaes_isa"](https://github.com/mjosaarinen/lwaes_isa) 
for AES-128/192/256 and SM4 block ciphers, we hope to extend this eventually
to full freely usable assembler listings of these primitives -- an open
source "performance library" of sorts.

##	SHA-3

The SHA-3 functions utilize a subset of bitmanip instructions only, simply
emulated by functions in [bitmanip.c](bitmanip.h). The file [sha3.c](sha3.c)
provides padding; testing wrappers and is used by the unit tests in
[test_sha3.c](test_sha3.c). These are not subject to optimization exploration.
The cryptographic permutation Keccak-p is used via a function pointer
`void (*sha3_keccakp)(void *)` which must be set to an implementation of
this 1600-bit, 24-round keyless permutation that is the foundation of all
current permutation-based NIST cryptography (even beyond FIPS 202).


**Disclaimer and Status**

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

