# Lightweight RISC-V ISA Extensions and Standard Hash Functions

March 11, 2020  Markku-Juhani O. Saarinen <mjos@pqshield.com>

##	Description

RISC-V design exploration for the primary current and near future hash
function standards:

*	**SHA-3**: [FIPS PUB 202](https://doi.org/10.6028/NIST.FIPS.202)
	"SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions"
	algorithms SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128 and SHAKE256.
*	**SHA-2**: [FIPS PUB 180-4](https://doi.org/10.6028/NIST.FIPS.180-4)
	"Secure Hash Standard (SHS)" algorithms SHA-224, SHA-256, SHA-384, and
	SHA-512. These are denoted as SHA2-xxx here to avoid confusion.

Currently this repository contains "runnable pseudocode" implementations
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
	(The RISC-V Crypto Extension))[https://github.com/scarv/riscv-crypto].
*	**Bitmanip**:
	(The RISC-V Bitmanip Extension)[https://github.com/riscv/riscv-bitmanip].

As is being done with [lwaes_isa](https://github.com/mjosaarinen/lwaes_isa) 
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

##	SHA-2



