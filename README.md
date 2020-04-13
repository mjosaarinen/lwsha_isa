#   RISC-V ISA Extensions and Standard Hash Functions

March 11, 2020  Markku-Juhani O. Saarinen <mjos@pqshield.com>

**Updated** March 31, 2020: Changed the two-operand instructions, added
consideration for SHA2-512 on RV32 and also the Chinese hash SM3.

##  Description and Goal

[RISC-V](https://riscv.org/) ISA Extension design exploration for the current
primary hash function standards:

*   **SHA-3**:
    *"SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions"*
    ([FIPS PUB 202](https://doi.org/10.6028/NIST.FIPS.202))
    algorithms SHA3-224, SHA3-256, SHA3-384, SHA3-512, SHAKE128, and SHAKE256.
*   **SHA-2**: *"Secure Hash Standard (SHS)"*
    ([FIPS PUB 180-4](https://doi.org/10.6028/NIST.FIPS.180-4))
    algorithms SHA-224, SHA-256, SHA-384, and SHA-512.
    These older functions are denoted SHA2-xxx to avoid confusion.

Presently this repository contains "runnable pseudocode" implementations
and unit tests for all. Running `make` followed by `./xtest` should execute
those tests on most Linux type PCs without any special hardware or software
(you may have to adjust `Makefile`).

The main purpose of this work is to facilitate quantitative analysis such
as instruction counts. We focus on the core iterations: the
Keccak-p permutation for SHA-3 and the two SHA-2 compression functions
(one for SHA2-225/256 and another for SHA2-384/512). Some preliminary
investigations have also been made with the Chinese SM3 hash standard.

This work is related to the following RISC-V Extension profiles which
are also works in progress.

*   **Crypto**:
    [RISC-V Cryptographic Extension Proposals](https://github.com/scarv/riscv-crypto).
    Draft version 0.2.1, March 9, 2020.
*   **Bitmanip**:
    [RISC-V Bitmanip (Bit Manipulation) Extension](https://github.com/riscv/riscv-bitmanip). Draft version of January 29, 2020.

This work complements the analysis done in the crypto extension with somewhat
different algorithm implementation techniques.

As is being done with ["lwaes_isa"](https://github.com/mjosaarinen/lwaes_isa)
for AES-128/192/256 and SM4 block ciphers, we hope to extend this eventually
to full freely usable assembler listings of these primitives -- an open
source "performance library" of sorts.

Unlike with AES, these instructions are not required for resistance against
cache-timing attacks, which is not an issue for any of them.

##  SHA-3

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

##  SHA-2 Basic Extensions

The SHA-2 code explores the use of special instructions for "Scalar SHA2
Acceleration", which offer to accelerate all SHA2 algorithms on RV64 and
SHA2-224/256 on RV32.  The file [sha2.c](sha2.c) provides padding testing
wrappers and is used by the unit tests in [test_sha2.c](test_sha2.c).

These instructions implement the "sigma functions" defined in Sections
4.1.2 and 4.1.3 of FIPS 180-4. By convention, I'll write the upper case
sigma letter Σ as "sum" and lower case σ as "sig".
This naming convention is arbitrary and may change later.

Their emulation functions are in respective compression function
implementation files. For example for SHA-256 we have:
```C
uint32_t sha256_sum0(uint32_t rs1)
{
    return rvb_ror(rs1, 2) ^ rvb_ror(rs1, 13) ^ rvb_ror(rs1, 22);
}

uint32_t sha256_sum1(uint32_t rs1)
{
    return rvb_ror(rs1, 6) ^ rvb_ror(rs1, 11) ^ rvb_ror(rs1, 25);
}

uint32_t sha256_sig0(uint32_t rs1)
{
    return rvb_ror(rs1, 7) ^ rvb_ror(rs1, 18) ^ (rs1 >> 3);
}

uint32_t sha256_sig1(uint32_t rs1)
{
    return rvb_ror(rs1, 17) ^ rvb_ror(rs1, 19) ^ (rs1 >> 10);
}
```

We have:

*   [rv32_sha256.c](rv32_sha256.c) is an implementation of the SHA2-224/256
    compression function on RV32 (the RV64 implementation is probably
    equivalent).
*   [rv64_sha512.c](rv64_sha512.c) is an implementation of the SHA2-384/512
    compression function on RV64.

For both of these implementations the state is 8 words and each message
block is 16 words so 24 words fit nicely in the register file.

There are two kinds of steps; message scheduling steps K and rounds R.
SHA2-224/256 has 48 × K steps and 64 × R steps while SHA2-384/512 has
64 × K steps and 80 × R steps (their structure is equivalent on both,
although data path size differs 32/64-bit).

Hence we have the following core loop instruction mix:

| **Type**  | **K** | **R** | SHA2-256  | SHA2-512  |
|----------:|------:|------:|----------:|----------:|
| ADD       |   3   |   7   |   592     |   752     |
| AND       |   0   |   3   |   192     |   240     |
| ANDN      |   0   |   1   |   64      |   80      |
| OR        |   0   |   2   |   128     |   160     |
| SHAx_y    |   2   |   2   |   224     |   288     |
| **Total** |   5   |   15  | **1200**  | **1520**  |

Each SHAx instruction would decompose into 5-10 base instructions (even with
rotate), so this is a significant speedup (2 × faster or more).
Note that we are ignoring the operations required for endianess, padding, and
Merkle-Damgård addition here.


##  SHA2-512 on RV32

[rv32_sha512.c](rv32_sha512.c) is an implementation of the SHA2-384/512
compression function on RV32 and is more complicated than the
two other versions. The large number of 64-bit additions will result in
a lot of SLTUs because RISC-V has no carry flag. Those additions
also make the interleaving technique used for SHA-3 unusable. However
splitting the "Sum" and "Sigma" operations into six double-operand
instructions (each a linear operation with two 32-bit inputs) gives a
reasonable performance boost.

For example the 64-bit Σ0 and Σ1 functions (upper case Sigma; "sum") from
Section 4.1.3 of FIPS 180-4 are split into half using shifts in
[rv32_sha512.c](rv32_sha512.c) as follows:
```C
uint32_t sha512_sum0l(uint32_t rs1, uint32_t rs2)
{
    return  (rs1 << 25) ^ (rs1 << 30) ^ (rs1 >> 28) ^
            (rs2 >>  7) ^ (rs2 >>  2) ^ (rs2 <<  4);
}

uint32_t sha512_sum1l(uint32_t rs1, uint32_t rs2)
{
    return  (rs1 << 23) ^ (rs1 >> 14) ^ (rs1 >> 18) ^
            (rs2 >>  9) ^ (rs2 << 18) ^ (rs2 << 14);
}
```
What is noteworthy for "sum0l" and "sum1l" is that the high output words
can be computed by flipping the input operands rs1 and rs2. This is because
Σ0 and Σ1  are entirely made up of rotations and XORs.

However this is not possible for σ0 and σ1 as they have rotations
and a shift. For the high word instructions we flip the order
of input words to rs1=high, rs2=low so that the same data paths can
be used. This brings the total number of SHA2-512 instructions on RV32
to six.
```C
//  lower case sigma0, sima1 is "sig". low word of (rs2_rs1)
uint32_t sha512_sig0l(uint32_t rs1, uint32_t rs2)
{
    return  (rs1 >>  1) ^ (rs1 >>  7) ^ (rs1 >>  8) ^
            (rs2 << 31) ^ (rs2 << 25) ^ (rs2 << 24);
}

//  high word of (rs1_rs2) ( otherwise same but left shift 25 is missing )
uint32_t sha512_sig0h(uint32_t rs1, uint32_t rs2)
{
    return  (rs1 >>  1) ^ (rs1 >>  7) ^ (rs1 >>  8) ^
            (rs2 << 31) ^               (rs2 << 24);
}
```

The entire compression function state of 64 + 128 = 192 bytes no longer
fits into the register file; we choose to perform loads and stores on the
message extension. Anyway, the number of loads and stores greatly increases
in this variant.

So essentially the arithmetic instruction counts are doubled in relation
tor the 64-bit wide SHA-512, except that each ADD becomes four instructions;
three 32-bit ADDs and one SLTU.

| **Type**  | **K** | **R** | 64×K+80×R   |
|----------:|------:|------:|----------:|
| ADD       |   9   |   21  |   2256    |
| SLTU      |   3   |   7   |   752     |
| AND       |   0   |   6   |   480     |
| ANDN      |   0   |   2   |   160     |
| OR        |   0   |   4   |   320     |
| SHAx_y    |   4   |   4   |   576     |
| **Total** |   19  |   51  | **4544**  |

Note that if the 64-bit addition is hypothetically instead split into two
instructions, a 32-bit ADD (that sets the carry flag) and a 32-bit "ADC"
(add with carry) then the total instruction count comes down 17% to 3792.


##  SM3

The file [rv32_sm3.c](rv32_sm3.c) contains our initial exploration of the
compression function of Chinese Hash function [SM3](doc/sm3-ch.pdf)
[eng](doc/sm3-en.pdf) (GB/T 32905-2016, GM/T 0004-2012, ISO/IEC 10118-3:2018).
We also provide rudimentary instantiation in [sm3.c](sm3.c) and unit test in
[test_sm3.c](test_sm3.c).

Observations:

*   The external structure and padding mode of SM3 is very
    similar to SHA-256; It is possible to perform the entire compression
    function iteration without stack loads and stores here as well.
*   Gains from RORI are very high as the algorithm is highly dependent
    on rotations.
*   The message expansion LFSR is much denser than that of SHA-256, which is
    the main factor increasing the overall instruction count.
*   A straight-forward implementation does not have timing issues.

We are currently experimenting with two special instructions that implement
the P0 and P1 permutations (Section 4.4 of the specification, where these
mirror functions are expressed via left rotations):
```C
uint32_t sm3_p0(uint32_t rs1)
{
    return rs1 ^ rvb_ror(rs1, 15) ^ rvb_ror(rs1, 23);
}

uint32_t sm3_p1(uint32_t rs1)
{
    return rs1 ^ rvb_ror(rs1, 9) ^ rvb_ror(rs1, 17);
}
```
The also uses RORI and ANDN from Bitmanip.

I'm dividing the arithmetic ops in SM3 as keying steps 52 × K,
initial round steps 16 × R0, and main round steps 48 × R1.

| **Type**  |   K   |   R0  |   R1  | 52×K+16×R0+48×R1 |
|----------:|------:|------:|------:|------------:|
| ADD       |   0   |   8   |   8   |   512       |
| XOR       |   4   |   6   |   3   |   448       |
| AND       |   0   |   0   |   3   |   144       |
| ANDN      |   0   |   0   |   1   |   48        |
| OR        |   0   |   0   |   2   |   96        |
| RORI      |   2   |   5   |   5   |   424       |
| SM3_P0    |   0   |   1   |   1   |   64        |
| SM3_P1    |   1   |   0   |   0   |   52        |
| **Total** |   7   |   20  |   23  |   **1788**  |

We obtain 1788 total arithmetic ops for the compression function
sans looping and input/output loads.

Without the SM3_P0 and SM3_P1 instructions K, R1, R2 require
2 XORs and 2 RORIs more, bringing the total to 2136; the instructions
seem to offer less than 20% speed-up over base Bitmanip (which is
needed anyway). However it can be seen that these instructions are
structurally equivalent to the SHA256 Sigma functions above.

####

**Disclaimer and Status**

*   [PQShield](https://pqshield.com) offers no warranty or specific claims of
    standards compliance nor does not endorse this proposal above other
    proposals. PQShield may or may not implement SHA-2, SHA-3, SM3 or other
    algorithms according to this proposal in the future.
*   Despite being proposed in a personal capacity, this proposal
    constitutes a "contribution" as defined in Section 1.4 of the
    RISC-V foundation membership agreement.

Cheers,
- markku

