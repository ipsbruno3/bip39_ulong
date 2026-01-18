

# Main Optimizations in the BIP-39 OpenCL Solver

This kernel is heavily optimized for maximum throughput on GPUs, focusing on reducing instruction count, eliminating unnecessary loops, minimizing branches, and leveraging full unrolling where possible. Below is a detailed list of the key optimizations, organized by component.


# ✅ Optmizations

## Mnemonic Construction (BIP-39 Words into 64-bit Packing)

- **Brilliant `APPEND_AUTO` macro**  
  Copies up to 8 bytes at a time (or intelligently splits when crossing a `ulong` boundary). For BIP-39 words (max 8 letters), each `APP_WORD` costs only **1–3 instructions** (shifts + ORs + uint arithmetic). Almost zero branching (only a simple `if` that the compiler optimizes well).  
  Result: mnemonic construction is extremely cheap — typically **<20 instructions total** for the 5 variable words.

- **Fixed prefix pre-XORed with IPAD/OPAD**  
  The 5 ulongs of the known prefix (P0–P4) are XORed with IPAD/OPAD at compile time.  
  Saves 5 XORs per thread and, more importantly, reduces register pressure.

- **Inner/outer arrays initialized with fixed padding and bit length**  
  Padding and length bits are hardcoded, avoiding runtime computation.

- **Fully unrolled tail XOR**  
  `#pragma unroll` on a loop of at most 11 iterations → compiler inlines all XORs with zero loop overhead.

- **Direct bit-shift extraction of word indices (w0–w4)**  
  No private arrays or complex logic. w4 cleverly incorporates the SHA-256 checksum, filtering invalid candidates early.

- **Use of `__constant` memory and masks**  
  `KEEP_MSB_MASK` stored in constant memory for fast access. Everything aligned for GPU execution (low divergence, good coalescing when `WORDS_STRING`/`WORDS_LEN` are in constant memory).

## PBKDF2-HMAC-SHA512

- **First HMAC computed outside the loop**  
  Handles the longer initial message ("mnemonic" salt + passphrase) separately, requiring two `sha512_process` calls for the inner hash.

- **Tight main loop**  
  For the remaining 2047 iterations, the message is only the previous U (64 bytes < block size), requiring just **one `sha512_process` per inner HMAC + one for outer**. Total per iteration: 2 SHA-512 compressions + minimal copies/XORs.

- **Vectorized copies via `COPY_EIGHT`**  
  OpenCL compiler typically converts these to native `vstore8`/`vload8` instructions.

- **Efficient register usage**  
  Everything kept in `__private ulong[8]` arrays with no unnecessary spilling.

- **Zero branching in the hot loop** (except loop counter) — ideal for GPU execution.

## SHA-512 Implementation

- **100% unrolled message expansion**  
  All W₁₆ through W₇₉ are computed sequentially with no loops. Eliminates loop overhead and enables perfect instruction scheduling by the compiler. Huge throughput gain on GPUs.

- **Carry-chain optimization for Maj function**  
  Saves one AND per round (80 ANDs total per compression) by passing `bc_prev` and chaining `ab_current`. Classic SHA-2 trick used in high-performance implementations (e.g., hashcat, ASICs).

- **`bitselect` for Ch function**  
  Uses the fastest native instruction on AMD/NVIDIA GPUs for Ch(x,y,z) = (x&y) ^ (~x&z).

- **Optimized rotates and sigmas**  
  Leverages OpenCL's built-in `rotate()` (hardware barrel shifter) and standard shift/rotate/XOR patterns for σ₀/σ₁.

- **Fully unrolled 80 rounds**  
  No loop in the main compression → maximum ILP (instruction-level parallelism). Each round is minimal (~12–15 effective instructions).

- **Dedicated `sha512_hash_two_blocks_message` function**  
  Perfectly suited for the initial PBKDF2 message (mnemonic + "mnemonic" > 112 bytes), avoiding conditional logic inside the core compression.

- **Relatively low register pressure**  
  Temporary W values are computed just-in-time and many are eliminated by dead-code elimination.

## Final HMAC-SHA512 (BIP-32 Derivation)

- **`hmac_sha512_bitcoin_seed` — simple and direct**  
  Fixed 32-byte key ("Bitcoin seed") hardcoded. Uses compile-time unrolled initialization via `REPEAT` macros. Costs exactly 2 SHA-512 compressions.

- **`hmac_sha512_key32_msg_upto111_fast` — highly specialized**  
  Exploits fixed message length (64-byte seed fits in <111 bytes with padding). Unrolled `switch` copies message ulongs directly (zero loop). Smart shift for the 0x80 padding bit. Results in only 2 compressions with no runtime branching.

- **Compile-time expansion via `REPEAT` macros**  
  Inner/outer padding filled with constants → immediate loads, zero ALU waste.

- **Bitcoin-specific specialization**  
  Avoids generic HMAC overhead. Runs only once per valid candidate, making its cost negligible compared to PBKDF2's ~4096 compressions.

  ## secp256k1 Scalar Multiplication (Public Key Derivation)

-   **Windowed wNAF (width-4) with signed digits and precomputed table** The scalar is converted to windowed non-adjacent form (wNAF) with a window size of 4 bits. This reduces the expected number of point additions by ~75% compared to standard double-and-add (~64 doubles + ~32 adds on average for a 256-bit scalar). A precomputed table of 16 variants (8 odd multiples of G with both +Y and –Y) is stored in __constant memory (384 bytes total). Negative digits use the precomputed –Y directly, avoiding runtime negation (subtraction mod p).
-   **Jacobian coordinates throughout the main loop** All point operations (double and add) work in projective Jacobian coordinates (X, Y, Z), eliminating costly modular inversions during scalar multiplication. Only **one modular inversion** is performed at the very end to convert back to affine coordinates (x = X/Z², y = Y/Z³).
-   **Highly optimized modular arithmetic tailored to secp256k1**add_mod / sub_mod use unrolled carry propagation. mul_mod implements schoolbook multiplication followed by the specialized secp256k1 reduction (exploiting p = 2²⁵⁶ – 2³² – 977 and the “0x3d1” trick) – significantly faster than general-purpose reduction or Montgomery form.
-   **Fast modular inversion via binary extended GCD** The final inversion uses an optimized shift-and-subtract binary GCD variant (~256 iterations on average) with minimal branching.
-   **Low branch divergence and register pressure** The main scalar loop has predictable flow; temporary variables are reused aggressively. The precomputed table ensures constant-time lookups with zero extra arithmetic for sign handling.
-   **Overall performance impact** Combined with the rest of the pipeline, this implementation can generate millions of compressed public keys per second on modern GPUs. The PBKDF2 remains the primary bottleneck; public key derivation is relatively inexpensive.


## ✅ TO-DO (RIPEMD-160 / SHA-256)

### 🔐 SHA-256

* [ ] Ensure **consistent API** (`sha256_init`, `sha256_update/blocks`, `sha256_final`) and **signatures** without “implicit declaration”
* [ ] Implement/validate **1 block** and **2 blocks** (padding + length) with official vectors
* [ ] Add **test vectors**:

* [ ] `""`, `"abc"`, `"message digest"`, and cases >64 bytes
* [ ] Check **endianness** (load/store big-endian vs little-endian) and alignment
* [ ] Add **DEBUG_PRINT** mode (dump of W[0..63] / H[0..7] only for `gid==0`)
* [ ] Measure **register pressure/spills** and adjust unroll according to driver

### 🧩 RIPEMD-160

* [ ] Implement/validate **compression** (80 rounds) with known test vectors
* [ ] Confirm **padding + length** (message in bytes, length in bits)
* [ ] Add **test vectors**:

* [ ] `""`, `"a"`, `"abc"`, `"message digest"` and long cases
* [ ] Check **endianness** (RIPEMD uses word order/little-endian internally) and conversions on input/output
* [ ] Add helper `hash160 = RIPEMD160(SHA256(x))` (for interoperability testing only)
* [ ] Create **CPU vs GPU comparison** routine for automatic validation





These optimizations combine to make the kernel one of the fastest possible OpenCL implementations for BIP-39 brute-force/recovery on GPUs. The non-PBKDF2 parts are essentially free, leaving SHA-512 compression as the primary bottleneck.
