

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






These optimizations combine to make the kernel one of the fastest possible OpenCL implementations for BIP-39 brute-force/recovery on GPUs. The non-PBKDF2 parts are essentially free, leaving SHA-512 compression as the primary bottleneck.
