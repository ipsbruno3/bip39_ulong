#pragma OPENCL EXTENSION cl_khr_int64_base_atomics : enable
#pragma OPENCL EXTENSION cl_khr_byte_addressable_store : enable

#include "kernel/bip39.cl"
#include "kernel/pbkdf.cl"
#include "kernel/sha256.cl"
#include "kernel/seed.cl"
#define IPAD 0x3636363636363636UL
#define OPAD 0x5C5C5C5C5C5C5C5CUL

typedef struct {
  ulong master[10];
} test_t;

__constant ulong KEEP_MSB_MASK[9] = {
    0x0000000000000000UL, 0xFF00000000000000UL, 0xFFFF000000000000UL,
    0xFFFFFF0000000000UL, 0xFFFFFFFF00000000UL, 0xFFFFFFFFFF000000UL,
    0xFFFFFFFFFFFF0000UL, 0xFFFFFFFFFFFFFF00UL, 0xFFFFFFFFFFFFFFFFUL};



#define REPEAT_4LLX "%llx%llx%llx%llx"
#define REPEAT_8LLX REPEAT_4LLX REPEAT_4LLX
#define REPEAT_16LLX REPEAT_8LLX REPEAT_8LLX
#define ARG4(arr, off) arr[(off) + 0], arr[(off) + 1], arr[(off) + 2], arr[(off) + 3]
#define ARG8(arr, off) ARG4(arr, off), ARG4(arr, off + 4)
#define ARG16(arr, off) ARG8(arr, off), ARG8(arr, off + 8)

#define SPACE_BE 0x2000000000000000UL
#define REMAIN_BITS_LAST_BLOCK 64

#define APPEND_AUTO(dst, wi, cursor_bits, src_be, src_len_bytes)               \
  do {                                                                         \
    uint _lenB = (uint)(src_len_bytes);                                        \
    if (_lenB) {                                                               \
      ulong _src = (ulong)(src_be);                                            \
      if (_lenB < 8)                                                           \
        _src &= KEEP_MSB_MASK[_lenB];                                          \
      uint _bits = 8u * _lenB;                                                 \
      uint _c = (uint)(cursor_bits);                                           \
      uint _shift = 64u - _c;                                                  \
                                                                               \
      if (_bits <= _c) {                                                       \
        (dst)[(wi)] |= (_shift ? (_src >> _shift) : _src);                     \
        (cursor_bits) = _c - _bits;                                            \
        if ((cursor_bits) == 0u) {                                             \
          (wi)++;                                                              \
          (cursor_bits) = 64u;                                                 \
        }                                                                      \
      } else {                                                                 \
        (dst)[(wi)] |= (_shift ? (_src >> _shift) : _src);                     \
        uint _rem = _bits - _c;                                                \
        (wi)++;                                                                \
        (dst)[(wi)] |= (_src << _c);                                           \
        (cursor_bits) = 64u - _rem;                                            \
        if ((cursor_bits) == 0u) {                                             \
          (wi)++;                                                              \
          (cursor_bits) = 64u;                                                 \
        }                                                                      \
      }                                                                        \
    }                                                                          \
  } while (0)

#define APP_WORD(idx, is_last)                                                 \
  do {                                                                         \
    APPEND_AUTO(mnemLong, WI, CURSOR, WORDS_STRING[(idx)], WORDS_LEN[(idx)]);  \
    if (!(is_last))                                                            \
      APPEND_AUTO(mnemLong, WI, CURSOR, SPACE_BE, 1);                          \
  } while (0)

#define BLOCKS_KNOW_WORDS 5

__kernel void verify(__global test_t *output_hmac, const ulong offset) {
  const uint gid = get_global_id(0);
  const ulong low_offset = offset + (ulong)gid + OFFSET_LOW;
  const ulong lo = low_offset;

  const uint w0 = (uint)((lo >> 40) & 2047UL);
  const uint w1 = (uint)((lo >> 29) & 2047UL);
  const uint w2 = (uint)((lo >> 18) & 2047UL);
  const uint w3 = (uint)((lo >> 7) & 2047UL);

  const uint hi7 = (uint)(lo & 0x7FUL);
  const uint chk_byte = (uint)(sha256_from_byte(HIGH, lo) & 0xFFu);
  const uint cs4 = (chk_byte >> 4) & 0xFu;
  const uint w4 = (hi7 << 4) | cs4;

  ulong mnemLong[16] = {P0,  P1,  P2,  P3,  P4,  0UL, 0UL, 0UL,
                        0UL, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL};

  uint WI = BLOCKS_KNOW_WORDS;
  uint CURSOR = REMAIN_BITS_LAST_BLOCK;

  APP_WORD(w0, 0);
  APP_WORD(w1, 0);
  APP_WORD(w2, 0);
  APP_WORD(w3, 0);
  APP_WORD(w4, 1);

  ulong inner[32] = {(P0 ^ IPAD),
                     (P1 ^ IPAD),
                     (P2 ^ IPAD),
                     (P3 ^ IPAD),
                     (P4 ^ IPAD),
                     0UL,
                     0UL,
                     0UL,
                     0UL,
                     0UL,
                     0UL,
                     0UL,
                     0UL,
                     0UL,
                     0UL,
                     0UL,
                     7885351518267664739UL,
                     6442450944UL,
                     0UL,
                     0UL,
                     0UL,
                     0UL,
                     0UL,
                     0UL,
                     0UL,
                     0UL,
                     0UL,
                     0UL,
                     0UL,
                     0UL,
                     0UL,
                     1120UL};

  ulong outer[32] = {(P0 ^ OPAD),
                     (P1 ^ OPAD),
                     (P2 ^ OPAD),
                     (P3 ^ OPAD),
                     (P4 ^ OPAD),
                     0UL,
                     0UL,
                     0UL,
                     0UL,
                     0UL,
                     0UL,
                     0UL,
                     0UL,
                     0UL,
                     0UL,
                     0UL,
                     0x5C5C5C5C5C5C5C5CUL,
                     0UL,
                     0UL,
                     0UL,
                     0UL,
                     0UL,
                     0UL,
                     0UL,
                     0x8000000000000000UL,
                     0UL,
                     0UL,
                     0UL,
                     0UL,
                     0UL,
                     0UL,
                     1536UL};

#pragma unroll
  for (int i = BLOCKS_KNOW_WORDS; i < 16; i++) {
    inner[i] = mnemLong[i] ^ IPAD;
    outer[i] = mnemLong[i] ^ OPAD;
  }

  if (gid == 1) {
    for (uint w = 0; w < 12; w++) {
      ulong v = mnemLong[w];
      for (uint i = 0; i < 8; i++) {
        uchar b = (uchar)((v >> (56 - 8 * i)) & 0xFF);
        if (b >= 32 && b <= 126)
          printf("%c", (char)b);
      }
    }
  }
  ulong pbkdLong[8] = {0};
  // aqui você chama seu PBKDF2/HMAC...
  pbkdf2_hmac_sha512_long(inner, outer, pbkdLong);
  if (gid == 1) {
    // expected: abandon abandon abandon abandon abandon abandon abandon abandon
    // abandon abandon abandon about
    // 5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4
    // Uso (imprime 16 ulongs em hex contínuo + newline)
    printf("\n" REPEAT_8LLX "\n", ARG8(pbkdLong, 0));
  }
  // hmac_sha512_bitcoin_seed(pbkd, output_hmac[gid].master);
}

#undef APP_WORD
#undef APPEND_AUTO
