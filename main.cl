#pragma OPENCL EXTENSION cl_khr_int64_base_atomics : enable
#pragma OPENCL EXTENSION cl_khr_byte_addressable_store : enable

#include "kernel/bip39.cl"
#include "kernel/sha256.cl"
#include "kernel/sha512.cl"
#include "kernel/pbkdf.cl"
#define IPAD 0x3636363636363636UL
#define OPAD 0x5C5C5C5C5C5C5C5CUL

typedef struct { ulong master[10]; } test_t;

// ---- BE pack (corrigido) ----
#define PACK8_BE(c0,c1,c2,c3,c4,c5,c6,c7) ( \
  ((ulong)(uchar)(c0) << 56) | ((ulong)(uchar)(c1) << 48) | \
  ((ulong)(uchar)(c2) << 40) | ((ulong)(uchar)(c3) << 32) | \
  ((ulong)(uchar)(c4) << 24) | ((ulong)(uchar)(c5) << 16) | \
  ((ulong)(uchar)(c6) <<  8) | ((ulong)(uchar)(c7) <<  0) )

__constant ulong KEEP_MSB_MASK[9] = {
  0x0000000000000000UL,
  0xFF00000000000000UL,
  0xFFFF000000000000UL,
  0xFFFFFF0000000000UL,
  0xFFFFFFFF00000000UL,
  0xFFFFFFFFFF000000UL,
  0xFFFFFFFFFFFF0000UL,
  0xFFFFFFFFFFFFFF00UL,
  0xFFFFFFFFFFFFFFFFUL
};

#define SPACE_BE 0x2000000000000000UL  // ' ' no MSB

// dst: ulong stream big-endian por byte
#define APPEND_AUTO(dst, wi, cursor_bits, src_be, src_len_bytes)               \
  do {                                                                         \
    uint _lenB = (uint)(src_len_bytes);                                        \
    if (_lenB) {                                                               \
      ulong _src = (ulong)(src_be);                                            \
      if (_lenB < 8) _src &= KEEP_MSB_MASK[_lenB];                             \
      uint _bits = 8u * _lenB;                                                 \
      uint _c = (uint)(cursor_bits);                                           \
      uint _shift = 64u - _c;                                                  \
                                                                               \
      if (_bits <= _c) {                                                       \
        (dst)[(wi)] |= (_shift ? (_src >> _shift) : _src);                     \
        (cursor_bits) = _c - _bits;                                            \
        if ((cursor_bits) == 0u) { (wi)++; (cursor_bits) = 64u; }              \
      } else {                                                                 \
        (dst)[(wi)] |= (_shift ? (_src >> _shift) : _src);                     \
        uint _rem = _bits - _c;                                                \
        (wi)++;                                                                \
        (dst)[(wi)] |= (_src << _c);                                           \
        (cursor_bits) = 64u - _rem;                                            \
        if ((cursor_bits) == 0u) { (wi)++; (cursor_bits) = 64u; }              \
      }                                                                        \
    }                                                                          \
  } while (0)

#define APP_WORD(idx, is_last) do { \
  APPEND_AUTO(mnemLong, WI, CURSOR, WORDS_STRING[(idx)], WORDS_LEN[(idx)]); \
  if (!(is_last)) APPEND_AUTO(mnemLong, WI, CURSOR, SPACE_BE, 1); \
} while(0)

__kernel void verify(__global test_t *output_hmac,
                     const ulong low,
                     const ulong high)
{
  const uint gid = get_global_id(0);
  const ulong low_offset = low + (ulong)gid;

  // ---- extrai indices (sem array privado) ----
  const uint w0 = (uint)((low_offset >> 51) & 2047UL);
  const uint w1 = (uint)((low_offset >> 40) & 2047UL);
  const uint w2 = (uint)((low_offset >> 29) & 2047UL);
  const uint w3 = (uint)((low_offset >> 18) & 2047UL);

  // seu w4 depende do checksum/sha256: mantive sua ideia
  // (ajuste se sua lógica de checksum for diferente)
  const uint w4 = (uint)((((low_offset & ((1UL<<18)-1UL)) << 11) & 2047UL)
                  | (uint)((sha256_from_byte(high, low_offset) >> 4) & 2047UL));

  // ---- prefixo constante (7 ulongs) ----
  const ulong P0 = PACK8_BE('a','b','a','n','d','o','n',' ');
  const ulong P1 = PACK8_BE('a','b','a','n','d','o','n',' ');
  const ulong P2 = PACK8_BE('a','b','a','n','d','o','n',' ');
  const ulong P3 = PACK8_BE('a','b','a','n','d','o','n',' ');
  const ulong P4 = PACK8_BE('a','b','a','n','d','o','n',' ');
  const ulong P5 = PACK8_BE('a','b','a','n','d','o','n',' ');
  const ulong P6 = PACK8_BE('a','b','a','n','d','o','n',' ');

  // ---- stream para a parte variável começa em mnemLong[7] ----
  ulong mnemLong[16] = { P0,P1,P2,P3,P4,P5,P6, 0UL,0UL,0UL,0UL,0UL,0UL,0UL,0UL,0UL };

  uint WI = 7;
  uint CURSOR = 64; // bits livres no word atual

  // ---- append 5 palavras + espaços (última sem espaço) ----
  APP_WORD(w0, 0);
  APP_WORD(w1, 0);
  APP_WORD(w2, 0);
  APP_WORD(w3, 0);
  APP_WORD(w4, 1);

  // ---- inner/outer: prefixo XOR em compile-time + tail XOR em runtime ----
  ulong inner[32] = {
    (P0 ^ IPAD),(P1 ^ IPAD),(P2 ^ IPAD),(P3 ^ IPAD),
    (P4 ^ IPAD),(P5 ^ IPAD),(P6 ^ IPAD),
    0UL,0UL,0UL,0UL,0UL,0UL,0UL,0UL,0UL,
    7885351518267664739UL, 6442450944UL,
    0UL,0UL,0UL,0UL,0UL,0UL,0UL,0UL,
    0UL,0UL,0UL,0UL,0UL,1120UL
  };

  ulong outer[32] = {
    (P0 ^ OPAD),(P1 ^ OPAD),(P2 ^ OPAD),(P3 ^ OPAD),
    (P4 ^ OPAD),(P5 ^ OPAD),(P6 ^ OPAD),
    0UL,0UL,0UL,0UL,0UL,0UL,0UL,0UL,0UL,
    0x5C5C5C5C5C5C5C5CUL, 0UL,
    0UL,0UL,0UL,0UL,0UL,0UL,
    0x8000000000000000UL, 0UL,0UL,0UL,0UL,0UL,0UL,1536UL
  };

  // XOR só do tail (7..15) — parte variável
  #pragma unroll
  for (int i = 7; i < 16; i++) {
    inner[i] = mnemLong[i] ^ IPAD;
    outer[i] = mnemLong[i] ^ OPAD;
  }
  if (!gid) {
    for (uint w = 0; w < 12; w++) {
      ulong v = mnemLong[w];
      for (uint i = 0; i < 8; i++) {
        uchar b = (uchar)((v >> (56 - 8 * i)) & 0xFF);
        if (b >= 32 && b <= 126)
          printf("%c", (char)b);
      }
    }
  }
  // aqui você chama seu PBKDF2/HMAC...
    pbkdf2_hmac_sha512_long(inner, outer, mnemLong);
  // hmac_sha512_bitcoin_seed(pbkd, output_hmac[gid].master);





  // hmac_sha512_bitcoin_seed(pbkd, output_hmac[gid].master);
}

#undef APP_WORD
#undef APPEND_AUTO
