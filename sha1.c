#include "includes/assert.c"
#include "includes/types32.c"
#include "includes/limits32.c"


struct ctx_sha1m1 {
  U32 index;
  U32 len_low;
  U32 len_high;
  U32 hash[5];
  U32 W[80];
};


void sha1m1_init(struct ctx_sha1m1 *context) {
  context->hash[0] = 0x67452301;
  context->hash[1] = 0xEFCDAB89;
  context->hash[2] = 0x98BADCFE;
  context->hash[3] = 0x10325476;
  context->hash[4] = 0xC3D2E1F0;
  context->index   = 0;
  U32 j;
  for (j = 0; j < 80; j++)
    context->W[j] = 0;
}


void sha1m1_update(struct ctx_sha1m1 *context, const U8 src, const U32 srclen) {
  assert(
       srclen            < U32_MAX - context->len_low 
    || context->len_high < U32_MAX,
    "sha1m1_update: Input length is too long. It's bigger than 2^64\n"
  );

  U32       j, k;
  const U32 J_LIMIT = srclen / 4;
  for (j = 0; j < 16 && j < J_LIMIT; j++) {
    context->W[j]  = src[4 * j]     << 24;
    context->W[j] |= src[4 * j + 1] << 16;
    context->W[j] |= src[4 * j + 2] << 8;
    context->W[j] |= src[4 * j + 3];
  }
  switch (j) {
    case 0:
      if (0 != srclen)
        W[j] = src[j];
      break;
  }
}


void sha1m1_digest(struct ctx_sha1m1 *context) {
}


U32 shift_left_circular(const U32 x, const U32 n) {
  assert(0 <= n && n < 32, "shift_left_circular: %d not in range 0 <= n < 32", n);
  return (x << n) | (x >> (32 - n));
}


U32 sha1_f(const U32 t, const U32 B, const U32 C, const U32 D) {
  if (0 <= t && t <= 19)
    return (B & C) | (~B & D);
  if (20 <= t && t <= 39)
    return B ^ C ^ D;
  if (40 <= t && t <= 59)
    return (B & C) | (B & D) | (C & D);
  if (60 <= t && t <= 79)
    return B ^ C ^ D;
}


U32 sha1_K(const U32 t) {
  if (0 <= t && t <= 19)
    return 0x5A827999;
  if (20 <= t && t <= 39)
    return 0x6ED9EBA1;
  if (40 <= t && t <= 59)
    return 0x8F1BBCDC;
  if (60 <= t && t <= 79)
    return 0xCA62C1D6;
}


U32 sum32(U32 x, U32 y) {
/*
 * return (x + y) % (U32_MAX + 1)
 * 
 * if (x + y) >= (U32_MAX + 1):
 *   return (x + y) - (U32_MAX + 1)
 * else:
 *   return (x + y)
 */
  if (x <= U32_MAX - y)
    return x + y;

  if (U32_MAX / 2 <= x) {
    x -= U32_MAX / 2;
    if (U32_MAX / 2 <= y) {
      y -= U32_MAX / 2;
      /*
       * Why -2? Off by one because we are looking for mod (U32_MAX + 1)
       * and off by another one because U32_MAX is odd and U32_MAX / 2 throws away 0.5
       * (we subtract U32_MAX / 2 two times thus it makes to subtract 1 from the final result)
       */
      return x + y - 2;
    }
    /* Check that operation below is possible with 32-bit variables
     * [     max x     ]   [     max y     ]
     * (U32_MAX / 2 - 1) + (U32_MAX / 2 - 1) - U32_MAX / 2 - 2
     */
    return x + y - U32_MAX / 2 - 2;
  }

  if (U32_MAX / 2 <= y) {
    y -= U32_MAX / 2;
    if (U32_MAX / 2 <= x) {
      x -= U32_MAX / 2;
      return x + y - 2;
    }
    return x + y - U32_MAX / 2 - 2;
  }
}


void assert_sum32(void) {
  assert(0 == sum32(0, 0), "sum32(0, 0) != 0");
  assert(1 == sum32(0, 1), "sum32(0, 1) != 1");
  assert(1 == sum32(1, 0), "sum32(1, 0) != 1");
  assert(2 == sum32(1, 1), "sum32(1, 1) != 2");
  assert(3160 == sum32(101, 3059), "sum32(101, 3059) != 3160");
  assert(0 == sum32(1, U32_MAX), "sum32(1, U32_MAX) != 0");
  assert(0 == sum32(U32_MAX, 1), "sum32(U32_MAX, 1) != 0");
  assert(1 == sum32(2, U32_MAX), "sum32(2, U32_MAX) != 1");
  assert(1 == sum32(U32_MAX, 2), "sum32(U32_MAX, 2) != 1");
  assert(U32_MAX - 1 == sum32(U32_MAX, U32_MAX), "sum32(U32_MAX, U32_MAX) != U32_MAX - 1");
}

