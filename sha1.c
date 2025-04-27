#include "includes/assert.c"
#include "includes/types32.c"
#include "includes/limits32.c"


U32 shift_left_circular(const U32 x, const U32 n);
U32 sum32(U32 x, U32 y);
U32 sha1_f(const U32 t, const U32 B, const U32 C, const U32 D);
U32 sha1_K(const U32 t);


struct ctx_sha1m1 {
  U32 index;
  U32 subindex;
  U32 len_low;
  U32 len_high;
  U32 hash[5];
  U32 W[80];
};


void sha1m1_init(struct ctx_sha1m1 *context) {
  context->hash[0]  = 0x67452301;
  context->hash[1]  = 0xEFCDAB89;
  context->hash[2]  = 0x98BADCFE;
  context->hash[3]  = 0x10325476;
  context->hash[4]  = 0xC3D2E1F0;
  context->index    = 0;
  context->subindex = 0;
  context->len_low  = 0;
  context->len_high = 0;
  U32 j;
  for (j = 0; j < 80; j++)
    context->W[j] = 0;
}


U32 sha1m1_read(struct ctx_sha1m1 *context, const U8 src[], const U32 srclen) {
        U32 j;
  const U32 shift[] = {24, 16, 8, 0};

  for (j = 0; j < 16 && context->index == 0 && context->subindex == 0; j++)
    context->W[j] = 0;

  for (j = 0; j < srclen && context->index < 16;) {
    for (; j < srclen && context->subindex < 4; j++, context->subindex++)
      context->W[context->index] |= src[j] << shift[context->subindex];
    if (context->subindex == 4) {
      context->subindex = 0;
      context->index++;
    }
  }

  return j * 8;
}


void sha1m1_process(struct ctx_sha1m1 *context) {
  assert(context->index == 16, "sha1m1_process: index %u != 16", context->index);

  U32 t, A, B, C, D, E, TEMP;

  for (t = 16; t < 80; t++)
    context->W[t] = shift_left_circular(context->W[t-3] ^ context->W[t-8] ^ context->W[t-14] ^ context->W[t-16], 1);

  A = context->hash[0];
  B = context->hash[1];
  C = context->hash[2];
  D = context->hash[3];
  E = context->hash[4];
  
  for (t = 0; t < 80; t++) {
    TEMP = shift_left_circular(A, 5);
    TEMP = sum32(TEMP, sha1_f(t, B, C, D));
    TEMP = sum32(TEMP, E);
    TEMP = sum32(TEMP, context->W[t]);
    TEMP = sum32(TEMP, sha1_K(t));
    E = D;
    D = C;
    C = shift_left_circular(B, 30);
    B = A;
    A = TEMP;
  }

  context->hash[0] = sum32(context->hash[0], A);
  context->hash[1] = sum32(context->hash[1], B);
  context->hash[2] = sum32(context->hash[2], C);
  context->hash[3] = sum32(context->hash[3], D);
  context->hash[4] = sum32(context->hash[4], E);
}


void sha1m1_update(struct ctx_sha1m1 *context, const U8 src[], const U32 srclen) {
  assert(srclen < U32_MAX - context->len_low 
           || context->len_high < U32_MAX,
         "sha1m1_update: Input length is too long. It's bigger than 2^64"
  );

  U32 j, len;

  for (j = 0; j < srclen; j += 64) {
    len = sha1m1_read(context, src + j, srclen - j);
    if (U32_MAX - context->len_low < len) {
      context->len_high++;
      context->len_low = len - (U32_MAX - context->len_low);
    } else {
      context->len_low += len;
    }
    if (context->index == 16) {
      sha1m1_process(context);
      context->index = 0;
    }
  }
}


void sha1m1_pad(struct ctx_sha1m1 *context) {
  const U8 pad[65] = {
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00
  };

  if (context->index < 14) {
    sha1m1_read(context, pad, 64);
    context->W[14] = context->len_high;
    context->W[15] = context->len_low;
    return;
  }

  sha1m1_read(context, pad, 64);
  sha1m1_process(context);
  context->index = 0;
  sha1m1_read(context, pad + 1, 64);
  context->W[14] = context->len_high;
  context->W[15] = context->len_low;
}


void sha1m1_digest(struct ctx_sha1m1 *context) {
  sha1m1_pad(context);
  sha1m1_process(context);
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

