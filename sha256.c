#include "includes/assert.c"
#include "includes/types32.c"
#include "includes/limits32.c"

struct ctx_sha256 {
  U32 index;
  U32 subindex;
  U32 len_low;
  U32 len_high;
  U32 hash[8];
  U32 W[64];
};


void sha256_init(struct ctx_sha256 *context);
U32  sha256_read(struct ctx_sha256 *context, const U8 src[], const U32 srclen);
void sha256_process(struct ctx_sha256 *context);
void sha256_update(struct ctx_sha256 *context, const U8 src[], const U32 srclen);
void sha256_pad(struct ctx_sha256 *context);
void sha256_digest(struct ctx_sha256 *context);
U32  rotr(U32 x, U32 n);
U32  sha256_CH(U32 x, U32 y, U32 z);
U32  sha256_MAJ(U32 x, U32 y, U32 z);
U32  sha256_BSIG0(U32 x);
U32  sha256_BSIG1(U32 x);
U32  sha256_SSIG0(U32 x);
U32  sha256_SSIG1(U32 x);
U32  sum32(U32 x, U32 y);
void assert_sum32(void);


const U32 sha256_K[64] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};


void sha256_init(struct ctx_sha256 *context) {
  U32 j;

  context->hash[0]  = 0x6a09e667;
  context->hash[1]  = 0xbb67ae85;
  context->hash[2]  = 0x3c6ef372;
  context->hash[3]  = 0xa54ff53a;
  context->hash[4]  = 0x510e527f;
  context->hash[5]  = 0x9b05688c;
  context->hash[6]  = 0x1f83d9ab;
  context->hash[7]  = 0x5be0cd19;
  context->index    = 0;
  context->subindex = 0;
  context->len_high = 0;
  context->len_low  = 0;

  for (j = 0; j < 64; j++)
    context->W[j] = 0;
}


U32 sha256_read(struct ctx_sha256 *context, const U8 src[], const U32 srclen) {
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


void sha256_process(struct ctx_sha256 *context) {
  U32 t, a, b, c, d, e, f, g, h, T1, T2;

  assert(context->index == 16, "sha256_process: index %u != 16. There are not enough words to process hash", context->index);

  for (t = 16; t < 64; t++) {
    context->W[t] = sha256_SSIG1(context->W[t - 2]);
    context->W[t] = sum32(context->W[t], context->W[t-7]);
    context->W[t] = sum32(context->W[t], sha256_SSIG0(context->W[t-15]));
    context->W[t] = sum32(context->W[t], context->W[t-16]);
  }

  a = context->hash[0];
  b = context->hash[1];
  c = context->hash[2];
  d = context->hash[3];
  e = context->hash[4];
  f = context->hash[5];
  g = context->hash[6];
  h = context->hash[7];

  for (t = 0; t < 64; t++) {
    T1 = sum32(h, sha256_BSIG1(e));
    T1 = sum32(T1, sha256_CH(e, f, g));
    T1 = sum32(T1, sha256_K[t]);
    T1 = sum32(T1, context->W[t]);
    T2 = sum32(sha256_BSIG0(a), sha256_MAJ(a, b, c));
    h = g;
    g = f;
    f = e;
    e = sum32(d, T1);
    d = c;
    c = b;
    b = a;
    a = sum32(T1, T2);
  }

  context->hash[0] = sum32(a, context->hash[0]);
  context->hash[1] = sum32(b, context->hash[1]);
  context->hash[2] = sum32(c, context->hash[2]);
  context->hash[3] = sum32(d, context->hash[3]);
  context->hash[4] = sum32(e, context->hash[4]);
  context->hash[5] = sum32(f, context->hash[5]);
  context->hash[6] = sum32(g, context->hash[6]);
  context->hash[7] = sum32(h, context->hash[7]);
}


void sha256_update(struct ctx_sha256 *context, const U8 src[], const U32 srclen) {
  U32 j, len;

  assert(srclen < U32_MAX - context->len_low 
           || context->len_high < U32_MAX,
         "sha1_update: Input length is too long. It's bigger than 2^64"
  );

  for (j = 0; j < srclen; j += 64) {
    len = sha256_read(context, src + j, srclen - j);
    if (U32_MAX - context->len_low < len) {
      context->len_high++;
      context->len_low = len - (U32_MAX - context->len_low);
    } else {
      context->len_low += len;
    }
    if (context->index == 16) {
      sha256_process(context);
      context->index = 0;
    }
  }
}


void sha256_pad(struct ctx_sha256 *context) {
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
    sha256_read(context, pad, 64);
    context->W[14] = context->len_high;
    context->W[15] = context->len_low;
    return;
  }

  sha256_read(context, pad, 64);
  sha256_process(context);
  context->index = 0;
  sha256_read(context, pad + 1, 64);
  context->W[14] = context->len_high;
  context->W[15] = context->len_low;
}


void sha256_digest(struct ctx_sha256 *context) {
  sha256_pad(context);
  sha256_process(context);
}


U32 rotr(U32 x, U32 n) {
  assert(0 <= n && n < 32, "rotr: %d is not in range 0 <= n < 32", n);
  return x >> n | x << (32 - n);
}


U32 sha256_CH(U32 x, U32 y, U32 z) {
  return x & y ^ ~x & z;
}


U32 sha256_MAJ(U32 x, U32 y, U32 z) {
  return x & y ^ x & z ^ y & z;
}


U32 sha256_BSIG0(U32 x) {
  return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}


U32 sha256_BSIG1(U32 x) {
  return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}


U32 sha256_SSIG0(U32 x) {
  return rotr(x, 7) ^ rotr(x, 18) ^ x >> 3;
}


U32 sha256_SSIG1(U32 x) {
  return rotr(x, 17) ^ rotr(x, 19) ^ x >> 10;
}

#ifndef SUM32_C
#define SUM32_C

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

#endif

