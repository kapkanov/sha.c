#include "../includes/types32.c"
#include "../sha1.c"
#include <stdio.h>

U32 hash[5];

U32 *str2hash(const U8 src[]) {
  U32 j, k, m;
  U8  table[103];

  for (j = '0'; j <= '9'; j++)
    table[j] = j - '0';
  for (j = 'A'; j <= 'F'; j++)
    table[j] = j - 'A' + 10;
  for (j = 'a'; j <= 'f'; j++)
    table[j] = j - 'a' + 10;

  for (j = 0; j < 5; j++)
    hash[j] = 0;

  for (j = 0; j < 5; j++) {
    for (k = 0; k < 8; k++)
      hash[j] = hash[j] << 4 | table[src[k + j * 8]];
  }

  return hash;
}

void test_sha1m1(const U8 src[], const U32 srclen, const U8 res[]) {
  struct ctx_sha1m1 ctx;
  U32 j;
  sha1m1_init(&ctx);
  sha1m1_update(&ctx, src, srclen);
  sha1m1_digest(&ctx);
  str2hash(res);
  for (j = 0; j < 5 && ctx.hash[j] == hash[j]; j++);
  if (j != 5)
    printf("Test failed for %s\n", src);
}

I32 main(void) {
  struct ctx_sha1m1 ctx;
  U32 j;

  test_sha1m1("abc", 3, "a9993e364706816aba3e25717850c26c9cd0d89d");
  test_sha1m1("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, "84983e441c3bd26ebaae4aa1f95129e5e54670f1");

  return 0;
}
