#include "../includes/types32.c"
#include "../sha1.c"
#include <stdio.h>

void test_sha1m1(const U8 src[], const U32 srclen, const U32 hash[5]) {
  struct ctx_sha1m1 ctx;
  U32 j;
  sha1m1_init(&ctx);
  sha1m1_update(&ctx, src, srclen);
  sha1m1_digest(&ctx);
  for (j = 0; j < 5 && ctx.hash[j] == hash[j]; j++);
  if (j != 5)
    printf("Test failed for %s\n", src);
}

I32 main(void) {
  struct ctx_sha1m1 ctx;
  U32 hash[5];
  U32 j;

  hash[0] = 0xa9993e36; hash[1] = 0x4706816a; hash[2] = 0xba3e2571; hash[3] = 0x7850c26c; hash[4] = 0x9cd0d89d;
  test_sha1m1("abc", 3, hash);

  hash[0] = 0x84983e44; hash[1] = 0x1c3bd26e; hash[2] = 0xbaae4aa1; hash[3] = 0xf95129e5; hash[4] = 0xe54670f1;
  test_sha1m1("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, hash);

  hash[0] = 0xc2db330f; hash[1] = 0x6083854c; hash[2] = 0x99d4b5bf; hash[3] = 0xb6e8f29f; hash[4] = 0x201be699;
  test_sha1m1("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 56, hash);

  /*
  sha1m1_init(&ctx);
  sha1m1_update(&ctx, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56);
  sha1m1_digest(&ctx);
  for (j = 0; j < 5; j++)
    printf("%x", ctx.hash[j]);
  putchar('\n');
  */

  return 0;
}
