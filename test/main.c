#include "../sha1.c"
#include "../sha256.c"
#include <stdio.h>

U32 hash[8];

U32 *str2hash(const U8 src[], const U32 hash_size) {
  assert_types32();
  assert_limits32();
  assert_sum32();

  U32 j, k, m;
  U8  table[103];

  for (j = '0'; j <= '9'; j++)
    table[j] = j - '0';
  for (j = 'A'; j <= 'F'; j++)
    table[j] = j - 'A' + 10;
  for (j = 'a'; j <= 'f'; j++)
    table[j] = j - 'a' + 10;

  for (j = 0; j < hash_size; j++)
    hash[j] = 0;

  for (j = 0; j < hash_size; j++) {
    for (k = 0; k < 8; k++)
      hash[j] = hash[j] << 4 | table[src[k + j * 8]];
  }

  return hash;
}

void test_sha1m1(const U8 src[], const U32 srclen, const U32 repeat_count, const U8 res[]) {
  struct ctx_sha1 ctx;
  U32             j;

  str2hash(res, 5);

  sha1_init(&ctx);
  for (j = 0; j < repeat_count; j++)
    sha1_update(&ctx, src, srclen);
  sha1_digest(&ctx);

  for (j = 0; j < 5 && ctx.hash[j] == hash[j]; j++);

  if (srclen > 20) {
    if (j != 5)
      printf("sha1: Test failed for %.20s...\n", src);
    return;
  }

  if (j != 5)
    printf("sha1: Test failed for %s\n", src);
}

void test_sha256(const U8 src[], const U32 srclen, const U32 repeat_count, const U8 res[]) {
  struct ctx_sha256 ctx;
  U32               j;

  str2hash(res, 8);

  sha256_init(&ctx);
  for (j = 0; j < repeat_count; j++)
    sha256_update(&ctx, src, srclen);
  sha256_digest(&ctx);

  for (j = 0; j < 8 && ctx.hash[j] == hash[j]; j++);

  if (srclen > 20) {
    if (j != 8)
      printf("sha256: Test failed for %.20s...\n", src);
    return;
  }

  if (j != 8)
    printf("sha256: Test failed for %s\n", src);
}

void strcp(const U8 src[], const U32 srclen, U8 dst[]) {
  U32 j;

  for (j = 0; j < srclen; j++)
    dst[j] = src[j];
}

I32 main(void) {
  struct ctx_sha1 ctx;
  U32             j, k;
  U8              str[1000000];

  test_sha1m1("", 0, 1, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
  test_sha1m1("abc", 3, 1, "a9993e364706816aba3e25717850c26c9cd0d89d");
  test_sha1m1("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, 1, "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
  test_sha1m1("a", 1, 1000000, "34AA973CD4C4DAA4F61EEB2BDBAD27316534016F");
  test_sha1m1("0123456701234567012345670123456701234567012345670123456701234567", 64, 10, "DEA356A2CDDD90C7A7ECEDC5EBB563934F460452");

  test_sha256("abc", 3, 1, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  return 0;
}
