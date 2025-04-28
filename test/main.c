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

  assert_types32();
  assert_limits32();
  assert_sum32();

  test_sha1m1("", 0, 1, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
  test_sha1m1("abc", 3, 1, "a9993e364706816aba3e25717850c26c9cd0d89d");
  test_sha1m1("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, 1, "84983e441c3bd26ebaae4aa1f95129e5e54670f1");
  test_sha1m1("a", 1, 1000000, "34AA973CD4C4DAA4F61EEB2BDBAD27316534016F");
  test_sha1m1("0123456701234567012345670123456701234567012345670123456701234567", 64, 10, "DEA356A2CDDD90C7A7ECEDC5EBB563934F460452");

  test_sha256("abc", 3, 1, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  test_sha256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56, 1, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
  test_sha256("0123456701234567012345670123456701234567012345670123456701234567", 64, 10, "594847328451bdfa85056225462cc1d867d877fb388df0ce35f25ab5562bfbb5");
  test_sha256("", 0, 1, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  test_sha256("\xbe\x27\x46\xc6\xdb\x52\x76\x5f\xdb\x2f\x88\x70\x0f\x9a\x73", 15, 1, "a00decddb8580e9396c6cba8a4f0ebe921089d88fc5e477efcded2e07b8828a6");
  test_sha256("\x83\x26\x75\x4e\x22\x77\x37\x2f\x4f\xc1\x2b\x20\x52\x7a\xfe\xf0\x4d\x8a\x05\x69\x71\xb1\x1a\xd5\x71\x23\xa7\xc1\x37\x76\x00\x00\xd7\xbe\xf6\xf3\xc1\xf7\xa9\x08\x3a\xa3\x9d\x81\x0d\xb3\x10\x77\x7d\xab\x8b\x1e\x7f\x02\xb8\x4a\x26\xc7\x73\x32\x5f\x8b\x23\x74\xde\x7a\x4b\x5a\x58\xcb\x5c\x5c\xf3\x5b\xce\xe6\xfb\x94\x6e\x5b\xd6\x94\xfa\x59\x3a\x8b\xeb\x3f\x9d\x65\x92\xec\xed\xaa\x66\xca\x82\xa2\x9d\x0c\x51\xbc\xf9\x33\x62\x30\xe5\xd7\x84\xe4\xc0\xa4\x3f\x8d\x79\xa3\x0a\x16\x5c\xba\xbe\x45\x2b\x77\x4b\x9c\x71\x09\xa9\x7d\x13\x8f\x12\x92\x28\x96\x6f\x6c\x0a\xdc\x10\x6a\xad\x5a\x9f\xdd\x30\x82\x57\x69\xb2\xc6\x71\xaf\x67\x59\xdf\x28\xeb\x39\x3d\x54\xd6", 163, 1, "97dbca7df46d62c8a422c941dd7e835b8ad3361763f7e9b2d95f4f0da6e1ccbc");
  return 0;
}




