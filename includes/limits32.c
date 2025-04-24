#ifndef LIMITS32_C
#define LIMITS32_C

#include "assert.c"
#include "types32.c"

const I8  I8_MIN  = -128;
const I8  I8_MAX  =  127;
const U8  U8_MAX  =  255;

const I16 I16_MIN = -32768;
const I16 I16_MAX =  32767;
const U16 U16_MAX =  65535;

const I32 I32_MIN = -2147483648;
const I32 I32_MAX =  2147483647;
const U32 U32_MAX =  4294967295;

void assert_limits32(void) {
  const U8 max8_unsigned = 0xff;
  assert(U8_MAX == max8_unsigned, "U8_MAX: expected %lu but got %lu\n", max8_unsigned, U8_MAX);
     
  const I8 min8_signed = 0x80;
  assert(I8_MIN == min8_signed, "I8_MIN: expected %d but got %d\n", min8_signed, I8_MIN);

  const I8 max8_signed = 0x7f;
  assert(I8_MAX == max8_signed, "I8_MAX: expected %d but got %d\n", max8_signed, I8_MAX);

  const U16 max16_unsigned = 0xffff;
  assert(U16_MAX == max16_unsigned, "U16_MAX: expected %d but got %d\n", max16_unsigned, U16_MAX);

  const I16 min16_signed = 0x8000;
  assert(I16_MIN == min16_signed, "I16_MIN: expected %d but got %d\n", min16_signed, I16_MIN);

  const I16 max16_signed = 0x7fff;
  assert(I16_MAX == max16_signed, "I16_MAX: expected %d but got %d\n", max16_signed, I16_MAX);

  /*
   * 2^32 - 1 = 2 * 2^31 - 1 = 2^31 - 1 + 2^31 = 2^30 * 2 - 1 + 2^30 * 2
   */
  const U32 two_pow_thirty_unsigned = 1024 * 1024 * 1024;
  U32       max32_unsigned;
  max32_unsigned  = 2 * two_pow_thirty_unsigned;
  max32_unsigned -= 1;
  max32_unsigned += 2 * two_pow_thirty_unsigned;
  assert(U32_MAX == max32_unsigned, "U32_MAX: expected %lu but got %lu\n", max32_unsigned, U32_MAX);
  assert(0xffffffff == U32_MAX, "U32_MAX in binary: expected %lu but got %lu\n", 0xffffffff, U32_MAX);
  
  /*
   * 2^31 - 1 = 2 * 2^30 - 1 = 2^30 - 1 + 2^30
   */
  const I32 two_pow_thirty_signed = 1024 * 1024 * 1024;
  I32       max32_signed;
  max32_signed  = two_pow_thirty_signed;
  max32_signed -= 1;
  max32_signed += two_pow_thirty_signed;
  assert(I32_MAX == max32_signed, "I32_MAX: expected %d but got %d\n", max32_signed, I32_MAX);
  assert(0x7fffffff == I32_MAX, "I32_MAX in binary: expected %d but got %d\n", 0x7fffffff, I32_MAX);
}

#endif
