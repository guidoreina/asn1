#include <string.h>
#include <math.h>
#include "asn1/ber/common.h"

#define IS_DIGIT(x) (((x) >= '0') && ((x) <= '9'))

size_t asn1::ber::encode_tag(tag_class tc,
                             primitive_constructed pc,
                             tag_number tn,
                             uint8_t* buf)
{
  if (tn < 31) {
    buf[0] = (static_cast<uint8_t>(tc) << 6) |
             (static_cast<uint8_t>(pc) << 5) |
             static_cast<uint8_t>(tn);

    return 1;
  } else {
    buf[0] = (static_cast<uint8_t>(tc) << 6) |
             (static_cast<uint8_t>(pc) << 5) |
             static_cast<uint8_t>(0x1f);

    if (tn <= 0x7full) {
      buf[1] = static_cast<uint8_t>(tn);

      return 2;
    } else if (tn <= 0x3fffull) {
      buf[1] = 0x80 | static_cast<uint8_t>((tn >> 7) & 0x7f);
      buf[2] = static_cast<uint8_t>(tn & 0x7f);

      return 3;
    } else if (tn <= 0x1fffffull) {
      buf[1] = 0x80 | static_cast<uint8_t>((tn >> 14) & 0x7f);
      buf[2] = 0x80 | static_cast<uint8_t>((tn >> 7) & 0x7f);
      buf[3] = static_cast<uint8_t>(tn & 0x7f);

      return 4;
    } else if (tn <= 0xfffffffull) {
      buf[1] = 0x80 | static_cast<uint8_t>((tn >> 21) & 0x7f);
      buf[2] = 0x80 | static_cast<uint8_t>((tn >> 14) & 0x7f);
      buf[3] = 0x80 | static_cast<uint8_t>((tn >> 7) & 0x7f);
      buf[4] = static_cast<uint8_t>(tn & 0x7f);

      return 5;
    } else if (tn <= 0x7ffffffffull) {
      buf[1] = 0x80 | static_cast<uint8_t>((tn >> 28) & 0x7f);
      buf[2] = 0x80 | static_cast<uint8_t>((tn >> 21) & 0x7f);
      buf[3] = 0x80 | static_cast<uint8_t>((tn >> 14) & 0x7f);
      buf[4] = 0x80 | static_cast<uint8_t>((tn >> 7) & 0x7f);
      buf[5] = static_cast<uint8_t>(tn & 0x7f);

      return 6;
    } else if (tn <= 0x3ffffffffffull) {
      buf[1] = 0x80 | static_cast<uint8_t>((tn >> 35) & 0x7f);
      buf[2] = 0x80 | static_cast<uint8_t>((tn >> 28) & 0x7f);
      buf[3] = 0x80 | static_cast<uint8_t>((tn >> 21) & 0x7f);
      buf[4] = 0x80 | static_cast<uint8_t>((tn >> 14) & 0x7f);
      buf[5] = 0x80 | static_cast<uint8_t>((tn >> 7) & 0x7f);
      buf[6] = static_cast<uint8_t>(tn & 0x7f);

      return 7;
    } else if (tn <= 0x1ffffffffffffull) {
      buf[1] = 0x80 | static_cast<uint8_t>((tn >> 42) & 0x7f);
      buf[2] = 0x80 | static_cast<uint8_t>((tn >> 35) & 0x7f);
      buf[3] = 0x80 | static_cast<uint8_t>((tn >> 28) & 0x7f);
      buf[4] = 0x80 | static_cast<uint8_t>((tn >> 21) & 0x7f);
      buf[5] = 0x80 | static_cast<uint8_t>((tn >> 14) & 0x7f);
      buf[6] = 0x80 | static_cast<uint8_t>((tn >> 7) & 0x7f);
      buf[7] = static_cast<uint8_t>(tn & 0x7f);

      return 8;
    } else if (tn <= 0xffffffffffffffull) {
      buf[1] = 0x80 | static_cast<uint8_t>((tn >> 49) & 0x7f);
      buf[2] = 0x80 | static_cast<uint8_t>((tn >> 42) & 0x7f);
      buf[3] = 0x80 | static_cast<uint8_t>((tn >> 35) & 0x7f);
      buf[4] = 0x80 | static_cast<uint8_t>((tn >> 28) & 0x7f);
      buf[5] = 0x80 | static_cast<uint8_t>((tn >> 21) & 0x7f);
      buf[6] = 0x80 | static_cast<uint8_t>((tn >> 14) & 0x7f);
      buf[7] = 0x80 | static_cast<uint8_t>((tn >> 7) & 0x7f);
      buf[8] = static_cast<uint8_t>(tn & 0x7f);

      return 9;
    } else if (tn <= 0x7fffffffffffffffull) {
      buf[1] = 0x80 | static_cast<uint8_t>((tn >> 56) & 0x7f);
      buf[2] = 0x80 | static_cast<uint8_t>((tn >> 49) & 0x7f);
      buf[3] = 0x80 | static_cast<uint8_t>((tn >> 42) & 0x7f);
      buf[4] = 0x80 | static_cast<uint8_t>((tn >> 35) & 0x7f);
      buf[5] = 0x80 | static_cast<uint8_t>((tn >> 28) & 0x7f);
      buf[6] = 0x80 | static_cast<uint8_t>((tn >> 21) & 0x7f);
      buf[7] = 0x80 | static_cast<uint8_t>((tn >> 14) & 0x7f);
      buf[8] = 0x80 | static_cast<uint8_t>((tn >> 7) & 0x7f);
      buf[9] = static_cast<uint8_t>(tn & 0x7f);

      return 10;
    } else {
      buf[1] = 0x80 | static_cast<uint8_t>((tn >> 63) & 0x7f);
      buf[2] = 0x80 | static_cast<uint8_t>((tn >> 56) & 0x7f);
      buf[3] = 0x80 | static_cast<uint8_t>((tn >> 49) & 0x7f);
      buf[4] = 0x80 | static_cast<uint8_t>((tn >> 42) & 0x7f);
      buf[5] = 0x80 | static_cast<uint8_t>((tn >> 35) & 0x7f);
      buf[6] = 0x80 | static_cast<uint8_t>((tn >> 28) & 0x7f);
      buf[7] = 0x80 | static_cast<uint8_t>((tn >> 21) & 0x7f);
      buf[8] = 0x80 | static_cast<uint8_t>((tn >> 14) & 0x7f);
      buf[9] = 0x80 | static_cast<uint8_t>((tn >> 7) & 0x7f);
      buf[10] = static_cast<uint8_t>(tn & 0x7f);

      return 11;
    }

    // More compact but slower.
/*
    int i;
    for (i = 63; (i > 0) && (((tn >> i) & 0x7f) == 0); i -= 7);

    uint8_t* ptr = buf + 1;

    for (; i > 0; i -= 7) {
      *ptr++ = 0x80 | ((tn >> i) & 0x7f);
    }

    *ptr = tn & 0x7f;

    return ptr + 1 - buf;
*/
  }
}

size_t asn1::ber::encode_length(size_t len, uint8_t* buf)
{
  if (len <= 0x7full) {
    buf[0] = static_cast<uint8_t>(len);
    return 1;
  } else if (len <= 0xffull) {
    buf[0] = 0x80 | static_cast<uint8_t>(1);

    buf[1] = static_cast<uint8_t>(len);

    return 2;
  } else if (len <= 0xffffull) {
    buf[0] = 0x80 | static_cast<uint8_t>(2);

    buf[1] = static_cast<uint8_t>((len >> 8) & 0xff);
    buf[2] = static_cast<uint8_t>(len & 0xff);

    return 3;
  } else if (len <= 0xffffffull) {
    buf[0] = 0x80 | static_cast<uint8_t>(3);

    buf[1] = static_cast<uint8_t>((len >> 16) & 0xff);
    buf[2] = static_cast<uint8_t>((len >> 8) & 0xff);
    buf[3] = static_cast<uint8_t>(len & 0xff);

    return 4;
  } else if (len <= 0xffffffffull) {
    buf[0] = 0x80 | static_cast<uint8_t>(4);

    buf[1] = static_cast<uint8_t>((len >> 24) & 0xff);
    buf[2] = static_cast<uint8_t>((len >> 16) & 0xff);
    buf[3] = static_cast<uint8_t>((len >> 8) & 0xff);
    buf[4] = static_cast<uint8_t>(len & 0xff);

    return 5;
  } else if (len <= 0xffffffffffull) {
    buf[0] = 0x80 | static_cast<uint8_t>(5);

    buf[1] = static_cast<uint8_t>((len >> 32) & 0xff);
    buf[2] = static_cast<uint8_t>((len >> 24) & 0xff);
    buf[3] = static_cast<uint8_t>((len >> 16) & 0xff);
    buf[4] = static_cast<uint8_t>((len >> 8) & 0xff);
    buf[5] = static_cast<uint8_t>(len & 0xff);

    return 6;
  } else if (len <= 0xffffffffffffull) {
    buf[0] = 0x80 | static_cast<uint8_t>(6);

    buf[1] = static_cast<uint8_t>((len >> 40) & 0xff);
    buf[2] = static_cast<uint8_t>((len >> 32) & 0xff);
    buf[3] = static_cast<uint8_t>((len >> 24) & 0xff);
    buf[4] = static_cast<uint8_t>((len >> 16) & 0xff);
    buf[5] = static_cast<uint8_t>((len >> 8) & 0xff);
    buf[6] = static_cast<uint8_t>(len & 0xff);

    return 7;
  } else if (len <= 0xffffffffffffffull) {
    buf[0] = 0x80 | static_cast<uint8_t>(7);

    buf[1] = static_cast<uint8_t>((len >> 48) & 0xff);
    buf[2] = static_cast<uint8_t>((len >> 40) & 0xff);
    buf[3] = static_cast<uint8_t>((len >> 32) & 0xff);
    buf[4] = static_cast<uint8_t>((len >> 24) & 0xff);
    buf[5] = static_cast<uint8_t>((len >> 16) & 0xff);
    buf[6] = static_cast<uint8_t>((len >> 8) & 0xff);
    buf[7] = static_cast<uint8_t>(len & 0xff);

    return 8;
  } else {
    buf[0] = 0x80 | static_cast<uint8_t>(8);

    buf[1] = static_cast<uint8_t>((len >> 56) & 0xff);
    buf[2] = static_cast<uint8_t>((len >> 48) & 0xff);
    buf[3] = static_cast<uint8_t>((len >> 40) & 0xff);
    buf[4] = static_cast<uint8_t>((len >> 32) & 0xff);
    buf[5] = static_cast<uint8_t>((len >> 24) & 0xff);
    buf[6] = static_cast<uint8_t>((len >> 16) & 0xff);
    buf[7] = static_cast<uint8_t>((len >> 8) & 0xff);
    buf[8] = static_cast<uint8_t>(len & 0xff);

    return 9;
  }

  // More compact but slower.
/*
  if (len <= 0x7full) {
    buf[0] = static_cast<uint8_t>(len);
    return 1;
  } else {
    int i;
    for (i = 56; (i > 0) && (((len >> i) & 0xff) == 0); i -= 8);

    uint8_t* b = buf + 1;

    for (; i >= 0; i -= 8) {
      *b++ = (len >> i) & 0xff;
    }

    size_t noctets = b - 1 - buf;

    buf[0] = 0x80 | static_cast<uint8_t>(noctets);

    return 1 + noctets;
  }
*/
}

size_t asn1::ber::encode_integer(int64_t n, uint8_t* buf)
{
  // If the value is positive.
  if (n >= 0) {
    if (n < 0x80ll) {
      buf[0] = static_cast<uint8_t>(n);

      return 1;
    } else if (n < 0x8000ll) {
      buf[0] = static_cast<uint8_t>((n >> 8) & 0xff);
      buf[1] = static_cast<uint8_t>(n & 0xff);

      return 2;
    } else if (n < 0x800000ll) {
      buf[0] = static_cast<uint8_t>((n >> 16) & 0xff);
      buf[1] = static_cast<uint8_t>((n >> 8) & 0xff);
      buf[2] = static_cast<uint8_t>(n & 0xff);

      return 3;
    } else if (n < 0x80000000ll) {
      buf[0] = static_cast<uint8_t>((n >> 24) & 0xff);
      buf[1] = static_cast<uint8_t>((n >> 16) & 0xff);
      buf[2] = static_cast<uint8_t>((n >> 8) & 0xff);
      buf[3] = static_cast<uint8_t>(n & 0xff);

      return 4;
    } else if (n < 0x8000000000ll) {
      buf[0] = static_cast<uint8_t>((n >> 32) & 0xff);
      buf[1] = static_cast<uint8_t>((n >> 24) & 0xff);
      buf[2] = static_cast<uint8_t>((n >> 16) & 0xff);
      buf[3] = static_cast<uint8_t>((n >> 8) & 0xff);
      buf[4] = static_cast<uint8_t>(n & 0xff);

      return 5;
    } else if (n < 0x800000000000ll) {
      buf[0] = static_cast<uint8_t>((n >> 40) & 0xff);
      buf[1] = static_cast<uint8_t>((n >> 32) & 0xff);
      buf[2] = static_cast<uint8_t>((n >> 24) & 0xff);
      buf[3] = static_cast<uint8_t>((n >> 16) & 0xff);
      buf[4] = static_cast<uint8_t>((n >> 8) & 0xff);
      buf[5] = static_cast<uint8_t>(n & 0xff);

      return 6;
    } else if (n < 0x80000000000000ll) {
      buf[0] = static_cast<uint8_t>((n >> 48) & 0xff);
      buf[1] = static_cast<uint8_t>((n >> 40) & 0xff);
      buf[2] = static_cast<uint8_t>((n >> 32) & 0xff);
      buf[3] = static_cast<uint8_t>((n >> 24) & 0xff);
      buf[4] = static_cast<uint8_t>((n >> 16) & 0xff);
      buf[5] = static_cast<uint8_t>((n >> 8) & 0xff);
      buf[6] = static_cast<uint8_t>(n & 0xff);

      return 7;
    } else {
      buf[0] = static_cast<uint8_t>((n >> 56) & 0xff);
      buf[1] = static_cast<uint8_t>((n >> 48) & 0xff);
      buf[2] = static_cast<uint8_t>((n >> 40) & 0xff);
      buf[3] = static_cast<uint8_t>((n >> 32) & 0xff);
      buf[4] = static_cast<uint8_t>((n >> 24) & 0xff);
      buf[5] = static_cast<uint8_t>((n >> 16) & 0xff);
      buf[6] = static_cast<uint8_t>((n >> 8) & 0xff);
      buf[7] = static_cast<uint8_t>(n & 0xff);

      return 8;
    }
  } else if (n >= -0x80ll) {
    buf[0] = static_cast<uint8_t>(n);

    return 1;
  } else if (n >= -0x8000ll) {
    buf[0] = static_cast<uint8_t>((n >> 8) & 0xff);
    buf[1] = static_cast<uint8_t>(n & 0xff);

    return 2;
  } else if (n >= -0x800000ll) {
    buf[0] = static_cast<uint8_t>((n >> 16) & 0xff);
    buf[1] = static_cast<uint8_t>((n >> 8) & 0xff);
    buf[2] = static_cast<uint8_t>(n & 0xff);

    return 3;
  } else if (n >= -0x80000000ll) {
    buf[0] = static_cast<uint8_t>((n >> 24) & 0xff);
    buf[1] = static_cast<uint8_t>((n >> 16) & 0xff);
    buf[2] = static_cast<uint8_t>((n >> 8) & 0xff);
    buf[3] = static_cast<uint8_t>(n & 0xff);

    return 4;
  } else if (n >= -0x8000000000ll) {
    buf[0] = static_cast<uint8_t>((n >> 32) & 0xff);
    buf[1] = static_cast<uint8_t>((n >> 24) & 0xff);
    buf[2] = static_cast<uint8_t>((n >> 16) & 0xff);
    buf[3] = static_cast<uint8_t>((n >> 8) & 0xff);
    buf[4] = static_cast<uint8_t>(n & 0xff);

    return 5;
  } else if (n >= -0x800000000000ll) {
    buf[0] = static_cast<uint8_t>((n >> 40) & 0xff);
    buf[1] = static_cast<uint8_t>((n >> 32) & 0xff);
    buf[2] = static_cast<uint8_t>((n >> 24) & 0xff);
    buf[3] = static_cast<uint8_t>((n >> 16) & 0xff);
    buf[4] = static_cast<uint8_t>((n >> 8) & 0xff);
    buf[5] = static_cast<uint8_t>(n & 0xff);

    return 6;
  } else if (n >= -0x80000000000000ll) {
    buf[0] = static_cast<uint8_t>((n >> 48) & 0xff);
    buf[1] = static_cast<uint8_t>((n >> 40) & 0xff);
    buf[2] = static_cast<uint8_t>((n >> 32) & 0xff);
    buf[3] = static_cast<uint8_t>((n >> 24) & 0xff);
    buf[4] = static_cast<uint8_t>((n >> 16) & 0xff);
    buf[5] = static_cast<uint8_t>((n >> 8) & 0xff);
    buf[6] = static_cast<uint8_t>(n & 0xff);

    return 7;
  } else {
    buf[0] = static_cast<uint8_t>((n >> 56) & 0xff);
    buf[1] = static_cast<uint8_t>((n >> 48) & 0xff);
    buf[2] = static_cast<uint8_t>((n >> 40) & 0xff);
    buf[3] = static_cast<uint8_t>((n >> 32) & 0xff);
    buf[4] = static_cast<uint8_t>((n >> 24) & 0xff);
    buf[5] = static_cast<uint8_t>((n >> 16) & 0xff);
    buf[6] = static_cast<uint8_t>((n >> 8) & 0xff);
    buf[7] = static_cast<uint8_t>(n & 0xff);

    return 8;
  }

  // More compact but slower.
/*
  uint8_t* v = buf;
  size_t len;
  int i;

  if (n >= 0) {
    for (i = 56; (i > 0) && (((n >> i) & 0xff) == 0); i -= 8);

    if (((n >> i) & 0x80) == 0x80) {
      v[0] = 0;
      len = 1;
    } else {
      len = 0;
    }
  } else {
    for (i = 56; (i > 0) && (((n >> i) & 0xff) == 0xff); i -= 8);

    if (((n >> i) & 0x80) == 0x00) {
      v[0] = static_cast<uint8_t>(0xff);
      len = 1;
    } else {
      len = 0;
    }
  }

  for (; i >= 0; i -= 8) {
    v[len++] = (n >> i) & 0xff;
  }

  return len;
*/
}

static inline void encode_significand(uint64_t significand,
                                      size_t len,
                                      uint8_t* buf)
{
  size_t l = 0;

  switch (len) {
    case 7:
      buf[l++] = static_cast<uint8_t>((significand >> 48) & 0xff);

      // Fall through.
    case 6:
      buf[l++] = static_cast<uint8_t>((significand >> 40) & 0xff);

      // Fall through.
    case 5:
      buf[l++] = static_cast<uint8_t>((significand >> 32) & 0xff);

      // Fall through.
    case 4:
      buf[l++] = static_cast<uint8_t>((significand >> 24) & 0xff);

      // Fall through.
    case 3:
      buf[l++] = static_cast<uint8_t>((significand >> 16) & 0xff);

      // Fall through.
    case 2:
      buf[l++] = static_cast<uint8_t>((significand >> 8) & 0xff);

      // Fall through.
    default:
      buf[l++] = static_cast<uint8_t>(significand & 0xff);
  }
}

size_t asn1::ber::encode_real(double n, uint8_t* buf)
{
  // Format (most significant bit first):
  //    1 bit: sign
  //  11 bits: biased exponent
  //  52 bits: significand

  uint64_t u64;
  memcpy(&u64, &n, sizeof(uint64_t));

  // Extract components.
  uint8_t sign = static_cast<uint8_t>((u64 >> 57) & 0x40);
  uint16_t biased_exponent = static_cast<uint16_t>((u64 >> 52) & 0x7ff);
  uint64_t significand = u64 & 0x0fffffffffffffull;

  switch (biased_exponent) {
    default:
      {
        // The number has the format: 1.<fraction>,
        // where <fraction> is 52 bits long.
        //
        // The 1 is the implicit bit, which is now added.
        significand |= (0x01ull << 52);

        // To get rid of the decimal separator, we have to move the decimal
        // separator 52 positions to the right (multiply by 2^52).
        //
        // Subtract the bias (1023) and the 52 (1023 + 52 = 1075).
        int16_t exponent = biased_exponent - 1075;

        // The significand is 7 bytes long.
        size_t l = 7;

        // Normalize: the least significant bit has to be 1.
        //
        // Shift bits to the right until the least significant bit is 1.
        // Every time we shift bits one position to the right,
        // we are dividing by 2, so later we have to increment the exponent as
        // many times as we have shifted.
        while ((significand & 0xff) == 0) {
          significand >>= 8;
          l--;
        }

        exponent += (8 * (7 - l));

        while ((significand & 0x01) == 0) {
          significand >>= 1;
          exponent++;
        }

        size_t len;

        // Encode first byte and exponent.

        if (exponent >= 0) {
          if (exponent < 0x80) {
            buf[0] = 0x80 | sign | 0x00;

            buf[1] = static_cast<uint8_t>(exponent);

            len = 2;
          } else {
            buf[0] = 0x80 | sign | 0x01;

            buf[1] = static_cast<uint8_t>((exponent >> 8) & 0xff);
            buf[2] = static_cast<uint8_t>(exponent & 0xff);

            len = 3;
          }
        } else if (exponent >= -0x80) {
          buf[0] = 0x80 | sign | 0x00;

          buf[1] = static_cast<uint8_t>(exponent);

          len = 2;
        } else {
          buf[0] = 0x80 | sign | 0x01;

          buf[1] = static_cast<uint8_t>((exponent >> 8) & 0xff);
          buf[2] = static_cast<uint8_t>(exponent & 0xff);

          len = 3;
        }

        // Encode significand.
        encode_significand(significand, l, buf + len);

        // significand * (2 ^ exponent) == n.

        return len + l;
      }

      break;
    case 0x00:
      if (significand == 0) {
        if (sign == 0x00) {
          // +0.0: ITU X.690: 8.5.2.
          return 0;
        } else {
          // -0.0: ITU X.690: 8.5.3 => 8.5.9.
          buf[0] = 0x43;
          return 1;
        }
      } else {
        // Subnormal number.

        // The number has the format: 0.<fraction>,
        // where <fraction> is 52 bits long.

        // To get rid of the decimal separator, we have to move the decimal
        // separator 52 positions to the right (multiply by 2^52).
        //
        // Exponent = -(bias (1022) + 52) = -1074.
        int16_t exponent = -1074;

        // The significand is 7 bytes long.
        size_t l = 7;

        // Normalize: the least significant bit has to be 1.
        //
        // Shift bits to the right until the least significant bit is 1.
        // Every time we shift bits one position to the right,
        // we are dividing by 2, so later we have to increment the exponent as
        // many times as we have shifted.
        while ((significand & 0xff) == 0) {
          significand >>= 8;
          l--;
        }

        exponent += (8 * (7 - l));

        while ((significand & 0x01) == 0) {
          significand >>= 1;
          exponent++;
        }

        // Encode first byte and exponent.
        buf[0] = 0x80 | sign | 0x01;

        buf[1] = static_cast<uint8_t>((exponent >> 8) & 0xff);
        buf[2] = static_cast<uint8_t>(exponent & 0xff);

        // Encode significand.
        encode_significand(significand, l, buf + 3);

        // significand * (2 ^ exponent) == n.

        return 3 + l;
      }

      break;
    case 0x7ff:
      if (significand == 0) {
        if (sign == 0x00) {
          // +infinity: ITU X.690: 8.5.9.
          buf[0] = 0x40;
        } else {
          // -infinity: ITU X.690: 8.5.9.
          buf[0] = 0x41;
        }
      } else {
        // NaN: ITU X.690: 8.5.9.
        buf[0] = 0x42;
      }

      return 1;
  }
}

size_t asn1::ber::encode_utc_time(time_t t, uint8_t* buf)
{
  struct tm tm;
  gmtime_r(&t, &tm);

  unsigned year = tm.tm_year - 100;
  unsigned mon = 1 + tm.tm_mon;

  buf[0] = '0' + (year / 10);
  buf[1] = '0' + (year % 10);
  buf[2] = '0' + (mon / 10);
  buf[3] = '0' + (mon % 10);
  buf[4] = '0' + (tm.tm_mday / 10);
  buf[5] = '0' + (tm.tm_mday % 10);
  buf[6] = '0' + (tm.tm_hour / 10);
  buf[7] = '0' + (tm.tm_hour % 10);
  buf[8] = '0' + (tm.tm_min / 10);
  buf[9] = '0' + (tm.tm_min % 10);
  buf[10] = '0' + (tm.tm_sec / 10);
  buf[11] = '0' + (tm.tm_sec % 10);
  buf[12] = 'Z';

  return 13;
}

size_t asn1::ber::encode_generalized_time(const struct timeval& tv,
                                          uint8_t* buf)
{
  struct tm tm;
  gmtime_r(&tv.tv_sec, &tm);

  unsigned year = 1900 + tm.tm_year;
  unsigned mon = 1 + tm.tm_mon;

  buf[0] = '0' + (year / 1000);
  year %= 1000;

  buf[1] = '0' + (year / 100);
  year %= 100;

  buf[2] = '0' + (year / 10);
  buf[3] = '0' + (year % 10);

  buf[4] = '0' + (mon / 10);
  buf[5] = '0' + (mon % 10);
  buf[6] = '0' + (tm.tm_mday / 10);
  buf[7] = '0' + (tm.tm_mday % 10);
  buf[8] = '0' + (tm.tm_hour / 10);
  buf[9] = '0' + (tm.tm_hour % 10);
  buf[10] = '0' + (tm.tm_min / 10);
  buf[11] = '0' + (tm.tm_min % 10);
  buf[12] = '0' + (tm.tm_sec / 10);
  buf[13] = '0' + (tm.tm_sec % 10);

  size_t len;

  if (tv.tv_usec != 0) {
    unsigned ms;
    if ((ms = tv.tv_usec / 1000) != 0) {
      buf[14] = '.';

      buf[15] = '0' + (ms / 100);

      if ((ms %= 100) != 0) {
        buf[16] = '0' + (ms / 10);

        if ((ms %= 10) != 0) {
          buf[17] = '0' + ms;

          len = 18;
        } else {
          len = 17;
        }
      } else {
        len = 16;
      }
    } else {
      len = 14;
    }
  } else {
    len = 14;
  }

  buf[len] = 'Z';

  return len + 1;
}

int64_t asn1::ber::decode_integer(const void* buf, uint64_t len)
{
  const uint8_t* const b = static_cast<const uint8_t*>(buf);

  uint64_t n;

  switch (len) {
    case 8:
      n  = (static_cast<uint64_t>(b[0]) << 56);
      n |= (static_cast<uint64_t>(b[1]) << 48);
      n |= (static_cast<uint64_t>(b[2]) << 40);
      n |= (static_cast<uint64_t>(b[3]) << 32);
      n |= (static_cast<uint64_t>(b[4]) << 24);
      n |= (static_cast<uint64_t>(b[5]) << 16);
      n |= (static_cast<uint64_t>(b[6]) << 8);
      n |=  static_cast<uint64_t>(b[7]);

      return n;
    case 7:
      n =  (static_cast<uint64_t>(b[0]) << 48);
      n |= (static_cast<uint64_t>(b[1]) << 40);
      n |= (static_cast<uint64_t>(b[2]) << 32);
      n |= (static_cast<uint64_t>(b[3]) << 24);
      n |= (static_cast<uint64_t>(b[4]) << 16);
      n |= (static_cast<uint64_t>(b[5]) << 8);
      n |=  static_cast<uint64_t>(b[6]);

      break;
    case 6:
      n =  (static_cast<uint64_t>(b[0]) << 40);
      n |= (static_cast<uint64_t>(b[1]) << 32);
      n |= (static_cast<uint64_t>(b[2]) << 24);
      n |= (static_cast<uint64_t>(b[3]) << 16);
      n |= (static_cast<uint64_t>(b[4]) << 8);
      n |=  static_cast<uint64_t>(b[5]);

      break;
    case 5:
      n =  (static_cast<uint64_t>(b[0]) << 32);
      n |= (static_cast<uint64_t>(b[1]) << 24);
      n |= (static_cast<uint64_t>(b[2]) << 16);
      n |= (static_cast<uint64_t>(b[3]) << 8);
      n |=  static_cast<uint64_t>(b[4]);

      break;
    case 4:
      n =  (static_cast<uint64_t>(b[0]) << 24);
      n |= (static_cast<uint64_t>(b[1]) << 16);
      n |= (static_cast<uint64_t>(b[2]) << 8);
      n |=  static_cast<uint64_t>(b[3]);

      break;
    case 3:
      n =  (static_cast<uint64_t>(b[0]) << 16);
      n |= (static_cast<uint64_t>(b[1]) << 8);
      n |=  static_cast<uint64_t>(b[2]);

      break;
    case 2:
      n =  (static_cast<uint64_t>(b[0]) << 8);
      n |=  static_cast<uint64_t>(b[1]);

      break;
    default:
      n = static_cast<uint64_t>(b[0]);
  }

  // If the number is positive...
  if ((*b & 0x80) == 0) {
    return n;
  } else {
    return ((~static_cast<uint64_t>(0) << (len << 3)) | n);
  }
}

static bool decode_exponent(const uint8_t* b,
                            uint64_t len,
                            int64_t& exponent,
                            uint64_t& offset)
{
  uint64_t n;
  size_t l;
  uint64_t off;
  bool positive;

  switch (b[0] & 0x03) {
    case 0x00:
      if (len >= 3) {
        n = b[1];
        l = 1;
        off = 2;
        positive = ((b[1] & 0x80) == 0x00);
      } else {
        return false;
      }

      break;
    case 0x01:
      if (len >= 4) {
        n = (static_cast<uint64_t>(b[1]) << 8) | static_cast<uint64_t>(b[2]);
        l = 2;
        off = 3;
        positive = ((b[1] & 0x80) == 0x00);
      } else {
        return false;
      }

      break;
    case 0x02:
      if (len >= 5) {
        n = (static_cast<uint64_t>(b[1]) << 16) |
            (static_cast<uint64_t>(b[2]) << 8) |
             static_cast<uint64_t>(b[3]);

        l = 3;
        off = 4;
        positive = ((b[1] & 0x80) == 0x00);
      } else {
        return false;
      }

      break;
    default:
      l = b[1];

      if ((l > 0) && (l <= 8) && (2 + l + 1 <= len)) {
        switch (l) {
          case 1:
            n = b[2];
            break;
          case 2:
            n = (static_cast<uint64_t>(b[2]) << 8) |
                 static_cast<uint64_t>(b[3]);

            break;
          case 3:
            n = (static_cast<uint64_t>(b[2]) << 16) |
                (static_cast<uint64_t>(b[3]) << 8) |
                 static_cast<uint64_t>(b[4]);

            break;
          case 4:
            n = (static_cast<uint64_t>(b[2]) << 24) |
                (static_cast<uint64_t>(b[3]) << 16) |
                (static_cast<uint64_t>(b[4]) << 8) |
                 static_cast<uint64_t>(b[5]);

            break;
          case 5:
            n = (static_cast<uint64_t>(b[2]) << 32) |
                (static_cast<uint64_t>(b[3]) << 24) |
                (static_cast<uint64_t>(b[4]) << 16) |
                (static_cast<uint64_t>(b[5]) << 8) |
                 static_cast<uint64_t>(b[6]);

            break;
          case 6:
            n = (static_cast<uint64_t>(b[2]) << 40) |
                (static_cast<uint64_t>(b[3]) << 32) |
                (static_cast<uint64_t>(b[4]) << 24) |
                (static_cast<uint64_t>(b[5]) << 16) |
                (static_cast<uint64_t>(b[6]) << 8) |
                 static_cast<uint64_t>(b[7]);

            break;
          case 7:
            n = (static_cast<uint64_t>(b[2]) << 48) |
                (static_cast<uint64_t>(b[3]) << 40) |
                (static_cast<uint64_t>(b[4]) << 32) |
                (static_cast<uint64_t>(b[5]) << 24) |
                (static_cast<uint64_t>(b[6]) << 16) |
                (static_cast<uint64_t>(b[7]) << 8) |
                 static_cast<uint64_t>(b[8]);

            break;
          default:
            n = (static_cast<uint64_t>(b[2]) << 56) |
                (static_cast<uint64_t>(b[3]) << 48) |
                (static_cast<uint64_t>(b[4]) << 40) |
                (static_cast<uint64_t>(b[5]) << 32) |
                (static_cast<uint64_t>(b[6]) << 24) |
                (static_cast<uint64_t>(b[7]) << 16) |
                (static_cast<uint64_t>(b[8]) << 8) |
                 static_cast<uint64_t>(b[9]);
        }

        off = 2 + l;
        positive = ((b[2] & 0x80) == 0x00);
      } else {
        return false;
      }
  }

  // If the exponent is positive...
  int64_t exp;
  if (positive) {
    exp = n;
  } else {
    exp = (~static_cast<uint64_t>(0) << (l << 3)) | n;
  }

  // If the exponent is neither too small nor too big...
  if ((exp >= -1074) && (exp <= 1023)) {
    exponent = exp;
    offset = off;

    return true;
  }

  return false;
}

static bool decode_significand(const uint8_t* b,
                               uint64_t len,
                               uint64_t& significand)
{
  uint64_t n;

  switch (len) {
    case 1:
      n = b[0];
      break;
    case 2:
      n = (static_cast<uint64_t>(b[0]) << 8) | static_cast<uint64_t>(b[1]);
      break;
    case 3:
      n = (static_cast<uint64_t>(b[0]) << 16) |
          (static_cast<uint64_t>(b[1]) << 8) |
           static_cast<uint64_t>(b[2]);

      break;
    case 4:
      n = (static_cast<uint64_t>(b[0]) << 24) |
          (static_cast<uint64_t>(b[1]) << 16) |
          (static_cast<uint64_t>(b[2]) << 8) |
           static_cast<uint64_t>(b[3]);

      break;
    case 5:
      n = (static_cast<uint64_t>(b[0]) << 32) |
          (static_cast<uint64_t>(b[1]) << 24) |
          (static_cast<uint64_t>(b[2]) << 16) |
          (static_cast<uint64_t>(b[3]) << 8) |
           static_cast<uint64_t>(b[4]);

      break;
    case 6:
      n = (static_cast<uint64_t>(b[0]) << 40) |
          (static_cast<uint64_t>(b[1]) << 32) |
          (static_cast<uint64_t>(b[2]) << 24) |
          (static_cast<uint64_t>(b[3]) << 16) |
          (static_cast<uint64_t>(b[4]) << 8) |
           static_cast<uint64_t>(b[5]);

      break;
    case 7:
      n = (static_cast<uint64_t>(b[0]) << 48) |
          (static_cast<uint64_t>(b[1]) << 40) |
          (static_cast<uint64_t>(b[2]) << 32) |
          (static_cast<uint64_t>(b[3]) << 24) |
          (static_cast<uint64_t>(b[4]) << 16) |
          (static_cast<uint64_t>(b[5]) << 8) |
           static_cast<uint64_t>(b[6]);

      break;
    case 8:
      n = (static_cast<uint64_t>(b[0]) << 56) |
          (static_cast<uint64_t>(b[1]) << 48) |
          (static_cast<uint64_t>(b[2]) << 40) |
          (static_cast<uint64_t>(b[3]) << 32) |
          (static_cast<uint64_t>(b[4]) << 24) |
          (static_cast<uint64_t>(b[5]) << 16) |
          (static_cast<uint64_t>(b[6]) << 8) |
           static_cast<uint64_t>(b[7]);

      break;
    default:
      return false;
  }

  significand = n;

  return true;
}

bool asn1::ber::decode_real(const void* buf, uint64_t len, double& n)
{
  switch (len) {
    default:
      {
        const uint8_t* const b = static_cast<const uint8_t*>(buf);

        // Binary encoding?
        if ((b[0] & 0x80) == 0x80) {
          // Check base.
          unsigned base;
          switch (b[0] & 0x30) {
            case 0x00:
              base = 2;
              break;
            case 0x10:
              base = 8;
              break;
            case 0x20:
              base = 16;
              break;
            default:
              return false;
          }

          // Decode exponent.
          int64_t exponent;
          uint64_t offset;
          if (decode_exponent(b, len, exponent, offset)) {
            // Decode significand.
            uint64_t significand;
            if (decode_significand(b + offset, len - offset, significand)) {
              int64_t mantissa;

              // Check factor.
              switch (b[0] & 0x0c) {
                case 0x00:
                  if (significand <= 0x7fffffffffffffffull) {
                    mantissa = significand;
                  } else {
                    return false;
                  }

                  break;
                case 0x04:
                  if (significand <= 0x3fffffffffffffffull) {
                    mantissa = significand << 1;
                  } else {
                    return false;
                  }

                  break;
                case 0x08:
                  if (significand <= 0x1fffffffffffffffull) {
                    mantissa = significand << 2;
                  } else {
                    return false;
                  }

                  break;
                default:
                  if (significand <= 0x0fffffffffffffffull) {
                    mantissa = significand << 3;
                  } else {
                    return false;
                  }

                  break;
              }

              // Negative?
              if ((b[0] & 0x40) == 0x40) {
                mantissa = -mantissa;
              }

              switch (base) {
                case 8:
                  exponent *= 3;
                  break;
                case 16:
                  exponent *= 4;
                  break;
              }

              double res = ldexp(mantissa, exponent);

              if (isfinite(res)) {
                n = res;
                return true;
              }
            }
          }
        } else {
          // Decimal encoding.

          enum class representation {
            nr1,
            nr2,
            nr3
          };

          representation nr;

          // Check given number representation.
          switch (b[0] & 0x3f) {
            case 1:
              nr = representation::nr1;
              break;
            case 2:
              nr = representation::nr2;
              break;
            case 3:
              nr = representation::nr3;
              break;
            default:
              return false;
          }

          representation rep = representation::nr1;

          char str[32];
          char* out = str;

          int state = 0; // Initial state.

          for (uint64_t i = 1; i < len; i++) {
            switch (state) {
              case 0: // Initial state.
                switch (b[i]) {
                  case '0':
                  case '1':
                  case '2':
                  case '3':
                  case '4':
                  case '5':
                  case '6':
                  case '7':
                  case '8':
                  case '9':
                    *out++ = b[i];

                    state = 2; // Integer part.
                    break;
                  case '+':
                  case '-':
                    *out++ = b[i];

                    state = 1; // After sign of the integer part.
                    break;
                  case '.':
                  case ',':
                    *out++ = '.';

                    rep = representation::nr2;

                    // After decimal separator, fractional part mandatory.
                    state = 4;
                    break;
                  case ' ':
                  case '\t':
                    break;
                  default:
                    return false;
                }

                break;
              case 1: // After sign of the integer part.
                switch (b[i]) {
                  case '0':
                  case '1':
                  case '2':
                  case '3':
                  case '4':
                  case '5':
                  case '6':
                  case '7':
                  case '8':
                  case '9':
                    *out++ = b[i];

                    state = 2; // Integer part.
                    break;
                  case '.':
                  case ',':
                    *out++ = '.';

                    rep = representation::nr2;

                    // After decimal separator, fractional part mandatory.
                    state = 4;
                    break;
                  default:
                    return false;
                }

                break;
              case 2: // Integer part.
                switch (b[i]) {
                  case '0':
                  case '1':
                  case '2':
                  case '3':
                  case '4':
                  case '5':
                  case '6':
                  case '7':
                  case '8':
                  case '9':
                    *out++ = b[i];
                    break;
                  case '.':
                  case ',':
                    *out++ = '.';

                    rep = representation::nr2;

                    // After decimal separator, fractional part optional.
                    state = 3;
                    break;
                  case 'e':
                  case 'E':
                    *out++ = 'e';

                    rep = representation::nr3;

                    state = 5; // After 'e'.
                    break;
                  default:
                    return false;
                }

                break;
              case 3: // After decimal separator, fractional part optional.
                switch (b[i]) {
                  case '0':
                  case '1':
                  case '2':
                  case '3':
                  case '4':
                  case '5':
                  case '6':
                  case '7':
                  case '8':
                  case '9':
                    *out++ = b[i];
                    break;
                  case 'e':
                  case 'E':
                    *out++ = 'e';

                    rep = representation::nr3;

                    state = 5; // After 'e'.
                    break;
                  default:
                    return false;
                }

                break;
              case 4: // After decimal separator, fractional part mandatory.
                switch (b[i]) {
                  case '0':
                  case '1':
                  case '2':
                  case '3':
                  case '4':
                  case '5':
                  case '6':
                  case '7':
                  case '8':
                  case '9':
                    *out++ = b[i];

                    // After decimal separator, fractional part optional.
                    state = 3;
                    break;
                  default:
                    return false;
                }

                break;
              case 5: // After 'e'.
                switch (b[i]) {
                  case '0':
                  case '1':
                  case '2':
                  case '3':
                  case '4':
                  case '5':
                  case '6':
                  case '7':
                  case '8':
                  case '9':
                    *out++ = b[i];

                    state = 7; // Exponent.
                    break;
                  case '+':
                  case '-':
                    *out++ = b[i];

                    state = 6; // After sign of the exponent.
                    break;
                  default:
                    return false;
                }

                break;
              case 6: // After sign of the exponent.
                switch (b[i]) {
                  case '0':
                  case '1':
                  case '2':
                  case '3':
                  case '4':
                  case '5':
                  case '6':
                  case '7':
                  case '8':
                  case '9':
                    *out++ = b[i];

                    state = 7; // Exponent.
                    break;
                  default:
                    return false;
                }

                break;
              case 7: // Exponent.
                switch (b[i]) {
                  case '0':
                  case '1':
                  case '2':
                  case '3':
                  case '4':
                  case '5':
                  case '6':
                  case '7':
                  case '8':
                  case '9':
                    *out++ = b[i];
                    break;
                  default:
                    return false;
                }

                break;
            }
          }

          switch (state) {
            case 2: // Integer part.
            case 3: // After decimal separator, fractional part optional.
            case 7: // Exponent.
              if (static_cast<unsigned>(nr) >= static_cast<unsigned>(rep)) {
                *out = 0;
                n = atof(str);

                return true;
              }

              break;
          }
        }
      }

      break;
    case 0:
      // ITU X.690: 8.5.2.
      n = 0.0;

      return true;
    case 1:
      {
        static const uint64_t positive_infinity = 0x7ff0000000000000ull;
        static const uint64_t negative_infinity = 0xfff0000000000000ull;
        static const uint64_t nan = 0x7ff0000000000001ull;

        const uint8_t* const b = static_cast<const uint8_t*>(buf);

        switch (b[0]) {
          case 0x40:
            // +infinity: ITU X.690: 8.5.9.
            memcpy(&n, &positive_infinity, sizeof(double));

            return true;
          case 0x41:
            // -infinity: ITU X.690: 8.5.9.
            memcpy(&n, &negative_infinity, sizeof(double));

            return true;
          case 0x42:
            // NaN: ITU X.690: 8.5.9.
            memcpy(&n, &nan, sizeof(double));

            return true;
          case 0x43:
            // -0.0: ITU X.690: 8.5.3 => 8.5.9.
            n = -0.0;

            return true;
        }
      }

      break;
  }

  return false;
}

bool asn1::ber::decode_utc_time(const void* buf, uint64_t len, time_t& t)
{
  const uint8_t* const b = static_cast<const uint8_t*>(buf);

  if ((IS_DIGIT(b[0])) &&
      (IS_DIGIT(b[1])) &&
      (IS_DIGIT(b[2])) &&
      (IS_DIGIT(b[3])) &&
      (IS_DIGIT(b[4])) &&
      (IS_DIGIT(b[5])) &&
      (IS_DIGIT(b[6])) &&
      (IS_DIGIT(b[7])) &&
      (IS_DIGIT(b[8])) &&
      (IS_DIGIT(b[9]))) {
    struct tm tm;
    tm.tm_year = ((b[0] - '0') * 10) + (b[1] - '0');

    if (tm.tm_year < 70) {
      tm.tm_year += 100;
    }

    tm.tm_mon = ((b[2] - '0') * 10) + (b[3] - '0');

    if ((tm.tm_mon >= 1) && (tm.tm_mon <= 12)) {
      tm.tm_mon--;

      tm.tm_mday = ((b[4] - '0') * 10) + (b[5] - '0');

      if ((tm.tm_mday >= 1) && (tm.tm_mday <= 31)) {
        tm.tm_hour = ((b[6] - '0') * 10) + (b[7] - '0');

        if (tm.tm_hour <= 23) {
          tm.tm_min = ((b[8] - '0') * 10) + (b[9] - '0');

          if (tm.tm_min <= 59) {
            tm.tm_isdst = -1;

            size_t off;

            switch (b[10]) {
              case 'Z':
                if (len == 11) {
                  tm.tm_sec = 0;

                  t = timegm(&tm);

                  return true;
                } else {
                  return false;
                }

                break;
              case '0':
              case '1':
              case '2':
              case '3':
              case '4':
              case '5':
                if ((len >= 13) && (IS_DIGIT(b[11]))) {
                  tm.tm_sec = ((b[10] - '0') * 10) + (b[11] - '0');

                  switch (b[12]) {
                    case 'Z':
                      if (len == 13) {
                        t = timegm(&tm);

                        return true;
                      } else {
                        return false;
                      }

                      break;
                    case '+':
                    case '-':
                      off = 13;
                      break;
                    default:
                      return false;
                  }
                } else {
                  return false;
                }

                break;
              case '+':
              case '-':
                tm.tm_sec = 0;

                off = 11;

                break;
              default:
                return false;
            }

            if (off + 4 == len) {
              if ((IS_DIGIT(b[off])) &&
                  (IS_DIGIT(b[off + 1])) &&
                  (IS_DIGIT(b[off + 2])) &&
                  (IS_DIGIT(b[off + 3]))) {
                unsigned hour = ((b[off] - '0') * 10) + (b[off + 1] - '0');

                if (hour <= 23) {
                  unsigned min = ((b[off + 2] - '0') * 10) + (b[off + 3] - '0');

                  if (min <= 59) {
                    time_t diff = (hour * 3600) + (min * 60);

                    if (b[off - 1] == '+') {
                      t = timegm(&tm) - diff;
                    } else {
                      t = timegm(&tm) + diff;
                    }

                    return true;
                  }
                }
              }
            }
          }
        }
      }
    }
  }

  return false;
}

static bool decode_time_fraction(const uint8_t* b,
                                 uint64_t len,
                                 uint64_t& off,
                                 uint64_t max,
                                 uint64_t& fraction,
                                 uint64_t& total)
{
  uint64_t res = 0;
  uint64_t n = 1;

  uint64_t i;
  for (i = off; i < len; i++) {
    if (IS_DIGIT(b[i])) {
      if ((n *= 10) <= max) {
        res = (res * 10) + (b[i] - '0');
      } else {
        return false;
      }
    } else {
      break;
    }
  }

  if (n > 1) {
    off = i;
    fraction = res;
    total = n;

    return true;
  } else {
    return false;
  }
}

bool asn1::ber::decode_generalized_time(const void* buf,
                                        uint64_t len,
                                        struct timeval& tv)
{
  const uint8_t* const b = static_cast<const uint8_t*>(buf);

  if ((len >= 10) &&
      (IS_DIGIT(b[0])) &&
      (IS_DIGIT(b[1])) &&
      (IS_DIGIT(b[2])) &&
      (IS_DIGIT(b[3])) &&
      (IS_DIGIT(b[4])) &&
      (IS_DIGIT(b[5])) &&
      (IS_DIGIT(b[6])) &&
      (IS_DIGIT(b[7])) &&
      (IS_DIGIT(b[8])) &&
      (IS_DIGIT(b[9]))) {
    struct tm tm;
    tm.tm_year = ((b[0] - '0') * 1000) +
                 ((b[1] - '0') * 100) +
                 ((b[2] - '0') * 10) +
                  (b[3] - '0');

    if (tm.tm_year >= 1970) {
      tm.tm_year -= 1900;

      tm.tm_mon = ((b[4] - '0') * 10) + (b[5] - '0');

      if ((tm.tm_mon >= 1) && (tm.tm_mon <= 12)) {
        tm.tm_mon--;

        tm.tm_mday = ((b[6] - '0') * 10) + (b[7] - '0');

        if ((tm.tm_mday >= 1) && (tm.tm_mday <= 31)) {
          tm.tm_hour = ((b[8] - '0') * 10) + (b[9] - '0');

          if (tm.tm_hour <= 23) {
            tm.tm_isdst = -1;

            uint64_t off;

            if (len >= 12) {
              switch (b[10]) {
                case '0':
                case '1':
                case '2':
                case '3':
                case '4':
                case '5':
                  if (IS_DIGIT(b[11])) {
                    tm.tm_min = ((b[10] - '0') * 10) + (b[11] - '0');

                    if (len >= 14) {
                      switch (b[12]) {
                        case '0':
                        case '1':
                        case '2':
                        case '3':
                        case '4':
                        case '5':
                          if (IS_DIGIT(b[13])) {
                            tm.tm_sec = ((b[12] - '0') * 10) + (b[13] - '0');

                            if (len >= 16) {
                              switch (b[14]) {
                                case '.':
                                case ',':
                                  {
                                    off = 15;

                                    uint64_t fraction;
                                    uint64_t total;

                                    if (decode_time_fraction(b,
                                                             len,
                                                             off,
                                                             1000000ull,
                                                             fraction,
                                                             total)) {
                                      tv.tv_usec = fraction *
                                                   (1000000ull / total);
                                    } else {
                                      return false;
                                    }
                                  }

                                  break;
                                default:
                                  tv.tv_usec = 0;

                                  off = 14;
                              }
                            } else {
                              tv.tv_usec = 0;

                              off = 14;
                            }
                          } else {
                            return false;
                          }

                          break;
                        case '.':
                        case ',':
                          {
                            off = 13;

                            uint64_t fraction;
                            uint64_t total;

                            if (decode_time_fraction(b,
                                                     len,
                                                     off,
                                                     10000000ull,
                                                     fraction,
                                                     total)) {
                              uint64_t microseconds = fraction *
                                                      (60000000ull / total);

                              tm.tm_sec = microseconds / 1000000ull;
                              tv.tv_usec = microseconds % 1000000ull;
                            } else {
                              return false;
                            }
                          }

                          break;
                        default:
                          tm.tm_sec = 0;

                          tv.tv_usec = 0;

                          off = 12;
                      }
                    } else {
                      tm.tm_sec = 0;

                      tv.tv_usec = 0;

                      off = 12;
                    }
                  } else {
                    return false;
                  }

                  break;
                case '.':
                case ',':
                  {
                    off = 11;

                    uint64_t fraction;
                    uint64_t total;

                    if (decode_time_fraction(b,
                                             len,
                                             off,
                                             100000000ull,
                                             fraction,
                                             total)) {
                      uint64_t microseconds = fraction *
                                              (3600000000ull / total);

                      tm.tm_min = microseconds / 60000000ull;

                      microseconds %= 60000000ull;

                      tm.tm_sec = microseconds / 1000000ull;
                      tv.tv_usec = microseconds % 1000000ull;
                    } else {
                      return false;
                    }
                  }

                  break;
                default:
                  tm.tm_min = 0;
                  tm.tm_sec = 0;

                  tv.tv_usec = 0;

                  off = 10;
              }
            } else {
              tm.tm_min = 0;
              tm.tm_sec = 0;

              tv.tv_usec = 0;

              off = 10;
            }

            if (off + 1 == len) {
              if (b[off] == 'Z') {
                // UTC.
                tv.tv_sec = timegm(&tm);

                return true;
              }
            } else if (off == len) {
              // Local time.
              tv.tv_sec = mktime(&tm);

              return true;
            } else if (off + 3 == len) {
              if (((b[off] == '+') || (b[off] == '-')) &&
                  (IS_DIGIT(b[off + 1])) &&
                  (IS_DIGIT(b[off + 2]))) {
                unsigned hour = ((b[off + 1] - '0') * 10) + (b[off + 2] - '0');

                if (hour <= 23) {
                  time_t diff = hour * 3600;

                  if (b[off] == '+') {
                    tv.tv_sec = timegm(&tm) - diff;
                  } else {
                    tv.tv_sec = timegm(&tm) + diff;
                  }

                  return true;
                }
              }
            } else if (off + 5 == len) {
              if (((b[off] == '+') || (b[off] == '-')) &&
                  (IS_DIGIT(b[off + 1])) &&
                  (IS_DIGIT(b[off + 2])) &&
                  (IS_DIGIT(b[off + 3])) &&
                  (IS_DIGIT(b[off + 4]))) {
                unsigned hour = ((b[off + 1] - '0') * 10) + (b[off + 2] - '0');

                if (hour <= 23) {
                  unsigned min = ((b[off + 3] - '0') * 10) + (b[off + 4] - '0');

                  if (min <= 59) {
                    time_t diff = (hour * 3600) + (min * 60);

                    if (b[off] == '+') {
                      tv.tv_sec = timegm(&tm) - diff;
                    } else {
                      tv.tv_sec = timegm(&tm) + diff;
                    }

                    return true;
                  }
                }
              }
            }
          }
        }
      }
    }
  }

  return false;
}

bool asn1::ber::decode_oid(const void* buf,
                           uint64_t len,
                           uint64_t* oid,
                           size_t& ncomponents)
{
  if (len > 0) {
    const uint8_t* const b = static_cast<const uint8_t*>(buf);

    size_t count = 0;

    uint64_t component = 0;
    size_t componentlen = 0;

    for (uint64_t i = 0; i < len; i++) {
      if ((componentlen < 10) || (b[i] <= 1)) {
        component |= (b[i] & 0x7fu);

        // If the most significant bit is not set...
        if ((b[i] & 0x80u) == 0) {
          if (count < max_oid_components) {
            if (count > 0) {
              oid[count++] = component;
            } else {
              if (component < 0x80ull) {
                if ((oid[0] = component / 40) <= 2) {
                  oid[1] = component % 40;
                } else {
                  return false;
                }
              } else {
                oid[0] = 2;
                oid[1] = component - 80;
              }

              count = 2;
            }

            component = 0;
            componentlen = 0;
          } else {
            return false;
          }
        } else {
          component <<= 7;
          componentlen++;
        }
      } else {
        return false;
      }
    }

    if (componentlen == 0) {
      ncomponents = count;
      return true;
    }
  }

  return false;
}
