#include <string.h>
#include "asn1/ber/common.h"

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
