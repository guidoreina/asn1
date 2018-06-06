#ifndef ASN1_BER_TAG_H
#define ASN1_BER_TAG_H

#include <stdint.h>

namespace asn1 {
  namespace ber {
    enum class tag_class : uint8_t {
      Universal = 0,
      Application = 1,
      ContextSpecific = 2,
      Private = 3
    };

    enum class universal_class : uint8_t {
      EndOfContent = 0,
      Boolean = 1,
      Integer = 2,
      Bitstring = 3,
      Octetstring = 4,
      Null = 5,
      ObjectIdentifier = 6,
      ObjectDescriptor = 7,
      External = 8,
      Real = 9,
      Enumerated = 10,
      EmbeddedPDV = 11,
      UTF8String = 12,
      RelativeOID = 13,
      Sequence = 16,
      Set = 17,
      NumericString = 18,
      PrintableString = 19,
      TeletexString = 20,
      VideotexString = 21,
      IA5String = 22,
      UTCTime = 23,
      GeneralizedTime = 24,
      GraphicString = 25,
      VisibleString = 26,
      GeneralString = 27,
      UniversalString = 28,
      CharacterString = 29,
      BMPString = 30
    };

    typedef uint64_t tag_number;

    enum class primitive_constructed {
      Primitive,
      Constructed
    };

    static const tag_number not_specified = ~static_cast<tag_number>(0);

    enum class tagging {
      Implicit,
      Explicit
    };
  }
}

#endif // ASN1_BER_TAG_H
