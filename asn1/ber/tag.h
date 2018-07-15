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
      EndOfContents = 0,
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

    static inline const char* to_string(tag_class tc)
    {
      switch (tc) {
        case tag_class::Universal:       return "Universal";
        case tag_class::Application:     return "Application";
        case tag_class::ContextSpecific: return "Context-specific";
        case tag_class::Private:         return "Private";
        default:                         return "(unknown)";
      }
    }

    const char* to_string(universal_class uc);

    static inline const char* to_string(primitive_constructed pc)
    {
      switch (pc) {
        case primitive_constructed::Primitive:   return "Primitive";
        case primitive_constructed::Constructed: return "Constructed";
        default:                                 return "(unknown)";
      }
    }

    static inline const char* to_string(tagging tg)
    {
      switch (tg) {
        case tagging::Implicit: return "Implicit";
        case tagging::Explicit: return "Explicit";
        default:                return "(unknown)";
      }
    }
  }
}

#endif // ASN1_BER_TAG_H
