#include "asn1/ber/tag.h"

const char* asn1::ber::to_string(universal_class uc)
{
  switch (uc) {
    case universal_class::EndOfContents:    return "end-of-contents";
    case universal_class::Boolean:          return "boolean";
    case universal_class::Integer:          return "integer";
    case universal_class::Bitstring:        return "bitstring";
    case universal_class::Octetstring:      return "octetstring";
    case universal_class::Null:             return "null";
    case universal_class::ObjectIdentifier: return "object identifier";
    case universal_class::ObjectDescriptor: return "object descriptor";
    case universal_class::External:         return "external";
    case universal_class::Real:             return "real";
    case universal_class::Enumerated:       return "enumerated";
    case universal_class::EmbeddedPDV:      return "embedded-pdv";
    case universal_class::UTF8String:       return "UTF8String";
    case universal_class::RelativeOID:      return "relative OID";
    case universal_class::Sequence:         return "sequence";
    case universal_class::Set:              return "set";
    case universal_class::NumericString:    return "NumericString";
    case universal_class::PrintableString:  return "PrintableString";
    case universal_class::TeletexString:    return "TeletexString";
    case universal_class::VideotexString:   return "VideotexString";
    case universal_class::IA5String:        return "IA5String";
    case universal_class::UTCTime:          return "UTCTime";
    case universal_class::GeneralizedTime:  return "GeneralizedTime";
    case universal_class::GraphicString:    return "GraphicString";
    case universal_class::VisibleString:    return "VisibleString";
    case universal_class::GeneralString:    return "GeneralString";
    case universal_class::UniversalString:  return "UniversalString";
    case universal_class::CharacterString:  return "character string";
    case universal_class::BMPString:        return "BMPString";
    default:                                return "(unknown)";
  }
}
