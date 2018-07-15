#ifndef ASN1_BER_ERROR_H
#define ASN1_BER_ERROR_H

namespace asn1 {
  namespace ber {
    enum class error {
      unexpected_eof,
      unexpected_end_of_contents,
      invalid_universal_class,
      invalid_tag_number,
      invalid_length,
      max_depth_exceeded,
      invalid_value,
      callback
    };

    static inline const char* to_string(error err)
    {
      switch (err) {
        case error::unexpected_eof:
          return "unexpected end-of-file";
        case error::unexpected_end_of_contents:
          return "unexpected end-of-contents";
        case error::invalid_universal_class:
          return "invalid universal class";
        case error::invalid_tag_number:
          return "invalid tag number";
        case error::invalid_length:
          return "invalid length";
        case error::max_depth_exceeded:
          return "maximum depth exceeded";
        case error::invalid_value:
          return "invalid value";
        case error::callback:
          return "error callback";
        default:
          return "(unknown)";
      }
    }
  }
}

#endif // ASN1_BER_ERROR_H
