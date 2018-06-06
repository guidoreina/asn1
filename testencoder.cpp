#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "asn1/ber/encoder.h"

class fhexwriter {
  public:
    // Constructor.
    fhexwriter(FILE* file)
      : _M_file(file)
    {
    }

    // Destructor.
    ~fhexwriter()
    {
      fwrite("\n", 1, 1, _M_file);
    }

    // Write.
    bool write(const void* buf, size_t len) const
    {
      const uint8_t* b = static_cast<const uint8_t*>(buf);

      for (size_t i = 0; i < len; i++, _M_count++) {
        fprintf(_M_file, "%s%02x", (_M_count > 0) ? " " : "", b[i]);
      }

      return true;
    }

  private:
    FILE* _M_file;
    mutable size_t _M_count = 0;
};

class fbinwriter {
  public:
    // Constructor.
    fbinwriter(FILE* file)
      : _M_file(file)
    {
    }

    // Destructor.
    ~fbinwriter() = default;

    // Write.
    bool write(const void* buf, size_t len) const
    {
      fwrite(buf, 1, len, _M_file);
      return true;
    }

  private:
    FILE* _M_file;
};

int main()
{
  asn1::ber::encoder<> encoder;

  encoder.start_sequence(asn1::ber::tag_class::ContextSpecific,
                         asn1::ber::tagging::Implicit,
                         1);

    encoder.add_integer(asn1::ber::tag_class::ContextSpecific,
                        asn1::ber::tagging::Explicit,
                        10,
                        1);

    encoder.add_integer(asn1::ber::tag_class::ContextSpecific,
                        asn1::ber::tagging::Explicit,
                        20,
                        2);

    encoder.start_sequence(asn1::ber::tag_class::ContextSpecific,
                           asn1::ber::tagging::Explicit,
                           30);

      encoder.add_integer(asn1::ber::tag_class::ContextSpecific,
                          asn1::ber::tagging::Explicit,
                          300,
                          30);

      encoder.add_integer(asn1::ber::tag_class::ContextSpecific,
                          asn1::ber::tagging::Explicit,
                          310,
                          31);

      encoder.add_integer(asn1::ber::tag_class::ContextSpecific,
                          asn1::ber::tagging::Explicit,
                          320,
                          32);

      encoder.start_sequence(asn1::ber::tag_class::ContextSpecific,
                             asn1::ber::tagging::Explicit,
                             330);

        encoder.add_integer(asn1::ber::tag_class::ContextSpecific,
                            asn1::ber::tagging::Explicit,
                            3300,
                            -330);

        encoder.add_integer(asn1::ber::tag_class::ContextSpecific,
                            asn1::ber::tagging::Explicit,
                            3400,
                            -340);

        encoder.add_bitstring(asn1::ber::tag_class::ContextSpecific,
                              asn1::ber::tagging::Explicit,
                              3500,
                              "ABCD",
                              28,
                              encoder.copy::Shallow);

        encoder.add_utc_time(asn1::ber::tag_class::ContextSpecific,
                             asn1::ber::tagging::Explicit,
                             3600);

        encoder.add_generalized_time(asn1::ber::tag_class::ContextSpecific,
                                     asn1::ber::tagging::Explicit,
                                     3700);

        encoder.add_real(asn1::ber::tag_class::ContextSpecific,
                         asn1::ber::tagging::Explicit,
                         3800,
                         1.23E308);

        encoder.add_utf8_string(asn1::ber::tag_class::ContextSpecific,
                                asn1::ber::tagging::Explicit,
                                3900,
                                "Test",
                                4,
                                encoder.copy::Shallow);

      encoder.end_sequence();

    encoder.end_sequence();

  encoder.end_sequence();

  fhexwriter writer(stdout);

  encoder.encode(writer);

  return 0;
}
