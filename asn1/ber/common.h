#ifndef ASN1_BER_COMMON_H
#define ASN1_BER_COMMON_H

#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include "asn1/ber/tag.h"

namespace asn1 {
  namespace ber {
    // Maximum number of object identifier components.
    static constexpr const size_t max_oid_components = 64;

    size_t encode_tag(tag_class tc,
                      primitive_constructed pc,
                      tag_number tn,
                      uint8_t* buf);

    size_t encode_length(size_t len, uint8_t* buf);

    size_t encode_integer(int64_t n, uint8_t* buf);

    size_t encode_real(double n, uint8_t* buf);

    size_t encode_utc_time(time_t t, uint8_t* buf);

    size_t encode_generalized_time(const struct timeval& tv, uint8_t* buf);

    int64_t decode_integer(const void* buf, uint64_t len);

    bool decode_real(const void* buf, uint64_t len, double& n);

    bool decode_utc_time(const void* buf, uint64_t len, time_t& t);

    bool decode_generalized_time(const void* buf,
                                 uint64_t len,
                                 struct timeval& tv);

    bool decode_oid(const void* buf,
                    uint64_t len,
                    uint64_t* oid,
                    size_t& ncomponents);
  }
}

#endif // ASN1_BER_COMMON_H
