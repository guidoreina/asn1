#ifndef ASN1_BER_ENCODER_H
#define ASN1_BER_ENCODER_H

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <limits.h>
#include "asn1/ber/tag.h"
#include "asn1/ber/common.h"

namespace asn1 {
  namespace ber {
    template<size_t number_static_values = 128, size_t max_values = ULONG_MAX>
    class encoder {
      static_assert(number_static_values > 1,
                    "The number of static values has to be greater than 1");

      static_assert(max_values >= number_static_values,
                    "The maximum number of values has to be greater or equal "
                    "than the number of static values");

      public:
        enum class copy {
          Shallow,
          Deep
        };

        // Constructor.
        encoder() = default;

        // Destructor.
        ~encoder();

        // Clear.
        void clear();

        // Get current length.
        size_t length() const;

        // Add boolean.
        bool add_boolean(tag_class tc, tagging tg, tag_number tn, bool val);

        // Add integer.
        bool add_integer(tag_class tc, tagging tg, tag_number tn, int64_t val);

        // Add bit string.
        bool add_bitstring(tag_class tc,
                           tagging tg,
                           tag_number tn,
                           const void* val,
                           size_t nbits,
                           copy cp = copy::Deep);

        // Add octet string.
        bool add_octetstring(tag_class tc,
                             tagging tg,
                             tag_number tn,
                             const void* val,
                             size_t len,
                             copy cp = copy::Deep);

        // Add NULL.
        bool add_null(tag_class tc, tagging tg, tag_number tn);

        // Add real.
        bool add_real(tag_class tc, tagging tg, tag_number tn, double val);

        // Add enumerated.
        bool add_enumerated(tag_class tc,
                            tagging tg,
                            tag_number tn,
                            int64_t val);

        // Add UTF-8 string.
        bool add_utf8_string(tag_class tc,
                             tagging tg,
                             tag_number tn,
                             const void* val,
                             size_t len,
                             copy cp = copy::Deep);

        // Start sequence.
        bool start_sequence(tag_class tc, tagging tg, tag_number tn);

        // End sequence.
        bool end_sequence();

        // Start set.
        bool start_set(tag_class tc, tagging tg, tag_number tn);

        // End set.
        bool end_set();

        // Add numeric string.
        bool add_numeric_string(tag_class tc,
                                tagging tg,
                                tag_number tn,
                                const void* val,
                                size_t len,
                                copy cp = copy::Deep);

        // Add printable string.
        bool add_printable_string(tag_class tc,
                                  tagging tg,
                                  tag_number tn,
                                  const void* val,
                                  size_t len,
                                  copy cp = copy::Deep);

        // Add teletex string.
        bool add_teletex_string(tag_class tc,
                                tagging tg,
                                tag_number tn,
                                const void* val,
                                size_t len,
                                copy cp = copy::Deep);

        // Add videotex string.
        bool add_videotex_string(tag_class tc,
                                 tagging tg,
                                 tag_number tn,
                                 const void* val,
                                 size_t len,
                                 copy cp = copy::Deep);

        // Add IA5 string.
        bool add_ia5_string(tag_class tc,
                            tagging tg,
                            tag_number tn,
                            const void* val,
                            size_t len,
                            copy cp = copy::Deep);

        // Add UTC time.
        bool add_utc_time(tag_class tc, tagging tg, tag_number tn);
        bool add_utc_time(tag_class tc, tagging tg, tag_number tn, time_t val);
        bool add_utc_time(tag_class tc,
                          tagging tg,
                          tag_number tn,
                          const struct timeval& val);

        // Add generalized time.
        bool add_generalized_time(tag_class tc, tagging tg, tag_number tn);
        bool add_generalized_time(tag_class tc,
                                  tagging tg,
                                  tag_number tn,
                                  time_t val);

        bool add_generalized_time(tag_class tc,
                                  tagging tg,
                                  tag_number tn,
                                  const struct timeval& val);

        // Add graphic string.
        bool add_graphic_string(tag_class tc,
                                tagging tg,
                                tag_number tn,
                                const void* val,
                                size_t len,
                                copy cp = copy::Deep);

        // Add visible string.
        bool add_visible_string(tag_class tc,
                                tagging tg,
                                tag_number tn,
                                const void* val,
                                size_t len,
                                copy cp = copy::Deep);

        // Add general string.
        bool add_general_string(tag_class tc,
                                tagging tg,
                                tag_number tn,
                                const void* val,
                                size_t len,
                                copy cp = copy::Deep);

        // Add universal string.
        bool add_universal_string(tag_class tc,
                                  tagging tg,
                                  tag_number tn,
                                  const void* val,
                                  size_t len,
                                  copy cp = copy::Deep);

        // Add BMP string.
        bool add_bmp_string(tag_class tc,
                            tagging tg,
                            tag_number tn,
                            const void* val,
                            size_t len,
                            copy cp = copy::Deep);

        // Encode.
        template<typename Writer>
        bool encode(Writer& writer) const;

      private:
        struct value {
          // Universal class.
          universal_class uc;

          enum class type {
            Value,
            ShallowCopy,
            DeepCopy,
            BitstringShallowCopy,
            BitstringDeepCopy,
            Null,
            Constructed,
            ExplicitTag
          };

          // Value type.
          type t;

          // Encoded tag.
          uint8_t tag[11];

          // Length of the encoded tag.
          size_t taglen;

          // Encoded length.
          uint8_t len[9];

          // Length of the encoded length.
          size_t lenlen;

          // Value.
          union {
            void* ptr;

            // Encoded value.
            uint8_t v[19];
          };

          // Length of the value.
          size_t vlen;

          // Bit length (only for bitstrings).
          size_t bitlen;

          // Index of the parent value, -1 if it has no parent.
          ssize_t parent;

          // Get length of the value.
          size_t length() const;

          // Encode.
          template<typename Writer>
          bool encode(Writer& writer) const;
        };

        value _M_static_values[number_static_values];

        value* _M_dynamic_values = nullptr;

        size_t _M_size = number_static_values;
        size_t _M_used = 0;

        ssize_t _M_parent = -1;

        // Add integer.
        bool add_integer(tag_class tc,
                         universal_class uc,
                         tagging tg,
                         tag_number tn,
                         int64_t val);

        // Add octet string.
        bool add_octetstring(tag_class tc,
                             universal_class uc,
                             tagging tg,
                             tag_number tn,
                             const void* val,
                             size_t len,
                             copy cp = copy::Deep);

        // Start constructed.
        bool start_constructed(tag_class tc,
                               universal_class uc,
                               tagging tg,
                               tag_number tn);

        // End constructed.
        bool end_constructed(universal_class uc);

        // Create value.
        struct value* create_value(tag_class tc,
                                   primitive_constructed pc,
                                   universal_class uc,
                                   tagging tg,
                                   tag_number tn);

        // New value.
        struct value* new_value();

        // End value.
        void end_value(struct value* value);

        // Get value.
        const struct value* get(size_t idx) const;
        struct value* get(size_t idx);

        // Disable copy constructor and assignment operator.
        encoder(const encoder&) = delete;
        encoder& operator=(const encoder&) = delete;
    };

    template<size_t number_static_values, size_t max_values>
    inline encoder<number_static_values, max_values>::~encoder()
    {
      clear();

      if (_M_dynamic_values) {
        free(_M_dynamic_values);
      }
    }

    template<size_t number_static_values, size_t max_values>
    inline void encoder<number_static_values, max_values>::clear()
    {
      for (size_t i = 0; i < _M_used; i++) {
        struct value* value = get(i);
        switch (value->t) {
          case value::type::DeepCopy:
          case value::type::BitstringDeepCopy:
            free(value->ptr);
            break;
          default:
            ;
        }
      }

      _M_used = 0;
      _M_parent = -1;
    }

    template<size_t number_static_values, size_t max_values>
    inline size_t encoder<number_static_values, max_values>::length() const
    {
      return (_M_used > 0) ? get(0)->length() : 0;
    }

    template<size_t number_static_values, size_t max_values>
    bool encoder<number_static_values, max_values>::add_boolean(tag_class tc,
                                                                tagging tg,
                                                                tag_number tn,
                                                                bool val)
    {
      struct value* value;
      if ((value = create_value(tc,
                                primitive_constructed::Primitive,
                                universal_class::Boolean,
                                tg,
                                tn)) != nullptr) {
        value->t = value::type::Value;

        value->v[0] = val ? 0xff : 0x00;
        value->vlen = 1;

        end_value(value);

        return true;
      }

      return false;
    }

    template<size_t number_static_values, size_t max_values>
    inline bool
    encoder<number_static_values, max_values>::add_integer(tag_class tc,
                                                           tagging tg,
                                                           tag_number tn,
                                                           int64_t val)
    {
      return add_integer(tc, universal_class::Integer, tg, tn, val);
    }

    template<size_t number_static_values, size_t max_values>
    bool
    encoder<number_static_values, max_values>::add_bitstring(tag_class tc,
                                                             tagging tg,
                                                             tag_number tn,
                                                             const void* val,
                                                             size_t nbits,
                                                             copy cp)
    {
      // Compute length.
      size_t len;
      if ((nbits & 0x07) == 0) {
        len = nbits >> 3;
      } else {
        len = (nbits >> 3) + 1;
      }

      typename value::type type;
      void* ptr;

      if (cp == copy::Shallow) {
        type = value::type::BitstringShallowCopy;
        ptr = const_cast<void*>(val);
      } else {
        if ((ptr = malloc(len)) != nullptr) {
          memcpy(ptr, val, len);
          type = value::type::BitstringDeepCopy;
        } else {
          return false;
        }
      }

      struct value* value;
      if ((value = create_value(tc,
                                primitive_constructed::Primitive,
                                universal_class::Bitstring,
                                tg,
                                tn)) != nullptr) {
        value->t = type;
        value->ptr = ptr;
        value->vlen = 1 + len;
        value->bitlen = nbits;

        end_value(value);

        return true;
      } else {
        if (cp == copy::Deep) {
          free(ptr);
        }
      }

      return false;
    }

    template<size_t number_static_values, size_t max_values>
    inline bool
    encoder<number_static_values, max_values>::add_octetstring(tag_class tc,
                                                               tagging tg,
                                                               tag_number tn,
                                                               const void* val,
                                                               size_t len,
                                                               copy cp)
    {
      return add_octetstring(tc,
                             universal_class::Octetstring,
                             tg,
                             tn,
                             val,
                             len,
                             cp);
    }

    template<size_t number_static_values, size_t max_values>
    bool encoder<number_static_values, max_values>::add_null(tag_class tc,
                                                             tagging tg,
                                                             tag_number tn)
    {
      struct value* value;
      if ((value = create_value(tc,
                                primitive_constructed::Primitive,
                                universal_class::Null,
                                tg,
                                tn)) != nullptr) {
        value->t = value::type::Null;

        value->vlen = 0;

        end_value(value);

        return true;
      }

      return false;
    }

    template<size_t number_static_values, size_t max_values>
    bool encoder<number_static_values, max_values>::add_real(tag_class tc,
                                                             tagging tg,
                                                             tag_number tn,
                                                             double val)
    {
      struct value* value;
      if ((value = create_value(tc,
                                primitive_constructed::Primitive,
                                universal_class::Real,
                                tg,
                                tn)) != nullptr) {
        value->t = value::type::Value;

        value->vlen = encode_real(val, value->v);

        end_value(value);

        return true;
      }

      return false;
    }

    template<size_t number_static_values, size_t max_values>
    inline bool
    encoder<number_static_values, max_values>::add_enumerated(tag_class tc,
                                                              tagging tg,
                                                              tag_number tn,
                                                              int64_t val)
    {
      return add_integer(tc, universal_class::Enumerated, tg, tn, val);
    }

    template<size_t number_static_values, size_t max_values>
    inline bool
    encoder<number_static_values, max_values>::add_utf8_string(tag_class tc,
                                                               tagging tg,
                                                               tag_number tn,
                                                               const void* val,
                                                               size_t len,
                                                               copy cp)
    {
      return add_octetstring(tc,
                             universal_class::UTF8String,
                             tg,
                             tn,
                             val,
                             len,
                             cp);
    }

    template<size_t number_static_values, size_t max_values>
    inline bool
    encoder<number_static_values, max_values>::start_sequence(tag_class tc,
                                                              tagging tg,
                                                              tag_number tn)
    {
      return start_constructed(tc, universal_class::Sequence, tg, tn);
    }

    template<size_t number_static_values, size_t max_values>
    inline bool encoder<number_static_values, max_values>::end_sequence()
    {
      return end_constructed(universal_class::Sequence);
    }

    template<size_t number_static_values, size_t max_values>
    inline bool
    encoder<number_static_values, max_values>::start_set(tag_class tc,
                                                         tagging tg,
                                                         tag_number tn)
    {
      return start_constructed(tc, universal_class::Set, tg, tn);
    }

    template<size_t number_static_values, size_t max_values>
    inline bool encoder<number_static_values, max_values>::end_set()
    {
      return end_constructed(universal_class::Set);
    }

    template<size_t number_static_values, size_t max_values>
    inline bool encoder<number_static_values,
                        max_values>::add_numeric_string(tag_class tc,
                                                        tagging tg,
                                                        tag_number tn,
                                                        const void* val,
                                                        size_t len,
                                                        copy cp)
    {
      return add_octetstring(tc,
                             universal_class::NumericString,
                             tg,
                             tn,
                             val,
                             len,
                             cp);
    }

    template<size_t number_static_values, size_t max_values>
    inline bool encoder<number_static_values,
                        max_values>::add_printable_string(tag_class tc,
                                                          tagging tg,
                                                          tag_number tn,
                                                          const void* val,
                                                          size_t len,
                                                          copy cp)
    {
      return add_octetstring(tc,
                             universal_class::PrintableString,
                             tg,
                             tn,
                             val,
                             len,
                             cp);
    }

    template<size_t number_static_values, size_t max_values>
    inline bool encoder<number_static_values,
                        max_values>::add_teletex_string(tag_class tc,
                                                        tagging tg,
                                                        tag_number tn,
                                                        const void* val,
                                                        size_t len,
                                                        copy cp)
    {
      return add_octetstring(tc,
                             universal_class::TeletexString,
                             tg,
                             tn,
                             val,
                             len,
                             cp);
    }

    template<size_t number_static_values, size_t max_values>
    inline bool encoder<number_static_values,
                        max_values>::add_videotex_string(tag_class tc,
                                                         tagging tg,
                                                         tag_number tn,
                                                         const void* val,
                                                         size_t len,
                                                         copy cp)
    {
      return add_octetstring(tc,
                             universal_class::VideotexString,
                             tg,
                             tn,
                             val,
                             len,
                             cp);
    }

    template<size_t number_static_values, size_t max_values>
    inline bool
    encoder<number_static_values, max_values>::add_ia5_string(tag_class tc,
                                                              tagging tg,
                                                              tag_number tn,
                                                              const void* val,
                                                              size_t len,
                                                              copy cp)
    {
      return add_octetstring(tc,
                             universal_class::IA5String,
                             tg,
                             tn,
                             val,
                             len,
                             cp);
    }

    template<size_t number_static_values, size_t max_values>
    inline bool
    encoder<number_static_values, max_values>::add_utc_time(tag_class tc,
                                                            tagging tg,
                                                            tag_number tn)
    {
      return add_utc_time(tc, tg, tn, time(nullptr));
    }

    template<size_t number_static_values, size_t max_values>
    bool encoder<number_static_values, max_values>::add_utc_time(tag_class tc,
                                                                 tagging tg,
                                                                 tag_number tn,
                                                                 time_t val)
    {
      struct value* value;
      if ((value = create_value(tc,
                                primitive_constructed::Primitive,
                                universal_class::UTCTime,
                                tg,
                                tn)) != nullptr) {
        value->t = value::type::Value;

        value->vlen = encode_utc_time(val, value->v);

        end_value(value);

        return true;
      }

      return false;
    }

    template<size_t number_static_values, size_t max_values>
    inline bool encoder<number_static_values,
                        max_values>::add_utc_time(tag_class tc,
                                                  tagging tg,
                                                  tag_number tn,
                                                  const struct timeval& val)
    {
      return add_utc_time(tc, tg, tn, val.tv_sec);
    }

    template<size_t number_static_values, size_t max_values>
    inline bool encoder<number_static_values,
                        max_values>::add_generalized_time(tag_class tc,
                                                          tagging tg,
                                                          tag_number tn)
    {
      struct timeval tv;
      gettimeofday(&tv, nullptr);

      return add_generalized_time(tc, tg, tn, tv);
    }

    template<size_t number_static_values, size_t max_values>
    inline bool encoder<number_static_values,
                        max_values>::add_generalized_time(tag_class tc,
                                                          tagging tg,
                                                          tag_number tn,
                                                          time_t val)
    {
      struct timeval tv{val, 0};
      return add_generalized_time(tc, tg, tn, tv);
    }

    template<size_t number_static_values, size_t max_values>
    bool encoder<number_static_values,
                 max_values>::add_generalized_time(tag_class tc,
                                                   tagging tg,
                                                   tag_number tn,
                                                   const struct timeval& val)
    {
      struct value* value;
      if ((value = create_value(tc,
                                primitive_constructed::Primitive,
                                universal_class::GeneralizedTime,
                                tg,
                                tn)) != nullptr) {
        value->t = value::type::Value;

        value->vlen = encode_generalized_time(val, value->v);

        end_value(value);

        return true;
      }

      return false;
    }

    template<size_t number_static_values, size_t max_values>
    inline bool encoder<number_static_values,
                        max_values>::add_graphic_string(tag_class tc,
                                                        tagging tg,
                                                        tag_number tn,
                                                        const void* val,
                                                        size_t len,
                                                        copy cp)
    {
      return add_octetstring(tc,
                             universal_class::GraphicString,
                             tg,
                             tn,
                             val,
                             len,
                             cp);
    }

    template<size_t number_static_values, size_t max_values>
    inline bool encoder<number_static_values,
                        max_values>::add_visible_string(tag_class tc,
                                                        tagging tg,
                                                        tag_number tn,
                                                        const void* val,
                                                        size_t len,
                                                        copy cp)
    {
      return add_octetstring(tc,
                             universal_class::VisibleString,
                             tg,
                             tn,
                             val,
                             len,
                             cp);
    }

    template<size_t number_static_values, size_t max_values>
    inline bool encoder<number_static_values,
                        max_values>::add_general_string(tag_class tc,
                                                        tagging tg,
                                                        tag_number tn,
                                                        const void* val,
                                                        size_t len,
                                                        copy cp)
    {
      return add_octetstring(tc,
                             universal_class::GeneralString,
                             tg,
                             tn,
                             val,
                             len,
                             cp);
    }

    template<size_t number_static_values, size_t max_values>
    inline bool encoder<number_static_values,
                        max_values>::add_universal_string(tag_class tc,
                                                          tagging tg,
                                                          tag_number tn,
                                                          const void* val,
                                                          size_t len,
                                                          copy cp)
    {
      return add_octetstring(tc,
                             universal_class::UniversalString,
                             tg,
                             tn,
                             val,
                             len,
                             cp);
    }

    template<size_t number_static_values, size_t max_values>
    inline bool
    encoder<number_static_values, max_values>::add_bmp_string(tag_class tc,
                                                              tagging tg,
                                                              tag_number tn,
                                                              const void* val,
                                                              size_t len,
                                                              copy cp)
    {
      return add_octetstring(tc,
                             universal_class::BMPString,
                             tg,
                             tn,
                             val,
                             len,
                             cp);
    }

    template<size_t number_static_values, size_t max_values>
    template<typename Writer>
    inline
    bool encoder<number_static_values, max_values>::encode(Writer& writer) const
    {
      if (_M_parent == -1) {
        for (size_t i = 0; i < _M_used; i++) {
          if (!get(i)->encode(writer)) {
            return false;
          }
        }

        return true;
      }

      return false;
    }

    template<size_t number_static_values, size_t max_values>
    inline
    size_t encoder<number_static_values, max_values>::value::length() const
    {
      return taglen + lenlen + vlen;
    }

    template<size_t number_static_values, size_t max_values>
    template<typename Writer>
    bool encoder<number_static_values,
                 max_values>::value::encode(Writer& writer) const
    {
      // Write tag.
      if (writer.write(tag, taglen)) {
        // Write length.
        if (writer.write(len, lenlen)) {
          switch (t) {
            case value::type::Value:
              // Write value.
              if (!writer.write(v, vlen)) {
                return false;
              }

              break;
            case value::type::ShallowCopy:
            case value::type::DeepCopy:
              // Write value.
              if (!writer.write(ptr, vlen)) {
                return false;
              }

              break;
            case value::type::BitstringShallowCopy:
            case value::type::BitstringDeepCopy:
              // Write value.
              if ((bitlen & 0x07) == 0) {
                static const uint8_t unused = 0;

                if ((!writer.write(&unused, 1)) ||
                    (!writer.write(ptr, vlen - 1))) {
                  return false;
                }
              } else {
                uint8_t unused = 8 - (bitlen & 0x07);

                if (!writer.write(&unused, 1)) {
                  return false;
                }

                if (vlen > 2) {
                  if (!writer.write(ptr, vlen - 2)) {
                    return false;
                  }
                }

                uint8_t c = static_cast<const uint8_t*>(ptr)[vlen - 2] &
                            (static_cast<uint8_t>(0xff) << unused);

                if (!writer.write(&c, 1)) {
                  return false;
                }
              }

              break;
            case value::type::Null:
            case value::type::Constructed:
            case value::type::ExplicitTag:
              break;
          }
        } else {
          return false;
        }
      } else {
        return false;
      }

      return true;
    }

    template<size_t number_static_values, size_t max_values>
    bool encoder<number_static_values,
                 max_values>::add_integer(tag_class tc,
                                          universal_class uc,
                                          tagging tg,
                                          tag_number tn,
                                          int64_t val)
    {
      struct value* value;
      if ((value = create_value(tc,
                                primitive_constructed::Primitive,
                                uc,
                                tg,
                                tn)) != nullptr) {
        value->t = value::type::Value;

        // Encode integer.
        value->vlen = encode_integer(val, value->v);

        end_value(value);

        return true;
      }

      return false;
    }

    template<size_t number_static_values, size_t max_values>
    bool encoder<number_static_values,
                 max_values>::add_octetstring(tag_class tc,
                                              universal_class uc,
                                              tagging tg,
                                              tag_number tn,
                                              const void* val,
                                              size_t len,
                                              copy cp)
    {
      typename value::type type;
      void* ptr;

      if (cp == copy::Shallow) {
        type = value::type::ShallowCopy;
        ptr = const_cast<void*>(val);
      } else {
        if ((ptr = malloc(len)) != nullptr) {
          memcpy(ptr, val, len);
          type = value::type::DeepCopy;
        } else {
          return false;
        }
      }

      struct value* value;
      if ((value = create_value(tc,
                                primitive_constructed::Primitive,
                                uc,
                                tg,
                                tn)) != nullptr) {
        value->t = type;
        value->ptr = ptr;
        value->vlen = len;

        end_value(value);

        return true;
      } else {
        if (cp == copy::Deep) {
          free(ptr);
        }
      }

      return false;
    }

    template<size_t number_static_values, size_t max_values>
    bool encoder<number_static_values,
                 max_values>::start_constructed(tag_class tc,
                                                universal_class uc,
                                                tagging tg,
                                                tag_number tn)
    {
      struct value* value;
      if ((value = create_value(tc,
                                primitive_constructed::Constructed,
                                uc,
                                tg,
                                tn)) != nullptr) {
        value->t = value::type::Constructed;

        value->vlen = 0;

        // This value is the current parent.
        _M_parent = _M_used - 1;

        return true;
      }

      return false;
    }

    template<size_t number_static_values, size_t max_values>
    bool encoder<number_static_values,
                 max_values>::end_constructed(universal_class uc)
    {
      if (_M_parent != -1) {
        struct value* value = get(_M_parent);

        if (value->uc == uc) {
          _M_parent = value->parent;

          end_value(value);

          return true;
        }
      }

      return false;
    }

    template<size_t number_static_values, size_t max_values>
    struct encoder<number_static_values, max_values>::value*
    encoder<number_static_values,
            max_values>::create_value(tag_class tc,
                                      primitive_constructed pc,
                                      universal_class uc,
                                      tagging tg,
                                      tag_number tn)
    {
      // If either the value will have a parent or it is the first value...
      if ((_M_parent != -1) || (_M_used == 0)) {
        struct value* value;

        // Universal class?
        if (tc == tag_class::Universal) {
          // Create value.
          if ((value = new_value()) != nullptr) {
            // Encode tag.
            value->taglen = encode_tag(tc,
                                       pc,
                                       static_cast<tag_number>(uc),
                                       value->tag);
          } else {
            return nullptr;
          }
        } else if (tn != not_specified) {
          // Create value.
          if ((value = new_value()) != nullptr) {
            // Implicit tagging?
            if (tg == tagging::Implicit) {
              // Encode tag.
              value->taglen = encode_tag(tc, pc, tn, value->tag);
            } else {
              // Create child value.
              struct value* child;
              if ((child = new_value()) != nullptr) {
                value->uc = uc;

                // Value is a explicit tag.
                value->t = value::type::ExplicitTag;

                // Encode tag.
                value->taglen = encode_tag(tc,
                                           primitive_constructed::Constructed,
                                           tn,
                                           value->tag);

                value->vlen = 0;

                value->parent = _M_parent;

                // Make '_M_parent' point to the explicit tag.
                _M_parent = _M_used - 2;

                // Encode child tag.
                child->taglen = encode_tag(tag_class::Universal,
                                           pc,
                                           static_cast<tag_number>(uc),
                                           child->tag);

                value = child;
              } else {
                _M_used--;
                return nullptr;
              }
            }
          } else {
            return nullptr;
          }
        } else {
          return nullptr;
        }

        value->uc = uc;

        value->parent = _M_parent;

        return value;
      }

      return nullptr;
    }

    template<size_t number_static_values, size_t max_values>
    struct encoder<number_static_values, max_values>::value*
    encoder<number_static_values, max_values>::new_value()
    {
      // If there are enough static values...
      if (_M_used < number_static_values) {
        return _M_static_values + _M_used++;
      }

      // If there are enough dynamic values...
      if (_M_used + 1 < _M_size) {
        return _M_dynamic_values + _M_used++ - number_static_values;
      }

      // If the limit has not been reached...
      if (_M_size < max_values) {
        size_t dynsize = _M_size - number_static_values;
        size_t total;

        if (dynsize > 0) {
          size_t tmp;
          if ((tmp = (dynsize * 2)) > dynsize) {
            dynsize = tmp;

            if ((tmp = number_static_values + dynsize) > dynsize) {
              if (tmp <= max_values) {
                total = tmp;
              } else {
                total = max_values;
                dynsize = max_values - number_static_values;
              }
            } else {
              // Overflow.
              return nullptr;
            }
          } else {
            // Overflow.
            return nullptr;
          }
        } else {
          dynsize = number_static_values;
          total = 2 * number_static_values;
        }

        struct value* values;
        if ((values = static_cast<struct value*>(
                        realloc(_M_dynamic_values,
                                dynsize * sizeof(struct value))
                      )) != nullptr) {
          _M_dynamic_values = values;
          _M_size = total;

          return _M_dynamic_values + _M_used++ - number_static_values;
        }
      }

      return nullptr;
    }

    template<size_t number_static_values, size_t max_values>
    void
    encoder<number_static_values, max_values>::end_value(struct value* value)
    {
      // Encode length.
      value->lenlen = encode_length(value->vlen, value->len);

      // If the value has a parent...
      if (value->parent != -1) {
        // Get parent.
        struct value* parent = get(value->parent);

        // Increment parent's value length.
        parent->vlen += value->length();

        // If the parent is a explicit tag...
        if (parent->t == value::type::ExplicitTag) {
          // Encode parent's length.
          parent->lenlen = encode_length(parent->vlen, parent->len);

          // Make '_M_parent' point to the grandparent.
          _M_parent = parent->parent;

          // If the parent has a parent (if there is grandparent)...
          if (_M_parent != -1) {
            // Get grandparent.
            struct value* grandparent = get(_M_parent);

            // Increment grandparent's value length.
            grandparent->vlen += parent->length();
          }
        }
      }
    }

    template<size_t number_static_values, size_t max_values>
    inline const struct encoder<number_static_values, max_values>::value*
    encoder<number_static_values, max_values>::get(size_t idx) const
    {
      return (idx < number_static_values) ?
               &_M_static_values[idx] :
               &_M_dynamic_values[idx - number_static_values];
    }

    template<size_t number_static_values, size_t max_values>
    inline struct encoder<number_static_values, max_values>::value*
    encoder<number_static_values, max_values>::get(size_t idx)
    {
      return (idx < number_static_values) ?
               &_M_static_values[idx] :
               &_M_dynamic_values[idx - number_static_values];
    }
  }
}

#endif // ASN1_BER_ENCODER_H
