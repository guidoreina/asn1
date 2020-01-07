#ifndef ASN1_BER_DECODER_H
#define ASN1_BER_DECODER_H

#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "asn1/ber/tag.h"
#include "asn1/ber/common.h"
#include "asn1/ber/error.h"

namespace asn1 {
  namespace ber {
    class decoder {
      public:
        static const uint64_t indefinite_length = ULLONG_MAX;

        // Constructor.
        decoder() = default;

        // Destructor.
        ~decoder() = default;

        // Decode.
        template<typename Reader, typename ASN1Object, size_t max_depth = 64>
        static bool decode(Reader& reader, ASN1Object& obj);

      private:
        static const uint64_t value_max_len = ULLONG_MAX - 1;

        // Valid universal class?
        static bool valid_universal_class(primitive_constructed pc,
                                          tag_number tn);

        // Valid length?
        static bool valid_length(tag_class tc, tag_number tn, uint64_t len);

        // Primitive.
        template<typename ASN1Object>
        static bool primitive(tag_class tc,
                              tag_number tn,
                              const void* buf,
                              uint64_t len,
                              uint64_t valueoff,
                              uint64_t valuelen,
                              uint64_t offset,
                              ASN1Object& obj);

        struct tag {
          // Reserved?
          bool reserved;

          // Primitive? constructed?
          bool pc[2];

          // Minimum length.
          uint64_t minlen;

          // Maximum length.
          uint64_t maxlen;
        };

        static constexpr const struct tag _M_tags[] = {
        //  reserved     primitive   constructed    minlen    maxlen
           {false,      {true,       false},        0,        0            }, // End-of-contents
           {false,      {true,       false},        1,        1            }, // Boolean
           {false,      {true,       false},        1,        8            }, // Integer
           {false,      {true,       true },        1,        value_max_len}, // Bitstring
           {false,      {true,       true },        0,        value_max_len}, // Octetstring
           {false,      {true,       false},        0,        0            }, // Null
           {false,      {true,       false},        0,        value_max_len}, // Object identifier
           {false,      {true,       true },        0,        value_max_len}, // Object descriptor
           {false,      {false,      true },        0,        value_max_len}, // External
           {false,      {true,       false},        0,        32           }, // Real
           {false,      {true,       false},        1,        8            }, // Enumerated
           {false,      {false,      true },        0,        value_max_len}, // Embedded PDV
           {false,      {true,       true },        0,        value_max_len}, // UTF8String
           {false,      {true,       false},        0,        value_max_len}, // Relative OID
           {true,       {false,      false},        0,        0            }, // Reserved
           {true,       {false,      false},        0,        0            }, // Reserved
           {false,      {false,      true },        0,        value_max_len}, // Sequence
           {false,      {false,      true },        0,        value_max_len}, // Set
           {false,      {true,       true },        0,        value_max_len}, // NumericString
           {false,      {true,       true },        0,        value_max_len}, // PrintableString
           {false,      {true,       true },        0,        value_max_len}, // TeletexString
           {false,      {true,       true },        0,        value_max_len}, // VideotexString
           {false,      {true,       true },        0,        value_max_len}, // IA5String
           {false,      {true,       true },        11,       17           }, // UTCTime
           {false,      {true,       true },        10,       26           }, // GeneralizedTime
           {false,      {true,       true },        0,        value_max_len}, // GraphicString
           {false,      {true,       true },        0,        value_max_len}, // VisibleString
           {false,      {true,       true },        0,        value_max_len}, // GeneralString
           {false,      {true,       true },        0,        value_max_len}, // UniversalString
           {false,      {true,       true },        0,        value_max_len}, // CharacterString
           {false,      {true,       true },        0,        value_max_len}  // BMPString
        };
    };

    template<typename Reader, typename ASN1Object, size_t max_depth>
    bool decoder::decode(Reader& reader, ASN1Object& obj)
    {
      struct value {
        // Tag class.
        tag_class tc;

        // Primitive/Constructed (P/C).
        primitive_constructed pc;

        // Tag number.
        tag_number tn;

        // Length of the value.
        uint64_t valuelen;

        // Total length (header + value).
        uint64_t totallen;

        // Left to be read.
        uint64_t remaining;

        // Start offset.
        uint64_t offset;

        // How much data has been given to the user so far.
        uint64_t valueoff;
      };

      enum class state {
        initial,
        reading_identifier_octets,
        reading_length_octets,
        reading_length_long_form,
        processing_length,
        reading_contents_octets,
        processing_value,
        end_of_value
      };

      value values[max_depth + 1];
      value* v = values;

      state s = state::initial;

      uint64_t offset = 0;

      size_t depth = 0;

      uint8_t buf[32];

      static_assert(sizeof(buf) >= 32,
                    "The size of 'buf' must be greater or equal than 32");

      uint64_t len = 0;

      const void* ptr = nullptr;
      int64_t read = 0;

      do {
        int c;

        switch (s) {
          case state::initial:
            // Get next character.
            if ((c = reader.getc()) >= 0) {
              // Save offset.
              v->offset = offset;

              // Get tag class.
              v->tc = static_cast<tag_class>(
                        (static_cast<uint8_t>(c) >> 6) & 0x03
                      );

              // Get Primitive/Constructed.
              v->pc = static_cast<primitive_constructed>(
                        (static_cast<uint8_t>(c) >> 5) & 0x01
                      );

              // Get tag number.
              if ((v->tn = static_cast<tag_number>(
                             static_cast<uint8_t>(c) & 0x1f
                           )) < 0x1f) {
                // If not the universal class or the universal class tag is
                // valid...
                if ((v->tc != tag_class::Universal) ||
                    (valid_universal_class(v->pc, v->tn))) {
                  s = state::reading_length_octets;
                } else {
                  obj.error(error::invalid_universal_class, offset);
                  return false;
                }
              } else {
                if (v->tc != tag_class::Universal) {
                  v->tn = 0;

                  len = 0;

                  s = state::reading_identifier_octets;
                } else {
                  obj.error(error::invalid_universal_class,
                            offset,
                            "invalid tag number");

                  return false;
                }
              }

              offset++;
            } else {
              obj.error(error::unexpected_eof,
                        offset,
                        "unexpected end-of-file while parsing identifier "
                        "octets");

              return false;
            }

            break;
          case state::reading_identifier_octets:
            // Get next character.
            if ((c = reader.getc()) >= 0) {
              // If the tag number is not too big...
              if (len < 10) {
                v->tn |= (static_cast<uint8_t>(c) & 0x7f);

                // If the most significant bit is not set...
                if ((static_cast<uint8_t>(c) & 0x80) == 0) {
                  s = state::reading_length_octets;
                } else {
                  v->tn <<= 7;

                  len++;
                }
              } else {
                if (static_cast<uint8_t>(c) <= 1) {
                  v->tn |= static_cast<uint8_t>(c);

                  s = state::reading_length_octets;
                } else {
                  obj.error(error::invalid_tag_number,
                            offset,
                            "tag number is too big");

                  return false;
                }
              }

              offset++;
            } else {
              obj.error(error::unexpected_eof,
                        offset,
                        "unexpected end-of-file while parsing tag number");

              return false;
            }

            break;
          case state::reading_length_octets:
            // Get next character.
            if ((c = reader.getc()) >= 0) {
              // If the most significant bit is not set...
              if ((static_cast<uint8_t>(c) & 0x80) == 0) {
                // Short form.
                v->valuelen = static_cast<uint8_t>(c);

                s = state::processing_length;
              } else {
                // Long form (the most significant bit is set).
                switch (len = static_cast<uint8_t>(c) & 0x7f) {
                  case 1:
                  case 2:
                  case 3:
                  case 4:
                  case 5:
                  case 6:
                  case 7:
                  case 8:
                    v->valuelen = 0;

                    s = state::reading_length_long_form;

                    break;
                  case 0:
                    // Indefinite form.
                    if (v->pc == primitive_constructed::Constructed) {
                      // If the maximum depth has not been exceeded...
                      if (++depth <= max_depth) {
                        // Start constructed.
                        if (obj.start_constructed(v->tc,
                                                  v->tn,
                                                  indefinite_length,
                                                  0)) {
                          v->valuelen = indefinite_length;

                          v++;

                          s = state::initial;
                        } else {
                          obj.error(error::callback, offset);
                          return false;
                        }
                      } else {
                        obj.error(error::max_depth_exceeded, offset);
                        return false;
                      }
                    } else {
                      obj.error(error::invalid_length,
                                offset,
                                "indefinite form not allowed for primitive "
                                "types");

                      return false;
                    }

                    break;
                  case 0xff:
                    obj.error(error::invalid_length, offset);
                    return false;
                  default:
                    obj.error(error::invalid_length,
                              offset,
                              "length is too big");

                    return false;
                }
              }

              offset++;
            } else {
              obj.error(error::unexpected_eof,
                        offset,
                        "unexpected end-of-file while parsing tag length");

              return false;
            }

            break;
          case state::reading_length_long_form:
            // Get next character.
            if ((c = reader.getc()) >= 0) {
              if (--len > 0) {
                v->valuelen |= (static_cast<uint64_t>(c) << (len << 3));
              } else {
                v->valuelen |= static_cast<uint64_t>(c);

                s = state::processing_length;
              }

              offset++;
            } else {
              obj.error(error::unexpected_eof,
                        offset,
                        "unexpected end-of-file while parsing tag length");

              return false;
            }

            break;
          case state::processing_length:
            // If the length is valid...
            if (valid_length(v->tc, v->tn, v->valuelen)) {
              // Compute total length.
              v->totallen = (offset - v->offset) + v->valuelen;

              v->valueoff = 0;

              // If there is value...
              if (v->valuelen > 0) {
                // Primitive?
                if (v->pc == primitive_constructed::Primitive) {
                  v->remaining = v->valuelen;

                  len = 0;

                  s = state::reading_contents_octets;
                } else {
                  // If the maximum depth has not been exceeded...
                  if (++depth <= max_depth) {
                    if (obj.start_constructed(v->tc,
                                              v->tn,
                                              v->valuelen,
                                              v->totallen)) {
                      v++;

                      s = state::initial;
                    } else {
                      obj.error(error::callback, offset);
                      return false;
                    }
                  } else {
                    obj.error(error::max_depth_exceeded, offset);
                    return false;
                  }
                }
              } else {
                // Primitive?
                if (v->pc == primitive_constructed::Primitive) {
                  len = 0;

                  ptr = "";
                  read = 0;

                  s = state::processing_value;
                } else {
                  if ((obj.start_constructed(v->tc,
                                             v->tn,
                                             v->valuelen,
                                             v->totallen)) &&
                      (obj.end_constructed(v->tc, v->tn, v->totallen))) {
                    s = state::end_of_value;
                  } else {
                    obj.error(error::callback, offset);
                    return false;
                  }
                }
              }
            } else {
              obj.error(error::invalid_length, offset);
              return false;
            }

            break;
          case state::reading_contents_octets:
            // Read value.
            if ((read = reader.get(ptr, v->remaining)) > 0) {
              // If we have read the remaining data...
              if ((v->remaining -= read) == 0) {
                s = state::processing_value;
              } else {
                // Compute space left in the buffer.
                uint64_t left = sizeof(buf) - len;

                // If what we have read fits in the buffer and there is space
                // left...
                if (static_cast<uint64_t>(read) < left) {
                  // Append read data to the buffer.
                  memcpy(buf + len, ptr, read);

                  len += read;
                } else {
                  // If the buffer is empty...
                  if (len == 0) {
                    // Give data to the user.
                    if (primitive(v->tc,
                                  v->tn,
                                  ptr,
                                  read,
                                  v->valueoff,
                                  v->valuelen,
                                  offset,
                                  obj)) {
                      v->valueoff += read;
                    } else {
                      return false;
                    }
                  } else {
                    // Fill buffer with the read data.
                    memcpy(buf + len, ptr, left);

                    // Give data to the user.
                    if (primitive(v->tc,
                                  v->tn,
                                  buf,
                                  sizeof(buf),
                                  v->valueoff,
                                  v->valuelen,
                                  offset,
                                  obj)) {
                      v->valueoff += sizeof(buf);

                      // If there is remaining data...
                      if ((read -= left) > 0) {
                        ptr = static_cast<const uint8_t*>(ptr) + left;

                        // If the remaining data fits in the buffer and there is
                        // space left...
                        if (static_cast<uint64_t>(read) < sizeof(buf)) {
                          // Copy remaining data to the buffer.
                          memcpy(buf, ptr, read);

                          len = read;
                        } else {
                          // Give remaining data to the user.
                          if (primitive(v->tc,
                                        v->tn,
                                        ptr,
                                        read,
                                        v->valueoff,
                                        v->valuelen,
                                        offset,
                                        obj)) {
                            v->valueoff += read;

                            len = 0;
                          } else {
                            return false;
                          }
                        }
                      } else {
                        len = 0;
                      }
                    } else {
                      return false;
                    }
                  }
                }
              }
            } else {
              obj.error(error::unexpected_eof,
                        offset,
                        "unexpected end-of-file while reading contents "
                        "octets");

              return false;
            }

            break;
          case state::processing_value:
            // Increment offset.
            offset += v->valuelen;

            // If the value would fit in the buffer...
            if (len + static_cast<uint64_t>(read) <= sizeof(buf)) {
              // If the buffer is not empty...
              if (len > 0) {
                memcpy(buf + len, ptr, read);

                ptr = buf;
                read += len;
              }

              // Universal class?
              if (v->tc == tag_class::Universal) {
                switch (static_cast<universal_class>(v->tn)) {
                  case universal_class::EndOfContents:
                    if (depth > 0) {
                      v--;

                      if (v->valuelen == indefinite_length) {
                        // Compute length of the TLV.
                        v->totallen = offset - v->offset;

                        if (obj.end_constructed(v->tc, v->tn, v->totallen)) {
                          depth--;
                        } else {
                          obj.error(error::callback, offset);
                          return false;
                        }
                      } else {
                        obj.error(error::unexpected_end_of_contents,
                                  offset - 2);

                        return false;
                      }
                    } else {
                      obj.error(error::unexpected_end_of_contents,
                                offset - 2);

                      return false;
                    }

                    break;
                  case universal_class::Boolean:
                    // Give data to the user.
                    if (!obj.boolean(ptr,
                                     v->valuelen,
                                     *static_cast<const uint8_t*>(ptr) != 0)) {
                      obj.error(error::callback, offset);
                      return false;
                    }

                    break;
                  case universal_class::Integer:
                    // Give data to the user.
                    if (!obj.integer(ptr,
                                     v->valuelen,
                                     decode_integer(ptr, v->valuelen))) {
                      obj.error(error::callback, offset);
                      return false;
                    }

                    break;
                  case universal_class::Null:
                    // Give data to the user.
                    if (!obj.null()) {
                      obj.error(error::callback, offset);
                      return false;
                    }

                    break;
                  case universal_class::ObjectIdentifier:
                    {
                      // Decode object identifier.
                      uint64_t oid[max_oid_components];
                      size_t ncomponents;
                      if (decode_oid(ptr, v->valuelen, oid, ncomponents)) {
                        // Give data to the user.
                        if (!obj.oid(ptr, v->valuelen, oid, ncomponents)) {
                          obj.error(error::callback, offset);
                          return false;
                        }
                      } else {
                        obj.error(error::invalid_value,
                                  offset - v->valuelen,
                                  "invalid oid");

                        return false;
                      }
                    }

                    break;
                  case universal_class::Real:
                    {
                      // Decode real.
                      double d;
                      if (decode_real(ptr, v->valuelen, d)) {
                        // Give data to the user.
                        if (!obj.real(ptr, v->valuelen, d)) {
                          obj.error(error::callback, offset);
                          return false;
                        }
                      } else {
                        obj.error(error::invalid_value,
                                  offset - v->valuelen,
                                  "invalid real");

                        return false;
                      }
                    }

                    break;
                  case universal_class::Enumerated:
                    // Give data to the user.
                    if (!obj.enumerated(ptr,
                                        v->valuelen,
                                        decode_integer(ptr, v->valuelen))) {
                      obj.error(error::callback, offset);
                      return false;
                    }

                    break;
                  case universal_class::UTCTime:
                    {
                      // Decode UTC time.
                      time_t t;
                      if (decode_utc_time(ptr, v->valuelen, t)) {
                        // Give data to the user.
                        if (!obj.utc_time(ptr, v->valuelen, t)) {
                          obj.error(error::callback, offset);
                          return false;
                        }
                      } else {
                        obj.error(error::invalid_value,
                                  offset - v->valuelen,
                                  "invalid UTC time");

                        return false;
                      }
                    }

                    break;
                  case universal_class::GeneralizedTime:
                    {
                      // Decode generalized time.
                      struct timeval tv;
                      if (decode_generalized_time(ptr, v->valuelen, tv)) {
                        // Give data to the user.
                        if (!obj.generalized_time(ptr, v->valuelen, tv)) {
                          obj.error(error::callback, offset);
                          return false;
                        }
                      } else {
                        obj.error(error::invalid_value,
                                  offset - v->valuelen,
                                  "invalid generalized time");

                        return false;
                      }
                    }

                    break;
                  default:
                    // Give data to the user.
                    if (!primitive(v->tc,
                                   v->tn,
                                   ptr,
                                   read,
                                   v->valueoff,
                                   v->valuelen,
                                   offset,
                                   obj)) {
                      return false;
                    }
                }
              } else {
                // Give data to the user.
                if (!primitive(v->tc,
                               v->tn,
                               ptr,
                               read,
                               v->valueoff,
                               v->valuelen,
                               offset,
                               obj)) {
                  return false;
                }
              }
            } else {
              // If the buffer is empty...
              if (len == 0) {
                // Give data to the user.
                if (!primitive(v->tc,
                               v->tn,
                               ptr,
                               read,
                               v->valueoff,
                               v->valuelen,
                               offset,
                               obj)) {
                  return false;
                }
              } else {
                // Compute space left in the buffer.
                uint64_t left = sizeof(buf) - len;

                // Append read data to the buffer.
                memcpy(buf + len, ptr, left);

                // Give data to the user.
                if (primitive(v->tc,
                              v->tn,
                              buf,
                              sizeof(buf),
                              v->valueoff,
                              v->valuelen,
                              offset,
                              obj)) {
                  v->valueoff += sizeof(buf);

                  ptr = static_cast<const uint8_t*>(ptr) + left;
                  read -= left;

                  // Give remaining data to the user.
                  if (!primitive(v->tc,
                                 v->tn,
                                 ptr,
                                 read,
                                 v->valueoff,
                                 v->valuelen,
                                 offset,
                                 obj)) {
                    return false;
                  }
                } else {
                  return false;
                }
              }
            }

            // Fall through.
          case state::end_of_value:
            do {
              if (depth > 0) {
                // Save length of the TLV.
                len = v->totallen;

                v--;

                if (v->valuelen != indefinite_length) {
                  if (len < v->valuelen) {
                    v->valuelen -= len;

                    v++;

                    s = state::initial;

                    break;
                  } else if (len == v->valuelen) {
                    if (obj.end_constructed(v->tc, v->tn, v->totallen)) {
                      depth--;
                    } else {
                      obj.error(error::callback, offset);
                      return false;
                    }
                  } else {
                    obj.error(error::invalid_length, offset);
                    return false;
                  }
                } else {
                  v++;

                  s = state::initial;

                  break;
                }
              } else {
                return true;
              }
            } while (true);

            break;
        }
      } while (true);
    }

    inline bool decoder::valid_universal_class(primitive_constructed pc,
                                               tag_number tn)
    {
      return ((!_M_tags[tn].reserved) &&
              (_M_tags[tn].pc[static_cast<uint8_t>(pc)]));
    }

    inline bool decoder::valid_length(tag_class tc, tag_number tn, uint64_t len)
    {
      if (tc == tag_class::Universal) {
        return ((len >= _M_tags[tn].minlen) && (len <= _M_tags[tn].maxlen));
      } else {
        return (len <= value_max_len);
      }
    }

    template<typename ASN1Object>
    inline bool decoder::primitive(tag_class tc,
                                   tag_number tn,
                                   const void* buf,
                                   uint64_t len,
                                   uint64_t valueoff,
                                   uint64_t valuelen,
                                   uint64_t offset,
                                   ASN1Object& obj)
    {
      if (valueoff == 0) {
        if (tc == tag_class::Universal) {
          if (static_cast<universal_class>(tn) == universal_class::Bitstring) {
            if ((*static_cast<const uint8_t*>(buf) > 7) ||
                ((valuelen == 1) && (*static_cast<const uint8_t*>(buf) != 0))) {
              obj.error(error::invalid_value,
                        offset - valuelen,
                        "invalid bitstring");

              return false;
            }
          }
        }
      }

      if (obj.primitive(tc, tn, buf, len, valueoff, valuelen)) {
        return true;
      } else {
        obj.error(error::callback, offset);
        return false;
      }
    }
  }
}

#endif // ASN1_BER_DECODER_H
