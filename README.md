ASN.1 encoder and decoder
=========================
# Encoder
The ASN.1 encoder class is a template class with two parameters:

* `number_static_values`: values to be encoded are stored first in a static array of `number_static_values` elements. When more values have to be encoded, they are dynamically allocated.
* `max_values`: maximum number of values allowed to be encoded (static + dynamic).

String values can be added either as a deep-copy (a buffer is allocated to hold the user data) or as a shallow-copy (a pointer to the user data is used).

The following data values are supported:

* boolean
* integer
* bitstring
* octetstring
* null
* real
* enumerated
* UTF8String
* sequence
* set
* NumericString
* PrintableString
* TeletexString
* VideotexString
* IA5String
* UTCTime
* GeneralizedTime
* GraphicString
* VisibleString
* GeneralString
* UniversalString
* BMPString

(The string values are not checked, they are expected to be in the right format)


# Decoder
The ASN.1 decoder class has the method `decode()` to decode ASN.1.

It receives two parameters:

* `reader`: template object which must have the following methods:
  * `int getc()`: to read the next character.
  * `int64_t get(const void*& buf, uint64_t len)`: to read up to `len` bytes (data is not copied, a reference is returned).
* `obj`: template object which must have the following methods:
  * `bool start_constructed(asn1::ber::tag_class tc, asn1::ber::tag_number tn)`: start of a constructed.
  * `bool end_constructed(asn1::ber::tag_class tc, asn1::ber::tag_number tn)`: end of a constructed.
  * `bool boolean(const void* buf, uint64_t len, bool val)`: boolean value.
  * `bool integer(const void* buf, uint64_t len, int64_t val)`: integer value.
  * `bool null()`: null value.
  * `bool real(const void* buf, uint64_t len, double val)`: real value.
  * `bool enumerated(const void* buf, uint64_t len, int64_t val)`: enumerated value.
  * `bool utc_time(const void* buf, uint64_t len, time_t val)`: UTCTime value.
  * `bool generalized_time(const void* buf, uint64_t len, const struct timeval& val)`: GeneralizedTime value.
  * `bool primitive(asn1::ber::tag_class tc, asn1::ber::tag_number tn, const void* buf, uint64_t len, uint64_t valueoff, uint64_t valuelen)`: primitive value.
  * `void error(asn1::ber::error e, uint64_t offset, const char* msg = nullptr)`: an error has occurred.
