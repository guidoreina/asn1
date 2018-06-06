ASN.1 encoder
=============
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
