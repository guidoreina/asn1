#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include "asn1/ber/decoder.h"

class reader {
  public:
    // Constructor.
    reader() = default;

    // Destructor.
    ~reader()
    {
      if (_M_buf != MAP_FAILED) {
        munmap(_M_buf, _M_filesize);
      }

      if (_M_fd != -1) {
        close(_M_fd);
      }
    }

    // Open.
    bool open(const char* filename)
    {
      // If the file exists and is a regular file...
      struct stat sb;
      if ((stat(filename, &sb) == 0) && (S_ISREG(sb.st_mode))) {
        // Open file for reading.
        if ((_M_fd = ::open(filename, O_RDONLY)) != -1) {
          // Map file into memory.
          if ((_M_buf = mmap(nullptr,
                             sb.st_size,
                             PROT_READ,
                             MAP_SHARED,
                             _M_fd,
                             0)) != MAP_FAILED) {
            _M_filesize = sb.st_size;

            _M_ptr = static_cast<const uint8_t*>(_M_buf);
            _M_end = _M_ptr + _M_filesize;

            return true;
          }
        }
      }

      return false;
    }

    // Get character.
    int getc()
    {
      // If the end of file has not been reached...
      if (!eof()) {
        return *_M_ptr++;
      }

      return -1;
    }

    // Read.
    int64_t get(const void*& buf, uint64_t len)
    {
      uint64_t remaining = _M_end - _M_ptr;

      if (remaining < len) {
        len = remaining;
      }

      buf = _M_ptr;
      _M_ptr += len;

      return len;
    }

    // End of file?
    bool eof() const
    {
      return (_M_ptr == _M_end);
    }

    // Get offset.
    size_t offset() const
    {
      return _M_ptr - static_cast<const uint8_t*>(_M_buf);
    }

  private:
    int _M_fd = -1;

    void* _M_buf = MAP_FAILED;

    size_t _M_filesize;

    const uint8_t* _M_ptr;
    const uint8_t* _M_end;

    // Disable copy constructor and assignment operator.
    reader(const reader&) = delete;
    reader& operator=(const reader&) = delete;
};

class asn1_object {
  public:
    // Constructor.
    asn1_object() = default;

    // Destructor.
    ~asn1_object() = default;

    // Set initial offset.
    void initial_offset(size_t offset)
    {
      _M_initial_offset = offset;
    }

    // Start constructed.
    bool start_constructed(asn1::ber::tag_class tc, asn1::ber::tag_number tn)
    {
      indent();

      // Universal class?
      if (tc == asn1::ber::tag_class::Universal) {
        printf("%s: %s\n",
               to_string(tc),
               to_string(static_cast<asn1::ber::universal_class>(tn)));
      } else {
        printf("%s: %lu\n", to_string(tc), tn);
      }

      indent();
      printf("{\n");

      _M_depth++;

      return true;
    }

    // End constructed.
    bool end_constructed(asn1::ber::tag_class tc, asn1::ber::tag_number tn)
    {
      if (_M_depth > 0) {
        _M_depth--;

        indent();
        printf("}\n");

        return true;
      } else {
        fprintf(stderr, "End-of-constructed while having depth 0.\n");
        return false;
      }
    }

    // Boolean.
    bool boolean(const void* buf, uint64_t len, bool val)
    {
      print("Boolean", buf, len, "%s", val ? "true" : "false");

      return true;
    }

    // Integer.
    bool integer(const void* buf, uint64_t len, int64_t val)
    {
      print("Integer", buf, len, "%ld", val);

      return true;
    }

    // Null.
    bool null()
    {
      indent();
      printf("[Null]\n");

      return true;
    }

    // Real.
    bool real(const void* buf, uint64_t len, double val)
    {
      print("Real", buf, len, "%e", val);

      return true;
    }

    // Enumerated.
    bool enumerated(const void* buf, uint64_t len, int64_t val)
    {
      print("Enumerated", buf, len, "%ld", val);

      return true;
    }

    // UTC time.
    bool utc_time(const void* buf, uint64_t len, time_t val)
    {
      struct tm tm;
      gmtime_r(&val, &tm);

      print("UTC time",
            buf,
            len,
            "%04u/%02u/%02u %02u:%02u:%02u",
            1900 + tm.tm_year,
            1 + tm.tm_mon,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec);

      return true;
    }

    // Generalized time.
    bool generalized_time(const void* buf,
                          uint64_t len,
                          const struct timeval& val)
    {
      struct tm tm;
      gmtime_r(&val.tv_sec, &tm);

      print("Generalized time",
            buf,
            len,
            "%04u/%02u/%02u %02u:%02u:%02u.%u",
            1900 + tm.tm_year,
            1 + tm.tm_mon,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec,
            val.tv_usec);

      return true;
    }

    // Primitive.
    bool primitive(asn1::ber::tag_class tc,
                   asn1::ber::tag_number tn,
                   const void* buf,
                   uint64_t len,
                   uint64_t valueoff,
                   uint64_t valuelen)
    {
      // Beginning of the primitive value?
      if (valueoff == 0) {
        indent();

        // Universal class?
        if (tc == asn1::ber::tag_class::Universal) {
          printf("[Primitive] Tag class: %s, tag: %s\n",
                 to_string(tc),
                 to_string(static_cast<asn1::ber::universal_class>(tn)));
        } else {
          printf("[Primitive] Tag class: %s, tag number: %lu\n",
                 to_string(tc),
                 tn);
        }
      } else {
        indent();
        spaces(indent_size);
        printf("=================================================\n");
      }

      indent();
      spaces(indent_size);

      if (len == valuelen) {
        printf("Value:\n");
      } else {
        printf("Value %lu-%lu/%lu:\n",
               valueoff + 1,
               valueoff + len,
               valuelen);
      }

      ascii_dump(buf, len);

      printf("\n");

      indent();
      spaces(indent_size);

      if (len == valuelen) {
        printf("Hexadecimal:\n");
      } else {
        printf("Hexadecimal %lu-%lu/%lu:\n",
               valueoff + 1,
               valueoff + len,
               valuelen);
      }

      hexdump(buf, len);

      return true;
    }

    // Error.
    void error(asn1::ber::error e, uint64_t offset, const char* msg = nullptr)
    {
      if (msg) {
        fprintf(stderr,
                "Error: %s, at offset: %lu, message: '%s'.\n",
                to_string(e),
                _M_initial_offset + offset,
                msg);
      } else {
        fprintf(stderr,
                "Error: %s, at offset: %lu.\n",
                to_string(e),
                _M_initial_offset + offset);
      }
    }

  private:
    static const size_t indent_size = 2;

    static const size_t number_hex_chars_per_line = 16;
    static const size_t
           number_ascii_chars_per_line = (number_hex_chars_per_line * 3) - 1;

    size_t _M_depth = 0;

    size_t _M_initial_offset;

    // Print.
    void print(const char* type,
               const void* buf,
               uint64_t len,
               const char* format,
               ...) const
    {
      indent();
      printf("[%s]\n", type);

      indent();
      spaces(indent_size);
      printf("Value:\n");

      indent();
      spaces(2 * indent_size);

      va_list ap;
      va_start(ap, format);

      vprintf(format, ap);

      va_end(ap);

      printf("\n\n");

      indent();
      spaces(indent_size);
      printf("Hexadecimal:\n");

      hexdump(buf, len);
    }

    // Hexadecimal dump.
    void hexdump(const void* buf, size_t len) const
    {
      const uint8_t* const b = static_cast<const uint8_t*>(buf);

      for (size_t i = 0; i < len; i++) {
        if ((i % number_hex_chars_per_line) == 0) {
          if (i > 0) {
            printf("\n");
          }

          indent();
          spaces(2 * indent_size);

          printf("%02x", b[i]);
        } else {
          printf(" %02x", b[i]);
        }
      }

      printf("\n");
    }

    // ASCII dump.
    void ascii_dump(const void* buf, size_t len) const
    {
      const char* const b = static_cast<const char*>(buf);

      for (size_t i = 0; i < len; i++) {
        if ((i % number_ascii_chars_per_line) == 0) {
          if (i > 0) {
            printf("\n");
          }

          indent();
          spaces(2 * indent_size);
        }

        if (isprint(b[i])) {
          printf("%c", b[i]);
        } else {
          printf(".");
        }
      }

      printf("\n");
    }

    // Indent.
    void indent() const
    {
      spaces(_M_depth * indent_size);
    }

    // Write spaces.
    static void spaces(size_t count)
    {
      for (size_t i = 0; i < count; i++) {
        printf(" ");
      }
    }
};

int main(int argc, const char** argv)
{
  if (argc == 2) {
    reader reader;
    if (reader.open(argv[1])) {
      do {
        asn1_object obj;

        // Set initial offset.
        obj.initial_offset(reader.offset());

        // Decode.
        if (asn1::ber::decoder::decode(reader, obj)) {
          // End of file?
          if (reader.eof()) {
            return 0;
          } else {
            printf("========================================\n");
          }
        } else {
          fprintf(stderr, "Error decoding.\n");
          break;
        }
      } while (true);
    } else {
      fprintf(stderr, "Error opening file '%s'.\n", argv[1]);
    }
  } else {
    fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
  }

  return -1;
}
