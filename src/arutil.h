/*

    arutil

    Basic GNU *.a reader utility
    shygoo 2018, 2020
    License: MIT

    https://en.wikipedia.org/wiki/Ar_(Unix)

*/

#ifndef ARUTIL_H
#define ARUTIL_H

#include <cstdint>
#include <cstdlib>

#define AR_FILE_SIG "!<arch>\n"
enum {
AR_FILE_SIG_LEN = 8
};

class CArReader {
  using ar_header_t = struct {
    char szIdentifier[16];
    char szTimestamp[12];
    char szOwnerId[6];
    char szGroupId[6];
    char szFileMode[8];
    char szSize[10];
    char szEndChar[2];
  };

  char* m_CurRealIdentifier{nullptr};
  char* m_ExIdentifierBlock{nullptr};
  uint8_t* m_CurBlock{nullptr};
  size_t m_CurBlockSize{0};

  uint8_t* m_Buffer{nullptr};
  size_t m_Size{0};
  size_t m_CurPos{0};

  static auto ArTrimIdentifier(char* str) -> char*;

 public:
  CArReader();
  ~CArReader();

  auto Load(const char* path) -> bool;

  auto SeekNextBlock() -> bool;
  auto GetBlockIdentifier() -> const char* const;
  auto GetBlockData() -> uint8_t*;
  [[nodiscard]] auto GetBlockSize() const -> size_t const;
};

#endif  // ARUTIL_H
