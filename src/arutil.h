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
#define AR_FILE_SIG_LEN 8

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

  char* m_CurRealIdentifier;
  char* m_ExIdentifierBlock;
  uint8_t* m_CurBlock;
  size_t m_CurBlockSize;

  uint8_t* m_Buffer;
  size_t m_Size;
  size_t m_CurPos;

  static auto ArTrimIdentifier(char* str) -> char*;

 public:
  CArReader();
  ~CArReader();

  auto Load(const char* path) -> bool;

  auto SeekNextBlock() -> bool;
  auto GetBlockIdentifier() -> const char* const;
  auto GetBlockData() -> uint8_t*;
  auto GetBlockSize() -> size_t const;
};

#endif  // ARUTIL_H
