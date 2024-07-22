/*

    arutil

    Basic GNU *.a reader utility
    shygoo 2018, 2020
    License: MIT

    https://en.wikipedia.org/wiki/Ar_(Unix)

*/

#include "arutil.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <fstream>

auto CArReader::ArTrimIdentifier(char* str) -> char* {
  char* org = str;

  while (*str != '\n' && *str != '\0' && *str != '/') {
    str++;
  }
  *str = '\0';

  return org;
}

CArReader::CArReader() : m_CurRealIdentifier(nullptr), m_ExIdentifierBlock(nullptr), m_CurBlock(nullptr), m_CurBlockSize(0), m_Buffer(nullptr), m_Size(0), m_CurPos(0) {}

CArReader::~CArReader() {
  if (m_Buffer != nullptr) {
    delete[] m_Buffer;
  }
}

auto CArReader::Load(const char* path) -> bool {
  if (m_Buffer != nullptr) {
    delete[] m_Buffer;
    m_CurPos = 0;
    m_Size = 0;
  }

  std::ifstream file;
  file.open(path, std::ifstream::binary);

  if (!file.is_open()) {
    return false;
  }

  file.seekg(0, std::ifstream::end);
  m_Size = file.tellg();

  file.seekg(0, std::ifstream::beg);
  m_Buffer = new uint8_t[m_Size];
  file.read(reinterpret_cast<char*>(m_Buffer), m_Size);

  if (memcmp(AR_FILE_SIG, m_Buffer, AR_FILE_SIG_LEN) == 0) {
    m_CurPos += 8;
  } else {
    m_Buffer = nullptr;
    m_CurPos = 0;
    m_Size = 0;
    delete[] m_Buffer;
    return false;
  }

  return true;
}

auto CArReader::SeekNextBlock() -> bool {
  if (m_CurPos >= m_Size) {
    return false;  // EOF
  }

  auto* header = reinterpret_cast<ar_header_t*>(m_Buffer + m_CurPos);

  m_CurPos += sizeof(ar_header_t);

  size_t const blockSize = atoll(header->szSize);

  if (header->szIdentifier[0] == '/') {
    if (header->szIdentifier[1] == '/') {
      // extended identifier block
      m_ExIdentifierBlock = reinterpret_cast<char*>(&m_Buffer[m_CurPos]);
      m_CurPos += blockSize;
      SeekNextBlock();
      return true;
    }

    if (header->szIdentifier[1] == ' ') {
      // symbol reference block, skip
      m_CurPos += blockSize;
      SeekNextBlock();
      return true;
    }

    // block uses extended identifier
    size_t const exIdentifierOffset = atoll(&header->szIdentifier[1]);
    m_CurRealIdentifier = ArTrimIdentifier(&m_ExIdentifierBlock[exIdentifierOffset]);
  } else {
    m_CurRealIdentifier = ArTrimIdentifier(header->szIdentifier);
  }

  m_CurBlock = &m_Buffer[m_CurPos];
  m_CurBlockSize = blockSize;
  m_CurPos += blockSize;

  if (m_CurPos % 2 != 0) {
    m_CurPos++;
  }
  return true;
}

auto CArReader::GetBlockIdentifier() -> const char* const  { return m_CurRealIdentifier; }

auto CArReader::GetBlockData() -> uint8_t* { return m_CurBlock; }

auto CArReader::GetBlockSize() -> size_t const { return m_CurBlockSize; }
