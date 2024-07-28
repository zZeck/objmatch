/*

    Signature file reader for n64sym
    shygoo 2020
    License: MIT

*/

#include "signaturefile.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <fstream>
#include <map>
#include <string>
#include <vector>

#include <boost/crc.hpp>

#include "elfutil.h"

#ifndef min
#define min(a, b) (((a) < (b)) ? (a) : (b))
#endif

CSignatureFile::CSignatureFile() = default;

CSignatureFile::~CSignatureFile() {
  for (auto symbol : m_Symbols) {
    delete symbol.relocs;
  }

  delete[] m_Buffer;
}

auto CSignatureFile::GetNumSymbols() -> size_t { return m_Symbols.size(); }

auto CSignatureFile::GetSymbolSize(size_t nSymbol) -> uint32_t {
  if (nSymbol >= m_Symbols.size()) {
    return 0;
  }

  return m_Symbols[nSymbol].size;
}

auto CSignatureFile::GetSymbolName(size_t nSymbol, char *str, size_t nMaxChars) -> bool {
  if (nSymbol >= m_Symbols.size()) {
    return false;
  }

  strncpy(str, m_Symbols[nSymbol].name, nMaxChars);

  return true;
}

auto CSignatureFile::GetNumRelocs(size_t nSymbol) -> size_t {
  if (nSymbol >= m_Symbols.size() || m_Symbols[nSymbol].relocs == nullptr) {
    return 0;
  }

  return m_Symbols[nSymbol].relocs->size();
}

auto CSignatureFile::GetRelocOffset(size_t nSymbol, size_t nReloc) -> uint32_t {
  if (nSymbol >= m_Symbols.size() || m_Symbols[nSymbol].relocs == nullptr || nReloc >= m_Symbols[nSymbol].relocs->size()) {
    return 0;
  }

  reloc_t const reloc = m_Symbols[nSymbol].relocs->at(nReloc);

  return reloc.offset;
}

auto CSignatureFile::GetRelocType(size_t nSymbol, size_t nReloc) -> uint8_t {
  if (nSymbol >= m_Symbols.size() || m_Symbols[nSymbol].relocs == nullptr || nReloc >= m_Symbols[nSymbol].relocs->size()) {
    return -1;
  }

  reloc_t const reloc = m_Symbols[nSymbol].relocs->at(nReloc);

  return reloc.type;
}

auto CSignatureFile::GetRelocName(size_t nSymbol, size_t nReloc, char *str, size_t nMaxChars) -> bool {
  if (nSymbol >= m_Symbols.size() || m_Symbols[nSymbol].relocs == nullptr || nReloc >= m_Symbols[nSymbol].relocs->size()) {
    return false;
  }

  reloc_t const reloc = m_Symbols[nSymbol].relocs->at(nReloc);

  strncpy(str, reloc.name, nMaxChars);
  return true;
}

void CSignatureFile::ReadStrippedWord(uint8_t *dst, const uint8_t *src, int relType) {
  memcpy(dst, src, 4);

  switch (relType) {
    case 4:
      // targ26
      dst[0] &= 0xFC;
      dst[1] = 0x00;
      dst[2] = 0x00;
      dst[3] = 0x00;
      break;
    case 5:
    case 6:
      // hi/lo16
      dst[2] = 0x00;
      dst[3] = 0x00;
      break;
  }
}

// void debug(const uint8_t *buf, size_t size)
//{
//     printf("\n");
//     for(size_t i = 0; i < size; i++)
//     {
//         printf("%02X ", buf[i]);
//     }
// }

auto CSignatureFile::TestSymbol(size_t nSymbol, const uint8_t *buffer) -> bool {
  if (nSymbol >= m_Symbols.size()) {
    return 0;
  }

  symbol_info_t &symbol = m_Symbols[nSymbol];

  boost::crc_32_type resultA;
  boost::crc_32_type resultB;

  uint32_t crcA = 0;
  uint32_t crcB = 0;

  if (symbol.relocs == nullptr) {
    resultA.process_bytes(buffer, min(symbol.size, 8));
    auto crcA = resultA.checksum();

    if (symbol.crcA != crcA) {
      return false;
    }

    resultB.process_bytes(buffer, symbol.size);
    auto crcB = resultB.checksum();

    return (symbol.crcB == crcB);
  }

  size_t offset = 0;

  auto reloc = symbol.relocs->begin();
  uint32_t const crcA_limit = min(symbol.size, 8);

  //resultA.reset();
  while (offset < crcA_limit && reloc != symbol.relocs->end()) {
    if (offset < reloc->offset) {
      // read up to relocated op or crcA_limit
      resultA.process_bytes(&buffer[offset], min(reloc->offset, crcA_limit) - offset);
      resultB.process_bytes(&buffer[offset], min(reloc->offset, crcA_limit) - offset);

      offset = min(reloc->offset, crcA_limit);
    } else if (offset == reloc->offset) {
      // strip and read relocated op
      uint8_t op[4];
      ReadStrippedWord(op, &buffer[offset], reloc->type);
      resultA.process_bytes(op, 4);
      resultB.process_bytes(op, 4);
      offset += 4;
      reloc++;
    }
  }

  if (offset < crcA_limit) {
    resultA.process_bytes(&buffer[offset], crcA_limit - offset);
    resultB.process_bytes(&buffer[offset], crcA_limit - offset);
    offset = crcA_limit;
  }

  crcA = resultA.checksum();

  if (symbol.crcA != crcA) {
    return false;
  }

  while (offset < symbol.size && reloc != symbol.relocs->end()) {
    if (offset < reloc->offset) {
      // read up to relocated op
      resultB.process_bytes(&buffer[offset], reloc->offset - offset);
      offset = reloc->offset;
    } else if (offset == reloc->offset) {
      // strip and read relocated op
      uint8_t op[4];
      ReadStrippedWord(op, &buffer[offset], reloc->type);
      resultB.process_bytes(op, sizeof(op));
      offset += 4;
      reloc++;
    }
  }

  if (offset < symbol.size) {
    resultB.process_bytes(&buffer[offset], symbol.size - offset);
    offset = symbol.size;
  }

  crcB = resultB.checksum();

  return (symbol.crcB == crcB);
}

auto CSignatureFile::RelocOffsetCompare(const reloc_t &a, const reloc_t &b) -> bool { return a.offset < b.offset; }

void CSignatureFile::SortRelocationsByOffset() {
  for (auto symbol : m_Symbols) {
    if (symbol.relocs != nullptr) {
      std::sort(symbol.relocs->begin(), symbol.relocs->end(), RelocOffsetCompare);
    }
  }
}

auto CSignatureFile::GetRelocationDirectiveValue(const char *str) -> int {
  if (strcmp(".targ26", str) == 0) return R_MIPS_26;
  if (strcmp(".hi16", str) == 0) return R_MIPS_HI16;
  if (strcmp(".lo16", str) == 0) return R_MIPS_LO16;
  return -1;
}

auto CSignatureFile::LoadFromMemory(const char *contents) -> bool {
  if (m_Buffer != nullptr) {
    delete[] m_Buffer;
    m_Buffer = nullptr;
    m_Size = 0;
  }

  m_Size = strlen(contents);
  m_Buffer = new char[m_Size + 1];
  memcpy(m_Buffer, contents, m_Size);
  m_Buffer[m_Size] = '\0';

  Parse();
  SortRelocationsByOffset();

  return true;
}

auto CSignatureFile::Load(const char *path) -> bool {
  if (m_Buffer != nullptr) {
    delete[] m_Buffer;
    m_Buffer = nullptr;
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
  m_Buffer = new char[m_Size];
  file.read(m_Buffer, m_Size);

  Parse();
  SortRelocationsByOffset();

  return true;
}

void CSignatureFile::Parse() {
  const char *token = nullptr;
  while ((token = GetNextToken()) != nullptr) {
  top_level:

    if (token[0] == '.') {
      // relocation directive
      int const relocType = GetRelocationDirectiveValue(token);
      if (relocType == -1) {
        printf("error: invalid relocation directive '%s'\n", token);
        goto errored;
      }

      if (m_Symbols.empty()) {
        printf("error: no symbol defined for this relocation directive\n");
      }

      const char *relName = GetNextToken();

      if (m_Symbols.back().relocs == nullptr) {
        m_Symbols.back().relocs = new std::vector<reloc_t>;
      }

      while ((token = GetNextToken()) != nullptr) {
        uint32_t offset = 0;
        if (!ParseNumber(token, &offset)) {
          goto top_level;
        }

        m_Symbols.back().relocs->push_back({relName, static_cast<uint8_t>(relocType), offset});
      }

      continue;
    }

    if ((isalpha(token[0]) == 0) && token[0] != '_') {
      printf("error: unexpected '%s'\n", token);
      goto errored;
    }

    symbol_info_t symbolInfo;
    symbolInfo.relocs = nullptr;
    symbolInfo.name = token;

    const char *szSize = GetNextToken();
    const char *szCrcA = GetNextToken();
    const char *szCrcB = GetNextToken();

    if (!ParseNumber(szSize, &symbolInfo.size) || !ParseNumber(szCrcA, &symbolInfo.crcA) || !ParseNumber(szCrcB, &symbolInfo.crcB)) {
      printf("error: invalid symbol parameters\n");
      goto errored;
    }

    m_Symbols.push_back(symbolInfo);
  }

errored:;
}

auto CSignatureFile::IsEOF() const -> bool const { return (m_Pos >= m_Size); }

auto CSignatureFile::AtEndOfLine() -> bool {
  while (!IsEOF() && (m_Buffer[m_Pos] == ' ' || m_Buffer[m_Pos] == '\t' || m_Buffer[m_Pos] == '\r')) {
    m_Pos++;
  }

  return (m_Buffer[m_Pos] == '\n' || m_Buffer[m_Pos] == '\0');
}

void CSignatureFile::SkipWhitespace() {
  while (!IsEOF() && (isspace(m_Buffer[m_Pos]) != 0)) {
    m_Pos++;
  }

  while (m_Buffer[m_Pos] == '#') {
    while (!IsEOF() && m_Buffer[m_Pos] != '\n') {
      m_Pos++;
    }

    while (!IsEOF() && (isspace(m_Buffer[m_Pos]) != 0)) {
      m_Pos++;
    }
  }
}

auto CSignatureFile::GetNextToken() -> char * {
  if (IsEOF()) {
    return nullptr;
  }

  SkipWhitespace();

  if (IsEOF()) {
    return nullptr;
  }

  size_t const tokenPos = m_Pos;

  while (!IsEOF() && (isspace(m_Buffer[m_Pos]) == 0)) {
    m_Pos++;
  }

  m_Buffer[m_Pos++] = '\0';

  return &m_Buffer[tokenPos];
}

auto CSignatureFile::ParseNumber(const char *str, uint32_t *result) -> bool {
  char *endp = nullptr;
  *result = strtoull(str, &endp, 0);
  return static_cast<size_t>(endp - str) == strlen(str);
}
