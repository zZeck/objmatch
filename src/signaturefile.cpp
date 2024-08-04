/*

    Signature file reader for n64sym
    shygoo 2020
    License: MIT

*/

#include "signaturefile.h"
#include "signature.h"

#include <elf.h>
#include <yaml-cpp/yaml.h>

#include <algorithm>
#include <boost/crc.hpp>
#include <cctype>
#include <cstring>
#include <fstream>
#include <map>
#include <string>
#include <vector>

CSignatureFile::CSignatureFile() = default;

CSignatureFile::~CSignatureFile() {
  /*for (auto symbol : m_Symbols) {
    delete symbol.relocs;
  }*/

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
  if (nSymbol >= m_Symbols.size()) {
    return 0;
  }

  return m_Symbols[nSymbol].relocs.size();
}

auto CSignatureFile::GetRelocOffset(size_t nSymbol, size_t nReloc) -> uint32_t {
  if (nSymbol >= m_Symbols.size() || nReloc >= m_Symbols[nSymbol].relocs.size()) {
    return 0;
  }

  reloc_entry_t const reloc = m_Symbols[nSymbol].relocs.at(nReloc);

  return reloc.offset;
}

auto CSignatureFile::GetRelocType(size_t nSymbol, size_t nReloc) -> uint8_t {
  if (nSymbol >= m_Symbols.size() || nReloc >= m_Symbols[nSymbol].relocs.size()) {
    return -1;
  }

  reloc_entry_t const reloc = m_Symbols[nSymbol].relocs.at(nReloc);

  return reloc.type;
}

auto CSignatureFile::GetRelocName(size_t nSymbol, size_t nReloc, char *str, size_t nMaxChars) -> bool {
  if (nSymbol >= m_Symbols.size() || nReloc >= m_Symbols[nSymbol].relocs.size()) {
    return false;
  }

  reloc_entry_t const reloc = m_Symbols[nSymbol].relocs.at(nReloc);

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

auto CSignatureFile::TestSymbol(size_t nSymbol, const uint8_t *buffer) -> bool {
  if (nSymbol >= m_Symbols.size()) {
    return 0;
  }

  symbol_entry_t &symbol = m_Symbols[nSymbol];

  boost::crc_32_type resultA;
  boost::crc_32_type resultB;

  uint32_t crcA = 0;
  uint32_t crcB = 0;

  if (symbol.relocs.size() == 0) {
    resultA.process_bytes(buffer, std::min(symbol.size, 8U));
    auto crcA = resultA.checksum();

    if (symbol.crc_a != crcA) {
      return false;
    }

    resultB.process_bytes(buffer, symbol.size);
    auto crcB = resultB.checksum();

    return (symbol.crc_b == crcB);
  }

  size_t offset = 0;

  auto reloc = symbol.relocs.begin();
  uint32_t const crcA_limit = std::min(symbol.size, 8U);

  // resultA.reset();
  while (offset < crcA_limit && reloc != symbol.relocs.end()) {
    if (offset < reloc->offset) {
      // read up to relocated op or crcA_limit
      resultA.process_bytes(&buffer[offset], std::min(reloc->offset, crcA_limit) - offset);
      resultB.process_bytes(&buffer[offset], std::min(reloc->offset, crcA_limit) - offset);

      offset = std::min(reloc->offset, crcA_limit);
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

  if (symbol.crc_a != crcA) {
    return false;
  }

  while (offset < symbol.size && reloc != symbol.relocs.end()) {
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

  return (symbol.crc_b == crcB);
}

auto CSignatureFile::RelocOffsetCompare(const reloc_entry_t &a, const reloc_entry_t &b) -> bool { return a.offset < b.offset; }

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

  return true;
}

void CSignatureFile::Parse() {
  YAML::Node node = YAML::Load(m_Buffer);
  m_Symbols = node.as<std::vector<symbol_entry_t>>();
}
