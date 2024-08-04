/*

    Signature file reader for n64sym
    shygoo 2020
    License: MIT

*/

#ifndef SIGNATUREFILE_H
#define SIGNATUREFILE_H

#include <cstdint>
#include <vector>

#include <signature.h>

class CSignatureFile {
 private:
  char *m_Buffer{nullptr};
  size_t m_Size{0};
  size_t m_Pos{0};

  std::vector<symbol_entry_t> m_Symbols;

  static auto GetRelocationDirectiveValue(const char *str) -> int;
  static auto RelocOffsetCompare(const reloc_entry_t &a, const reloc_entry_t &b) -> bool;
  static void ReadStrippedWord(uint8_t *dst, const uint8_t *src, int relType);

  void Parse();

 public:
  CSignatureFile();
  ~CSignatureFile();
  auto Load(const char *path) -> bool;
  auto LoadFromMemory(const char *contents) -> bool;
  auto GetNumSymbols() -> size_t;
  auto GetSymbolSize(size_t nSymbol) -> uint32_t;
  auto GetSymbolName(size_t nSymbol, char *str, size_t nMaxChars) -> bool;
  auto TestSymbol(size_t nSymbol, const uint8_t *buffer) -> bool;

  // relocs
  auto GetNumRelocs(size_t nSymbol) -> size_t;
  auto GetRelocName(size_t nSymbol, size_t nReloc, char *str, size_t nMaxChars) -> bool;
  auto GetRelocType(size_t nSymbol, size_t nReloc) -> uint8_t;
  auto GetRelocOffset(size_t nSymbol, size_t nReloc) -> uint32_t;
};

#endif  // SIGNATUREFILE_H
