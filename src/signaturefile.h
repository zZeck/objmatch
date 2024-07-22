/*

    Signature file reader for n64sym
    shygoo 2020
    License: MIT

*/

#ifndef SIGNATUREFILE_H
#define SIGNATUREFILE_H

#include <cstdint>
#include <vector>

class CSignatureFile {
 private:
  using reloc_t = struct {
    const char *name;
    uint8_t type;
    uint32_t offset;
  };

  using symbol_info_t = struct {
    const char *name;
    uint32_t size;
    uint32_t crcA;
    uint32_t crcB;
    std::vector<reloc_t> *relocs;
  };

  char *m_Buffer;
  size_t m_Size;
  size_t m_Pos;

  std::vector<symbol_info_t> m_Symbols;

  static auto ParseNumber(const char *str, uint32_t *result) -> bool;
  static auto GetRelocationDirectiveValue(const char *str) -> int;
  static auto RelocOffsetCompare(const reloc_t &a, const reloc_t &b) -> bool;
  static void ReadStrippedWord(uint8_t *dst, const uint8_t *src, int relType);

  void SkipWhitespace();
  auto GetNextToken() -> char *;
  auto AtEndOfLine() -> bool;
  void Parse();
  auto IsEOF() -> bool const;

  void SortRelocationsByOffset();

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
