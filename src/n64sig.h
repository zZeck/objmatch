/*

    n64sig
    Signature file generator for n64sym
    shygoo 2020
    License: MIT

*/

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "elfutil.h"

#ifndef N64SIG_H
#define N64SIG_H

using n64sig_output_fmt_t = enum { N64SIG_FMT_DEFAULT, N64SIG_FMT_JSON };

class CN64Sig {
  using reloc_entry_t = struct {
    uint8_t relocType;
    char relocSymbolName[128];
    // uint32_t param;
  };

  struct reloc_entry_cmp_t {
    auto operator()(const reloc_entry_t &a, const reloc_entry_t &b) const -> bool const {
      int const t = strcmp(a.relocSymbolName, b.relocSymbolName);
      if (t == 0) {
        return a.relocType < b.relocType;
      }
      return t < 0;
    }
  };

  using reloc_map_t = std::map<reloc_entry_t, std::vector<uint16_t>, reloc_entry_cmp_t>;

  using symbol_entry_t = struct {
    char name[64];
    uint32_t size;
    uint32_t crc_a;
    uint32_t crc_b;
    reloc_map_t *relocs;
  };

  std::map<uint32_t, symbol_entry_t> m_SymbolMap;
  std::vector<const char *> m_LibPaths;

  bool m_bVerbose{false};
  n64sig_output_fmt_t m_OutputFormat{N64SIG_FMT_DEFAULT};
  size_t m_NumProcessedSymbols{0};

  static auto GetRelTypeName(uint8_t relType) -> const char *const;
  static void FormatAnonymousSymbol(char *symbolName);
  static void StripAndGetRelocsInSymbol(const char *objectName, reloc_map_t &relocs, CElfSymbol *symbol, CElfContext &elf);
  void ProcessLibrary(const char *path);
  void ProcessObject(CElfContext &elf, const char *objectName);
  void ProcessObject(const char *path);
  void ProcessFile(const char *path);
  void ScanRecursive(const char *path);

 public:
  CN64Sig();
  ~CN64Sig();

  void AddLibPath(const char *path);
  void SetVerbose(bool bVerbose);
  auto SetOutputFormat(const char *format) -> bool;
  auto Run() -> bool;
};

#endif
