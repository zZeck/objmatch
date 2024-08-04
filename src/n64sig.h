/*

    n64sig
    Signature file generator for n64sym
    shygoo 2020
    License: MIT

*/

#include <gelf.h>
#include <libelf.h>
#include <string.h>

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "signature.h"

#ifndef N64SIG_H
#define N64SIG_H

using n64sig_output_fmt_t = enum { N64SIG_FMT_DEFAULT, N64SIG_FMT_JSON };

class CN64Sig {
  std::vector<const char *> m_LibPaths;

  bool m_bVerbose{false};
  n64sig_output_fmt_t m_OutputFormat{N64SIG_FMT_DEFAULT};
  size_t m_NumProcessedSymbols{0};

  static auto GetRelTypeName(uint8_t relType) -> const char *const;
  static void FormatAnonymousSymbol(char *symbolName);
  void ProcessLibrary(const char *path);
  void ProcessObject(Elf *elf, const char *objectName);
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

 private:
  static void StripAndGetRelocsInSymbol(const char *objectName, std::vector<reloc_entry_t> &relocs, GElf_Sym *symbol, Elf *elf);
  std::map<uint32_t, symbol_entry_t> m_SymbolMap;
};

#endif
