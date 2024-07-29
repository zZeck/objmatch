/*

    n64sym
    Symbol identifier tool for N64 games
    shygoo 2017, 2020
    License: MIT

*/

#ifndef N64SYM_H
#define N64SYM_H

#include <algorithm>
#include <array>
#include <cstdarg>
#include <cstdlib>
#include <fstream>
#include <set>
#include <vector>

#include "elfutil.h"
#include "signaturefile.h"
#include "threadpool.h"

using n64sym_output_fmt_t = enum { N64SYM_FMT_DEFAULT, N64SYM_FMT_PJ64, N64SYM_FMT_NEMU, N64SYM_FMT_ARMIPS, N64SYM_FMT_N64SPLIT, N64SYM_FMT_SPLAT };

class CN64Sym {
 public:
  CN64Sym();
  ~CN64Sym();
  auto LoadBinary(const char* binPath) -> bool;
  void AddLibPath(const char* libPath);
  void UseBuiltinSignatures(bool bUseBuiltinSignatures);
  void SetVerbose(bool bVerbose);
  void SetThoroughScan(bool bThorough);
  auto SetOutputFormat(const char* fmtName) -> bool;
  void SetHeaderSize(uint32_t headerSize);
  auto SetOutputPath(const char* path) -> bool;
  auto Run() -> bool;
  void DumpResults();

 private:
  using n64sym_fmt_lut_t = struct {
    const char* name;
    n64sym_output_fmt_t fmt;
  };

  static constexpr std::array<n64sym_fmt_lut_t, 6> FormatNames = {{
    { .name = "default", .fmt = N64SYM_FMT_DEFAULT},
    { .name = "pj64", .fmt = N64SYM_FMT_PJ64},
    { .name = "nemu", .fmt = N64SYM_FMT_NEMU},
    { .name = "armips", .fmt = N64SYM_FMT_ARMIPS},
    { .name = "n64split", .fmt = N64SYM_FMT_N64SPLIT},
    { .name = "splat", .fmt = N64SYM_FMT_SPLAT}
  }};

  using obj_processing_context_t = struct {
    CN64Sym* mt_this;
    const char* libraryPath;
    const char* blockIdentifier;
    uint8_t* blockData;
    size_t blockSize;
  };

  using search_result_t = struct {
    uint32_t address;  // from jump target
    uint32_t size;     // data match size
    char name[64];
  };

  using partial_match_t = struct {
    uint32_t address;
    int nBytesMatched;
  };

  CThreadPool m_ThreadPool;

  uint8_t* m_Binary{nullptr};
  size_t m_BinarySize{0};
  uint32_t m_HeaderSize{0x80000000};

  bool m_bVerbose{false};
  bool m_bUseBuiltinSignatures{false};
  bool m_bThoroughScan{false};
  bool m_bOverrideHeaderSize{false};

  std::ostream* m_Output;
  std::ofstream m_OutputFile;

  n64sym_output_fmt_t m_OutputFormat{N64SYM_FMT_DEFAULT};

  size_t m_NumSymbolsToCheck{0};
  size_t m_NumSymbolsChecked{0};

  pthread_mutex_t m_ProgressMutex{};

  std::vector<search_result_t> m_Results;
  std::vector<const char*> m_LibPaths;
  std::set<uint32_t> m_LikelyFunctionOffsets;

  CSignatureFile m_BuiltinSigs;

  void ScanRecursive(const char* path);

  void ProcessFile(const char* path);
  void ProcessLibrary(const char* path);
  void ProcessObject(const char* path);
  void ProcessObject(obj_processing_context_t* objProcessingCtx);
  static auto ProcessObjectProc(void* _objProcessingCtx) -> void*;
  void ProcessSignatureFile(const char* path);
  void ProcessSignatureFile(CSignatureFile& sigFile);

  static auto TestElfObjectText(CElfContext* elf, const char* data, int* nBytesMatched) -> bool;
  auto TestSignatureSymbol(CSignatureFile& sigFile, size_t nSymbol, uint32_t offset) -> bool;

  void TallyNumSymbolsToCheck();
  void CountSymbolsRecursive(const char* path);
  void CountSymbolsInFile(const char* path);
  static auto CountGlobalSymbolsInElf(CElfContext& elf) -> size_t;

  auto AddResult(search_result_t result) -> bool;
  void AddSymbolResults(CElfContext* elf, uint32_t baseAddress, uint32_t maxTextOffset = 0);
  void AddRelocationResults(CElfContext* elf, const char* block, const char* altNamePrefix, int maxTextOffset = 0);
  static auto ResultCmp(search_result_t a, search_result_t b) -> bool;
  void SortResults();

  void ProgressInc(size_t numSymbols);
  void Log(const char* format, ...) const;
  void Output(const char* format, ...);
  static void ClearLine(int nChars);
};

#endif  // N64SYM_H
