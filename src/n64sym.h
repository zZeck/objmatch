#include <algorithm>
#include <array>
#include <cstdarg>
#include <cstdlib>
#include <fstream>
#include <set>
#include <vector>
#include <iostream>

#include "signature.h"
#include "splat_out.h"

using n64sym_output_fmt_t = enum { N64SYM_FMT_DEFAULT, N64SYM_FMT_PJ64, N64SYM_FMT_NEMU, N64SYM_FMT_ARMIPS, N64SYM_FMT_N64SPLIT, N64SYM_FMT_SPLAT };

class CN64Sym {
 public:
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

 private:
  using n64sym_fmt_lut_t = struct {
    const char* name;
    n64sym_output_fmt_t fmt;
  };

  static constexpr std::array<n64sym_fmt_lut_t, 6> FormatNames = {{{.name = "default", .fmt = N64SYM_FMT_DEFAULT},
                                                                   {.name = "pj64", .fmt = N64SYM_FMT_PJ64},
                                                                   {.name = "nemu", .fmt = N64SYM_FMT_NEMU},
                                                                   {.name = "armips", .fmt = N64SYM_FMT_ARMIPS},
                                                                   {.name = "n64split", .fmt = N64SYM_FMT_N64SPLIT},
                                                                   {.name = "splat", .fmt = N64SYM_FMT_SPLAT}}};

  using obj_processing_context_t = struct {
    CN64Sym* mt_this;
    const char* libraryPath;
    const char* blockIdentifier;
    uint8_t* blockData;
    size_t blockSize;
  };

  using search_result_t = struct {
    uint32_t address;  // from jump target
    uint64_t size;     // data match size
    std::string name;
  };

  using partial_match_t = struct {
    uint32_t address;
    int nBytesMatched;
  };

  enum rel_info {
    not_rel,
    local_rel,
    global_rel
  };

  using section_guess = struct {
    uint64_t rom_offset;
    uint64_t section_vram;
    uint64_t symbol_offset;
    uint64_t section_offset;
    uint64_t section_size;
    rel_info rel;
    std::string symbol_name;
    std::string section_name;
    std::string object_name;
  };

  uint8_t* m_Binary{nullptr};
  size_t m_BinarySize{0};
  uint32_t m_HeaderSize{0x80000000};

  bool m_bVerbose{false};
  bool m_bUseBuiltinSignatures{false};
  bool m_bThoroughScan{false};
  bool m_bOverrideHeaderSize{false};

  std::ostream *m_Output = &std::cout;
  std::ofstream m_OutputFile;

  n64sym_output_fmt_t m_OutputFormat{N64SYM_FMT_DEFAULT};

  std::vector<search_result_t> m_Results;
  std::vector<const char*> m_LibPaths;
  std::set<uint32_t> m_LikelyFunctionOffsets;

  void DumpResults();

  using sig_obj_sec_sym = struct {
    std::string symbol_name;
    std::string section_name;
    std::string object_name;
    uint64_t symbol_offset;
    uint64_t section_size;
  };

  std::vector<splat_out> ProcessSignatureFile(std::vector<sig_object> const &sigFile);

  auto TestSignatureSymbol(sig_symbol const &sig_sym, uint32_t offset, sig_section const &sig_sec, sig_object const &sig_obj, std::unordered_map<std::string, sig_obj_sec_sym> sym_map) -> std::vector<section_guess>;

  auto AddResult(search_result_t result) -> bool;
  static auto ResultCmp(search_result_t a, search_result_t b) -> bool;
  void SortResults();

  void Log(const char* format, ...) const;
  void Output(const char* format, ...);
  static void ClearLine(int nChars);
};

static void ReadStrippedWord(uint8_t* dst, const uint8_t* src, int relType);
auto TestSymbol(sig_symbol const &sig_sym, const uint8_t* buffer) -> bool;
