#include <algorithm>
#include <array>
#include <cstdarg>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <set>
#include <vector>

#include "signature.h"
#include "splat_out.h"

class ObjMatch {
 public:
  ~ObjMatch();
  auto LoadBinary(const char* binPath) -> bool;
  void AddLibPath(const char* libPath);
  void SetHeaderSize(uint32_t headerSize);
  auto SetOutputPath(const char* path) -> bool;
  auto Run() -> bool;

 private:
  enum rel_info { not_rel, local_rel, global_rel };

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

  bool m_bOverrideHeaderSize{false};

  std::ostream* m_Output = &std::cout;
  std::ofstream m_OutputFile;

  std::vector<const char*> m_LibPaths;
  std::set<uint32_t> m_LikelyFunctionOffsets;

  using sig_obj_sec_sym = struct {
    std::string symbol_name;
    std::string section_name;
    std::string object_name;
    uint64_t symbol_offset;
    uint64_t section_size;
  };

  std::vector<splat_out> ProcessSignatureFile(std::vector<sig_object> const& sigFile);

  auto TestSignatureSymbol(sig_symbol const& sig_sym, uint32_t offset, sig_section const& sig_sec, sig_object const& sig_obj,
                           std::unordered_map<std::string, sig_obj_sec_sym> sym_map) -> std::vector<section_guess>;
};

static void ReadStrippedWord(uint8_t* dst, const uint8_t* src, int relType);
auto TestSymbol(sig_symbol const& sig_sym, const uint8_t* buffer) -> bool;
