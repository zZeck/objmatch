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

using binary_info = struct binary_info {
  std::vector<uint8_t> m_Binary{};
  size_t m_BinarySize{};
  uint32_t m_HeaderSize{};
};

using bin_func_offsets = struct bin_func_offsets {
  uint8_t *m_Binary{};
  std::set<uint32_t> m_LikelyFunctionOffsets{};
};

using sig_obj_sec_sym = struct sig_obj_sec_sym {
  std::string symbol_name{};
  std::string section_name{};
  std::string object_name{};
  uint64_t symbol_offset{};
  uint64_t section_size{};
};

enum rel_info { not_rel, local_rel, global_rel };

using section_guess = struct section_guess {
  uint64_t rom_offset{};
  uint64_t section_vram{};
  uint64_t symbol_offset{};
  uint64_t section_offset{};
  uint64_t section_size{};
  rel_info rel{};
  std::string symbol_name{};
  std::string section_name{};
  std::string object_name{};
};

static void ReadStrippedWord(uint8_t *dst, const uint8_t *src, uint64_t relType);
auto TestSymbol(sig_symbol const &symbol, const uint8_t *buffer) -> bool;

auto ObjMatchBloop(const char *binPath, const char *libPath) -> bool;

auto ProcessSignatureFile(std::vector<sig_object> const &sigFile, binary_info const &b_info, const std::set<uint32_t> &m_LikelyFunctionOffsets) -> std::vector<splat_out>;

auto TestSignatureSymbol(sig_symbol const &sig_sym, uint32_t rom_offset, sig_section const &sig_sec, sig_object const &sig_obj,
                         std::unordered_map<std::string, sig_obj_sec_sym> sym_map, binary_info const &b_info) -> std::vector<section_guess>;
