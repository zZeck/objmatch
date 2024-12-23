#include "objmatch.h"

#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <unistd.h>
#include <crc32c/crc32c.h>

#include <algorithm>
#include <bit>
#include <boost/crc.hpp>
#include <cstdio>
#include <filesystem>
#include <format>
#include <fstream>
#include <map>
#include <print>
#include <set>

#include "splat_out.h"

std::vector<uint8_t> func_buf{};

namespace {
auto readswap32(const std::span<const uint8_t, 4> &buf) -> uint32_t {
  uint32_t word{};
  std::memcpy(&word, buf.data(), 4);

  return std::byteswap(word);
}

auto read32(const std::span<const uint8_t, 4> &buf) -> uint32_t {
  uint32_t word{};
  std::memcpy(&word, buf.data(), 4);

  return word;
}

auto readswap16(const std::span<const uint8_t, 2> &buf) -> uint16_t {
  uint16_t word{};
  std::memcpy(&word, buf.data(), 2);

  return std::byteswap(word);
}

auto LoadBinary(const char *binPath) -> binary_info {
  binary_info b_info;

  std::ifstream file{binPath, std::ios::binary};

  b_info.m_BinarySize = std::filesystem::file_size(binPath);
  b_info.m_Binary = std::vector<uint8_t>(b_info.m_BinarySize);

  b_info.m_Binary.reserve(b_info.m_BinarySize);
  file.read(reinterpret_cast<char*>(b_info.m_Binary.data()), b_info.m_BinarySize);

  const std::filesystem::path fs_path{binPath};
  if ((fs_path.extension() == ".z64" || fs_path.extension() == ".n64" || fs_path.extension() == ".v64") /*&& !m_bOverrideHeaderSize*/) {
    uint32_t const endianCheck = readswap32(std::span<const uint8_t, 4>{b_info.m_Binary.data(), 4});

    if (endianCheck == 0x40123780) {
      for (size_t i = 0; i < b_info.m_BinarySize; i += sizeof(uint32_t)) {
        uint32_t const data = readswap32(std::span<const uint8_t, 4>{&b_info.m_Binary[i], 4});
        std::memcpy(&b_info.m_Binary[i], &data, 4);
      }
    } else if (endianCheck == 0x37804012) {
      for (size_t i = 0; i < b_info.m_BinarySize; i += sizeof(uint16_t)) {
        uint16_t const data = readswap16(std::span<const uint8_t, 2>{&b_info.m_Binary[i], 2});
        std::memcpy(&b_info.m_Binary[i], &data, 2);
      }
    }

    boost::crc_32_type result;
    result.process_bytes(&b_info.m_Binary[0x40], 0xFC0);
    auto const bootCheck = result.checksum();

    const auto entryPointOff = bootCheck == 0x0B050EE0 ? 0x100000 : // 6103
      bootCheck == 0xACC8580A ? 0x200000 : // 6106
      0;

    const uint32_t entryPoint = readswap32(std::span<const uint8_t, 4>{&b_info.m_Binary[0x08], 4});

    b_info.m_HeaderSize = entryPoint - entryPointOff - 0x1000;
  }

  return b_info;
}
}

auto TestSymbol(sig_symbol const &symbol, const std::span<const uint8_t> &buffer) -> bool {
  func_buf.resize(symbol.size);
  func_buf.reserve(symbol.size);
  std::memcpy(func_buf.data(), buffer.data(), symbol.size);

  for (const auto &reloc : symbol.relocations) {
    if (reloc.type == 4) {
      //R_MIPS_26
      func_buf[0] &= 0xFC;
      func_buf[1] = 0x00;
      func_buf[2] = 0x00;
      func_buf[3] = 0x00;
    } else if (reloc.type == 5 || reloc.type == 6) {
      //R_MIPS_HI16 || R_MIPS_LO16
      func_buf[2] = 0x00;
      func_buf[3] = 0x00;
    }
  }

  const auto crcA = crc32c::Crc32c(func_buf.data(), std::min(symbol.size, static_cast<uint64_t>(8)));

  if (symbol.crc_8 != crcA) return false;

  const auto crcB = crc32c::Crc32c(func_buf.data(), symbol.size);

  return symbol.crc_all == crcB;
}

auto ObjMatchBloop(const char *binPath, const char *libPath) -> bool {
  auto b_info = LoadBinary(binPath);

  if (b_info.m_Binary.empty()) return false;

  std::set<uint32_t> m_LikelyFunctionOffsets;

  for (size_t i = 0; i < b_info.m_BinarySize; i += sizeof(uint32_t)) {
    uint32_t const word = readswap32(std::span<const uint8_t, 4>{&b_info.m_Binary[i], 4});

    // JR RA (+ 8)
    if (word == 0x03E00008) {
      if (read32(std::span<const uint8_t, 4>{&b_info.m_Binary[i + 8], 4}) != 0x00000000) {
        m_LikelyFunctionOffsets.insert(i + 8);
      }
    }

    // ADDIU SP, SP, -n
    if ((word & 0xFFFF0000) == 0x27BD0000 && static_cast<int16_t>(word & 0xFFFF) < 0) {
      m_LikelyFunctionOffsets.insert(i);
    }

    // todo JALs?
  }

  const std::filesystem::path fs_path{libPath};
  if (fs_path.extension() == ".sig") {
    std::ifstream file {fs_path, std::ios::binary};
  
    const auto file_size {std::filesystem::file_size(fs_path)};
    std::vector<char> yaml_data(file_size);
    yaml_data.reserve(file_size);

    file.read(yaml_data.data(), file_size);

    auto sigs = sig_yaml::deserialize(yaml_data);

    auto temp = ProcessSignatureFile(sigs, b_info, m_LikelyFunctionOffsets);

    const auto output = splat_yaml::serialize(temp);

    std::println("{}", std::string_view(output));
  }

  return true;
}

auto ProcessSignatureFile(std::vector<sig_object> const &sigFile, binary_info const &b_info, const std::set<uint32_t> &m_LikelyFunctionOffsets)
    -> std::vector<splat_out> {
  std::unordered_map<std::string, sig_obj_sec_sym> sym_map;
  for (auto const &sig_obj : sigFile) {
    for (auto const &sig_section : sig_obj.sections) {
      for (auto const &sig_sym : sig_section.symbols) {
        // should not be any repeats because of ODR
        sym_map[sig_sym.symbol] = sig_obj_sec_sym{.symbol_name = sig_sym.symbol,
                                                  .section_name = sig_section.name,
                                                  .object_name = sig_obj.file,
                                                  .symbol_offset = sig_sym.offset,
                                                  .section_size = sig_section.size};
      }
    }
  }

  std::vector<section_guess> results;
  for (auto const &sig_obj : sigFile) {
    for (auto const &sig_section : sig_obj.sections) {
      if (sig_section.name != ".text") continue;
      for (auto const &sig_sym : sig_section.symbols) {
        // multiple functions with the same crc can't be distinguished
        if (sig_sym.duplicate_crc) continue;
        std::vector<uint32_t> candidates;
        std::ranges::copy_if(m_LikelyFunctionOffsets, std::back_inserter(candidates),
                     [&sig_obj, &sig_section, &sig_sym, &b_info](uint32_t rom_offset) {
                       const std::span<const uint8_t> blah(&b_info.m_Binary[rom_offset], b_info.m_Binary.size() - rom_offset);
                       return TestSymbol(sig_sym, blah);
                     });
        // crc could match random code in game rom
        // if there are multiple matches, impossible to tell which is legit.
        // If no results, also done.
        if (candidates.size() != 1) continue;
        auto rom_offset = candidates[0];
        // should have a condition on the offset loop, so finding
        // result stops search? symbol could theoretically have been linked in more than once
        auto guesses = TestSignatureSymbol(sig_sym, rom_offset, sig_section, sig_obj, sym_map, b_info);
        results.insert(results.end(), guesses.begin(), guesses.end());
      }
    }
  }

  std::ranges::sort(results, [](section_guess const &a, section_guess const &b) {
    auto obj_name_cmp = a.object_name <=> b.object_name;
    if (obj_name_cmp != 0) return obj_name_cmp < 0;
    auto sec_name_cmp = a.section_name <=> b.section_name;
    if (sec_name_cmp != 0) return sec_name_cmp < 0;
    auto rel_cmp = a.rel <=> b.rel;
    if (rel_cmp != 0) return rel_cmp < 0;
    auto sig_offset_cmp = a.symbol_offset <=> b.symbol_offset;
    return sig_offset_cmp < 0;
  });

  const auto [first, last] = std::ranges::unique(results,
                          [](section_guess const &a, section_guess const &b) { return a.object_name == b.object_name && a.section_name == b.section_name; });

  results.erase(first, last);

  std::ranges::sort(results, [](section_guess const &a, section_guess const &b) { return a.section_offset < b.section_offset; });

  std::vector<splat_out> blah;
  // can crash if vector is empty it seems?
  for (auto section_guess = results.begin(); section_guess < results.end() - 1; ++section_guess) {
    auto off_comp = section_guess[0].section_offset + section_guess[0].section_size <=> section_guess[1].section_offset;
    if (off_comp == 0) {
      blah.push_back(splat_out{.start = section_guess[0].section_offset,
                               .vram = section_guess[0].section_vram,
                               .type = section_guess[0].section_name,
                               .name = section_guess[0].object_name});
      // careful, potential issue if NEXT section is omitted due to overlap
      // the endpoint of THIS section is lost
    }
    if (off_comp < 0) {
      blah.push_back(splat_out{.start = section_guess[0].section_offset,
                               .vram = section_guess[0].section_vram,
                               .type = section_guess[0].section_name,
                               .name = section_guess[0].object_name});
      blah.push_back(splat_out{.start = section_guess[0].section_offset + section_guess[0].section_size,
                               .vram = section_guess[0].section_vram + section_guess[0].section_size,
                               .type = "bin",
                               .name = std::format("0x{:x}", section_guess[0].section_offset + section_guess[0].section_size)});
    }
    if (off_comp > 0) {
      // error, sections would overlap.
      // print bin section to mark prior section's end
      blah.push_back(splat_out{.start = section_guess[0].section_offset,
                               .vram = section_guess[0].section_vram,
                               .type = "bin",
                               .name = std::format("0x{:x}", section_guess[0].section_offset)});
    }
  }

  auto final = results.back();

  blah.push_back(splat_out{.start = final.section_offset, .vram = final.section_vram, .type = final.section_name, .name = final.object_name});
  blah.push_back(splat_out{.start = final.section_offset + final.section_size,
                           .vram = final.section_vram + final.section_size,
                           .type = "bin",
                           .name = std::format("0x{:x}", final.section_offset + final.section_size)});

  return blah;
}

auto TestSignatureSymbol(sig_symbol const &sig_sym, uint32_t rom_offset, sig_section const &sig_sec, sig_object const &sig_obj,
                         std::unordered_map<std::string, sig_obj_sec_sym> const &sym_map, binary_info const &b_info) -> std::vector<section_guess> {
  using test_t = struct test_t {
    uint32_t address{};
    sig_relocation relocation{};
    bool local{};
    bool hi16_set{};
    bool lo16_set{};
  };
  std::map<std::string, test_t> relocMap;

  std::vector<section_guess> section_guesses;

  // add results from relocations
  for (const auto &rel : sig_sym.relocations) {
    uint32_t const opcode = readswap32(std::span<const uint8_t, 4>{&b_info.m_Binary[rom_offset + rel.offset], 4});

    auto relocation_name = rel.name;

    if (rel.local) {
      const std::filesystem::path fs_path{sig_obj.file};
      relocation_name = std::format("{}_{}_{:04X}", fs_path.stem().string(), std::string_view{rel.name}.substr(1), rel.addend); 
      relocMap[relocation_name].local = true;
    }

    switch (rel.type) {
      case R_MIPS_HI16:
        if (!relocMap[relocation_name].hi16_set) {
          relocMap[relocation_name].address = (opcode & 0x0000FFFF) << 16;
          relocMap[relocation_name].hi16_set = true;
          relocMap[relocation_name].relocation = rel;
        }
        break;
      case R_MIPS_LO16:
        // this is to prevent multiple references to the same symbol
        // from all adding their lo16 to the address
        if (!relocMap[relocation_name].lo16_set) {
          relocMap[relocation_name].address += static_cast<int16_t>(opcode & 0x0000FFFF);
          relocMap[relocation_name].lo16_set = true;
          relocMap[relocation_name].relocation = rel;
        }
        break;
      case R_MIPS_26:
        relocMap[relocation_name].address = (b_info.m_HeaderSize & 0xF0000000) + ((opcode & 0x03FFFFFF) << 2);
        relocMap[relocation_name].relocation = rel;
        break;
      default:
        break;
    }
  }

  // Should I validate the .text ones by checking the sig_sym checksum
  // for the location?
  for (auto &i : relocMap) {
    if (i.second.local) {
      auto rel_target_section_name = i.second.relocation.name;
      auto rel_target_section = std::ranges::find_if(sig_obj.sections, [rel_target_section_name](const sig_section &some_sec_from_obj) {
        return some_sec_from_obj.name == rel_target_section_name;
      });
      auto eee = section_guess{
          .rom_offset = rom_offset,  // name better, rom_offset_searched
          .section_vram =
              i.second.address - i.second.relocation.addend,  // address from ROM code, minus the addend from reloc, to get to start of local section
          .symbol_offset = sig_sym.offset,                    // name better, symbol_searched_offset
          .section_offset = i.second.address - i.second.relocation.addend - b_info.m_HeaderSize,  // need to do calculation based on address
          .section_size = rel_target_section->size,
          .rel = rel_info::local_rel,
          .symbol_name = sig_sym.symbol,             // name better, symbol_name searched
          .section_name = i.second.relocation.name,  // name is the correct section for LOCAL
          .object_name = sig_obj.file                // object is correct for LOCAL
      };
      section_guesses.push_back(eee);
    } else {
      if (auto rel_symbol = sym_map.find(i.second.relocation.name); rel_symbol != sym_map.end()) {
        auto blah = section_guess{.rom_offset = rom_offset,
                                  .section_vram = i.second.address - i.second.relocation.addend - rel_symbol->second.symbol_offset,
                                  .symbol_offset = rel_symbol->second.symbol_offset,
                                  .section_offset = i.second.address - i.second.relocation.addend - rel_symbol->second.symbol_offset - b_info.m_HeaderSize,
                                  .section_size = rel_symbol->second.section_size,
                                  .rel = rel_info::global_rel,
                                  .symbol_name = rel_symbol->second.symbol_name,
                                  .section_name = rel_symbol->second.section_name,
                                  .object_name = rel_symbol->second.object_name};
        section_guesses.push_back(blah);
      } else {
        // symbol not found, not really an error, as it could be extern
        // and intended to be defined by library consumer
      }
    }
  }

  section_guesses.push_back(section_guess{.rom_offset = rom_offset,
                                          .section_vram = b_info.m_HeaderSize + rom_offset - sig_sym.offset,
                                          .symbol_offset = sig_sym.offset,
                                          .section_offset = rom_offset - sig_sym.offset,
                                          .section_size = sig_sec.size,
                                          .rel = rel_info::not_rel,
                                          .symbol_name = sig_sym.symbol,
                                          .section_name = sig_sec.name,
                                          .object_name = sig_obj.file});

  return section_guesses;
}
