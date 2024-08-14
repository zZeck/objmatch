#include "n64sym.h"

#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <unistd.h>

#include <boost/crc.hpp>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <filesystem>
#include <numeric>
#include <format>

#include "splat_out.h"

#ifndef bswap32
#ifdef __GNUC__
#define bswap32 __builtin_bswap32
#elif _MSC_VER
#define bswap32 _byteswap_ulong
#else
#define bswap32(n) (((unsigned)n & 0xFF000000) >> 24 | (n & 0xFF00) << 8 | (n & 0xFF0000) >> 8 | n << 24)
#endif
#endif

#ifndef bswap16
#ifdef __GNUC__
#define bswap16 __builtin_bswap16
#elif _MSC_VER
#define bswap16 _byteswap_ushort
#else
#define bswap16(n) (((unsigned)n & 0xFF00) >> 8 | n << 8)
#endif
#endif

CN64Sym::~CN64Sym() { delete[] m_Binary; }

auto CN64Sym::LoadBinary(const char* binPath) -> bool {
  if (m_Binary != nullptr) {
    delete[] m_Binary;
    m_BinarySize = 0;
  }

  std::ifstream file;
  file.open(binPath, std::ifstream::binary);

  if (!file.is_open()) {
    return false;
  }

  file.seekg(0, std::ifstream::end);
  m_BinarySize = file.tellg();
  m_Binary = new uint8_t[m_BinarySize];

  file.seekg(0, std::ifstream::beg);
  file.read(reinterpret_cast<char*>(m_Binary), m_BinarySize);

  const std::filesystem::path fs_path{binPath};
  if ((fs_path.extension() == ".z64" || fs_path.extension() == ".n64" || fs_path.extension() == ".v64") && !m_bOverrideHeaderSize) {
    if (m_BinarySize < 0x101000) {
      delete[] m_Binary;
      m_BinarySize = 0;
      return false;
    }

    uint32_t const endianCheck = bswap32(*reinterpret_cast<uint32_t*>(&m_Binary[0x00]));

    switch (endianCheck) {
      case 0x80371240:
        break;
      case 0x40123780:
        for (size_t i = 0; i < m_BinarySize; i += sizeof(uint32_t)) {
          *reinterpret_cast<uint32_t*>(&m_Binary[i]) = bswap32(*reinterpret_cast<uint32_t*>(&m_Binary[i]));
        }
        break;
      case 0x37804012:
        for (size_t i = 0; i < m_BinarySize; i += sizeof(uint16_t)) {
          *reinterpret_cast<uint16_t*>(&m_Binary[i]) = bswap16(*reinterpret_cast<uint16_t*>(&m_Binary[i]));
        }
        break;
    }

    uint32_t entryPoint = bswap32(*reinterpret_cast<uint32_t*>(&m_Binary[0x08]));

    boost::crc_32_type result;
    result.process_bytes(&m_Binary[0x40], 0xFC0);
    uint32_t bootCheck = result.checksum();

    switch (bootCheck) {
      case 0x0B050EE0:  // 6103
        entryPoint -= 0x100000;
        break;
      case 0xACC8580A:  // 6106
        entryPoint -= 0x200000;
        break;
    }

    m_HeaderSize = entryPoint - 0x1000;
  }

  return true;
}

void CN64Sym::AddLibPath(const char* libPath) { m_LibPaths.push_back(libPath); }

auto CN64Sym::SetOutputPath(const char* path) -> bool {
  m_OutputFile.open(path, std::ofstream::binary);

  if (!m_OutputFile.is_open()) {
    m_Output = &std::cout;
    return false;
  }

  m_Output = &m_OutputFile;
  return true;
}

void CN64Sym::SetHeaderSize(uint32_t headerSize) {
  m_bOverrideHeaderSize = true;
  m_HeaderSize = headerSize;
}

auto CN64Sym::Run() -> bool {
  if (m_Binary == nullptr) {
    return false;
  }

  m_LikelyFunctionOffsets.clear();

  for (size_t i = 0; i < m_BinarySize; i += sizeof(uint32_t)) {
    uint32_t const word = bswap32(*reinterpret_cast<uint32_t*>(&m_Binary[i]));

    // JR RA (+ 8)
    if (word == 0x03E00008) {
      if (*reinterpret_cast<uint32_t*>(&m_Binary[i + 8]) != 0x00000000) {
        m_LikelyFunctionOffsets.insert(i + 8);
      }
    }

    // ADDIU SP, SP, -n
    if ((word & 0xFFFF0000) == 0x27BD0000 && static_cast<int16_t>(word & 0xFFFF) < 0) {
      m_LikelyFunctionOffsets.insert(i);
    }

    // todo JALs?
  }

  for (auto& m_LibPath : m_LibPaths) {
    const std::filesystem::path fs_path{m_LibPath};
    if (fs_path.extension() == ".sig") {
      YAML::Node node = YAML::LoadFile(fs_path);
      auto sigs = node.as<std::vector<sig_object>>();

      auto temp = ProcessSignatureFile(sigs);

      YAML::Node node2;
      node2 = temp;
      YAML::Emitter emitter;
      emitter << node2;
      printf("%s\n", emitter.c_str());
    }
  }



  return true;
}

std::vector<splat_out> CN64Sym::ProcessSignatureFile(std::vector<sig_object> const &sigFile) {
  std::unordered_map<std::string, sig_obj_sec_sym> sym_map;
  for (auto const &sig_obj : sigFile) {
    for (auto const &sig_section : sig_obj.sections) {
      for (auto const &sig_sym : sig_section.symbols) {
        //should not be any repeats because of ODR
        sym_map[sig_sym.symbol] = sig_obj_sec_sym {
          .symbol_name = sig_sym.symbol,
          .section_name = sig_section.name,
          .object_name = sig_obj.file,
          .symbol_offset = sig_sym.offset,
          .section_size = sig_section.size
        };
      }
    }
  }

  std::vector<section_guess> results;
  for (auto const &sig_obj : sigFile) {
    //if(sig_obj.file != "env.o") continue;
    for (auto const &sig_section : sig_obj.sections) {
      if (sig_section.name != ".text") continue;
      for (auto const &sig_sym : sig_section.symbols) {
        //multiple functions with the same crc can't be distinguished
        if(sig_sym.duplicate_crc) continue;
        std::vector<uint32_t> candidates;
        std::copy_if(m_LikelyFunctionOffsets.cbegin(), m_LikelyFunctionOffsets.cend(), std::back_inserter(candidates), [&sig_obj, &sig_section, &sig_sym, this](uint32_t rom_offset) {
          auto temp = &m_Binary[rom_offset];
          return TestSymbol(sig_sym, temp);
        });
        //crc could match random code in game rom
        //if there are multiple matches, impossible to tell which is legit.
        //If no results, also done.
        if (candidates.size() != 1) continue;
        auto rom_offset = candidates[0];
        // should have a condition on the offset loop, so finding
        // result stops search? symbol could theoretically have been linked in more than once
        auto guesses = TestSignatureSymbol(sig_sym, rom_offset, sig_section, sig_obj, sym_map);
        results.insert(results.end(), guesses.begin(), guesses.end());
      }
    }
  }

  std::sort(results.begin(), results.end(), [](section_guess const &a, section_guess const &b)
    {
      auto obj_name_cmp = a.object_name <=> b.object_name;
      if(obj_name_cmp != 0) return obj_name_cmp < 0;
      auto sec_name_cmp = a.section_name <=> b.section_name;
      if(sec_name_cmp != 0) return sec_name_cmp < 0;
      auto rel_cmp = a.rel <=> b.rel;
      if(rel_cmp != 0) return rel_cmp < 0;
      auto sig_offset_cmp = a.symbol_offset <=> b.symbol_offset;
      return sig_offset_cmp < 0;
    });

  auto last = std::unique(results.begin(), results.end(), [](section_guess const &a, section_guess const &b)
    {
      return a.object_name == b.object_name && a.section_name == b.section_name;
    });

  results.erase(last, results.end());

  std::sort(results.begin(), results.end(), [](section_guess const &a, section_guess const &b)
  {
    return a.section_offset < b.section_offset;
  });

  std::vector<splat_out> blah;
  //can crash if vector is empty it seems?
  for (auto section_guess = results.begin(); section_guess < results.end()-1; ++section_guess) {
    auto off_comp = section_guess[0].section_offset + section_guess[0].section_size <=> section_guess[1].section_offset;
    if (off_comp == 0) {
      blah.push_back(splat_out {
        .start = section_guess[0].section_offset,
        .vram = section_guess[0].section_vram,
        .type = section_guess[0].section_name,
        .name = section_guess[0].object_name
      });
      //careful, potential issue if NEXT section is omitted due to overlap
      //the endpoint of THIS section is lost
    }
    if (off_comp < 0) {
      blah.push_back(splat_out {
        .start = section_guess[0].section_offset,
        .vram = section_guess[0].section_vram,
        .type = section_guess[0].section_name,
        .name = section_guess[0].object_name
      });
      blah.push_back(splat_out {
        .start = section_guess[0].section_offset + section_guess[0].section_size,
        .vram = section_guess[0].section_vram + section_guess[0].section_size,
        .type = "bin",
        .name = std::format("0x{:x}", section_guess[0].section_offset + section_guess[0].section_size)
      });
    }
    if (off_comp > 0) {
      // error, sections would overlap.
      // print bin section to mark prior section's end
      blah.push_back(splat_out {
        .start = section_guess[0].section_offset,
        .vram = section_guess[0].section_vram,
        .type = "bin",
        .name = std::format("0x{:x}", section_guess[0].section_offset)
      });
    }
  }



  return blah;
}

auto CN64Sym::TestSignatureSymbol(sig_symbol const &sig_sym, uint32_t rom_offset, sig_section const &sig_sec, sig_object const &sig_obj, std::unordered_map<std::string, sig_obj_sec_sym> sym_map) -> std::vector<section_guess> {
  typedef struct {
    uint32_t address;
    sig_relocation relocation;
    bool local;
  } test_t;
  std::map<std::string, test_t> relocMap;

  std::vector<section_guess> section_guesses;

  // add results from relocations
  for (auto rel : sig_sym.relocations) {
    auto temp = &m_Binary[rom_offset + rel.offset];
    auto temp1 = *reinterpret_cast<uint32_t*>(temp);

    uint32_t const opcode = bswap32(temp1);

    auto relocation_name = rel.name;

    if (rel.local) {
      const std::filesystem::path fs_path{sig_obj.file};
      char relocName[128];
      snprintf(relocName, sizeof(relocName), "%s_%s_%04X", fs_path.stem().c_str(), &rel.name.c_str()[1], rel.addend);
      relocation_name = std::string(relocName);
      relocMap[relocation_name].local = true;
    }

    switch (rel.type) {
      case R_MIPS_HI16:
        //if (!relocMap.contains(relocation_name)) {
        //  relocMap[relocation_name].haveHi16 = true;
        //  relocMap[relocation_name].haveLo16 = false;
        //}
        relocMap[relocation_name].address = (opcode & 0x0000FFFF) << 16;
        break;
      case R_MIPS_LO16:
        //if (relocMap.contains(relocation_name)) {
          relocMap[relocation_name].address += static_cast<int16_t>(opcode & 0x0000FFFF);
        //} else {
        //  printf("missing hi16?");
        //  exit(0);
        //}
        break;
      case R_MIPS_26:
        relocMap[relocation_name].address = (m_HeaderSize & 0xF0000000) + ((opcode & 0x03FFFFFF) << 2);
        break;
    }
    relocMap[relocation_name].relocation = rel;
  }

  //Should I validate the .text ones by checking the sig_sym checksum
  //for the location?
  for (auto& i : relocMap) {
    if(i.second.local) {
      auto rel_target_section_name = i.second.relocation.name;
      auto rel_target_section = std::find_if(sig_obj.sections.begin(), sig_obj.sections.end(), [rel_target_section_name](sig_section some_sec_from_obj) {
        return some_sec_from_obj.name == rel_target_section_name;
      });
      auto relocation_target_section = i.second.relocation.name;
      section_guesses.push_back(section_guess {
        .rom_offset = rom_offset, //name better, rom_offset_searched
        .symbol_offset = sig_sym.offset, //name better, symbol_searched_offset
        .section_offset = i.second.address - i.second.relocation.addend - m_HeaderSize, //need to do calculation based on address
        .section_vram = i.second.address - i.second.relocation.addend, //address from ROM code, minus the addend from reloc, to get to start of local section
        .symbol_name = sig_sym.symbol, //name better, symbol_name searched
        .section_size = rel_target_section->size,
        .rel = rel_info::local_rel,
        .section_name = i.second.relocation.name, //name is the correct section for LOCAL
        .object_name = sig_obj.file //object is correct for LOCAL
      });
    } else {
      if (auto rel_symbol = sym_map.find(i.second.relocation.name); rel_symbol != sym_map.end()) {
        section_guesses.push_back(section_guess {
          .rom_offset = rom_offset,
          .symbol_offset = rel_symbol->second.symbol_offset,
          .section_offset = i.second.address - i.second.relocation.addend - rel_symbol->second.symbol_offset - m_HeaderSize,
          .section_vram = i.second.address - i.second.relocation.addend - rel_symbol->second.symbol_offset,
          .symbol_name = rel_symbol->second.symbol_name,
          .section_size = rel_symbol->second.section_size,
          .rel = rel_info::global_rel,
          .section_name = rel_symbol->second.section_name,
          .object_name = rel_symbol->second.object_name
        });
      } else {
        //symbol not found, not really an error, as it could be extern
        //and intended to be defined by library consumer
      }
    }
  }

  section_guesses.push_back(section_guess {
    .rom_offset = rom_offset,
    .symbol_offset = sig_sym.offset,
    .section_offset =  rom_offset - sig_sym.offset,
    .section_vram = m_HeaderSize + rom_offset - sig_sym.offset,
    .symbol_name = sig_sym.symbol,
    .section_size = sig_sec.size,
    .rel = rel_info::not_rel,
    .section_name = sig_sec.name,
    .object_name = sig_obj.file
  });

  return section_guesses;
}

void ReadStrippedWord(uint8_t* dst, const uint8_t* src, int relType) {
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

auto TestSymbol(sig_symbol const &symbol, const uint8_t* buffer) -> bool {
  boost::crc_32_type resultA;
  boost::crc_32_type resultB;

  uint32_t crcA = 0;
  uint32_t crcB = 0;

  if (symbol.relocations.empty()) {
    resultA.process_bytes(buffer, std::min(symbol.size, reinterpret_cast<uint64_t>(UINT64_C(8))));
    auto crcA = resultA.checksum();

    if (symbol.crc_8 != crcA) {
      return false;
    }

    resultB.process_bytes(buffer, symbol.size);
    auto crcB = resultB.checksum();

    return (symbol.crc_all == crcB);
  }

  size_t offset = 0;

  auto reloc = symbol.relocations.begin();
  uint64_t const crcA_limit = std::min(symbol.size, reinterpret_cast<uint64_t>(UINT64_C(8)));

  // resultA.reset();
  while (offset < crcA_limit && reloc != symbol.relocations.end()) {
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

  if (symbol.crc_8 != crcA) {
    return false;
  }

  while (offset < symbol.size && reloc != symbol.relocations.end()) {
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

  return (symbol.crc_all == crcB);
}
