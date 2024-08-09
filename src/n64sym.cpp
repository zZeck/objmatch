/*

    n64sym
    Symbol identification tool for N64 games
    shygoo 2017, 2020
    License: MIT

*/

#include "n64sym.h"

#include <cstdio>
#include <fstream>
#include <iostream>
#include <map>
#include <set>

#include <boost/crc.hpp>
#include <fcntl.h>
#include <unistd.h>
#include <libelf.h>
#include <gelf.h>

#ifdef WIN32
#include <windirent.h>
#else
#include <dirent.h>
#endif
#include <filesystem>

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


extern const char gBuiltinSignatureFile[];

CN64Sym::CN64Sym() : m_Output(&std::cout) { /*m_BuiltinSigs.LoadFromMemory(gBuiltinSignatureFile);*/ }

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

  const std::filesystem::path fs_path { binPath };
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

void CN64Sym::SetVerbose(bool bVerbose) { m_bVerbose = bVerbose; }

void CN64Sym::UseBuiltinSignatures(bool bUseBuiltinSignatures) { m_bUseBuiltinSignatures = bUseBuiltinSignatures; }

void CN64Sym::SetThoroughScan(bool bThoroughScan) { m_bThoroughScan = bThoroughScan; }

auto CN64Sym::SetOutputFormat(const char* fmtName) -> bool {
  for (auto& FormatName : FormatNames) {
    if (strcmp(FormatName.name, fmtName) == 0) {
      m_OutputFormat = FormatName.fmt;
      return true;
    }
  }

  m_OutputFormat = N64SYM_FMT_DEFAULT;
  return false;
}

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

  //if (m_bUseBuiltinSignatures) {
  //  ProcessSignatureFile(m_BuiltinSigs);
  //}

  for (auto& m_LibPath : m_LibPaths) {
    const std::filesystem::path fs_path { m_LibPath };
    if (fs_path.extension() == ".sig") {
      YAML::Node node = YAML::LoadFile(fs_path);
      auto sigs = node.as<std::vector<sig_object>>();

      ProcessSignatureFile2(sigs);
    }
  }

  SortResults();
  DumpResults();

  return true;
}

void CN64Sym::DumpResults() {
  switch (m_OutputFormat) {
    case N64SYM_FMT_PJ64:
      for (auto& result : m_Results) {
        Output("%08X,code,%s\n", result.address, result.name.c_str());
      }
      break;
    case N64SYM_FMT_NEMU:
      Output("Root\n");
      Output("\tCPU\n");
      for (auto& result : m_Results) {
        Output("\t\tCPU 0x%08X: %s\n", result.address, result.name.c_str());
      }
      Output("\tMemory\n");
      Output("\tRSP\n");
      break;
    case N64SYM_FMT_ARMIPS:
      for (auto& result : m_Results) {
        Output(".definelabel %s, 0x%08X\n", result.name.c_str(), result.address);
      }
      break;
    case N64SYM_FMT_N64SPLIT:
      Output("labels:\n");
      for (auto& result : m_Results) {
        Output("   - [0x%08X, \"%s\"]\n", result.address, result.name.c_str());
      }
      break;
    case N64SYM_FMT_SPLAT:
      for (auto& result : m_Results) {
        Output("%s = 0x%08X;\n", result.name.c_str(), result.address);
      }
      break;
    case N64SYM_FMT_DEFAULT:
    default:
      for (auto& result : m_Results) {
        Output("%08X %s\n", result.address, result.name.c_str());
      }
      break;
  }
}

void CN64Sym::ProcessSignatureFile2(std::vector<sig_object> sigFile) {
  for (auto sig_obj : sigFile) {
    for(auto sig_section : sig_obj.sections) {
      if(sig_section.name != ".text") continue;
      for(auto sig_sym : sig_section.symbols) {
        for (auto offset : m_LikelyFunctionOffsets) {
          //should have a condition on the offset loop, so finding
          //result stops search? symbol could theoretically have been linked in more than once
          TestSignatureSymbol2(sig_sym, sig_obj.file, offset);
        }
      }
    }
  }
}

auto CN64Sym::TestSignatureSymbol2(sig_symbol sig_sym, std::string object_name, uint32_t offset) -> bool {
  typedef struct {
    uint32_t address;
    bool haveHi16;
    bool haveLo16;
  } test_t;
  std::map<std::string, test_t> relocMap;

  if (TestSymbol(sig_sym, &m_Binary[offset])) {
    AddResult(search_result_t {
      .address = m_HeaderSize + offset,
      .size = sig_sym.size,
      .name = sig_sym.symbol
    });

    // add results from relocations
    for (auto rel : sig_sym.relocations) {
      auto temp = &m_Binary[offset + rel.offset];
      auto temp1 = *reinterpret_cast<uint32_t*>(temp);

      uint32_t const opcode = bswap32(temp1);

      auto relocation_name = rel.name;

      if(rel.local) {
        const std::filesystem::path fs_path { object_name };
        char relocName[128];
        snprintf(relocName, sizeof(relocName), "%s_%s_%04X", fs_path.stem().c_str(), &rel.name.c_str()[1], rel.addend);
        relocation_name = std::string(relocName);
      }

      switch (rel.type) {
        case R_MIPS_HI16:
          if (!relocMap.contains(relocation_name)) {
            relocMap[relocation_name].haveHi16 = true;
            relocMap[relocation_name].haveLo16 = false;
          }
          relocMap[relocation_name].address = (opcode & 0x0000FFFF) << 16;
          break;
        case R_MIPS_LO16:
          if (relocMap.contains(relocation_name)) {
            relocMap[relocation_name].address += static_cast<int16_t>(opcode & 0x0000FFFF);
          } else {
            printf("missing hi16?");
            exit(0);
          }
          break;
        case R_MIPS_26:
          relocMap[relocation_name].address = (m_HeaderSize & 0xF0000000) + ((opcode & 0x03FFFFFF) << 2);
          break;
      }

      // printf("%s %02X %04X\n", relocName, relocType, relocOffset);
    }

    for (auto& i : relocMap) {
      AddResult(search_result_t {
        .address = i.second.address,
        .size = 0,
        .name = i.first
      });
    }
    // printf("-------\n");

    return true;
  }
  return false;
}

auto CN64Sym::AddResult(search_result_t result) -> bool {
  // todo use map
  if (result.address == 0) {
    return false;
  }

  for (auto& otherResult : m_Results) {
    if (otherResult.address == result.address) {
      return false;  // already have
    }
  }

  m_Results.push_back(result);
  return true;
}

auto CN64Sym::ResultCmp(search_result_t a, search_result_t b) -> bool { return (a.address < b.address); }

void CN64Sym::SortResults() { std::sort(m_Results.begin(), m_Results.end(), ResultCmp); }

void CN64Sym::ClearLine(int nChars) {
  printf("\r");
  printf("%*s", nChars, "");
  printf("\r");
}

void CN64Sym::Log(const char* format, ...) const {
  if (!m_bVerbose) {
    return;
  }

  va_list args;
  va_start(args, format);
  vprintf(format, args);
  va_end(args);
}

void CN64Sym::Output(const char* format, ...) {
  va_list args;
  va_start(args, format);

  size_t const len = vsnprintf(nullptr, 0, format, args);
  char* str = new char[len + 1];
  va_end(args);

  va_start(args, format);
  vsprintf(str, format, args);
  va_end(args);

  *m_Output << str;
  delete[] str;
}


void ReadStrippedWord(uint8_t *dst, const uint8_t *src, int relType) {
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

auto TestSymbol(sig_symbol symbol, const uint8_t *buffer) -> bool {
  boost::crc_32_type resultA;
  boost::crc_32_type resultB;

  uint32_t crcA = 0;
  uint32_t crcB = 0;

  if (symbol.relocations.size() == 0) {
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

