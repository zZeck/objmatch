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

#include "signaturefile.h"

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

auto IsFileWithSymbols(const char *path) -> bool {
  const std::filesystem::path fs_path { path };
  return fs_path.extension() == ".a" || fs_path.extension() == ".o" || fs_path.extension() == ".sig";
}

CN64Sym::CN64Sym() : m_Output(&std::cout) { m_BuiltinSigs.LoadFromMemory(gBuiltinSignatureFile); }

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

  TallyNumSymbolsToCheck();

  if (m_bUseBuiltinSignatures) {
    ProcessSignatureFile(m_BuiltinSigs);
  }

  for (auto& m_LibPath : m_LibPaths) {
    ScanRecursive(m_LibPath);
  }

  SortResults();
  DumpResults();

  return true;
}

void CN64Sym::DumpResults() {
  switch (m_OutputFormat) {
    case N64SYM_FMT_PJ64:
      for (auto& result : m_Results) {
        Output("%08X,code,%s\n", result.address, result.name);
      }
      break;
    case N64SYM_FMT_NEMU:
      Output("Root\n");
      Output("\tCPU\n");
      for (auto& result : m_Results) {
        Output("\t\tCPU 0x%08X: %s\n", result.address, result.name);
      }
      Output("\tMemory\n");
      Output("\tRSP\n");
      break;
    case N64SYM_FMT_ARMIPS:
      for (auto& result : m_Results) {
        Output(".definelabel %s, 0x%08X\n", result.name, result.address);
      }
      break;
    case N64SYM_FMT_N64SPLIT:
      Output("labels:\n");
      for (auto& result : m_Results) {
        Output("   - [0x%08X, \"%s\"]\n", result.address, result.name);
      }
      break;
    case N64SYM_FMT_SPLAT:
      for (auto& result : m_Results) {
        Output("%s = 0x%08X;\n", result.name, result.address);
      }
      break;
    case N64SYM_FMT_DEFAULT:
    default:
      for (auto& result : m_Results) {
        Output("%08X %s\n", result.address, result.name);
      }
      break;
  }
}

void CN64Sym::ScanRecursive(const char* path) {
  if (IsFileWithSymbols(path)) {
    ProcessFile(path);
    return;
  }
}

void CN64Sym::ProcessFile(const char* path) {
  const std::filesystem::path fs_path { path };
  if (fs_path.extension() == ".sig") {
    ProcessSignatureFile(path);
  }
}

void CN64Sym::ProcessSignatureFile(const char* path) {
  CSignatureFile sigFile;

  if (sigFile.Load(path)) {
    ProcessSignatureFile(sigFile);
  }
}

void CN64Sym::ProcessSignatureFile(CSignatureFile& sigFile) {
  size_t const numSymbols = sigFile.GetNumSymbols();

  const char* statusDescription = "(built-in signatures)";
  int percentDone = 0;
  int statusLineLen = printf("[  0%%] %s", statusDescription);

  for (size_t nSymbol = 0; nSymbol < numSymbols; nSymbol++) {
    uint32_t const symbolSize = sigFile.GetSymbolSize(nSymbol);
    uint32_t const endOffset = m_BinarySize - symbolSize;
    char symbolName[128];
    sigFile.GetSymbolName(nSymbol, symbolName, sizeof(symbolName));

    int const percentNow = static_cast<int>((static_cast<float>(nSymbol) / numSymbols) * 100);
    if (percentNow > percentDone) {
      ClearLine(statusLineLen);
      statusLineLen = printf("[%3d%%] %s", percentDone, statusDescription);
      percentDone = percentNow;
    }

    for (auto offset : m_LikelyFunctionOffsets) {
      if (TestSignatureSymbol(sigFile, nSymbol, offset)) {
        goto next_symbol;
      }
    }

    if (m_bThoroughScan) {
      for (uint32_t offset = 0; offset < endOffset; offset += 4) {
        if (TestSignatureSymbol(sigFile, nSymbol, offset)) {
          goto next_symbol;
        }
      }
    }

  next_symbol:;
  }

  ClearLine(statusLineLen);
}

auto CN64Sym::TestSignatureSymbol(CSignatureFile& sigFile, size_t nSymbol, uint32_t offset) -> bool {
  typedef struct {
    uint32_t address;
    bool haveHi16;
    bool haveLo16;
  } test_t;
  std::map<std::string, test_t> relocMap;

  if (sigFile.TestSymbol(nSymbol, &m_Binary[offset])) {
    search_result_t result;
    result.address = m_HeaderSize + offset;
    result.size = sigFile.GetSymbolSize(nSymbol);
    sigFile.GetSymbolName(nSymbol, result.name, sizeof(result.name));
    AddResult(result);

    // add results from relocations
    for (size_t nReloc = 0; nReloc < sigFile.GetNumRelocs(nSymbol); nReloc++) {
      char relocName[128];
      sigFile.GetRelocName(nSymbol, nReloc, relocName, sizeof(relocName));
      uint8_t const relocType = sigFile.GetRelocType(nSymbol, nReloc);
      uint32_t const relocOffset = sigFile.GetRelocOffset(nSymbol, nReloc);

      uint32_t const opcode = bswap32(*reinterpret_cast<uint32_t*>(&m_Binary[offset + relocOffset]));

      switch (relocType) {
        case R_MIPS_HI16:
          if (!relocMap.contains(relocName)) {
            relocMap[relocName].haveHi16 = true;
            relocMap[relocName].haveLo16 = false;
          }
          relocMap[relocName].address = (opcode & 0x0000FFFF) << 16;
          break;
        case R_MIPS_LO16:
          if (relocMap.contains(relocName)) {
            relocMap[relocName].address += static_cast<int16_t>(opcode & 0x0000FFFF);
          } else {
            printf("missing hi16?");
            exit(0);
          }
          break;
        case R_MIPS_26:
          relocMap[relocName].address = (m_HeaderSize & 0xF0000000) + ((opcode & 0x03FFFFFF) << 2);
          break;
      }

      // printf("%s %02X %04X\n", relocName, relocType, relocOffset);
    }

    for (auto& i : relocMap) {
      search_result_t relocResult;
      relocResult.address = i.second.address;
      relocResult.size = 0;
      strncpy(relocResult.name, i.first.c_str(), sizeof(relocResult.name) - 1);
      AddResult(relocResult);
    }
    // printf("-------\n");

    return true;
  }
  return false;
}

void CN64Sym::TallyNumSymbolsToCheck() {
  m_NumSymbolsToCheck = 0;

  if (m_bUseBuiltinSignatures) {
    m_NumSymbolsToCheck += m_BuiltinSigs.GetNumSymbols();
  }

  for (auto& m_LibPath : m_LibPaths) {
    CountSymbolsRecursive(m_LibPath);
  }
}

void CN64Sym::CountSymbolsInFile(const char* path) {
  const std::filesystem::path fs_path { path };
  if (fs_path.extension() == ".sig") {
    CSignatureFile sigFile;
    if (sigFile.Load(path)) {
      m_NumSymbolsToCheck += sigFile.GetNumSymbols();
    }
  }
}

void CN64Sym::CountSymbolsRecursive(const char* path) {
  if (IsFileWithSymbols(path)) {
    CountSymbolsInFile(path);
    return;
  }
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
