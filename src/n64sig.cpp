/*

    n64sig
    Signature file generator for n64sym
    shygoo 2020
    License: MIT

*/

#ifdef WIN32
#include <windirent.h>
#else
#include <dirent.h>
#endif

#include <fcntl.h>


#include <algorithm>
#include <boost/crc.hpp>
#include <cstring>
#include <filesystem>

#include "n64sig.h"

#include <gelf.h>
#include <libelf.h>

CN64Sig::CN64Sig() = default;

CN64Sig::~CN64Sig() = default;

void CN64Sig::AddLibPath(const char *path) { m_LibPaths.push_back(path); }

auto stricmp(const char *a, const char *b) -> int {
  size_t const alen = strlen(a);
  size_t const blen = strlen(b);

  size_t const len = std::min(alen, blen);

  for (size_t i = 0; i < len; i++) {
    int const ac = tolower(a[i]);
    int const bc = tolower(b[i]);

    if (ac < bc) return -1;
    if (ac > bc) return 1;
  }

  if (alen < blen) return -1;
  if (alen > blen) return 1;

  return 0;
}

auto strPastUnderscores(const char *s) -> const char *const {
  while (*s == '_') {
    s++;
  }
  return s;
}

auto CN64Sig::Run() -> bool {
  m_NumProcessedSymbols = 0;

  printf("# sig_v1\n\n");

  for (auto libPath : m_LibPaths) {
    ScanRecursive(libPath);
  }

  if (m_bVerbose) {
    printf("# %zu symbols\n", m_SymbolMap.size());
    printf("# %zu processed\n", m_NumProcessedSymbols);
  }

  // copy symbol map to into a vector and sort it by symbol name

  std::vector<symbol_entry_t> symbols;

  symbols.reserve(m_SymbolMap.size());
  for (auto &i : m_SymbolMap) {
    symbols.push_back(i.second);
  }

  std::sort(symbols.begin(), symbols.end(),
            [](symbol_entry_t &a, symbol_entry_t &b) { return stricmp(strPastUnderscores(a.name), strPastUnderscores(b.name)) < 0; });

  if (m_OutputFormat == N64SIG_FMT_DEFAULT) {
    for (auto &symbolEntry : symbols) {
      printf("%s 0x%04X 0x%08X 0x%08X\n", symbolEntry.name, symbolEntry.size, symbolEntry.crc_a, symbolEntry.crc_b);

      if (symbolEntry.relocs == nullptr) {
        continue;
      }

      for (auto &j : *symbolEntry.relocs) {
        const reloc_entry_t &relocEntry = j.first;
        const std::vector<uint16_t> &offsets = j.second;

        printf(" .%-6s %s", GetRelTypeName(relocEntry.relocType), relocEntry.relocSymbolName);

        for (auto &offset : offsets) {
          printf(" 0x%03X", offset);
        }

        printf("\n");
      }

      delete symbolEntry.relocs;

      printf("\n");
    }
  } else if (m_OutputFormat == N64SIG_FMT_JSON) {
    /*
    ["alCSPNew", 0x016C, 0x3DEB8DFE 0x8E97D34A, [
        ["targ26", "__initChanState", [0x0A4]],
        ["targ26", "alEvtqNew", [0x12C]]
    ]]
    */
    printf("[\n");

    bool bFirstSymbol = true;
    for (auto &symbolEntry : symbols) {
      printf("%s  [\"%s\", %u, %u, %u, [", (bFirstSymbol ? "" : ",\n"), symbolEntry.name, symbolEntry.size, symbolEntry.crc_a, symbolEntry.crc_b);

      if (symbolEntry.relocs == nullptr) {
        printf("]]");
        continue;
      }

      printf("\n");

      bool bFirstReloc = true;
      for (auto &i : *symbolEntry.relocs) {
        const reloc_entry_t &relocEntry = i.first;
        const std::vector<uint16_t> &offsets = i.second;

        printf(R"(%s    ["%s", "%s", [)", (bFirstReloc ? "" : ",\n"), GetRelTypeName(relocEntry.relocType), relocEntry.relocSymbolName);

        bool bFirstOffset = true;
        for (auto &offset : offsets) {
          printf("%s%d", (bFirstOffset ? "" : ", "), offset);
          bFirstOffset = false;
        }

        printf("]]");
        bFirstReloc = false;
      }

      printf("\n  ]]");
      bFirstSymbol = false;
    }

    printf("]");
  }

  return true;
}

auto CN64Sig::GetRelTypeName(uint8_t relType) -> const char *const {
  switch (relType) {
    case R_MIPS_26:
      return "targ26";
    case R_MIPS_LO16:
      return "lo16";
    case R_MIPS_HI16:
      return "hi16";
  }

  return nullptr;
}

void CN64Sig::FormatAnonymousSymbol(char *symbolName) {
  char *c = symbolName;
  while (*c++ != 0) {
    if (*c == '.') {
      *c = '_';
    }
  }
}

void CN64Sig::StripAndGetRelocsInSymbol(const char *objectName, reloc_map_t &relocs, GElf_Sym *symbol, Elf *elf) {
  size_t section_header_string_table_index = 0;
  elf_getshdrstrndx(elf, &section_header_string_table_index);  // must return 0 for success

  Elf_Scn *section = nullptr;
  Elf_Scn *rel_text_section = nullptr;
  GElf_Shdr rel_text_header;

  Elf_Scn *text_section = nullptr;
  GElf_Shdr text_header;
  while ((section = elf_nextscn(elf, section)) != nullptr) {
    // gelf functions need allocated space to copy to
    GElf_Shdr section_header;
    gelf_getshdr(section, &section_header);  // error if not returns &section_header?

    auto section_name = elf_strptr(elf, section_header_string_table_index, section_header.sh_name);

    if (strcmp(section_name, ".rel.text") == 0) {
      rel_text_section = section;
      rel_text_header = section_header;
    }

    if (strcmp(section_name, ".text") == 0) {
      text_section = section;
      text_header = section_header;
    }

    if (rel_text_section != nullptr && text_section != nullptr) break;
  }

  // FIX
  // this is a sign of bad design.
  // should only RUN a function like this if we KNOW there are relocations
  if (rel_text_section == nullptr || text_section == nullptr) return;

  auto relocation_data = elf_getdata(section, nullptr);

  auto symbol_section = elf_getscn(elf, rel_text_header.sh_link);
  GElf_Shdr symbol_section_header;
  gelf_getshdr(symbol_section, &symbol_section_header);
  auto symbol_data = elf_getdata(symbol_section, nullptr);

  // optional extended section index table
  auto extended_section_index_table_index =
      elf_scnshndx(symbol_section);  // > 0 or != 0 ??? 0 IS a legit index, but not for this section, and indicates failure.
  auto xndxdata = extended_section_index_table_index == 0 ? nullptr : elf_getdata(elf_getscn(elf, extended_section_index_table_index), nullptr);

  auto entry_count = rel_text_header.sh_size / rel_text_header.sh_entsize;
  uint32_t lastHi16Addend = 0;

  for (int relocation_index = 0; relocation_index < entry_count; relocation_index++) {
    GElf_Rel relocation;
    gelf_getrel(relocation_data, relocation_index, &relocation);  // why does this return relocation and take in argument by ptr?

    if (relocation.r_offset < symbol->st_value || relocation.r_offset >= symbol->st_value + symbol->st_size) {
      continue;
    }

    Elf32_Word extended_section_index;
    GElf_Sym symbol;  // should I be using symmem directly? why use the returned pointer?
    auto symbol_index = GELF_R_SYM(relocation.r_info);
    auto symbol_ptr = gelf_getsymshndx(symbol_data, xndxdata, symbol_index, &symbol,
                                       &extended_section_index);  // guess this works fine with extended section index table null?

    // some relocations have no symbol
    // although should I check for that by their type, rather than a failure here?
    // could be skipping over something that failed for another reason
    if (symbol_ptr == nullptr) continue;

    auto symbol_name = elf_strptr(elf, symbol_section_header.sh_link, symbol.st_name);
    auto symbol_type = GELF_ST_TYPE(symbol.st_info);
    auto symbol_binding = GELF_ST_BIND(symbol.st_info);

    auto section_referenced_by_symbol = elf_getscn(elf, symbol.st_shndx);
    GElf_Shdr section_referenced_by_symbol_header;
    gelf_getshdr(section_referenced_by_symbol, &section_referenced_by_symbol_header);


    auto relocation_type = GELF_R_TYPE(relocation.r_info);

    char relSymbolName[128];

    strncpy(relSymbolName, symbol_name, sizeof(relSymbolName) - 1);

    auto text_data = elf_getdata(text_section, nullptr);
    if (text_data->d_type != ELF_T_BYTE) {
    }  // this is an error

    auto opcode = reinterpret_cast<uint8_t *>(text_data->d_buf) + relocation.r_offset;

    reloc_entry_t relocEntry;

    if (symbol_binding == STB_LOCAL) {
      uint32_t addend = 0;

      // possibly could use libelf for this conversion using ELF_T_WORD or something?
      // the transformation to do here, depends the platform of the elf file
      // But not the platform I'm running on, right? because IN REGISTER, things will be in the expected order
      // probably should add comment explaining why alternatives are bad, alignment issues, host platform issues
      auto opcodeBE = opcode[0] << 8 * 3 | opcode[1] << 8 * 2 | opcode[2] << 8 * 1 | opcode[3] << 8 * 0;

      if (relocation_type == R_MIPS_HI16) {
        addend = (opcodeBE & 0xFFFF) << 16;
        GElf_Rel relocation2;
        gelf_getrel(relocation_data, relocation_index + 1, &relocation2);  // todo guard

        // next relocation must be LO16
        auto relocation2_type = GELF_R_TYPE(relocation2.r_info);
        if (relocation2_type != R_MIPS_LO16) {
          exit(EXIT_FAILURE);
        }

        auto opcode2 = reinterpret_cast<const uint8_t *>(text_data->d_buf) + relocation2.r_offset;
        auto opcode2BE = opcode2[0] << 8 * 3 | opcode2[1] << 8 * 2 | opcode2[2] << 8 * 1 | opcode2[3] << 8 * 0;

        addend += static_cast<int16_t>(opcode2BE & 0xFFFF);
        lastHi16Addend = addend;

        // printf("%08X\n", addend);
      } else if (relocation_type == R_MIPS_LO16) {
        addend = lastHi16Addend;
      } else if (relocation_type == R_MIPS_26) {
        addend = (opcodeBE & 0x03FFFFFF) << 2;
      }

      auto relSymbolSectionName = elf_strptr(elf, section_header_string_table_index, section_referenced_by_symbol_header.sh_name);

      snprintf(relSymbolName, sizeof(relSymbolName), "%s_%s_%04X", objectName, &relSymbolSectionName[1], addend);

      // printf("# %08X\n", relSymbol->Value());
    }

    // set addend to 0 before crc
    if (relocation_type == R_MIPS_HI16 || relocation_type == R_MIPS_LO16) {
      opcode[2] = 0x00;
      opcode[3] = 0x00;
    } else if (relocation_type == R_MIPS_26) {
      opcode[0] &= 0xFC;
      opcode[1] = 0x00;
      opcode[2] = 0x00;
      opcode[3] = 0x00;
    } else {
      printf("# warning unhandled relocation type\n");
      continue;
      // printf("unk rel %d\n", relType);
      // exit(0);
    }

    relocEntry.relocType = relocation_type;
    strncpy(relocEntry.relocSymbolName, relSymbolName, sizeof(relocEntry.relocSymbolName));

    relocs[relocEntry].push_back(relocation.r_offset - symbol.st_value);
  }
}

void CN64Sig::ProcessLibrary(const char *path) {
  auto archive_file_descriptor = open(path, O_RDONLY);

  // move to main or static?
  if (elf_version(EV_CURRENT) == EV_NONE) {
    printf("version out of date");
  }

  auto archive_elf = elf_begin(archive_file_descriptor, ELF_C_READ, nullptr);  // null check

  Elf_Cmd elf_command = ELF_C_READ;
  Elf *object_file_elf = nullptr;
  while ((object_file_elf = elf_begin(archive_file_descriptor, elf_command, archive_elf)) != nullptr) {
    auto archive_header = elf_getarhdr(object_file_elf);  // null check?

    const std::filesystem::path object_path{archive_header->ar_name};
    if (object_path.extension() != ".o") {
      elf_command = elf_next(object_file_elf);
      elf_end(object_file_elf);
      continue;
    }

    // use u8string later?
    auto objectName = strdup(object_path.stem().string().c_str());

    size_t elfsize = 0;
    auto rawelf = reinterpret_cast<uint8_t *>(elf_rawfile(object_file_elf, &elfsize));  // error check

    ProcessObject(object_file_elf, objectName);

    free(objectName);

    elf_command = elf_next(object_file_elf);
    elf_end(object_file_elf);
  }
  close(archive_file_descriptor);
}

void CN64Sig::ProcessObject(Elf *elf, const char *objectName) {
  // printf("# object: %s\n", objectName);

  size_t section_header_string_table_index = 0;
  elf_getshdrstrndx(elf, &section_header_string_table_index);  // must return 0 for success

  Elf_Scn *section = nullptr;
  Elf_Scn *text_section = nullptr;
  GElf_Shdr text_header;

  Elf_Scn *symtab_section = nullptr;
  GElf_Shdr symtab_header;
  while ((section = elf_nextscn(elf, section)) != nullptr) {
    // gelf functions need allocated space to copy to
    GElf_Shdr section_header;
    gelf_getshdr(section, &section_header);  // error if not returns &section_header?

    auto section_name = elf_strptr(elf, section_header_string_table_index, section_header.sh_name);

    if (strcmp(section_name, ".text") == 0) {
      text_section = section;
      text_header = section_header;
    }

    if (strcmp(section_name, ".symtab") == 0) {
      symtab_section = section;
      symtab_header = section_header;
    }
  }

  if (text_section == nullptr) return;

  auto text_data = elf_getdata(text_section, nullptr);

  auto text_index = elf_ndxscn (text_section);

  auto symbol_data = elf_getdata(symtab_section, nullptr);

  auto symbol_count = symtab_header.sh_size / symtab_header.sh_entsize;

  // optional extended section index table
  auto extended_section_index_table_index =
      elf_scnshndx(symtab_section);  // > 0 or != 0 ??? 0 IS a legit index, but not for this section, and indicates failure.
  auto xndxdata = extended_section_index_table_index == 0 ? nullptr : elf_getdata(elf_getscn(elf, extended_section_index_table_index), nullptr);

  for (int nSymbol = 0; nSymbol < symbol_count; nSymbol++) {
    GElf_Sym libelf_symbol;
    auto symbol_ptr = gelf_getsym(symbol_data, nSymbol, &libelf_symbol);

    auto symbol_referencing_section_index = libelf_symbol.st_shndx;
    auto symbol_name = elf_strptr(elf, symtab_header.sh_link, libelf_symbol.st_name);
    auto symbol_type = GELF_ST_TYPE(libelf_symbol.st_info);
    auto symbol_size = libelf_symbol.st_size;
    auto symbol_offset = libelf_symbol.st_value;

    if (symbol_referencing_section_index != text_index || symbol_type != STT_FUNC || symbol_size == 0) {
      continue;
    }

    symbol_entry_t symbolEntry;
    strncpy(symbolEntry.name, symbol_name, sizeof(symbolEntry.name) - 1);
    symbolEntry.relocs = new reloc_map_t;
    StripAndGetRelocsInSymbol(objectName, *symbolEntry.relocs, &libelf_symbol, elf);

    boost::crc_32_type result;

    symbolEntry.size = symbol_size;

    result.process_bytes(&reinterpret_cast<uint8_t *>(text_data->d_buf)[symbol_offset], std::min(reinterpret_cast<uint64_t>(symbol_size), reinterpret_cast<uint64_t>(UINT64_C(8))));
    symbolEntry.crc_a = result.checksum();
    result.reset();
    result.process_bytes(&reinterpret_cast<uint8_t *>(text_data->d_buf)[symbol_offset], symbol_size);
    symbolEntry.crc_b = result.checksum();

    m_NumProcessedSymbols++;

    if (m_SymbolMap.contains(symbolEntry.crc_b)) {
      if (m_bVerbose) {
        if (strcmp(symbolEntry.name, m_SymbolMap[symbolEntry.crc_b].name) != 0) {
          printf("# warning: skipped %s (have %s, crc: %08X)\n", symbolEntry.name, m_SymbolMap[symbolEntry.crc_b].name, symbolEntry.crc_b);
        }
      }

      delete symbolEntry.relocs;
      continue;
    }

    m_SymbolMap[symbolEntry.crc_b] = symbolEntry;
  }
}

void CN64Sig::ProcessObject(const char *path) {
  const std::filesystem::path fs_path{path};
  auto objectName = strdup(fs_path.stem().string().c_str());

  auto object_file_descriptor = open(path, O_RDONLY);

  // move to main or static?
  if (elf_version(EV_CURRENT) == EV_NONE) {
    printf("version out of date");
  }

  auto object_file_elf = elf_begin(object_file_descriptor, ELF_C_READ, nullptr);

  if (object_file_elf != nullptr) {
    ProcessObject(object_file_elf, objectName);
    elf_end(object_file_elf);
  }
  free(objectName);
  close(object_file_descriptor);
}

void CN64Sig::ProcessFile(const char *path) {
  const std::filesystem::path fs_path{path};
  if (fs_path.extension() == ".a") {
    ProcessLibrary(path);
  } else if (fs_path.extension() == ".o") {
    ProcessObject(path);
  }
}

void CN64Sig::ScanRecursive(const char *path) {
  const std::filesystem::path fs_path{path};
  if (fs_path.extension() == ".a" || fs_path.extension() == ".o") {
    ProcessFile(path);
    return;
  }
}

void CN64Sig::SetVerbose(bool bVerbose) { m_bVerbose = bVerbose; }

auto CN64Sig::SetOutputFormat(const char *format) -> bool {
  if (strcmp(format, "json") == 0) {
    m_OutputFormat = N64SIG_FMT_JSON;
    return true;
  }

  if (strcmp(format, "default") == 0) {
    m_OutputFormat = N64SIG_FMT_DEFAULT;
    return true;
  }

  return false;
}
