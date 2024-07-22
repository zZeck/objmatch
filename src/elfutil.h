/*

    elfutil

    Basic 32-bit big endian ELF reader
    shygoo 2018, 2020
    License: MIT

    https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
    http://www.skyfree.org/linux/references/ELF_Format.pdf
    http://www.sco.com/developers/devspecs/mipsabi.pdf

*/

#ifndef ELFUTIL_H
#define ELFUTIL_H

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

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

enum {
  EI_MAG0 = 0,
  EI_MAG1 = 1,
  EI_MAG2 = 2,
  EI_MAG3 = 3,
  EI_CLASS = 4,
  EI_DATA = 5,
  EI_VERSION = 6,
  EI_OSABI = 7,
  EI_ABIVERSION = 8,
  EI_PAD = 7,
  EI_NIDENT = 16
};

enum {
  ELFCLASSNONE = 0,  // Invalid class
  ELFCLASS32 = 1,    // 32-bit objects
  ELFCLASS64 = 2     // 64-bit objects
};

// mips relocation types
enum {
  R_MIPS_NONE = 0,
  R_MIPS_16 = 1,
  R_MIPS_32 = 2,
  R_MIPS_REL32 = 3,
  R_MIPS_26 = 4,
  R_MIPS_HI16 = 5,
  R_MIPS_LO16 = 6,
  R_MIPS_GPREL16 = 7,
  R_MIPS_LITERAL = 8,
  R_MIPS_GOT16 = 9,
  R_MIPS_CALL16 = 21
};

// special section numbers
enum { SHN_UNDEF = 0x0000, SHN_LORESERVE = 0xFF00, SHN_LOPROC = 0xFF00, SHN_HIPROC = 0xFF1F, SHN_ABS = 0xFFF1, SHN_COMMON = 0xFFF2, SHN_HIRESERVE = 0xFFFF };

// symbol bindings
enum { STB_LOCAL = 0, STB_GLOBAL = 1, STB_WEAK = 2, STB_LOPROC = 13, STB_HIPROC = 15 };

// symbol types
enum { STT_NOTYPE = 0, STT_OBJECT = 1, STT_FUNC = 2, STT_SECTION = 3, STT_FILE = 4, STT_LOPROC = 13, STT_HIPROC = 15 };

class CElfContext;
class CElfHeader;
class CElfSection;
class CElfSymbol;
class CElfRelocation;

using CElfHeader = struct CElfHeader {
  uint8_t e_ident[EI_NIDENT];
  uint16_t e_type;
  uint16_t e_machine;
  uint32_t e_version;
  uint32_t e_entry;
  uint32_t e_phoff;
  uint32_t e_shoff;
  uint32_t e_flags;
  uint16_t e_ehsize;
  uint16_t e_phentsize;
  uint16_t e_phnum;
  uint16_t e_shentsize;
  uint16_t e_shnum;
  uint16_t e_shstrndx;
};

class CElfContext {
  // CElfHeader* m_ElfHeader;
  uint8_t* m_Buffer{nullptr};
  size_t m_Size{0};

 public:
  auto Header() -> CElfHeader* { return reinterpret_cast<CElfHeader*>(m_Buffer); }

  CElfContext();

  auto Load(const char* path) -> bool;
  auto LoadFromMemory(uint8_t* buffer, size_t size) -> bool;

  auto ABI() -> uint8_t { return Header()->e_ident[EI_OSABI]; }
  auto Machine() -> uint16_t { return bswap16(Header()->e_machine); }
  auto SectionHeaderOffset() -> uint32_t { return bswap32(Header()->e_shoff); }
  auto SectionHeaderEntrySize() -> uint16_t { return bswap16(Header()->e_shentsize); }
  auto NumSections() -> uint16_t { return bswap16(Header()->e_shnum); }
  auto SectionNamesIndex() -> uint16_t { return bswap16(Header()->e_shstrndx); }

  [[nodiscard]] auto Size() const -> size_t const { return m_Size; }

  auto Section(int index) -> CElfSection*;
  auto Section(const char* name) -> CElfSection*;
  auto SectionIndexOf(const char* name, int* index) -> bool;

  auto NumSymbols() -> int;
  auto Symbol(int index) -> CElfSymbol*;

  auto NumTextRelocations() -> int;
  auto TextRelocation(int index) -> CElfRelocation*;
};

class CElfSection {
  uint32_t sh_name;
  uint32_t sh_type;
  uint32_t sh_flags;
  uint32_t sh_addr;
  uint32_t sh_offset;
  uint32_t sh_size;
  uint32_t sh_link;
  uint32_t sh_info;
  uint32_t sh_addralign;
  uint32_t sh_entsize;

 public:
  [[nodiscard]] auto NameOffset() const -> uint32_t const { return bswap32(sh_name); }
  [[nodiscard]] auto Offset() const -> uint32_t const { return bswap32(sh_offset); }
  [[nodiscard]] auto Size() const -> uint32_t const { return bswap32(sh_size); }

  auto Name(CElfContext* elf) const -> const char*;
  auto Data(CElfContext* elf) const -> const char*;
};

class CElfSymbol {
  uint32_t st_name;
  uint32_t st_value;
  uint32_t st_size;
  uint8_t st_info;
  uint8_t st_other;
  uint16_t st_shndx;

 public:
  [[nodiscard]] auto NameOffset() const -> uint32_t const { return bswap32(st_name); }
  [[nodiscard]] auto Value() const -> uint32_t const { return bswap32(st_value); }
  [[nodiscard]] auto Size() const -> uint32_t const { return bswap32(st_size); }
  [[nodiscard]] auto Info() const -> uint8_t const { return st_info; }
  [[nodiscard]] auto Other() const -> uint8_t const { return st_other; }
  [[nodiscard]] auto SectionIndex() const -> uint16_t const { return bswap16(st_shndx); }

  [[nodiscard]] auto Type() const -> uint8_t { return static_cast<uint8_t>(Info() & 0x0F); }
  [[nodiscard]] auto Binding() const -> uint8_t { return static_cast<uint8_t>(Info() >> 4); }
  auto Name(CElfContext* elf) const -> const char*;
  auto Section(CElfContext* elf) const -> const CElfSection*;
};

class CElfRelocation {
  uint32_t r_offset;
  uint32_t r_info;

 public:
  [[nodiscard]] auto Offset() const -> uint32_t const { return bswap32(r_offset); }
  [[nodiscard]] auto Info() const -> uint32_t const { return bswap32(r_info); }
  [[nodiscard]] auto SymbolIndex() const -> uint32_t { return Info() >> 8; }
  [[nodiscard]] auto Type() const -> uint8_t { return static_cast<uint8_t>(Info() & 0x0F); }

  auto Symbol(CElfContext* elf) const -> CElfSymbol*;
};

#endif  // ELFUTIL_H
