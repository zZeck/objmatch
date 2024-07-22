/*

    elfutil

    Basic 32-bit big endian ELF reader
    shygoo 2018, 2020
    License: MIT

    https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
    http://www.skyfree.org/linux/references/ELF_Format.pdf
    http://www.sco.com/developers/devspecs/mipsabi.pdf

*/

#include "elfutil.h"

#include <cstdint>

#include <fstream>

CElfContext::CElfContext() = default;

auto CElfContext::Load(const char* path) -> bool {
  std::ifstream file;
  file.open(path, std::ifstream::binary);
  if (!file.is_open()) {
    return false;
  }
  file.seekg(0, std::ifstream::end);
  m_Size = file.tellg();
  file.seekg(0, std::ifstream::beg);
  m_Buffer = new uint8_t[m_Size];
  file.read(reinterpret_cast<char*>(m_Buffer), m_Size);
  return true;
}

auto CElfContext::LoadFromMemory(uint8_t* buffer, size_t size) -> bool {
  
    delete[] m_Buffer;
  

  m_Size = size;
  m_Buffer = new uint8_t[m_Size];
  memcpy(m_Buffer, buffer, m_Size);

  return true;
}

//////////////

auto CElfContext::Section(int index) -> CElfSection* {
  if (index >= NumSections()) {
    return nullptr;
  }

  uint32_t const offset = SectionHeaderOffset() + index * SectionHeaderEntrySize();

  if (offset >= Size()) {
    return nullptr;
  }

  return reinterpret_cast<CElfSection*>(reinterpret_cast<char*>(m_Buffer) + offset);
}

auto CElfContext::Section(const char* name) -> CElfSection* {
  int const nsecs = NumSections();
  for (int i = 0; i < nsecs; i++) {
    CElfSection* sec = Section(i);
    const char* curName = sec->Name(this);

    if (curName != nullptr && strcmp(curName, name) == 0) {
      return sec;
    }
  }
  return nullptr;
}

auto CElfContext::SectionIndexOf(const char* name, int* index) -> bool {
  int const nsecs = NumSections();
  for (int i = 0; i < nsecs; i++) {
    CElfSection* sec = Section(i);
    const char* curName = sec->Name(this);

    if (curName != nullptr && strcmp(sec->Name(this), name) == 0) {
      *index = i;
      return true;
    }
  }
  return false;
}

auto CElfContext::NumSymbols() -> int {
  CElfSection* sym_sec = Section(".symtab");
  if (sym_sec == nullptr) {
    return 0;
  }
  return sym_sec->Size() / sizeof(CElfSymbol);
}

auto CElfContext::NumTextRelocations() -> int {
  CElfSection* rel_text_sec = Section(".rel.text");
  if (rel_text_sec == nullptr) {
    return 0;
  }
  return rel_text_sec->Size() / sizeof(CElfRelocation);
}

auto CElfContext::TextRelocation(int index) -> CElfRelocation* {
  CElfSection* rel_text_sec = Section(".rel.text");
  if (rel_text_sec == nullptr) {
    return nullptr;
  }
  return (CElfRelocation*)(rel_text_sec->Data(this) + (index * sizeof(CElfRelocation)));
}

auto CElfContext::Symbol(int index) -> CElfSymbol* {
  CElfSection* sym_sec = Section(".symtab");
  if (sym_sec == nullptr) {
    return nullptr;
  }
  return (CElfSymbol*)(sym_sec->Data(this) + (index * sizeof(CElfSymbol)));
}

//////////////

auto CElfSection::Name(CElfContext* elf) const -> const char* {
  CElfSection* shstr_sec = elf->Section(elf->SectionNamesIndex());

  if (shstr_sec == nullptr) {
    return nullptr;
  }

  uint32_t const nameOffset = NameOffset();

  if (nameOffset >= shstr_sec->Size()) {
    return nullptr;
  }

  if (shstr_sec->Offset() + nameOffset >= elf->Size()) {
    return nullptr;
  }

  const char* shstr_data = shstr_sec->Data(elf);
  return &shstr_data[NameOffset()];
}

auto CElfSection::Data(CElfContext* elf) const -> const char* {
  uint32_t const offset = Offset();

  if (offset >= elf->Size()) {
    return nullptr;
  }

  return (reinterpret_cast<char*>(elf->Header())) + Offset();
}

//////////////

auto CElfSymbol::Name(CElfContext* elf) const -> const char* {
  CElfSection* str_sec = elf->Section(".strtab");

  if (str_sec == nullptr) {
    return nullptr;
  }

  return str_sec->Data(elf) + NameOffset();
}

auto CElfSymbol::Section(CElfContext* elf) const -> const CElfSection* { return elf->Section(SectionIndex()); }

//////////////

auto CElfRelocation::Symbol(CElfContext* elf) const -> CElfSymbol* { return elf->Symbol(SymbolIndex()); }