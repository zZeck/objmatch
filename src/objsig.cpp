#include "objsig.h"

#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <yaml-cpp/yaml.h>

#include <algorithm>
#include <boost/crc.hpp>
#include <cstring>
#include <filesystem>
#include <vector>

#include "signature.h"

auto ObjSigAnalyze(const char *path) -> bool {
  const std::filesystem::path fs_path{path};
  if (fs_path.extension() == ".a") {
    auto temp = ProcessLibrary(fs_path.c_str());
    YAML::Node node;
    node = temp;
    YAML::Emitter emitter;
    emitter << node;
    printf("%s\n", emitter.c_str());
  }

  return true;
}

auto ProcessLibrary(const char *path) -> std::vector<sig_object> {
  auto archive_file_descriptor = open(path, O_RDONLY | O_CLOEXEC);

  // move to main or static?
  if (elf_version(EV_CURRENT) == EV_NONE) {
    printf("version out of date");
  }

  auto archive_elf = elf_begin(archive_file_descriptor, ELF_C_READ, nullptr);  // null check

  auto sig_library = std::vector<sig_object>();

  std::unordered_map<uint32_t, int> symbol_crcs;

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

    /// PROCESS OBJECT START

    size_t section_header_string_table_index = 0;
    elf_getshdrstrndx(object_file_elf, &section_header_string_table_index);  // must return 0 for success

    Elf_Scn *symtab_section = nullptr;
    GElf_Shdr symtab_header;

    using section_relocations = struct {
      Elf_Scn *section;
      Elf_Scn *relocations;
    };

    std::vector<section_relocations> sections;
    {
      Elf_Scn *section = nullptr;
      while ((section = elf_nextscn(object_file_elf, section)) != nullptr) {
        // gelf functions need allocated space to copy to
        GElf_Shdr section_header;
        gelf_getshdr(section, &section_header);  // error if not returns &section_header?

        auto section_name = elf_strptr(object_file_elf, section_header_string_table_index, section_header.sh_name);

        if (strcmp(section_name, ".text") == 0 || strcmp(section_name, ".data") == 0 || strcmp(section_name, ".rodata") == 0 ||
            strcmp(section_name, ".bss") == 0) {
          elf_ndxscn(section); //err check
          sections.push_back(section_relocations{.section = section});
        }

        if (section_header.sh_type == SHT_REL) {
          if (auto it = std::find_if(sections.begin(), sections.end(),
                                     [section_header](section_relocations section_rel) {
                                       auto index = elf_ndxscn(section_rel.section);

                                       return section_header.sh_info == index;
                                     });
              it != sections.end()) {
            it->relocations = section;
          }
        }

        // should I find this by section type?
        // SHT_SYMTAB
        if (strcmp(section_name, ".symtab") == 0) {
          symtab_section = section;
          symtab_header = section_header;
        }

        // SHT_REL
        // if (rel_text_section != nullptr && text_section != nullptr && symtab_section != nullptr) break;
      }
    }

    if (symtab_section == nullptr) {
      elf_command = elf_next(object_file_elf);
      elf_end(object_file_elf);
      continue;
    }

    auto symbol_data = elf_getdata(symtab_section, nullptr);

    auto symbol_count = symtab_header.sh_size / symtab_header.sh_entsize;  // do null check on header and make count 0 if null?

    // optional extended section index table
    // > 0 or != 0 ??? 0 IS a legit index, but not for this section, and indicates failure.
    auto extended_section_index_table_index = elf_scnshndx(symtab_section);
    auto xndxdata = extended_section_index_table_index == 0 ? nullptr : elf_getdata(elf_getscn(object_file_elf, extended_section_index_table_index), nullptr);

    auto sig_obj = sig_object{.file = object_path.string()};
    for (auto sec_rec : sections) {
      GElf_Shdr section_header;
      gelf_getshdr(sec_rec.section, &section_header);  // error if not returns &section_header?
      auto section_name = elf_strptr(object_file_elf, section_header_string_table_index, section_header.sh_name);

      auto section_index = elf_ndxscn(sec_rec.section);
      auto section_data = elf_getdata(sec_rec.section, nullptr); //what if section_data is null?

      GElf_Shdr rel_section_header;
      auto rel_section_header_ptr = gelf_getshdr(sec_rec.relocations, &rel_section_header);  // error if not returns &section_header?
      auto relocation_data = elf_getdata(sec_rec.relocations, nullptr);

      auto rel_entry_count = rel_section_header_ptr == nullptr ? 0 : rel_section_header.sh_size / rel_section_header.sh_entsize;

      auto sig_sec = sig_section{.size = section_header.sh_size, .name = std::string(section_name)};

      for (int nSymbol = 0; nSymbol < symbol_count; nSymbol++) {
        GElf_Sym libelf_symbol;
        gelf_getsym(symbol_data, nSymbol, &libelf_symbol); //err check

        auto symbol_referencing_section_index = libelf_symbol.st_shndx;
        auto symbol_name = elf_strptr(object_file_elf, symtab_header.sh_link, libelf_symbol.st_name);
        auto symbol_type = GELF_ST_TYPE(libelf_symbol.st_info);
        auto symbol_size = libelf_symbol.st_size;
        auto symbol_offset = libelf_symbol.st_value;

        //|| symbol_type != STT_FUNC
        // the symbol for the section, shares its name
        // processing it is worse than useless currently, because relocation handling 0s out the addends
        // in the entire section
        // Should I label week symbols in the output?
        // They basically just get processed for lookups
        // all that is needed is the symbol's offset
        // also is there any part of the code below that can misbehave with a weak symbol?
        if (symbol_referencing_section_index != section_index || (symbol_type != STB_WEAK && symbol_size == 0) || strcmp(symbol_name, section_name) == 0) {
          continue;
        }

        uint32_t lastHi16Addend = 0;

        auto sig_sym = sig_symbol{.offset = symbol_offset, .size = symbol_size, .symbol = std::string(symbol_name)};

        for (int relocation_index = 0; relocation_index < rel_entry_count; relocation_index++) {
          GElf_Rel relocation;
          gelf_getrel(relocation_data, relocation_index, &relocation);  // why does this return relocation and take in argument by ptr?

          if (relocation.r_offset < libelf_symbol.st_value || relocation.r_offset >= libelf_symbol.st_value + libelf_symbol.st_size) {
            continue;
          }

          Elf32_Word extended_section_index{};
          GElf_Sym rel_symbol;  // should I be using symmem directly? why use the returned pointer?
          auto rel_symbol_index = GELF_R_SYM(relocation.r_info);
          auto rel_symbol_ptr = gelf_getsymshndx(symbol_data, xndxdata, rel_symbol_index, &rel_symbol,
                                                 &extended_section_index);  // guess this works fine with extended section index table null?

          // some relocations have no symbol
          // although should I check for that by their type, rather than a failure here?
          // could be skipping over something that failed for another reason
          if (rel_symbol_ptr == nullptr) continue;

          auto rel_symbol_name = elf_strptr(object_file_elf, symtab_header.sh_link, rel_symbol.st_name);
          auto rel_symbol_binding = GELF_ST_BIND(rel_symbol.st_info);

          auto section_referenced_by_symbol = elf_getscn(object_file_elf, rel_symbol.st_shndx);
          GElf_Shdr section_referenced_by_symbol_header;
          gelf_getshdr(section_referenced_by_symbol, &section_referenced_by_symbol_header);

          auto relocation_type = GELF_R_TYPE(relocation.r_info);

          // HOW TO HANDLE OTHER TYPES NOW?
          //section_data or d_type is possibly null? lint error
          //if (section_data->d_type != ELF_T_BYTE) {
          //}  // this is an error

          auto opcode = reinterpret_cast<uint8_t *>(section_data->d_buf) + relocation.r_offset;

          auto is_local = false;
          uint32_t addend = 0;

          // both STB_LOCAL and STB_GLOBAL
          // binding types go through here
          // but only STB_LOCAL seems to ever have an addend that is not 0
          // perhaps this is because most globals, like function refs, will have an addend of 0?

          // possibly could use libelf for this conversion using ELF_T_WORD or something?
          // the transformation to do here, depends the platform of the elf file
          // But not the platform I'm running on, right? because IN REGISTER, things will be in the expected order
          // probably should add comment explaining why alternatives are bad, alignment issues, host platform issues
          auto opcodeBE = opcode[0] << 8 * 3 | opcode[1] << 8 * 2 | opcode[2] << 8 * 1 | opcode[3] << 8 * 0;

          if (relocation_type == R_MIPS_HI16) {
            addend = (opcodeBE & 0xFFFF) << 16;
            GElf_Rel relocation2;
            // note, index + 1
            gelf_getrel(relocation_data, relocation_index + 1, &relocation2);  // todo guard

            // next relocation must be LO16
            auto relocation2_type = GELF_R_TYPE(relocation2.r_info);
            if (relocation2_type != R_MIPS_LO16) {
              //error
            }

            auto opcode2 = reinterpret_cast<const uint8_t *>(section_data->d_buf) + relocation2.r_offset;
            auto opcode2BE = opcode2[0] << 8 * 3 | opcode2[1] << 8 * 2 | opcode2[2] << 8 * 1 | opcode2[3] << 8 * 0;

            addend += static_cast<int16_t>(opcode2BE & 0xFFFF);
            lastHi16Addend = addend;

          } else if (relocation_type == R_MIPS_LO16) {
            addend = lastHi16Addend;
          } else if (relocation_type == R_MIPS_26) {
            addend = (opcodeBE & 0x03FFFFFF) << 2;
          }

          if (rel_symbol_binding == STB_LOCAL) {
            is_local = true;
          }

          // THIS IS BAD DESIGN
          // mutates the elf buffer
          // If I want to try out new code
          // now the buffer is messed up and the relocation addend is wiped
          // Also, the .text symbol covers the range of all the function data
          // and processing it causes all addends to be wiped
          //  set addend to 0 before crc
          if (relocation_type == R_MIPS_HI16 || relocation_type == R_MIPS_LO16) {
            opcode[2] = 0x00;
            opcode[3] = 0x00;
          } else if (relocation_type == R_MIPS_26) {
            opcode[0] &= 0xFC;
            opcode[1] = 0x00;
            opcode[2] = 0x00;
            opcode[3] = 0x00;
          } else {
            // Need to log more context
            // printf("# warning unhandled relocation type\n");
            continue;
            // printf("unk rel %d\n", relType);
            // exit(0);
          }

          sig_sym.relocations.push_back(sig_relocation{.type = relocation_type,
                                                       .offset = relocation.r_offset - libelf_symbol.st_value,
                                                       .addend = addend,
                                                       .local = is_local,
                                                       .name = std::string(rel_symbol_name)});
        }

        //// STRIP AND RELCOS END

        //.bss had no data
        // Later, this should take relocations into account
        // rather than zeroing out that data out before this executes, in the rel handling.
        // This would avoid mutation of the buffer.
        if (section_data != nullptr && section_data->d_buf != nullptr) {
          boost::crc_32_type result;
          result.process_bytes(&reinterpret_cast<uint8_t *>(section_data->d_buf)[symbol_offset],
                               std::min(reinterpret_cast<uint64_t>(symbol_size), reinterpret_cast<uint64_t>(UINT64_C(8))));
          sig_sym.crc_8 = result.checksum();
          result.reset();
          result.process_bytes(&reinterpret_cast<uint8_t *>(section_data->d_buf)[symbol_offset], symbol_size);
          sig_sym.crc_all = result.checksum();
        }

        symbol_crcs[sig_sym.crc_all] += 1;
        sig_sec.symbols.push_back(sig_sym);
      }

      sig_obj.sections.push_back(sig_sec);
    }

    sig_library.push_back(sig_obj);
    elf_command = elf_next(object_file_elf);
    elf_end(object_file_elf);
  }
  close(archive_file_descriptor);

  // remove any symbols with matching CRCs
  // impossible to use the CRC alone to determine which one it is in ROM
  // FLIRT will not have this problem
  // still need them to use for lookups
  for (auto &sig_obj : sig_library) {
    for (auto &sig_section : sig_obj.sections) {
      for (auto &sig_sym : sig_section.symbols) {
        sig_sym.duplicate_crc = symbol_crcs[sig_sym.crc_all] > 1;
      }
    }
  }

  return sig_library;
}
