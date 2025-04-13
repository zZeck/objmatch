#include <algorithm>
#include <array>
#include <bit>
#include <crc32c/crc32c.h>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <elf.h>
#include <fcntl.h>
#include <png.h>
#include <print>
#include <ranges>
#include <span>
#include <tuple>
#include <vector>
#include <gelf.h>
#include <libelf.h>
#include <unistd.h>

#include "splat_out.h"
#include "signature.h"
#include "matcher.h"


namespace {
template<typename T>
auto vector_reserved(uint64_t size) -> std::vector<T> {
  std::vector<T> vec(size);
  vec.reserve(size);
  return vec;
}

auto readswap32(const std::span<const uint8_t, 4> &buf) -> uint32_t {
  uint32_t word{};
  std::memcpy(&word, buf.data(), 4);

  return std::byteswap(word);
}
}

auto load(const std::filesystem::path &path) -> std::vector<char> {
  auto file_size = std::filesystem::file_size(path);
  std::vector<char> file_data{vector_reserved<char>(file_size)};

  std::ifstream file {path, std::ios::in | std::ios::binary};
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  file.read(reinterpret_cast<char*>(file_data.data()), static_cast<int64_t>(file_size));
  return file_data;
}

auto matcher(const std::vector<splat_out> &yaml, const std::vector<char> &rom, int archive_file_descriptor, std::string prefix) -> std::vector<splat_out> {
  if(elf_version(EV_CURRENT) == EV_NONE) std::print("version out of date");

  auto sec_patterns = archive_to_section_patterns(archive_file_descriptor);

  std::ranges::sort(sec_patterns, [](section_pattern const &a, section_pattern const &b) {
    auto size_cmp = a.size <=> b.size;
    if (size_cmp != 0) return size_cmp < 0;
    auto crc_cmp = a.crc_all <=> b.crc_all;
    return crc_cmp < 0;
  });

  //this needs a test and fix, it's bugged
  //needs to remove any and ALL non-unique elements, not filter to a now unique list, leaving 1 representative element behind
  //for any that had duplicates
  const auto [first, last] = std::ranges::unique(sec_patterns,
    [](section_pattern const &a, section_pattern const &b) { return a.crc_all == b.crc_all; });

  sec_patterns.erase(first, last);

  using start_pattern = struct start_pattern {
    uint64_t start {};
    section_pattern pattern {};
  };

  std::vector<start_pattern> matched_patterns{};
  for(auto entry : yaml) {
    auto maybe_pattern = std::ranges::find_if(sec_patterns, [entry, rom](const auto &pattern) {
      auto data = std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(&rom[entry.start]), std::min(static_cast<uint64_t>(rom.size()), static_cast<uint64_t>(pattern.size)));
      return section_compare(pattern, data);
    });

    if (maybe_pattern != sec_patterns.end()) {
      const auto &pattern = *maybe_pattern;

      matched_patterns.push_back(start_pattern{
        .start = entry.start,
        .pattern = pattern
      });
    }
  }

  //problem: sometimes the same pattern matches multiple places in the yaml
  std::ranges::sort(matched_patterns, [](start_pattern const &a, start_pattern const &b) {
    auto crc_cmp = a.pattern.crc_all <=> b.pattern.crc_all;
    return crc_cmp < 0;
  });

  //group_by might be better, but that isn't compiling, and in this case the logical outcome is the same as chunk_by
  //the type for this is terrifying, and I can't get std::ranges::to<std::vector> to work
  //nor can I understand the error messages
  auto patterns_unique_only = matched_patterns
    | std::views::chunk_by([](start_pattern const &a, start_pattern const &b) {
      return a.pattern.crc_all == b.pattern.crc_all;
    })
    | std::views::filter(([](auto r) { return std::ranges::size(r) == 1; }) )
    | std::views::join;

  std::vector<splat_out> output{};
  for(auto i = 0; i < yaml.size(); i+=1) {
    const auto &entry = yaml[i];

    auto maybe_pattern = std::ranges::find_if(patterns_unique_only, [entry](const auto &pattern_match) {
      return entry.start == pattern_match.start;
    });

    if (maybe_pattern != patterns_unique_only.end()) {
      const auto &pattern = maybe_pattern->pattern;
      auto obj_name = std::filesystem::path {pattern.object};
      auto type = std::string{
        pattern.section == ".text" ? "c" :
        pattern.section == ".data" ? ".data" :
        pattern.section == ".rodata" ? ".rodata" :
        "bin"};

      output.push_back(splat_out{
        .start = entry.start,
        .vram = entry.vram,
        .type = type,
        .name = prefix + std::string{obj_name.stem()}
      });

      if(i+1 < yaml.size()) {
        const auto &next_entry = yaml[i + 1];
        if(next_entry.start > entry.start + pattern.size) {
          output.push_back(splat_out{
            .start = entry.start + pattern.size,
            .vram = entry.vram,
            .type = "bin",
            .name = std::format("bin_0x{:x}", entry.start + pattern.size)
          });
        } else if (next_entry.start < entry.start + pattern.size) {
          //error should be collected somehow, easier to test
          std::println(stderr, "Pattern {} {} matched at 0x{:x} is too large", pattern.object, pattern.section, entry.start);
        }
      } else output.push_back(splat_out{
        .start = entry.start + pattern.size,
        .vram = entry.vram,
        .type = "bin",
        .name = std::format("bin_0x{:x}", entry.start + pattern.size)
      });
    } else {
        auto copy = entry;
        output.push_back(copy);
    }
  }

  return output;
}

auto analyze(int archive_file_descriptor) -> void {
  if (elf_version(EV_CURRENT) == EV_NONE) std::print("version out of date");

  auto sec_patterns = archive_to_section_patterns(archive_file_descriptor);

  std::ranges::sort(sec_patterns, [](section_pattern const &a, section_pattern const &b) {
    auto size_cmp = a.size <=> b.size;
    if (size_cmp != 0) return size_cmp < 0;
    auto crc_cmp = a.crc_all <=> b.crc_all;
    return crc_cmp < 0;
  });

  //auto view1 = sec_patterns | std::views::chunk_by([](const section_pattern &x, const section_pattern &y) {
  //  return x.crc_all == y.crc_all;
  //});

  const auto [first, last] = std::ranges::unique(sec_patterns,
    [](section_pattern const &a, section_pattern const &b) { return a.crc_all == b.crc_all; });

  sec_patterns.erase(first, last);


  std::println("{}", std::string_view{pattern_yaml::serialize(sec_patterns)});

  return;
}


auto object_processing(Elf *object_file_elf) -> std::tuple<obj_ctx_status, object_context> {
  object_context obj_ctx{};
  auto archive_header = elf_getarhdr(object_file_elf);  // null check?

  obj_ctx.object_name = archive_header->ar_name;
  const std::filesystem::path object_path{archive_header->ar_name};
  // done to ignore / and //, hopefully nothing else. Perhaps they should be ignored directly rather than looking for ! .o
  if (object_path.extension() != ".o") return std::make_tuple(obj_ctx_status::not_object, object_context{});

  size_t section_header_string_table_index = 0;
  elf_getshdrstrndx(object_file_elf, &section_header_string_table_index);  // must return 0 for success
  obj_ctx.section_header_string_table_index = section_header_string_table_index;

  {
    Elf_Scn *section = nullptr;
    while ((section = elf_nextscn(object_file_elf, section)) != nullptr) {
      // gelf functions need allocated space to copy to
      GElf_Shdr section_header;
      gelf_getshdr(section, &section_header);  // error if not returns &section_header?

      auto section_name = elf_strptr(object_file_elf, obj_ctx.section_header_string_table_index, section_header.sh_name);

      //these could have slightly different names
      //should it just get all PROGBITS? are these all PROGBITS?
      if (strcmp(section_name, ".text") == 0 || strcmp(section_name, ".data") == 0 || strcmp(section_name, ".rodata") == 0 ||
          strcmp(section_name, ".bss") == 0) {
        elf_ndxscn(section); //err check
        obj_ctx.sections.push_back(section_relocations{.section = section});
      }

      // should I find this by section type?
      // SHT_SYMTAB
      if (strcmp(section_name, ".symtab") == 0) {
        obj_ctx.symtab_section = section;
        obj_ctx.symtab_header = section_header;
      }
    }

    //two loops, because I don't think you can STRICTLY SPEAKING
    //assume a relocation section will be AFTER the section it relocates
    while ((section = elf_nextscn(object_file_elf, section)) != nullptr) {
      // gelf functions need allocated space to copy to
      GElf_Shdr section_header;
      gelf_getshdr(section, &section_header);  // error if not returns &section_header?
      //SHT_RELA as well?
      if (section_header.sh_type == SHT_REL) {
        if (auto it = std::ranges::find_if(obj_ctx.sections,
                                   [section_header](section_relocations section_rel) {
                                     return section_header.sh_info == elf_ndxscn(section_rel.section);
                                   });
            it != obj_ctx.sections.end()) {
          it->relocations = section;
        }
      }

      // SHT_REL
      // if (rel_text_section != nullptr && text_section != nullptr && symtab_section != nullptr) break;
    }
  }

  if (obj_ctx.symtab_section == nullptr) return std::make_tuple(obj_ctx_status::no_symtab, object_context{});

  auto symbol_data = elf_getdata(obj_ctx.symtab_section, nullptr);
  obj_ctx.symbol_data = symbol_data;

  auto symbol_count = obj_ctx.symtab_header.sh_size / obj_ctx.symtab_header.sh_entsize;  // do null check on header and make count 0 if null?
  obj_ctx.symbol_count = symbol_count;

  // optional extended section index table
  // > 0 or != 0 ??? 0 IS a legit index, but not for this section, and indicates failure.
  auto extended_section_index_table_index = elf_scnshndx(obj_ctx.symtab_section);
  auto xndxdata = extended_section_index_table_index == 0 ? nullptr : elf_getdata(elf_getscn(object_file_elf, extended_section_index_table_index), nullptr);
  obj_ctx.xndxdata = xndxdata;

  return std::make_tuple(obj_ctx_status::ok, obj_ctx);
}

auto archive_to_section_patterns(int archive_file_descriptor) -> std::vector<section_pattern> {
  auto archive_elf = elf_begin(archive_file_descriptor, ELF_C_READ, nullptr);  // null check

  std::vector<section_pattern> section_patterns{};

  Elf_Cmd elf_command = ELF_C_READ;
  Elf *object_file_elf = nullptr;
  while ((object_file_elf = elf_begin(archive_file_descriptor, elf_command, archive_elf)) != nullptr) {
    auto [obj_status, obj_ctx] = object_processing(object_file_elf);

    if (obj_status != obj_ctx_status::ok) {
      elf_command = elf_next(object_file_elf);
      elf_end(object_file_elf);
      continue;
    }

    section_patterns.reserve(obj_ctx.sections.size());

    for (auto sec_rec : obj_ctx.sections) {
      using section_context = struct {
        GElf_Shdr section_header;
        char *section_name;
        size_t section_index;
        Elf_Data *section_data;
        std::span<uint8_t> section_span;
        Elf_Data *relocation_data;
        Elf64_Xword rel_entry_count;
      };

      auto [sig_sec, section_ctx] = ([&sec_rec, &object_file_elf, &obj_ctx]() {
        GElf_Shdr section_header;
        gelf_getshdr(sec_rec.section, &section_header);  // error if not returns &section_header?
        auto section_name = elf_strptr(object_file_elf, obj_ctx.section_header_string_table_index, section_header.sh_name);

        auto section_index = elf_ndxscn(sec_rec.section);
        auto section_data  = elf_getdata(sec_rec.section, nullptr); //what if section_data is null?
        auto section_span = std::span<uint8_t>(static_cast<uint8_t *>(section_data->d_buf), section_data->d_size);

        GElf_Shdr rel_section_header;
        auto rel_section_header_ptr = gelf_getshdr(sec_rec.relocations, &rel_section_header);  // error if not returns &section_header?
        auto relocation_data = elf_getdata(sec_rec.relocations, nullptr);

        auto rel_entry_count = rel_section_header_ptr == nullptr ? 0 : rel_section_header.sh_size / rel_section_header.sh_entsize;

        return std::make_tuple(
          sig_section { .size = section_header.sh_size, .name = std::string(section_name)},
          section_context {
            .section_header = section_header,
            .section_name = section_name,
            .section_index = section_index,
            .section_data = section_data,
            .section_span = section_span,
            .relocation_data = relocation_data,
            .rel_entry_count = rel_entry_count
          });
      })();

      // filter out no size
      if (section_ctx.section_data->d_size == 0) continue;
      // filter NOBITS like bss
      if (section_ctx.section_header.sh_type == SHT_NOBITS) continue;

      section_pattern sec_pat {
        .object = std::string(obj_ctx.object_name),
        .section = std::string(section_ctx.section_name),
        .size = section_ctx.section_data->d_size
      };

      uint32_t lastHi16Addend = 0;

      // copy the section into a buffer, then loop over all relocations and patch them to be 0s
      // FOR PERFORMANCE this should really be allocated outside of this loop and resized per iteration
      auto sec_buff = vector_reserved<uint8_t>(section_ctx.section_span.size());
      std::ranges::copy(section_ctx.section_span, sec_buff.begin());

      for (int relocation_index = 0; relocation_index < section_ctx.rel_entry_count; relocation_index++) {
        GElf_Rel relocation;
        gelf_getrel(section_ctx.relocation_data, relocation_index, &relocation);  // why does this return relocation and take in argument by ptr?

        auto relocation_type = GELF_R_TYPE(relocation.r_info);

        // HOW TO HANDLE OTHER TYPES NOW?
        //section_data or d_type is possibly null? lint error
        //if (section_data->d_type != ELF_T_BYTE) {
        //}  // this is an error

        const std::span<uint8_t, 4> opcode(&sec_buff[relocation.r_offset], 4);

        uint32_t addend = 0;

        // both STB_LOCAL and STB_GLOBAL
        // binding types go through here
        // but only STB_LOCAL seems to ever have an addend that is not 0
        // perhaps this is because most globals, like function refs, will have an addend of 0?

        // possibly could use libelf for this conversion using ELF_T_WORD or something?
        // the transformation to do here, depends the platform of the elf file
        // But not the platform I'm running on, right? because IN REGISTER, things will be in the expected order
        // probably should add comment explaining why alternatives are bad, alignment issues, host platform issues
        auto opcodeBE = readswap32(opcode);

        if (relocation_type == R_MIPS_HI16) {
          addend = (opcodeBE & 0xFFFF) << 16;
          GElf_Rel relocation2;
          // note, index + 1
          gelf_getrel(section_ctx.relocation_data, relocation_index + 1, &relocation2);  // todo guard

          // next relocation must be LO16
          auto relocation2_type = GELF_R_TYPE(relocation2.r_info);
          if (relocation2_type != R_MIPS_LO16) {
            //error
          }

          const std::span<uint8_t, 4> opcode2(&sec_buff[relocation2.r_offset], 4);
          auto opcode2BE = readswap32(opcode2);

          addend += static_cast<int16_t>(opcode2BE & 0xFFFF);
          lastHi16Addend = addend;

        } else if (relocation_type == R_MIPS_LO16) {
          addend = lastHi16Addend;
        } else if (relocation_type == R_MIPS_26) {
          addend = (opcodeBE & 0x03FFFFFF) << 2;
        }

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

        sec_pat.relocations.push_back(sec_relocation{.type = relocation_type,
                                                     .offset = relocation.r_offset,
                                                     .addend = addend});
      }

      if (section_ctx.section_span.size() > 0) {
        sec_pat.crc_8 = crc32c::Crc32c(sec_buff.data(), std::min(static_cast<uint64_t>(sec_buff.size()), static_cast<uint64_t>(8)));
        sec_pat.crc_all = crc32c::Crc32c(sec_buff.data(), sec_buff.size());
      }

      section_patterns.push_back(sec_pat);
    }

    elf_command = elf_next(object_file_elf);
    elf_end(object_file_elf);
  }

  return section_patterns;
}

std::vector<uint8_t> data_buf{};

auto section_compare(const section_pattern &pattern, std::span<const uint8_t> data) -> bool {
  if (pattern.size != data.size()) return false;

  data_buf.resize(pattern.size);
  data_buf.reserve(pattern.size);
  std::ranges::copy(data, data_buf.begin());

  for (const auto &reloc : pattern.relocations) {
    if (reloc.type == 4) {
      //R_MIPS_26
      data_buf[reloc.offset + 0] &= 0xFC;
      data_buf[reloc.offset + 1] = 0x00;
      data_buf[reloc.offset + 2] = 0x00;
      data_buf[reloc.offset + 3] = 0x00;
    } else if (reloc.type == 5 || reloc.type == 6) {
      //R_MIPS_HI16 || R_MIPS_LO16
      data_buf[reloc.offset + 2] = 0x00;
      data_buf[reloc.offset + 3] = 0x00;
    }
  }

  const auto crcA = crc32c::Crc32c(data_buf.data(), std::min(pattern.size, static_cast<uint64_t>(8)));

  if (pattern.crc_8 != crcA) return false;

  const auto crcB = crc32c::Crc32c(data_buf.data(), pattern.size);

  return pattern.crc_all == crcB;
}
