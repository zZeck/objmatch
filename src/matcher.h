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
#include <unordered_map>
#include <unistd.h>
#include "signature.h"

using section_relocations = struct {
  Elf_Scn *section;
  Elf_Scn *relocations;
};

using object_context = struct {
  size_t section_header_string_table_index;
  Elf_Scn *symtab_section;
  GElf_Shdr symtab_header;
  std::vector<section_relocations> sections;
  Elf_Data *symbol_data;
  Elf64_Xword symbol_count;
  Elf_Data *xndxdata;
};

enum class obj_ctx_status : std::uint8_t { ok, not_object, no_symtab };

auto object_processing(Elf *object_file_elf) -> std::tuple<obj_ctx_status, sig_object, object_context>;
auto matcher_main(int argc, const char* argv[]) -> int;
