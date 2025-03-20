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
  char *object_name;
  size_t section_header_string_table_index;
  Elf_Scn *symtab_section;
  GElf_Shdr symtab_header;
  std::vector<section_relocations> sections;
  Elf_Data *symbol_data;
  Elf64_Xword symbol_count;
  Elf_Data *xndxdata;
};

using sec_relocation = struct sec_relocation {
  uint64_t type{};
  uint64_t offset{};
  uint32_t addend{};

  auto operator==(const sec_relocation &x) const -> bool  = default;
};


using section_pattern = struct section_pattern {
  std::string object;
  std::string section;
  uint64_t size{};
  uint32_t crc_8{};
  uint32_t crc_all{};
  std::vector<sec_relocation> relocations;

  auto operator==(const section_pattern &x) const -> bool  = default;
};

enum class obj_ctx_status : std::uint8_t { ok, not_object, no_symtab };

auto object_processing(Elf *object_file_elf) -> std::tuple<obj_ctx_status, object_context>;
auto archive_to_section_patterns(int archive_file_descriptor) -> std::vector<section_pattern>;
auto matcher_main(int argc, const char* argv[]) -> int;
