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
#include "splat_out.h"
#include "section_pattern.h"

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




enum class obj_ctx_status : std::uint8_t { ok, not_object, no_symtab };

auto object_processing(Elf *object_file_elf) -> std::tuple<obj_ctx_status, object_context>;
auto archive_to_section_patterns(int archive_file_descriptor) -> std::vector<section_pattern>;
auto section_compare(const section_pattern &pattern, std::span<const uint8_t> data) -> bool;
auto load(const std::filesystem::path &path) -> std::vector<char>;
auto matcher(const std::vector<splat_out> &splat, const std::vector<char> &rom, int archive_file_descriptor, std::string prefix) -> std::vector<splat_out>;
auto analyze(int archive_file_descriptor) -> void;
