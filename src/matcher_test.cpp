#include <catch2/catch_test_macros.hpp>
#include <format>
#include <vector>
#include "signature.h"
#include "splat_out.h"

#include "matcher.h"
#include <libelf.h>

TEST_CASE("object_processing", "[matcher]") {
  auto archive_path = std::filesystem::path {"src/object_test_src/out/libexample.a"};
  auto archive_file_descriptor = open(archive_path.c_str(), O_RDONLY | O_CLOEXEC);

  // does catch2 have a place for global initialization?
  if (elf_version(EV_CURRENT) == EV_NONE) std::print("version out of date");

  auto archive_elf = elf_begin(archive_file_descriptor, ELF_C_READ, nullptr);  // null check

  auto sig_library = std::vector<sig_object>();

  Elf_Cmd elf_command = ELF_C_READ;
  //auto object_file_elf = elf_begin(archive_file_descriptor, elf_command, archive_elf); 
  //auto [obj_status, sig_obj, obj_ctx] = object_processing(object_file_elf);

  Elf *object_file_elf = nullptr;
  obj_ctx_status obj_status{};
  object_context obj_ctx{};
  while ((object_file_elf = elf_begin(archive_file_descriptor, elf_command, archive_elf)) != nullptr) {
    auto [obj_status_t, obj_ctx_t] = object_processing(object_file_elf);
    obj_status = obj_status_t;
    obj_ctx = obj_ctx_t;

    if (obj_status != obj_ctx_status::ok) {
      elf_command = elf_next(object_file_elf);
      elf_end(object_file_elf);
      continue;
    }
    break;
  }

  REQUIRE(obj_ctx.object_name == std::string{"example.o"});

  elf_command = elf_next(object_file_elf);
  elf_end(object_file_elf);
  close(archive_file_descriptor);
}

TEST_CASE("archive_to_section_patterns", "[matcher]") {
  auto archive_path = std::filesystem::path {"src/object_test_src/out/libexample.a"};
  auto archive_file_descriptor = open(archive_path.c_str(), O_RDONLY | O_CLOEXEC);

  // does catch2 have a place for global initialization?
  if (elf_version(EV_CURRENT) == EV_NONE) std::print("version out of date");

  auto temp0 = archive_to_section_patterns(archive_file_descriptor);

  close(archive_file_descriptor);

  REQUIRE(temp0.size() == 3);
  REQUIRE(temp0[0].object == std::string{"example.o"});
  REQUIRE(temp0[0].section == std::string{".text"});
  REQUIRE(temp0[1].object == std::string{"example.o"});
  REQUIRE(temp0[1].section == std::string{".data"});
  REQUIRE(temp0[2].object == std::string{"example.o"});
  REQUIRE(temp0[2].section == std::string{".bss"});
}

TEST_CASE("find_section_in_bin", "[matcher]") {
  auto start = std::filesystem::path {"src/object_test_src/out/start"};
  auto start_descriptor = open(start.c_str(), O_RDONLY | O_CLOEXEC);
  auto start_bin = std::filesystem::path {"src/object_test_src/out/start.bin"};
  auto archive_path = std::filesystem::path {"src/object_test_src/out/libexample.a"};
  auto archive_file_descriptor = open(archive_path.c_str(), O_RDONLY | O_CLOEXEC);

  // does catch2 have a place for global initialization?
  if (elf_version(EV_CURRENT) == EV_NONE) std::print("version out of date");

  

  auto sig_library = std::vector<sig_object>();

  Elf_Cmd elf_command = ELF_C_READ;
  //auto object_file_elf = elf_begin(archive_file_descriptor, elf_command, archive_elf); 
  //auto [obj_status, sig_obj, obj_ctx] = object_processing(object_file_elf);

  Elf_Scn *symtab_section{};
  GElf_Shdr symtab_header;
  GElf_Shdr lowest_alloc_section {
    .sh_addr = std::numeric_limits<Elf64_Addr>::max()
  };
  auto start_elf = elf_begin(start_descriptor, ELF_C_READ, nullptr);  // null check
  size_t section_header_string_table_index{};
  elf_getshdrstrndx(start_elf, &section_header_string_table_index);  // must return 0 for success

  Elf_Scn *section{};
  while ((section = elf_nextscn(start_elf, section)) != nullptr) {
    // gelf functions need allocated space to copy to
    GElf_Shdr section_header;
    gelf_getshdr(section, &section_header);  // error if not returns &section_header?

    auto section_name = elf_strptr(start_elf, section_header_string_table_index, section_header.sh_name);

    if (strcmp(section_name, ".symtab") == 0) {
      symtab_section = section;
      symtab_header = section_header;
    }

    if (section_header.sh_flags & SHF_ALLOC && section_header.sh_addr < lowest_alloc_section.sh_addr) {
      lowest_alloc_section = section_header;
    }
  }

  auto symbol_count = symtab_header.sh_size / symtab_header.sh_entsize; 
  auto symbol_data = elf_getdata(symtab_section, nullptr);

  GElf_Sym libelf_symbol;
  for (int nSymbol = 0; nSymbol < symbol_count; nSymbol++) {
    gelf_getsym(symbol_data, nSymbol, &libelf_symbol); //err check

    auto symbol_name = elf_strptr(start_elf, symtab_header.sh_link, libelf_symbol.st_name);

    if (strcmp(symbol_name, "example") == 0) {
      break;
    }
  }

  auto offset_in_bin = libelf_symbol.st_value - lowest_alloc_section.sh_addr;

  auto temp0 = archive_to_section_patterns(archive_file_descriptor);

  auto start_bin_data = load(start_bin);


  auto data = std::span<uint8_t>(reinterpret_cast<uint8_t *>(&start_bin_data[offset_in_bin]), std::min(static_cast<uint64_t>(start_bin_data.size()), static_cast<uint64_t>(temp0[0].size)));

  auto match = section_compare(temp0[0], data);


  elf_end(start_elf);
  close(start_descriptor);
  close(archive_file_descriptor);

  REQUIRE(match);
}

TEST_CASE("matcher", "[matcher]") {
  auto start = std::filesystem::path {"src/object_test_src/out/start"};
  auto start_descriptor = open(start.c_str(), O_RDONLY | O_CLOEXEC);
  auto start_bin = std::filesystem::path {"src/object_test_src/out/start.bin"};
  auto archive_path = std::filesystem::path {"src/object_test_src/out/libexample.a"};
  auto archive_file_descriptor = open(archive_path.c_str(), O_RDONLY | O_CLOEXEC);

  // does catch2 have a place for global initialization?
  if (elf_version(EV_CURRENT) == EV_NONE) std::print("version out of date");

  auto sig_library = std::vector<sig_object>();

  Elf_Cmd elf_command = ELF_C_READ;
  //auto object_file_elf = elf_begin(archive_file_descriptor, elf_command, archive_elf); 
  //auto [obj_status, sig_obj, obj_ctx] = object_processing(object_file_elf);

  Elf_Scn *symtab_section{};
  GElf_Shdr symtab_header;
  GElf_Shdr lowest_alloc_section {
    .sh_addr = std::numeric_limits<Elf64_Addr>::max()
  };
  auto start_elf = elf_begin(start_descriptor, ELF_C_READ, nullptr);  // null check
  size_t section_header_string_table_index{};
  elf_getshdrstrndx(start_elf, &section_header_string_table_index);  // must return 0 for success

  Elf_Scn *section{};
  while ((section = elf_nextscn(start_elf, section)) != nullptr) {
    // gelf functions need allocated space to copy to
    GElf_Shdr section_header;
    gelf_getshdr(section, &section_header);  // error if not returns &section_header?

    auto section_name = elf_strptr(start_elf, section_header_string_table_index, section_header.sh_name);

    if (strcmp(section_name, ".symtab") == 0) {
      symtab_section = section;
      symtab_header = section_header;
    }

    if (section_header.sh_flags & SHF_ALLOC && section_header.sh_addr < lowest_alloc_section.sh_addr) {
      lowest_alloc_section = section_header;
    }
  }

  auto symbol_count = symtab_header.sh_size / symtab_header.sh_entsize; 
  auto symbol_data = elf_getdata(symtab_section, nullptr);

  GElf_Sym libelf_symbol;
  Elf64_Addr text_offset{};
  Elf64_Xword text_size{};
  Elf64_Addr data_offset{};
  Elf64_Addr rodata_offset{};
  Elf64_Xword rodata_size{};
  for (int nSymbol = 0; nSymbol < symbol_count; nSymbol++) {
    gelf_getsym(symbol_data, nSymbol, &libelf_symbol); //err check

    auto symbol_name = elf_strptr(start_elf, symtab_header.sh_link, libelf_symbol.st_name);

    if (strcmp(symbol_name, "example") == 0) {
      text_offset = libelf_symbol.st_value - lowest_alloc_section.sh_addr;
      text_size = libelf_symbol.st_size;
    } else if (strcmp(symbol_name, "number0") == 0) {
      data_offset = libelf_symbol.st_value - lowest_alloc_section.sh_addr;
    } else if (strcmp(symbol_name, "number1") == 0) {
      rodata_offset = libelf_symbol.st_value - lowest_alloc_section.sh_addr;
      rodata_size = libelf_symbol.st_size;
    } 
  }

  auto start_bin_data = load(start_bin);

  auto prefix = std::string{"some/path/"};

  std::vector<splat_out> yaml {
    splat_out {
      .start = text_offset,
      .vram = 0,
      .type = "bin",
      .name = "random"
    }, splat_out {
      .start = data_offset,
      .vram = 0,
      .type = "bin",
      .name = "random"
    }, splat_out {
      .start = rodata_offset,
      .vram = 0,
      .type = "bin",
      .name = "random"
    }, splat_out {
      .start = rodata_offset + rodata_size + 5,
      .vram = 0,
      .type = "bin",
      .name = "random"
    }
  };

  auto result = matcher(yaml, start_bin_data, archive_file_descriptor, prefix);

  close(start_descriptor);
  close(archive_file_descriptor);

  std::vector<splat_out> expected {
    splat_out {
      .start = text_offset,
      .vram = 0,
      .type = "c",
      .name = prefix + "example"
    }, splat_out {
      .start = text_offset + text_size,
      .vram = 0,
      .type = "bin",
      .name = std::format("bin_0x{:x}", text_offset + text_size)
    },  splat_out {
      .start = data_offset,
      .vram = 0,
      .type = ".data",
      .name = prefix + "example"
    }, splat_out {
      .start = rodata_offset,
      .vram = 0,
      .type = ".rodata",
      .name = prefix + "example"
    }, splat_out {
      .start = rodata_offset + rodata_size,
      .vram = 0,
      .type = "bin",
      .name = std::format("bin_0x{:x}", rodata_offset + rodata_size)
    },
     splat_out {
      .start = rodata_offset + rodata_size + 5,
      .vram = 0,
      .type = "bin",
      .name = "random"
    }
  };

  REQUIRE(result == expected);
}

TEST_CASE("matcher duplicate sections", "[matcher]") {
  auto start = std::filesystem::path {"src/object_test_src/out/start_copy"};
  auto start_descriptor = open(start.c_str(), O_RDONLY | O_CLOEXEC);
  auto start_bin = std::filesystem::path {"src/object_test_src/out/start_copy.bin"};
  auto archive_path = std::filesystem::path {"src/object_test_src/out/libexample.a"};
  auto archive_file_descriptor = open(archive_path.c_str(), O_RDONLY | O_CLOEXEC);

  // does catch2 have a place for global initialization?
  if (elf_version(EV_CURRENT) == EV_NONE) std::print("version out of date");

  auto sig_library = std::vector<sig_object>();

  Elf_Cmd elf_command = ELF_C_READ;
  //auto object_file_elf = elf_begin(archive_file_descriptor, elf_command, archive_elf); 
  //auto [obj_status, sig_obj, obj_ctx] = object_processing(object_file_elf);

  Elf_Scn *symtab_section{};
  GElf_Shdr symtab_header;
  GElf_Shdr lowest_alloc_section {
    .sh_addr = std::numeric_limits<Elf64_Addr>::max()
  };
  auto start_elf = elf_begin(start_descriptor, ELF_C_READ, nullptr);  // null check
  size_t section_header_string_table_index{};
  elf_getshdrstrndx(start_elf, &section_header_string_table_index);  // must return 0 for success

  Elf_Scn *section{};
  while ((section = elf_nextscn(start_elf, section)) != nullptr) {
    // gelf functions need allocated space to copy to
    GElf_Shdr section_header;
    gelf_getshdr(section, &section_header);  // error if not returns &section_header?

    auto section_name = elf_strptr(start_elf, section_header_string_table_index, section_header.sh_name);

    if (strcmp(section_name, ".symtab") == 0) {
      symtab_section = section;
      symtab_header = section_header;
    }

    if (section_header.sh_flags & SHF_ALLOC && section_header.sh_addr < lowest_alloc_section.sh_addr) {
      lowest_alloc_section = section_header;
    }
  }

  auto symbol_count = symtab_header.sh_size / symtab_header.sh_entsize; 
  auto symbol_data = elf_getdata(symtab_section, nullptr);

  GElf_Sym libelf_symbol;
  Elf64_Addr text_offset{};
  Elf64_Xword text_size{};
  Elf64_Addr copy_text_offset{};
  Elf64_Xword copy_text_size{};
  for (int nSymbol = 0; nSymbol < symbol_count; nSymbol++) {
    gelf_getsym(symbol_data, nSymbol, &libelf_symbol); //err check

    auto symbol_name = elf_strptr(start_elf, symtab_header.sh_link, libelf_symbol.st_name);

    if (strcmp(symbol_name, "example") == 0) {
      text_offset = libelf_symbol.st_value - lowest_alloc_section.sh_addr;
      text_size = libelf_symbol.st_size;
    } else if (strcmp(symbol_name, "example2") == 0) {
      copy_text_offset = libelf_symbol.st_value - lowest_alloc_section.sh_addr;
      copy_text_size = libelf_symbol.st_size;
    }
  }

  auto start_bin_data = load(start_bin);

  auto prefix = std::string{"some/path/"};

  std::vector<splat_out> yaml {
    splat_out {
      .start = text_offset,
      .vram = 0,
      .type = "bin",
      .name = "random"
    }, splat_out {
      .start = copy_text_offset,
      .vram = 0,
      .type = "bin",
      .name = "random"
    }
  };

  auto result = matcher(yaml, start_bin_data, archive_file_descriptor, prefix);

  close(start_descriptor);
  close(archive_file_descriptor);

  REQUIRE(result == yaml);
}

TEST_CASE("matcher2", "[matcher]") {
  auto archive_path = std::filesystem::path {"src/object_test_src/out/libcopyexample.a"};
  auto archive_file_descriptor = open(archive_path.c_str(), O_RDONLY | O_CLOEXEC);

  // does catch2 have a place for global initialization?
  if (elf_version(EV_CURRENT) == EV_NONE) std::print("version out of date");

  analyze(archive_file_descriptor);

  close(archive_file_descriptor);

  REQUIRE(true);
}
