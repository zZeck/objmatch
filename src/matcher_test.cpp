#include <catch2/catch_test_macros.hpp>
#include <vector>

#include "matcher.h"

TEST_CASE("object_processing", "[matcher]") {
  auto archive_path = std::filesystem::path {"./src/object_test_src/out/libexample.a"};
  auto archive_file_descriptor = open(archive_path.c_str(), O_RDONLY | O_CLOEXEC);

  // does catch2 have a place for global initialization?
  if (elf_version(EV_CURRENT) == EV_NONE) std::print("version out of date");

  auto archive_elf = elf_begin(archive_file_descriptor, ELF_C_READ, nullptr);  // null check

  auto sig_library = std::vector<sig_object>();

  Elf_Cmd elf_command = ELF_C_READ;
  //auto object_file_elf = elf_begin(archive_file_descriptor, elf_command, archive_elf); 
  //auto [obj_status, sig_obj, obj_ctx] = object_processing(object_file_elf);

  Elf *object_file_elf = nullptr;
  while ((object_file_elf = elf_begin(archive_file_descriptor, elf_command, archive_elf)) != nullptr) {
    auto [obj_status, sig_obj, obj_ctx] = object_processing(object_file_elf);

    if (obj_status != obj_ctx_status::ok) {
      elf_command = elf_next(object_file_elf);
      elf_end(object_file_elf);
      continue;
    }

    elf_command = elf_next(object_file_elf);
    elf_end(object_file_elf);
    close(archive_file_descriptor);
  }
}
