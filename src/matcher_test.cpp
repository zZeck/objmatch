#include <catch2/catch_test_macros.hpp>
#include <vector>
#include "signature.h"

#include "matcher.h"

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
