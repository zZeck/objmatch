#include <catch2/catch_test_macros.hpp>
#include <filesystem>
#include <print>
#include <vector>
#include <string_view>
#include "files_to_mapping.h"

TEST_CASE("files to mapping", "[files to mapping]") {
  std::filesystem::path path {"src/file_mapping"};
  auto result = files_to_mapping(path);

  std::vector<file_path> expect {
    file_path {
      .file {"Asomething.o"},
      .path {"subdir0"}
    },
    file_path {
      .file {"Bsomething.o"},
      .path {"subdir1"}
    }
  };

  REQUIRE(result == expect);
}
