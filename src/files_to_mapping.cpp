#include <filesystem>
#include <ranges>
#include <vector>
#include "files_to_mapping.h"

auto files_to_mapping(std::filesystem::path path) -> std::vector<file_path> {
  auto blah = std::filesystem::recursive_directory_iterator(path);

  auto eee = blah
    | std::views::filter([](const std::filesystem::directory_entry &x) { return !x.is_directory() && (x.path().extension() == ".c" || x.path().extension() == ".s"); })
    | std::views::transform([path](const std::filesystem::directory_entry &x) {
      return file_path {
        .file {std::string{x.path().stem()} + ".o"},
        .path {std::filesystem::relative(x.path().parent_path(), path)}
      };
  });

  auto ggg = eee | std::ranges::to<std::vector>();
  return ggg;
}
