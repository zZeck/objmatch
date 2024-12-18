#include <filesystem>
#include <fstream>
#include <ryml.hpp>
#include <ryml_std.hpp>
#include <span>
#include <vector>

#include "signature.h"

auto main(int argc, const char *argv[]) -> int {
  const std::span<const char *> args{argv, static_cast<size_t>(argc)};

  const auto yaml_path{args[1]};

  std::ifstream file;
  file.open(yaml_path, std::ifstream::binary);

  const auto file_size{std::filesystem::file_size(yaml_path)};
  std::vector<char> yaml_data;
  yaml_data.reserve(file_size);

  yaml_data.assign(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());

  sig_yaml::deserialize(yaml_data);
}
