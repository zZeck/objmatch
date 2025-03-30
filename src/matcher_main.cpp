#include "matcher.h"

auto main(int argc, const char* argv[]) -> int {
  const std::span<const char *> args = {argv, static_cast<size_t>(argc)};

  auto file_path = std::filesystem::path {args[1]};

  auto yaml_data = load(file_path);
  auto yaml = splat_yaml::deserialize(yaml_data);

  auto rom_path = std::filesystem::path {args[2]};
  auto rom = load(rom_path);

  auto archive_path = std::filesystem::path {args[3]};
  auto archive_file_descriptor = open(archive_path.c_str(), O_RDONLY | O_CLOEXEC);

  // move to main or static?
  auto output = matcher(yaml, rom, archive_file_descriptor, "");

  close(archive_file_descriptor);

  return 0;
}
