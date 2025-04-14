#include <print>
#include "matcher.h"
#include "splat_out.h"
#include "files_to_mapping.h"
#include "file_path_yaml.h"

auto main(int argc, const char* argv[]) -> int {
  const std::span<const char *> args = {argv, static_cast<size_t>(argc)};

  if (*args[1] != 'f') {
    auto dir_path = std::filesystem::path {args[2]};

    auto result = files_to_mapping(dir_path);

    std::println("{}", std::string_view{file_path_yaml::serialize(result)});

    //auto archive_path = std::filesystem::path {args[2]};
    //auto archive_file_descriptor = open(archive_path.c_str(), O_RDONLY | O_CLOEXEC);

    //analyze(archive_file_descriptor);
    return 0;
  }

  auto file_path = std::filesystem::path {args[2]};

  auto yaml_data = load(file_path);
  auto yaml = splat_yaml::deserialize(yaml_data);

  auto rom_path = std::filesystem::path {args[3]};
  auto rom = load(rom_path);

  auto archive_path = std::filesystem::path {args[4]};
  auto archive_file_descriptor = open(archive_path.c_str(), O_RDONLY | O_CLOEXEC);

  auto dir_path = std::string {args[5]};
  auto result = files_to_mapping(dir_path);

  auto prefix = std::string {args[6]};

  // move to main or static?
  auto output = matcher(yaml, rom, archive_file_descriptor, result, prefix);

  close(archive_file_descriptor);

  auto blah = splat_yaml::serialize(output);

  std::println("{}", std::string_view(blah));

  return 0;
}
