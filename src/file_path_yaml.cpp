#include <vector>
#include "file_path.h"

#include <c4/format.hpp>
#include <ryml.hpp>
#include <ryml_std.hpp>

namespace file_path_yaml {
  auto serialize(const std::vector<file_path> &file_paths) -> std::vector<char> {
    ryml::Tree tree;
    auto root = tree.rootref();
    root |= ryml::SEQ;

    for(const auto &file_path : file_paths) {
      auto file_path_yaml = root.append_child();
      file_path_yaml |= ryml::MAP;
      file_path_yaml["file"] << file_path.file;
      file_path_yaml["path"] << file_path.path;
    }
    return ryml::emitrs_yaml<std::vector<char>>(tree);
  }
}
