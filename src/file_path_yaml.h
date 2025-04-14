#include <filesystem>
#include <vector>
#include "file_path.h"

namespace file_path_yaml {
  auto serialize(const std::vector<file_path> &file_path) -> std::vector<char>;
}
