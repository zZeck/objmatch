#pragma once
#include <string>

using file_path = struct file_path {
  std::string file;
  std::string path;

  auto operator==(const file_path &x) const -> bool  = default;
};
