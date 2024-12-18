#pragma once

#include <cstdint>
#include <string>
#include <vector>

using splat_out = struct splat_out {
  uint64_t start{};
  uint64_t vram{};
  std::string type;
  std::string name;
};

namespace splat_yaml {
    auto serialize(const std::vector<splat_out> &splat_outs) -> std::vector<char>;
}
