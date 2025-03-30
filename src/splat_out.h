#pragma once

#include <cstdint>
#include <string>
#include <vector>

using splat_out = struct splat_out {
  uint64_t start{};
  uint64_t vram{};
  std::string type;
  std::string name;

  auto operator==(const splat_out &x) const -> bool  = default;
};

namespace splat_yaml {
    auto deserialize(std::vector<char> &bytes) -> std::vector<splat_out>;
    auto serialize(const std::vector<splat_out> &splat_outs) -> std::vector<char>;
}
