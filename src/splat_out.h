#pragma once

#include <yaml-cpp/yaml.h>

#include <format>
#include <string>
#include <vector>

using splat_out = struct splat_out {
  uint64_t start{};
  uint64_t vram{};
  std::string type{};
  std::string name{};
};

namespace YAML {
template <>
struct convert<splat_out> {
  static auto encode(const splat_out &splat_out) -> Node {
    Node node;
    node["start"] = std::format("0x{:x}", splat_out.start);
    node["vram"] = std::format("0x{:x}", splat_out.vram);
    node["type"] = splat_out.type;
    node["name"] = splat_out.name;
    return node;
  }
  static auto decode(const Node &node, splat_out &splat_out) -> bool {
    splat_out.start = node["start"].as<uint64_t>();
    splat_out.vram = node["vram"].as<uint64_t>();
    splat_out.type = node["type"].as<std::string>();
    splat_out.name = node["name"].as<std::string>();
    return true;
  }
};
}
