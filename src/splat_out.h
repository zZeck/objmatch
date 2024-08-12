#pragma once

#include <vector>
#include <string>
#include <yaml-cpp/yaml.h>

using splat_out = struct {
  uint64_t start;
  uint64_t vram;
  std::string type;
  std::string name;
};

namespace YAML {
template <>
struct convert<splat_out> {
  static Node encode(const splat_out &splat_out) {
    Node node;
    node["start"] = splat_out.start;
    node["vram"] = splat_out.vram;
    node["type"] = splat_out.type;
    node["name"] = splat_out.name;
    return node;
  }
  static bool decode(const Node &node, splat_out &splat_out) {
    splat_out.start = node["start"].as<uint64_t>();
    splat_out.vram = node["vram"].as<uint64_t>();
    splat_out.type = node["type"].as<std::string>();
    splat_out.name = node["name"].as<std::string>();
    return true;
  }
};
}