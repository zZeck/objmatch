#include "splat_out.h"

#include <format>
#include <vector>
#include <print>

#include <c4/format.hpp>
#include <ryml.hpp>
#include <ryml_std.hpp>

namespace {
  template<typename T>
  auto vector_reserved(uint64_t size) -> std::vector<T> {
    std::vector<T> vec(size);
    vec.reserve(size);
    return vec;
  }
}

namespace splat_yaml {
auto deserialize(std::vector<char> &bytes) -> std::vector<splat_out> {
  ryml::Tree tree{ryml::parse_in_place(ryml::to_substr(bytes))};  // mutable (csubstr) overload

  auto root{tree.crootref()};
  auto count = root.num_children();

  auto splat_outs {vector_reserved<splat_out>(count)};
  std::transform(root.begin(), root.end(), splat_outs.begin(), [](auto obj_yaml)-> splat_out {
    uint64_t start{};
    if(obj_yaml.has_child("start")) obj_yaml["start"] >> start;
    uint64_t vram{};
    obj_yaml["vram"] >> vram;
    std::string type{};
    obj_yaml["type"] >> type;
    std::string name{};
    obj_yaml["name"] >> name;

    return splat_out{.start = start, .vram = vram, .type = type, .name = name};
  });

  return splat_outs;
}

auto serialize(const std::vector<splat_out> &splat_outs) -> std::vector<char> {
  ryml::Tree tree;
  auto root = tree.rootref();
  root |= ryml::SEQ;

  for(const auto &splat_out : splat_outs) {
    auto obj_yaml = root.append_child();
    obj_yaml |= ryml::MAP;
    obj_yaml |= c4::yml::_WIP_STYLE_FLOW_SL;
    obj_yaml["start"] << std::format("0x{:x}", splat_out.start);
    obj_yaml["vram"] << std::format("0x{:x}", splat_out.vram);
    obj_yaml["type"] << splat_out.type;
    obj_yaml["name"] << splat_out.name;
  }

  return ryml::emitrs_yaml<std::vector<char>>(tree);
}
}