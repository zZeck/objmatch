#include "splat_out.h"

#include <format>
#include <vector>

#include <c4/format.hpp>
#include <ryml.hpp>
#include <ryml_std.hpp>

namespace splat_yaml {
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