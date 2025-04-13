#include "section_pattern.h"

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

/*
  std::string object;
  std::string section;
  uint64_t size{};
  uint32_t crc_8{};
  uint32_t crc_all{};
  std::vector<sec_relocation> relocations;

  uint64_t type{};
  uint64_t offset{};
  uint32_t addend{};
*/

namespace pattern_yaml {
auto serialize(const std::vector<section_pattern> &patterns) -> std::vector<char> {
  ryml::Tree tree;
  auto root = tree.rootref();
  root |= ryml::SEQ;

  for(const auto &pattern : patterns) {
    auto pattern_yaml = root.append_child();
    pattern_yaml |= ryml::MAP;
    pattern_yaml["object"] << pattern.object;
    pattern_yaml["section"] << pattern.section;
    pattern_yaml["size"] << std::format("0x{:x}", pattern.size);
    pattern_yaml["crc_8"] << std::format("0x{:x}", pattern.crc_8);
    pattern_yaml["crc_all"] << std::format("0x{:x}", pattern.crc_all);
  }
  return ryml::emitrs_yaml<std::vector<char>>(tree);
}
}
