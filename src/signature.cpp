#include "signature.h"

#include <c4/yml/tree.hpp>
#include <print>
#include <ryml.hpp>
#include <ryml_std.hpp>
#include <vector>

namespace sig_yaml {
auto deserialize(std::vector<char> &bytes) -> std::vector<sig_object> {
  ryml::Tree tree{ryml::parse_in_place(ryml::to_substr(bytes))};  // mutable (csubstr) overload

  auto root{tree.crootref()};

  std::vector<sig_object> sig_objs;
  std::transform(root.begin(), root.end(), std::back_inserter(sig_objs), [](auto obj_yaml) -> sig_object {
    auto sections{obj_yaml["sections"]};
    std::vector<sig_section> sig_sections;
    std::transform(sections.begin(), sections.end(), std::back_inserter(sig_sections), [](auto obj_yaml_section) -> sig_section {
      auto symbols{obj_yaml_section["symbols"]};
      std::vector<sig_symbol> sig_symbols;
      std::transform(symbols.begin(), symbols.end(), std::back_inserter(sig_symbols), [](auto obj_yaml_symbol) -> sig_symbol {
        auto relocations{obj_yaml_symbol["relocations"]};
        std::vector<sig_relocation> sig_relocations;
        std::transform(relocations.begin(), relocations.end(), std::back_inserter(sig_relocations), [](auto obj_yaml_relocation) -> sig_relocation {
          uint64_t type{};
          obj_yaml_relocation["type"] >> type;
          uint64_t offset{};
          obj_yaml_relocation["offset"] >> offset;
          uint32_t addend{};
          obj_yaml_relocation["addend"] >> addend;
          bool local{};
          obj_yaml_relocation["local"] >> local;
          std::string name;
          obj_yaml_relocation["name"] >> name;

          return sig_relocation{.type = type, .offset = offset, .addend = addend, .local = local, .name{name}};
        });

        uint64_t offset{};
        obj_yaml_symbol["offset"] >> offset;
        uint64_t size{};
        obj_yaml_symbol["size"] >> size;
        uint32_t crc_8{};
        obj_yaml_symbol["crc_8"] >> crc_8;
        uint32_t crc_all{};
        obj_yaml_symbol["crc_all"] >> crc_all;
        bool duplicate_crc{};
        obj_yaml_symbol["duplicate_crc"] >> duplicate_crc;
        std::string symbol{};
        obj_yaml_symbol["symbol"] >> symbol;

        return sig_symbol{
            .offset = offset, .size = size, .crc_8 = crc_8, .crc_all = crc_all, .duplicate_crc = duplicate_crc, .symbol{symbol}, .relocations{sig_relocations}};
      });

      uint64_t size{};
      obj_yaml_section["size"] >> size;
      std::string name;
      obj_yaml_section["name"] >> name;

      return sig_section{.size = size, .name{name}, .symbols{sig_symbols}};
    });

    std::string file;
    obj_yaml["file"] >> file;
    return sig_object{.file{file}, .sections{sig_sections}};
  });

  return sig_objs;
}

auto serialize(const std::vector<sig_object> &sig_objs) -> std::vector<char> {
  ryml::Tree tree;
  auto root = tree.rootref();
  root |= ryml::SEQ;

  for (const auto &sig_obj : sig_objs) {
    auto obj_yaml = root.append_child();
    obj_yaml |= ryml::MAP;
    obj_yaml["file"] << sig_obj.file;

    auto obj_yaml_sections = obj_yaml.append_child({ryml::SEQ, "sections"});
    for (const auto &sig_section : sig_obj.sections) {
      auto obj_yaml_section = obj_yaml_sections.append_child();
      obj_yaml_section |= ryml::MAP;
      obj_yaml_section["size"] << sig_section.size;
      obj_yaml_section["name"] << sig_section.name;

      auto obj_yaml_symbols = obj_yaml_section.append_child({ryml::SEQ, "symbols"});
      for (const auto &sig_symbol : sig_section.symbols) {
        auto obj_yaml_symbol = obj_yaml_symbols.append_child();
        obj_yaml_symbol |= ryml::MAP;
        obj_yaml_symbol["offset"] << sig_symbol.offset;
        obj_yaml_symbol["size"] << sig_symbol.size;
        obj_yaml_symbol["crc_8"] << sig_symbol.crc_8;
        obj_yaml_symbol["crc_all"] << sig_symbol.crc_all;
        obj_yaml_symbol["duplicate_crc"] << std::format("{:s}", sig_symbol.duplicate_crc);
        obj_yaml_symbol["symbol"] << sig_symbol.symbol;

        auto obj_yaml_relocations = obj_yaml_symbol.append_child({ryml::SEQ, "relocations"});
        for (const auto &sig_reloc : sig_symbol.relocations) {
          auto obj_yaml_relocation = obj_yaml_relocations.append_child();
          obj_yaml_relocation |= ryml::MAP;

          obj_yaml_relocation["type"] << sig_reloc.type;
          obj_yaml_relocation["offset"] << sig_reloc.offset;
          obj_yaml_relocation["addend"] << sig_reloc.addend;
          obj_yaml_relocation["local"] << std::format("{:s}", sig_reloc.local);
          obj_yaml_relocation["name"] << sig_reloc.name;
        }
      }
    }
  }

  return ryml::emitrs_yaml<std::vector<char>>(tree);
}
}  // namespace sig_yaml