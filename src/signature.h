#pragma once

#include <cstdint>
#include <vector>

#include <yaml-cpp/yaml.h>
#include <string.h>

using sig_relocation = struct {
  uint64_t type;
  uint64_t offset;
  uint32_t addend;
  bool local;
  std::string name;
};

using sig_symbol = struct {
  uint64_t offset;
  uint64_t size;
  uint32_t crc_8;
  uint32_t crc_all;
  bool duplicate_crc;
  std::string symbol;
  std::vector<sig_relocation> relocations;
};

using sig_section = struct {
  uint64_t size;
  std::string name;
  std::vector<sig_symbol> symbols;
};

using sig_object = struct {
  std::string file;
  std::vector<sig_section> sections;
};

namespace YAML {
template <>
struct convert<sig_relocation> {
  static Node encode(const sig_relocation &sig_relocation) {
    Node node;
    node["type"] = sig_relocation.type;
    node["offset"] = sig_relocation.offset;
    node["addend"] = sig_relocation.addend;
    node["local"] = sig_relocation.local;
    node["name"] = sig_relocation.name;
    return node;
  }
  static bool decode(const Node &node, sig_relocation &sig_relocation) {
    sig_relocation.type = node["type"].as<uint64_t>();
    sig_relocation.offset = node["offset"].as<uint64_t>();
    sig_relocation.addend = node["addend"].as<uint32_t>();
    sig_relocation.local = node["local"].as<bool>();
    sig_relocation.name = node["name"].as<std::string>();
    return true;
  }
};

template <>
struct convert<sig_symbol> {
  static Node encode(const sig_symbol &sig_symbol) {
    Node node;
    node["offset"] = sig_symbol.offset;
    node["size"] = sig_symbol.size;
    node["crc_8"] = sig_symbol.crc_8;
    node["crc_all"] = sig_symbol.crc_all;
    node["duplicate_crc"] = sig_symbol.duplicate_crc;
    node["symbol"] = sig_symbol.symbol;
    node["relocations"] = sig_symbol.relocations;
    return node;
  }
  static bool decode(const Node &node, sig_symbol &sig_symbol) {
    sig_symbol.offset = node["offset"].as<uint64_t>();
    sig_symbol.size = node["size"].as<uint64_t>();
    sig_symbol.crc_8 = node["crc_8"].as<uint32_t>();
    sig_symbol.crc_all = node["crc_all"].as<uint32_t>();
    sig_symbol.duplicate_crc = node["duplicate_crc"].as<bool>();
    sig_symbol.symbol = node["symbol"].as<std::string>();
    sig_symbol.relocations = node["relocations"].as<std::vector<sig_relocation>>();
    return true;
  }
};

template <>
struct convert<sig_section> {
  static Node encode(const sig_section &sig_section) {
    Node node;
    node["size"] = sig_section.size;
    node["name"] = sig_section.name;
    node["symbols"] = sig_section.symbols;
    return node;
  }
  static bool decode(const Node &node, sig_section &sig_section) {
    sig_section.size = node["size"].as<uint64_t>();
    sig_section.name = node["name"].as<std::string>();
    sig_section.symbols = node["symbols"].as<std::vector<sig_symbol>>();
    return true;
  }
};

template <>
struct convert<sig_object> {
  static Node encode(const sig_object &sig_object) {
    Node node;
    node["file"] = sig_object.file;
    node["sections"] = sig_object.sections;
    return node;
  }
  static bool decode(const Node &node, sig_object &sig_object) {
    sig_object.file = node["file"].as<std::string>();
    sig_object.sections = node["sections"].as<std::vector<sig_section>>();
    return true;
  }
};
}

