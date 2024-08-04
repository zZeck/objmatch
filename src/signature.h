#pragma once

#include <cstdint>
#include <vector>

#include <yaml-cpp/yaml.h>
#include <string.h>

using reloc_entry_t = struct {
  uint32_t type;
  char name[128];
  uint32_t offset;
};

using symbol_entry_t = struct {
  char name[64];
  uint32_t size;
  uint32_t crc_a;
  uint32_t crc_b;
  std::vector<reloc_entry_t> relocs;
};


namespace YAML {
template <>
struct convert<reloc_entry_t> {
  static Node encode(const reloc_entry_t &reloc_entry_entry) {
    Node node;
    node["type"] = reloc_entry_entry.type;
    node["name"] = reloc_entry_entry.name;
    node["offset"] = reloc_entry_entry.offset;
    return node;
  }
  static bool decode(const Node &node, reloc_entry_t &reloc_entry_entry) {
    //if (!node.IsSequence()) return false;
    auto name = node["name"].as<std::string>();
    // check string length first
    strcpy(reloc_entry_entry.name, name.c_str());
    reloc_entry_entry.type = node["type"].as<uint32_t>();
    reloc_entry_entry.offset = node["offset"].as<uint32_t>();

    return true;
  }
};

template <>
struct convert<symbol_entry_t> {
  static Node encode(const symbol_entry_t &symbol_entry) {
    Node node;
    node["symbol"] = symbol_entry.name;
    node["size"] = symbol_entry.size;
    node["crc8"] = symbol_entry.crc_a;
    node["crcAll"] = symbol_entry.crc_b;
    node["relocations"] = symbol_entry.relocs;
    return node;
  }
  static bool decode(const Node &node, symbol_entry_t &symbol_entry) {
    //if (!node.IsSequence()) return false;
    auto name = node["symbol"].as<std::string>();
    // should check string length first
    strcpy(symbol_entry.name, name.c_str());
    symbol_entry.size = node["size"].as<uint32_t>();
    symbol_entry.crc_a = node["crc8"].as<uint32_t>();
    symbol_entry.crc_b = node["crcAll"].as<uint32_t>();
    // is this memory leaking?
    symbol_entry.relocs = node["relocations"].as<std::vector<reloc_entry_t>>();
    return true;
  }
};
}