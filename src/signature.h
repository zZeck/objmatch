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
    node["symbol"] = sig_symbol.symbol;
    node["relocations"] = sig_symbol.relocations;
    return node;
  }
  static bool decode(const Node &node, sig_symbol &sig_symbol) {
    sig_symbol.offset = node["offset"].as<uint64_t>();
    sig_symbol.size = node["size"].as<uint64_t>();
    sig_symbol.crc_8 = node["crc_8"].as<uint32_t>();
    sig_symbol.crc_all = node["crc_8"].as<uint32_t>();
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

